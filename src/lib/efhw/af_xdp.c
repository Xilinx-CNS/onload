/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */
#include <ci/efhw/af_xdp.h>

#ifdef EFHW_HAS_AF_XDP

#include <ci/driver/kernel_compat.h>

#include <ci/efhw/nic.h>
#include <ci/efhw/eventq.h>
#include <ci/driver/efab/hardware/af_xdp.h>

#include <linux/socket.h>

#include <linux/if_xdp.h>
#include <linux/file.h>
#include <linux/bpf.h>
#include <linux/mman.h>
#include <linux/fdtable.h>
#include <linux/sched/signal.h>
#include <net/sock.h>

#include <ci/efrm/syscall.h>

#define UMEM_BLOCK (PAGE_SIZE / sizeof(void*))
#define MAX_PDS 256

/* A block of addresses of user memory pages */
struct umem_block
{
  void* addrs[UMEM_BLOCK];
};

/* A collection of all the user memory pages for a VI */
struct umem_pages
{
  long page_count;
  long block_count;
  long used_page_count;

  struct umem_block** blocks;
};

/* Resources for waiting for and handling events */
struct event_waiter
{
  struct wait_queue_entry wait;

  struct efhw_nic* nic;
  struct efhw_ev_handler* ev_handlers;
  int evq;
  int budget;
};

/* Per-VI AF_XDP resources */
struct efhw_af_xdp_vi
{
  struct socket* sock;
  int owner_id;
  int rxq_capacity;
  int txq_capacity;
  unsigned flags;

  struct efab_af_xdp_offsets kernel_offsets;
  struct efhw_page user_offsets_page;
  struct event_waiter waiter;
};

struct protection_domain
{
  struct umem_pages umem;
  long buffer_table_count;
  long freed_buffer_table_count;
};

/* Per-NIC AF_XDP resources */
struct efhw_nic_af_xdp
{
  struct file* map;
  struct file* shadow;
  struct efhw_ev_handler* ev_handlers;
  struct efhw_af_xdp_vi* vi;
  struct protection_domain* pd;
};

/*----------------------------------------------------------------------------
 *
 * User memory helper functions
 *
 *---------------------------------------------------------------------------*/

/* Free the collection of page addresses. Does not free the pages themselves. */
static void umem_pages_free(struct umem_pages* pages)
{
  long block;

  for( block = 0; block < pages->block_count; ++block )
    kfree(pages->blocks[block]);

  kfree(pages->blocks);
}

/* Allocate storage for a number of new page addresses, initially NULL */
static int umem_pages_alloc(struct umem_pages* pages, long new_pages)
{
  long blocks = (pages->page_count + new_pages + UMEM_BLOCK - 1) / UMEM_BLOCK;
  void* alloc;

  alloc = krealloc(pages->blocks, blocks * sizeof(void*), GFP_KERNEL);
  if( alloc == NULL )
    return -ENOMEM;
  pages->blocks = alloc;

  /* It is important to update block_count after each allocation so that
   * it has the correct value if an allocation fails. umem_pages_free
   * will need the correct value to free everything that was allocated.
   */
  while( pages->block_count < blocks ) {
    alloc = kzalloc(sizeof(struct umem_block), GFP_KERNEL);
    if( alloc == NULL )
      return -ENOMEM;

    pages->blocks[pages->block_count++] = alloc;
  }

  pages->page_count += new_pages;
  return 0;
}

/* Access the user memory page address with the given linear index */
static void** umem_pages_addr_ptr(struct umem_pages* pages, long index)
{
  return &pages->blocks[index / UMEM_BLOCK]->addrs[index % UMEM_BLOCK];
}

static void umem_pages_set_addr(struct umem_pages* pages, long page, void* addr)
{
  *umem_pages_addr_ptr(pages, page) = addr;
  if( page > pages->used_page_count )
    pages->used_page_count = page;
}

static void* umem_pages_get_addr(struct umem_pages* pages, long page)
{
  return *umem_pages_addr_ptr(pages, page);
}

/*----------------------------------------------------------------------------
 *
 * VI access functions
 *
 *---------------------------------------------------------------------------*/

/* Get the VI with the given instance number */
static struct efhw_af_xdp_vi* vi_by_instance(struct efhw_nic* nic, int instance)
{
  struct efhw_nic_af_xdp* xdp = nic->af_xdp;

  if( xdp == NULL || instance >= nic->vi_lim )
    return NULL;

  return &xdp->vi[instance];
}

/* Get the VI with the given owner ID */
static struct protection_domain* pd_by_owner(struct efhw_nic* nic, int owner_id)
{
  struct efhw_nic_af_xdp* xdp = nic->af_xdp;

  if( xdp == NULL || owner_id > MAX_PDS || owner_id < 0 )
    return NULL;

  return &xdp->pd[owner_id];
}

/*----------------------------------------------------------------------------
 *
 * BPF/XDP helper functions
 *
 *---------------------------------------------------------------------------*/

/* Invoke the bpf() syscall args is assumed to be kernel memory */
static int sys_bpf(int cmd, union bpf_attr* attr)
{
#if defined(__NR_bpf) && defined(EFRM_SYSCALL_PTREGS) && defined(CONFIG_X86_64)
  struct pt_regs regs;
  static asmlinkage long (*sys_call)(const struct pt_regs*) = NULL;

  if( sys_call == NULL ) {
    if( efrm_syscall_table == NULL || efrm_syscall_table[__NR_bpf] == NULL )
      return -ENOSYS;

    sys_call = efrm_syscall_table[__NR_bpf];
  }

  regs.di = cmd;
  regs.si = (uintptr_t)(attr);
  regs.dx = sizeof(*attr);
  {
    int rc;
    mm_segment_t oldfs = get_fs();

    set_fs(KERNEL_DS);
    rc = sys_call(&regs);
    set_fs(oldfs);
    return rc;
  }
#else
  return -ENOSYS;
#endif
}

/* Allocate an FD for a file. Some operations need them. */
static int xdp_alloc_fd(struct file* file)
{
  int rc;

  /* TODO AF_XDP:
   * In weird context or when exiting process (that is current->files == NULL)
   * we cannot do much (for now this is a stack teardown) */
  if( !current || !current->files )
    return -EAGAIN;

  rc = get_unused_fd_flags(0);
  if( rc < 0 )
    return rc;

  get_file(file);
  fd_install(rc, file);
  return rc;
}

/* Create the xdp socket map to share with the BPF program */
static int xdp_map_create(int max_entries)
{
  int rc;
  union bpf_attr attr = {};

  attr.map_type = BPF_MAP_TYPE_XSKMAP;
  attr.key_size = sizeof(int);
  attr.value_size = sizeof(int);
  attr.max_entries = max_entries;
  strncpy(attr.map_name, "onload_xsks", sizeof(attr.map_name));
  rc = sys_bpf(BPF_MAP_CREATE, &attr);
  return rc;
}

/* Create the shadow map to support older kernels' dysfunctional redirection */
static int xdp_map_create_shadow(int max_entries)
{
  int rc;
  union bpf_attr attr = {};

  attr.map_type = BPF_MAP_TYPE_ARRAY;
  attr.key_size = sizeof(int);
  attr.value_size = 1;
  attr.max_entries = max_entries;
  strncpy(attr.map_name, "onload_shadow", sizeof(attr.map_name));
  rc = sys_bpf(BPF_MAP_CREATE, &attr);
  return rc;
}

/* Load the BPF program to redirect inbound packets to AF_XDP sockets.
 * See af_xdp_bpf.c for the program's source and compilation guidelines. */
static int xdp_prog_load(int map_fd, int shadow_fd)
{
  uint64_t mfdH = (uint64_t) map_fd << 32;
  uint64_t sfdH = (uint64_t) shadow_fd << 32;
  const uint64_t prog[] = {
    0x00000002000000b7, 0x0000000000041361,
    0x0000000000001261, 0x00000000000024bf,
    0x0000002200000407, 0x000000000028342d,
    0x0000000000002379, 0xffffffff00000418,
    0x0000ffff00000000, 0x000000000000435f,
    0x000000000023431d, 0x00000000000c2369,
    0x0000008100020355, 0x0000000000102369,
    0x0000000400000207, 0x00000017000004b7,
    0x0000000800020315, 0x0000dd86001c0355,
    0x00000014000004b7, 0x000000000000420f,
    0x0000000000002271, 0x0000001100010215,
    0x0000000600170255, 0x0000000000101261,
    0x00000000fffc2a63,  mfdH | 0x00001118,
    0x0000000000000000, 0x00000002000003b7,
    0x0000003300000085, 0x00000000000001bf,
    0x0000002000000167, 0x0000002000000177,
    0x00000000000d0155, 0x000000000000a2bf,
    0xfffffffc00000207,  sfdH | 0x00001118,
    0x0000000000000000, 0x0000000100000085,
    0x00000000000001bf, 0x00000002000000b7,
    0x0000000000050115, 0x00000000fffca261,
     mfdH | 0x00001118, 0x0000000000000000,
    0x00000000000003b7, 0x0000003300000085,
    0x0000000000000095,
  };

  char license[] = "GPL";
  union bpf_attr attr = {};
  int rc;

  attr.prog_type = BPF_PROG_TYPE_XDP;
  attr.insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
  attr.insns = (uintptr_t)prog;
  attr.license = (uintptr_t)license;
  strncpy(attr.prog_name, "xdpsock", strlen("xdpsock"));

  rc = sys_bpf(BPF_PROG_LOAD, &attr);
  return rc;
}

/* Update an element in the XDP socket map (using fds) */
static int xdp_map_update_fd(int map_fd, int key, int sock_fd)
{
  union bpf_attr attr = {};

  attr.map_fd = map_fd;
  attr.key = (uintptr_t)(&key);
  attr.value = (uintptr_t)(&sock_fd);

  return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

/* Update an element in the XDP socket map (using file pointers) */
static int xdp_map_update(struct file* map, struct file* shadow, int key,
                          struct file* sock)
{
  int rc, map_fd, shadow_fd, sock_fd;

  rc = map_fd = xdp_alloc_fd(map);
  if( rc < 0 )
    return rc;

  rc = shadow_fd = xdp_alloc_fd(shadow);
  if( rc < 0 )
    goto fail_shadow;

  rc = sock_fd = xdp_alloc_fd(sock);
  if( rc < 0 )
    goto fail_sock;

  rc = xdp_map_update_fd(map_fd, key, sock_fd);
  if( rc < 0 )
    goto fail_update;

  rc = xdp_map_update_fd(shadow_fd, key, 1);

  /* It should be impossible for only one update to succeed, but if that does
   * happen then we have an inconsistent state which may cause subtle problems.
   * Assert here to make the problem more obvious.
   */
  BUG_ON(rc < 0);

fail_update:
  __close_fd(current->files, sock_fd);
fail_sock:
  __close_fd(current->files, shadow_fd);
fail_shadow:
  __close_fd(current->files, map_fd);
  return rc;
}

/* Delete an element in the XDP socket map (using fds) */
static void xdp_map_delete_fd(int map_fd, int key)
{
  union bpf_attr attr = {};

  attr.map_fd = map_fd;
  attr.key = (uintptr_t)(&key);

  sys_bpf(BPF_MAP_DELETE_ELEM, &attr);
}

/* Delete an element in the XDP socket map (using file pointers) */
static void xdp_map_delete(struct file* map, struct file* shadow, int key)
{
  int fd;

  fd = xdp_alloc_fd(map);
  if( fd >= 0 ) {
    xdp_map_delete_fd(fd, key);
    __close_fd(current->files, fd);
  }

  fd = xdp_alloc_fd(shadow);
  if( fd >= 0 ) {
    xdp_map_delete_fd(fd, key);
    __close_fd(current->files, fd);
  }
}

/* Bind an AF_XDP socket to an interface */
static int xdp_bind(struct socket* sock, int ifindex, unsigned queue, unsigned flags)
{
  struct sockaddr_xdp sxdp = {};

  sxdp.sxdp_family = PF_XDP;
  sxdp.sxdp_ifindex = ifindex;
  sxdp.sxdp_queue_id = queue;
  sxdp.sxdp_flags = flags;

  return kernel_bind(sock, (struct sockaddr*)&sxdp, sizeof(sxdp));
}

/* Link an XDP program to an interface */
static int xdp_set_link(struct net_device* dev, struct bpf_prog* prog)
{
  bpf_op_t op = dev->netdev_ops->ndo_bpf;
  struct netdev_bpf bpf = {
    .command = XDP_SETUP_PROG,
    .prog = prog
  };

  if( !op )
    EFHW_ERR("%s: %s does not support XDP", __FUNCTION__, dev->name);

  return op ? op(dev, &bpf) : -ENOSYS;
}

/* Fault handler to provide buffer memory pages for our user mapping */
static vm_fault_t xdp_umem_fault(struct vm_fault* vmf) {
  struct umem_pages* pages = vmf->vma->vm_private_data;
  struct page* page;

  if( vmf->pgoff >= pages->used_page_count )
    return VM_FAULT_SIGSEGV;

  page = virt_to_page(umem_pages_get_addr(pages, vmf->pgoff));

  /* Linux page management assumes we won't provide individual pages from a
   * hugetlbfs page, and goes wrong in bad ways if we do. Prevent that by
   * returning an error here. Also raise a BUG() as this should never happen:
   * onload should disable hugetlbfs support, and there is currently no other
   * supported way to create an AF_XDP VI.
   */
  if( PageHuge(page) ) {
    EFHW_ERR("%s: hubetlbfs pages are incompatible with AF_XDP", __FUNCTION__);
    BUG();
    return VM_FAULT_SIGSEGV;
  }

  get_page(page);
  vmf->page = page;
  return 0;
}

static struct vm_operations_struct vm_ops = {
  .fault = xdp_umem_fault
};

/* Register user memory with an XDP socket */
static int xdp_register_umem(struct socket* sock, struct umem_pages* pages,
                             int chunk_size, int headroom)
{
  struct vm_area_struct* vma;
  int rc = -EFAULT;

  /* The actual fields present in this struct vary with kernel version, with
   * a flags fields added in 5.4. We don't currently need to set any flags,
   * so just zero everything we don't use.
   */
  struct xdp_umem_reg mr = {
    .len = pages->used_page_count << PAGE_SHIFT,
    .chunk_size = chunk_size,
    .headroom = headroom
  };

  mr.addr = vm_mmap(NULL, 0, mr.len, PROT_READ | PROT_WRITE, MAP_SHARED, 0);
  if( offset_in_page(mr.addr) )
    return mr.addr;

  down_write(&current->mm->mmap_sem);
  vma = find_vma(current->mm, mr.addr);
  up_write(&current->mm->mmap_sem);

  BUG_ON(vma == NULL);
  BUG_ON(vma->vm_start != mr.addr);

  vma->vm_private_data = pages;
  vma->vm_ops = &vm_ops;

  rc = kernel_setsockopt(sock, SOL_XDP, XDP_UMEM_REG, (char*)&mr, sizeof(mr));

  vm_munmap(mr.addr, mr.len);
  return rc;
}

/* Create the rings for an AF_XDP socket and associated umem */
static int xdp_create_ring(struct socket* sock,
                           struct efhw_page_map* page_map, void* kern_mem_base,
                           int capacity, int desc_size, int sockopt, long pgoff,
                           const struct xdp_ring_offset* xdp_offset,
                           struct efab_af_xdp_offsets_ring* kern_offset,
                           struct efab_af_xdp_offsets_ring* user_offset)
{
  int rc;
  unsigned long map_size, addr, pfn, pages;
  int64_t user_base, kern_base;
  struct vm_area_struct* vma;
  void* ring_base;

  user_base = page_map->n_pages << PAGE_SHIFT;

  rc = kernel_setsockopt(sock, SOL_XDP, sockopt, (char*)&capacity, sizeof(int));
  if( rc < 0 )
    return rc;

  map_size = xdp_offset->desc + (capacity + 1) * desc_size;
  addr = vm_mmap(sock->file, 0, map_size, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_POPULATE, pgoff);
  if( IS_ERR_VALUE(addr) )
      return addr;

  down_write(&current->mm->mmap_sem);

  vma = find_vma(current->mm, addr);
  if( vma == NULL ) {
    rc = -EFAULT;
  }
  else {
    rc = follow_pfn(vma, addr, &pfn);
    pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
  }
  up_write(&current->mm->mmap_sem);

  if( rc >= 0 ) {
    ring_base = phys_to_virt(pfn << PAGE_SHIFT);
    rc = efhw_page_map_add_lump(page_map, ring_base, pages);
  }

  vm_munmap(addr, map_size);

  if( rc < 0 )
    return rc;

  kern_base = ring_base - kern_mem_base;
  kern_offset->producer = kern_base + xdp_offset->producer;
  kern_offset->consumer = kern_base + xdp_offset->consumer;
  kern_offset->desc     = kern_base + xdp_offset->desc;

  user_offset->producer = user_base + xdp_offset->producer;
  user_offset->consumer = user_base + xdp_offset->consumer;
  user_offset->desc     = user_base + xdp_offset->desc;

  return 0;
}

static int xdp_create_rings(struct socket* sock,
                            struct efhw_page_map* page_map, void* kern_mem_base,
                            long rxq_capacity, long txq_capacity,
                            struct efab_af_xdp_offsets_rings* kern_offsets,
                            struct efab_af_xdp_offsets_rings* user_offsets)
{
  int rc, optlen;
  struct xdp_mmap_offsets mmap_offsets;

  EFHW_BUILD_ASSERT(EFAB_AF_XDP_DESC_BYTES == sizeof(struct xdp_desc));

  optlen = sizeof(mmap_offsets);
  rc = kernel_getsockopt(sock, SOL_XDP, XDP_MMAP_OFFSETS,
                         (char*)&mmap_offsets, &optlen);
  if( rc < 0 )
    return rc;

  rc = xdp_create_ring(sock, page_map, kern_mem_base,
                       rxq_capacity, sizeof(struct xdp_desc),
                       XDP_RX_RING, XDP_PGOFF_RX_RING,
                       &mmap_offsets.rx, &kern_offsets->rx, &user_offsets->rx);
  if( rc < 0 )
    return rc;

  rc = xdp_create_ring(sock, page_map, kern_mem_base,
                       txq_capacity, sizeof(struct xdp_desc),
                       XDP_TX_RING, XDP_PGOFF_TX_RING,
                       &mmap_offsets.tx, &kern_offsets->tx, &user_offsets->tx);
  if( rc < 0 )
    return rc;

  rc = xdp_create_ring(sock, page_map, kern_mem_base,
                       rxq_capacity, sizeof(uint64_t),
                       XDP_UMEM_FILL_RING, XDP_UMEM_PGOFF_FILL_RING,
                       &mmap_offsets.fr, &kern_offsets->fr, &user_offsets->fr);
  if( rc < 0 )
    return rc;

  rc = xdp_create_ring(sock, page_map, kern_mem_base,
                       txq_capacity, sizeof(uint64_t),
                       XDP_UMEM_COMPLETION_RING, XDP_UMEM_PGOFF_COMPLETION_RING,
                       &mmap_offsets.cr, &kern_offsets->cr, &user_offsets->cr);
  if( rc < 0 )
    return rc;

  return 0;
}

static void xdp_release_pd(struct efhw_nic* nic, int owner)
{
  struct protection_domain* pd = pd_by_owner(nic, owner);
  BUG_ON(pd == NULL);
  BUG_ON(pd->freed_buffer_table_count >= pd->buffer_table_count);

  if( ++pd->freed_buffer_table_count != pd->buffer_table_count )
    return;

  umem_pages_free(&pd->umem);
  memset(pd, 0, sizeof(*pd));
}

static void xdp_release_vi(struct efhw_nic* nic, struct efhw_af_xdp_vi* vi)
{
  xdp_map_delete(nic->af_xdp->map, nic->af_xdp->shadow, vi - nic->af_xdp->vi);
  efhw_page_free(&vi->user_offsets_page);
  fput(vi->sock->file);
  memset(vi, 0, sizeof(*vi));
}

/*----------------------------------------------------------------------------
 *
 * Public AF_XDP interface
 *
 *---------------------------------------------------------------------------*/
static void* af_xdp_mem(struct efhw_nic* nic, int instance)
{
  struct efhw_af_xdp_vi* vi = vi_by_instance(nic, instance);
  return vi ? &vi->kernel_offsets : NULL;
}

static int af_xdp_init(struct efhw_nic* nic, int instance,
                       int chunk_size, int headroom,
                       struct efhw_page_map* page_map)
{
  int rc;
  struct efhw_af_xdp_vi* vi;
  int owner_id;
  struct protection_domain* pd;
  struct socket* sock;
  struct file* file;
  struct efab_af_xdp_offsets* user_offsets;

  if( chunk_size == 0 ||
      chunk_size < headroom ||
      chunk_size > PAGE_SIZE ||
      PAGE_SIZE % chunk_size != 0 )
    return -EINVAL;

  vi = vi_by_instance(nic, instance);
  if( vi == NULL )
    return -ENODEV;

  if( vi->sock != NULL )
    return -EBUSY;

  owner_id = vi->owner_id;
  pd = pd_by_owner(nic, owner_id);
  if( vi == NULL )
    return -EINVAL;

  /* We need to use network namespace of network device so that
   * ifindex passed in bpf syscalls makes sense
   * TODO AF_XDP: there is a race here with device changing netns
   * TODO AF_XDP: this fails unless the user namespace has CAP_NET_RAW
   */
  rc = __sock_create(dev_net(nic->net_dev), AF_XDP, SOCK_RAW, 0, &sock, 0);
  if( rc < 0 )
    return rc;

  file = sock_alloc_file(sock, 0, NULL);
  if( IS_ERR(file) )
    return PTR_ERR(file);
  vi->sock = sock;

  rc = efhw_page_alloc_zeroed(&vi->user_offsets_page);
  if( rc < 0 )
    goto out_free_sock;
  user_offsets = (void*)efhw_page_ptr(&vi->user_offsets_page);

  rc = efhw_page_map_add_page(page_map, &vi->user_offsets_page);
  if( rc < 0 )
    goto out_free_user_offsets;

  rc = xdp_register_umem(sock, &pd->umem, chunk_size, headroom);
  if( rc < 0 )
    goto out_free_user_offsets;

  rc = xdp_create_rings(sock, page_map, &vi->kernel_offsets,
                        vi->rxq_capacity, vi->txq_capacity,
                        &vi->kernel_offsets.rings, &user_offsets->rings);
  if( rc < 0 )
    goto out_free_user_offsets;

  rc = xdp_map_update(nic->af_xdp->map, nic->af_xdp->shadow, instance, file);
  if( rc < 0 )
    goto out_free_user_offsets;

  /* TODO AF_XDP: currently instance number matches net_device channel */
  rc = xdp_bind(sock, nic->net_dev->ifindex, instance, vi->flags);
  if( rc == -EBUSY ) {
    /* AF_XDP resource release happens asynchronously - the socket through RCU
     * and the associated umem through deferred work on the global workqueue.
     * That means that even if we think we can re-use this instance, it may not
     * actually be free yet.
     * We stick an rcu_barrier() here in an attempt to force any outstanding
     * socket release to have completed, and try again.
     */
    rcu_barrier();
    flush_scheduled_work();
    rc = xdp_bind(sock, nic->net_dev->ifindex, instance, vi->flags);
  }
  if( rc < 0 )
    goto out_clear_map;

  if( vi->waiter.wait.func != NULL )
    add_wait_queue(sk_sleep(vi->sock->sk), &vi->waiter.wait);

  user_offsets->mmap_bytes = efhw_page_map_bytes(page_map);
  return 0;

 out_clear_map:
  xdp_map_delete(nic->af_xdp->map, nic->af_xdp->shadow, instance);
 out_free_user_offsets:
  efhw_page_free(&vi->user_offsets_page);
 out_free_sock:
  fput(file);
  memset(vi, 0, sizeof(*vi));
  return rc;
}

static int af_xdp_dmaq_kick(struct efhw_nic *nic, int instance)
{
  struct efhw_af_xdp_vi* vi;
  struct msghdr msg = {.msg_flags = MSG_DONTWAIT};
  vi = vi_by_instance(nic, instance);
  if( vi == NULL )
    return -ENODEV;

  return kernel_sendmsg(vi->sock, &msg, NULL, 0, 0);
}

/*----------------------------------------------------------------------------
 *
 * Initialisation and configuration discovery
 *
 *---------------------------------------------------------------------------*/
static int
af_xdp_nic_license_check(struct efhw_nic *nic, const uint32_t feature,
		       int* licensed)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return 0;
}


static int
af_xdp_nic_v3_license_check(struct efhw_nic *nic, const uint64_t app_id,
		       int* licensed)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return 0;
}


static int
af_xdp_nic_license_challenge(struct efhw_nic *nic,
			   const uint32_t feature,
			   const uint8_t* challenge,
			   uint32_t* expiry,
			   uint8_t* signature)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return 0;
}


static int
af_xdp_nic_v3_license_challenge(struct efhw_nic *nic,
			   const uint64_t app_id,
			   const uint8_t* challenge,
			   uint32_t* expiry,
			   uint32_t* days,
			   uint8_t* signature,
                           uint8_t* base_mac,
                           uint8_t* vadaptor_mac)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return 0;
}


static void
af_xdp_nic_tweak_hardware(struct efhw_nic *nic)
{
	nic->pio_num = 0;
	nic->pio_size = 0;
	nic->tx_alts_vfifos = 0;
	nic->tx_alts_cp_bufs = 0;
	nic->tx_alts_cp_buf_size = 0;
        nic->rx_variant = 0;
        nic->tx_variant = 0;
        nic->rx_prefix_len = 0;
	nic->flags = NIC_FLAG_RX_ZEROCOPY; /* TODO AFXDP: hardcoded for now */
}



static int
__af_xdp_nic_init_hardware(struct efhw_nic *nic,
			   struct efhw_ev_handler *ev_handlers,
			   const uint8_t *mac_addr)
{
	int map_fd, shadow_fd, rc;
	struct bpf_prog* prog;
	struct efhw_nic_af_xdp* xdp;

	xdp = kzalloc(sizeof(*xdp) +
		      nic->vi_lim * sizeof(struct efhw_af_xdp_vi) +
		      MAX_PDS * sizeof(struct protection_domain),
		      GFP_KERNEL);
	if( xdp == NULL )
		return -ENOMEM;

	xdp->ev_handlers = ev_handlers;
	xdp->vi = (struct efhw_af_xdp_vi*) (xdp + 1);
	xdp->pd = (struct protection_domain*) (xdp->vi + nic->vi_lim);

	rc = map_fd = xdp_map_create(nic->vi_lim);
	if( rc < 0 )
		goto fail_map;

	rc = shadow_fd = xdp_map_create_shadow(nic->vi_lim);
	if( rc < 0 )
		goto fail_shadow;

	rc = xdp_prog_load(map_fd, shadow_fd);
	if( rc < 0 )
		goto fail;

	prog = bpf_prog_get_type_dev(rc, BPF_PROG_TYPE_XDP, 1);
	__close_fd(current->files, rc);
	if( IS_ERR(prog) ) {
		rc = PTR_ERR(prog);
		goto fail;
	}

	rc = xdp_set_link(nic->net_dev, prog);
	if( rc < 0 )
		goto fail;

	xdp->map = fget(map_fd);
	__close_fd(current->files, map_fd);

	xdp->shadow = fget(shadow_fd);
	__close_fd(current->files, shadow_fd);

	nic->af_xdp = xdp;
	memcpy(nic->mac_addr, mac_addr, ETH_ALEN);

	af_xdp_nic_tweak_hardware(nic);
	return 0;

fail:
	__close_fd(current->files, shadow_fd);
fail_shadow:
	__close_fd(current->files, map_fd);
fail_map:
	kfree(xdp);
	return rc;
}

static int
af_xdp_nic_init_hardware(struct efhw_nic *nic,
			 struct efhw_ev_handler *ev_handlers,
			 const uint8_t *mac_addr)
{
	int rc = __af_xdp_nic_init_hardware(nic, ev_handlers, mac_addr);

/* This ifdefiry is copied from sys_bpf above, because this function is
 * useless otherwise. */
#if defined(__NR_bpf) && defined(EFRM_SYSCALL_PTREGS) && defined(CONFIG_X86_64)
	static asmlinkage long (*set)(const struct pt_regs*) = NULL;
	struct pt_regs regs;
	mm_segment_t oldfs;
	struct rlimit rlim;

	if (rc != -EPERM)
		return rc;

	/* EPERM probably means that we are limited by
	 * RLIMIT_MEMLOCK.  Let's work around it. */
	if (set == NULL) {
		if( efrm_syscall_table == NULL ||
		    efrm_syscall_table[__NR_setrlimit] == NULL)
			return -ENOSYS;
		set = efrm_syscall_table[__NR_setrlimit];
	}

	/* We need a page per a bpf call: + 3 pages */
	rlim.rlim_cur = task_rlimit(current, RLIMIT_MEMLOCK) +
				(3 << PAGE_SHIFT);
	rlim.rlim_max = CI_MAX(task_rlimit_max(current, RLIMIT_MEMLOCK),
			       rlim.rlim_cur);

	regs.di = RLIMIT_MEMLOCK;
	regs.si = (uintptr_t)&rlim;
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	rc = set(&regs);
	set_fs(oldfs);
	if (rc != 0)
		return rc;

	rc = __af_xdp_nic_init_hardware(nic, ev_handlers, mac_addr);
#endif
	return rc;
}
static void
af_xdp_nic_release_hardware(struct efhw_nic* nic)
{
  xdp_set_link(nic->net_dev, NULL);
  if( nic->af_xdp != NULL ) {
    fput(nic->af_xdp->map);
    fput(nic->af_xdp->shadow);
    kfree(nic->af_xdp);
  }
}

/*--------------------------------------------------------------------
 *
 * Event Management - and SW event posting
 *
 *--------------------------------------------------------------------*/

static int wait_callback(struct wait_queue_entry* wait, unsigned mode,
                         int flags, void* key)
{
  struct event_waiter* w = container_of(wait, struct event_waiter, wait);
  efhw_handle_wakeup_event(w->nic, w->ev_handlers, w->evq, w->budget);
  return 1;
}

/* This function will enable the given event queue with the requested
 * properties.
 */
static int
af_xdp_nic_event_queue_enable(struct efhw_nic *nic, uint evq, uint evq_size,
                              dma_addr_t *dma_addrs,
                              uint n_pages, int interrupting, int enable_dos_p,
                              int wakeup_evq, int flags, int* flags_out)
{
  struct efhw_af_xdp_vi* vi = vi_by_instance(nic, evq);

  if( vi == NULL )
    return -ENODEV;

  init_waitqueue_func_entry(&vi->waiter.wait, wait_callback);
  vi->waiter.nic = nic;
  vi->waiter.ev_handlers = nic->af_xdp->ev_handlers;
  vi->waiter.evq = wakeup_evq;
  /* The budget currently has little relevance as Onload doesn't try to
   * poll AF_XDP from an interrupt context. The value may need some thought
   * if that changes in future. */
  vi->waiter.budget = 64;

  if( vi->sock != NULL )
    add_wait_queue(sk_sleep(vi->sock->sk), &vi->waiter.wait);

  return 0;
}

static void
af_xdp_nic_event_queue_disable(struct efhw_nic *nic, uint evq,
			     int time_sync_events_enabled)
{
	struct efhw_af_xdp_vi* vi = vi_by_instance(nic, evq);
	if( vi != NULL )
		xdp_release_vi(nic, vi);
}

static void
af_xdp_nic_wakeup_request(struct efhw_nic *nic, volatile void __iomem* io_page,
			int vi_id, int rptr)
{
}

static void af_xdp_nic_sw_event(struct efhw_nic *nic, int data, int evq)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
}

/*--------------------------------------------------------------------
 *
 * EF10 specific event callbacks
 *
 *--------------------------------------------------------------------*/

static int
af_xdp_handle_event(struct efhw_nic *nic, struct efhw_ev_handler *h,
		  efhw_event_t *ev, int budget)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}


/*----------------------------------------------------------------------------
 *
 * TX Alternatives
 *
 *---------------------------------------------------------------------------*/


static int
af_xdp_tx_alt_alloc(struct efhw_nic *nic, int tx_q_id, int num_alt,
		  int num_32b_words, unsigned *cp_id_out, unsigned *alt_ids_out)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return -EOPNOTSUPP;
}


static int
af_xdp_tx_alt_free(struct efhw_nic *nic, int num_alt, unsigned cp_id,
		 const unsigned *alt_ids)
{
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}


/*----------------------------------------------------------------------------
 *
 * DMAQ low-level register interface
 *
 *---------------------------------------------------------------------------*/


static int
af_xdp_dmaq_tx_q_init(struct efhw_nic *nic, uint dmaq, uint evq_id, uint own_id,
                      uint tag, uint dmaq_size,
                      dma_addr_t *dma_addrs, int n_dma_addrs,
                      uint vport_id, uint stack_id, uint flags)
{
  struct efhw_af_xdp_vi* vi = vi_by_instance(nic, evq_id);
  if( vi == NULL )
    return -ENODEV;

  vi->owner_id = own_id;
  vi->txq_capacity = dmaq_size;

  return 0;
}


static int
af_xdp_dmaq_rx_q_init(struct efhw_nic *nic, uint dmaq, uint evq_id, uint own_id,
		    uint tag, uint dmaq_size,
		    dma_addr_t *dma_addrs, int n_dma_addrs,
		    uint vport_id, uint stack_id, uint ps_buf_size, uint flags)
{
  struct efhw_af_xdp_vi* vi = vi_by_instance(nic, evq_id);
  if( vi == NULL )
    return -ENODEV;

  vi->owner_id = own_id;
  vi->rxq_capacity = dmaq_size;
  vi->flags |= (flags & EFHW_VI_RX_ZEROCOPY) ? XDP_ZEROCOPY : XDP_COPY;

  return 0;
}


static void af_xdp_dmaq_tx_q_disable(struct efhw_nic *nic, uint dmaq)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
}

static void af_xdp_dmaq_rx_q_disable(struct efhw_nic *nic, uint dmaq)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - mid level API
 *
 *--------------------------------------------------------------------*/


static int af_xdp_flush_tx_dma_channel(struct efhw_nic *nic, uint dmaq)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return -EOPNOTSUPP;
}


static int af_xdp_flush_rx_dma_channel(struct efhw_nic *nic, uint dmaq)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return -EOPNOTSUPP;
}


/*--------------------------------------------------------------------
 *
 * Buffer table - API
 *
 *--------------------------------------------------------------------*/

static const int __af_xdp_nic_buffer_table_get_orders[] = {0,1,2,3,4,5,6,7,8,9,10};


static int
af_xdp_nic_buffer_table_alloc(struct efhw_nic *nic, int owner, int order,
                              struct efhw_buffer_table_block **block_out,
                              int reset_pending)
{
  struct efhw_buffer_table_block* block;
  struct protection_domain* pd = pd_by_owner(nic, owner);
  int rc;

  if( pd == NULL )
    return -ENODEV;

  /* We reserve some bits of the handle to store the order, needed later to
   * calculate the address of each entry within the block. This limits the
   * number of owners we can support. Alternatively, we could use the high bits
   * of btb_vaddr (as ef10 does), and mask these out when using the addresses.
   */
  if( owner >= (1 << 24) )
    return -ENOSPC;

  block = kzalloc(sizeof(**block_out), GFP_KERNEL);
  if( block == NULL )
    return -ENOMEM;

  /* TODO use af_xdp-specific data rather than repurposing ef10-specific */
  block->btb_hw.ef10.handle = order | (owner << 8);
  block->btb_vaddr = pd->umem.page_count << PAGE_SHIFT;

  rc = umem_pages_alloc(&pd->umem, EFHW_BUFFER_TABLE_BLOCK_SIZE << order);
  if( rc < 0 ) {
    kfree(block);
    return rc;
  }
  ++pd->buffer_table_count;

  *block_out = block;
  return 0;
}


static int
af_xdp_nic_buffer_table_realloc(struct efhw_nic *nic, int owner, int order,
                                struct efhw_buffer_table_block *block)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return -EOPNOTSUPP;
}


static void
af_xdp_nic_buffer_table_free(struct efhw_nic *nic,
                             struct efhw_buffer_table_block *block,
                             int reset_pending)
{
  int owner = block->btb_hw.ef10.handle >> 8;
  kfree(block);
  xdp_release_pd(nic, owner);
}


static int
af_xdp_nic_buffer_table_set(struct efhw_nic *nic,
                            struct efhw_buffer_table_block *block,
                            int first_entry, int n_entries,
                            dma_addr_t *dma_addrs)
{
  int i, j, owner, order;
  long page;
  struct protection_domain* pd;

  owner = block->btb_hw.ef10.handle >> 8;
  order = block->btb_hw.ef10.handle & 0xff;
  pd = pd_by_owner(nic, owner);
  if( pd == NULL )
    return -ENODEV;

  /* We are mapping between two address types.
   *
   * block->btb_vaddr stores the byte offset within the umem block, suitable for
   * use with AF_XDP descriptor queues. This is eventually used to provide the
   * "user" addresses returned from efrm_pd_dma_map, which in turn provide the
   * packet "dma" addresses posted to ef_vi, which are passed on to AF_XDP.
   * (Note: "user" and "dma" don't mean userland and DMA in this context).
   *
   * dma_addr is the corresponding kernel address, which we use to calculate the
   * addresses to store in vi->addrs, and later map into userland. This comes
   * from the "dma" (or "pci") addresses obtained by efrm_pd_dma_map which, for
   * a non-PCI device, are copied from the provided kernel addresses.
   * (Note: "dma" and "pci" don't mean DMA and PCI in this context either).
   *
   * We get one umem address giving the start of each buffer table block. The
   * block might contain several consecutive pages, which might be compound
   * (but all with the same order).
   *
   * We store one kernel address for each single page in the umem block. This is
   * somewhat profligate with memory; we could store one per buffer table block,
   * or one per compound page, with a slightly more complicated lookup when
   * finding each page during mmap.
   */

  page = (block->btb_vaddr >> PAGE_SHIFT) + (first_entry << order);
  if( page + (n_entries << order) > pd->umem.page_count )
    return -EINVAL;

  for( i = 0; i < n_entries; ++i ) {
    char* dma_addr = (char*)dma_addrs[i];
    for( j = 0; j < (1 << order); ++j, ++page, dma_addr += PAGE_SIZE )
      umem_pages_set_addr(&pd->umem, page, dma_addr);
  }

  return 0;
}


static void
af_xdp_nic_buffer_table_clear(struct efhw_nic *nic,
                              struct efhw_buffer_table_block *block,
                              int first_entry, int n_entries)
{
}


/*--------------------------------------------------------------------
 *
 * Port Sniff
 *
 *--------------------------------------------------------------------*/

static int
af_xdp_nic_set_tx_port_sniff(struct efhw_nic *nic, int instance, int enable,
			   int rss_context)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return -EOPNOTSUPP;
}


static int
af_xdp_nic_set_port_sniff(struct efhw_nic *nic, int instance, int enable,
			int promiscuous, int rss_context)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return -EOPNOTSUPP;
}

/*--------------------------------------------------------------------
 *
 * Error Stats
 *
 *--------------------------------------------------------------------*/

static int
af_xdp_get_rx_error_stats(struct efhw_nic *nic, int instance,
			void *data, int data_len, int do_reset)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return -EOPNOTSUPP;
}


/*--------------------------------------------------------------------
 *
 * Abstraction Layer Hooks
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops af_xdp_char_functional_units = {
	af_xdp_nic_init_hardware,
	af_xdp_nic_tweak_hardware,
	af_xdp_nic_release_hardware,
	af_xdp_nic_event_queue_enable,
	af_xdp_nic_event_queue_disable,
	af_xdp_nic_wakeup_request,
	af_xdp_nic_sw_event,
	af_xdp_handle_event,
	af_xdp_dmaq_tx_q_init,
	af_xdp_dmaq_rx_q_init,
	af_xdp_dmaq_tx_q_disable,
	af_xdp_dmaq_rx_q_disable,
	af_xdp_flush_tx_dma_channel,
	af_xdp_flush_rx_dma_channel,
	__af_xdp_nic_buffer_table_get_orders,
	sizeof(__af_xdp_nic_buffer_table_get_orders) /
		sizeof(__af_xdp_nic_buffer_table_get_orders[0]),
	af_xdp_nic_buffer_table_alloc,
	af_xdp_nic_buffer_table_realloc,
	af_xdp_nic_buffer_table_free,
	af_xdp_nic_buffer_table_set,
	af_xdp_nic_buffer_table_clear,
	af_xdp_nic_set_port_sniff,
	af_xdp_nic_set_tx_port_sniff,
	af_xdp_nic_license_challenge,
	af_xdp_nic_license_check,
	af_xdp_nic_v3_license_challenge,
	af_xdp_nic_v3_license_check,
	af_xdp_get_rx_error_stats,
	af_xdp_tx_alt_alloc,
	af_xdp_tx_alt_free,
	af_xdp_dmaq_kick,
	af_xdp_mem,
	af_xdp_init,
};

#endif /* EFHW_HAS_AF_XDP */
