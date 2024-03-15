/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */
#include <ci/efhw/af_xdp.h>

#ifdef EFHW_HAS_AF_XDP

#include <ci/driver/kernel_compat.h>

#include <ci/efhw/nic.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/buddy.h>
#include <ci/driver/efab/hardware/af_xdp.h>

#include <linux/socket.h>

#include <linux/ethtool.h>
#include <linux/if_xdp.h>
#include <linux/file.h>
#include <linux/bpf.h>
#include <linux/mman.h>
#include <linux/fdtable.h>
#include <linux/sched/signal.h>
#include <net/sock.h>
#include <net/xdp.h>

#include <ci/efrm/syscall.h>
#include <ci/efrm/efrm_filter.h>

#include "ethtool_rxclass.h"
#include "ethtool_flow.h"
#include "sw_buffer_table.h"

#define XDP_PROG_NAME "xdpsock"
#define BPF_FS_PATH "/sys/fs/bpf/"

static char *bpf_link_helper = NULL;
module_param(bpf_link_helper, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(bpf_link_helper, "Path to the bpf-link-helper application");

int enable_af_xdp_flow_filters = 1;
module_param(enable_af_xdp_flow_filters, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(enable_af_xdp_flow_filters,
                 "Enables flow filter use for AF_XDP devices ");
/* filter id when no actual filter is installed */
#define AF_XDP_NO_FILTER_MAGIC_ID 0x7FFFFF00

/* sys_call_area: a process-mapped area which can be used to perform
 * system calls from a module.
 *
 * There is no attempt to prevent the process from tampering this data.
 * This is why sys_call_area MUST NOT be used when executing a system call
 * with escalated privileges.  I.e. any system call which reads from or
 * writes to this area MUST be subject to normal security checks by kernel.
 *
 * The area is always mapped read-write, because in both cases the data is
 * written to the area (written by module and read by syscall or
 * vise-versa).  See also some comments about FOLL_WRITE in linux/mm/gup.c.
 */

struct sys_call_area {
  struct page* page;
  unsigned long user_addr;
  /* We may want to mmap more than one page in future.
   * Then we'll need a "size" field here.
   */
};

static void sys_call_area_unmap(struct sys_call_area* area)
{
  vm_munmap(area->user_addr, PAGE_SIZE);
}

static void sys_call_area_unpin(struct sys_call_area* area)
{
  unpin_user_page(area->page);
}

static void sys_call_area_free(struct sys_call_area* area)
{
  sys_call_area_unpin(area);
  sys_call_area_unmap(area);
}

static int __sys_call_area_alloc(struct sys_call_area* area, const char* func)
{
  int rc;

  /* It must be a normal user process.  Not a sofirq, kthread, workqueue,
   * etc.
   */
  EFHW_ASSERT(current);
  EFHW_ASSERT( ! (current->flags & PF_WQ_WORKER) );
  EFHW_ASSERT( ! (current->flags & PF_KTHREAD) );


  area->user_addr = vm_mmap(NULL, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_PRIVATE, 0);
  if( area->user_addr == 0 ) {
    EFHW_ERR("%s: ERROR: failed to allocate a page via vm_mmap()", func);
    return -ENOMEM;
  }

  mmap_read_lock(current->mm);
  rc = ci_pin_user_pages(area->user_addr, 1, FOLL_WRITE, &area->page);
  mmap_read_unlock(current->mm);
  if( rc != 1 ) {
    EFHW_ERR("%s: ERROR: failed to get a page: rc=%d:", func, rc);
    sys_call_area_unmap(area);
    return rc < 0 ? rc : -EFAULT;
  }

  return 0;
}
#define sys_call_area_alloc(area) __sys_call_area_alloc(area, __func__)

static void* sys_call_area_ptr(struct sys_call_area* area)
{
  return page_address(area->page);
}

static unsigned long
sys_call_area_user_addr(struct sys_call_area* area, void* ptr)
{
  return area->user_addr +
         ((uintptr_t)ptr - (uintptr_t)sys_call_area_ptr(area));
}

/* Resources for waiting for and handling events */
struct event_waiter
{
  struct wait_queue_entry wait;

  struct efhw_nic* nic;
  int evq;
  int budget;
};

/* Ring memory mapping artifacts */
struct ring_map {
  int n_pages;
  struct page** pages;
  void* vmapped_addr;
};

/* Are rings allocated as physically-continuous memory (linux<6.3) or
 * via vmalloc (linux>=6.3)? */
static bool rings_are_physically_continuous = true;

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

  struct ring_map ring_mapping[4];
};

/* Per-NIC AF_XDP resources */
struct efhw_nic_af_xdp
{
  struct file* map;
  struct efhw_af_xdp_vi* vi;
  struct efhw_buddy_allocator vi_allocator;
};

/*----------------------------------------------------------------------------
 *
 * VI access functions
 *
 *---------------------------------------------------------------------------*/

/* Get the VI with the given instance number */
static struct efhw_af_xdp_vi* vi_by_instance(struct efhw_nic* nic, int instance)
{
  struct efhw_nic_af_xdp* xdp = nic->arch_extra;

  if( xdp == NULL || instance >= nic->vi_lim )
    return NULL;

  return &xdp->vi[instance];
}

/*----------------------------------------------------------------------------
 *
 * BPF/XDP helper functions
 *
 *---------------------------------------------------------------------------*/


/* Invoke the bpf() syscall args is assumed to be kernel memory */
noinline
static int xdp_sys_bpf(int cmd, unsigned long user_addr)
{
  int rc = SYSCALL_DISPATCHn(3, bpf, (int, unsigned long, size_t),
                             cmd, user_addr, sizeof(union bpf_attr));
  return rc;
}

/* Allocate an FD for a file. Some operations need them. */
static int xdp_alloc_fd(struct file* file)
{
  int rc;

  /* We never run this function from any context except normal userland
   * process (i.e. no workqueue, kthread, etc). */
  EFHW_ASSERT(current);
  EFHW_ASSERT(current->files);

  rc = get_unused_fd_flags(0);
  if( rc < 0 )
    return rc;

  get_file(file);
  fd_install(rc, file);
  return rc;
}

static int xdp_map_lookup(struct sys_call_area* area, const char *map_path)
{
	union bpf_attr* attr = sys_call_area_ptr(area);
	char *filepath = (void *)(attr + 1);
	int ret;

	ret = strscpy(filepath, map_path, PAGE_SIZE - sizeof(*attr));
	if (ret < 0)
		return ret;

	memset(attr, 0, sizeof(*attr));
	attr->pathname = sys_call_area_user_addr(area, filepath);

	return xdp_sys_bpf(BPF_OBJ_GET, sys_call_area_user_addr(area, attr));
}

/* Create the xdp socket map to share with the BPF program */
static int xdp_map_create(struct sys_call_area* area, int max_entries)
{
  union bpf_attr* attr = sys_call_area_ptr(area);
  memset(attr, 0, sizeof(*attr));

  attr->map_type = BPF_MAP_TYPE_XSKMAP;
  attr->key_size = sizeof(int);
  attr->value_size = sizeof(int);
  attr->max_entries = max_entries;
  strncpy(attr->map_name, "onload_xsks", sizeof(attr->map_name));
  return xdp_sys_bpf(BPF_MAP_CREATE, sys_call_area_user_addr(area, attr));
}

/* Load the BPF program to redirect inbound packets to AF_XDP sockets.
 * See af_xdp_bpf.c for the program's source and compilation guidelines. */
static int xdp_prog_load(struct sys_call_area* area, int map_fd)
{
  const uint64_t const_prog[] = {
    0x00000002000000b7, 0x0000000000041361,
    0x0000000000001261, 0x00000000000024bf,
    0x0000002600000407, 0x000000000012342d,
    0x0000000000002379, 0xffffffff00000418,
    0x0000ffff00000000, 0x000000000000435f,
    0x00000000000d431d, 0x00000000000c2369,
    0x0000008100020355, 0x0000000000102369,
    0x0000000400000207, 0x0000000800080355,
    0x0000000000172271, 0x0000001100010215,
    0x0000000600050255, 0x0000000000101261,
    0x0000000000000118, /* <-- insert map_fd here */
                        0x0000000000000000,
    0x00000002000003b7, 0x0000003300000085,
    0x0000000000000095,
  };

  uint64_t* prog;
  char* license;
  union bpf_attr* attr;

  attr = sys_call_area_ptr(area);
  memset(attr, 0, sizeof(*attr));

  license = (void*)(attr + 1);
#define LICENSE "GPL"
  strncpy(license, LICENSE, strlen(LICENSE) + 1);

  prog = (void*)(license + strlen(LICENSE) + 1);
#undef LICENSE
  memcpy(prog, const_prog, sizeof(const_prog));
  prog[20] |= 0x1000; /* "immediate" flag */
  prog[20] |= (uint64_t) map_fd << 32; /* immediate value */

  attr->prog_type = BPF_PROG_TYPE_XDP;
  attr->insn_cnt = sizeof(const_prog) / sizeof(struct bpf_insn);
  attr->insns = sys_call_area_user_addr(area, prog);
  attr->license = sys_call_area_user_addr(area, license);
  strncpy(attr->prog_name, XDP_PROG_NAME, strlen(XDP_PROG_NAME));

  return xdp_sys_bpf(BPF_PROG_LOAD, sys_call_area_user_addr(area, attr));
}

/* Update an element in the XDP socket map (using fds) */
static int xdp_map_update_fd(int map_fd, int key, int sock_fd)
{
  int rc;
  union bpf_attr* attr;
  struct sys_call_area area;
  int* key_user;
  int* sock_user;

  rc = sys_call_area_alloc(&area);
  if( rc < 0 )
    return rc;

  attr = sys_call_area_ptr(&area);
  memset(attr, 0, sizeof(*attr));
  key_user = (void*)(attr + 1);
  sock_user = (void*)(key_user + 1);

  *key_user = key;
  *sock_user = sock_fd;
  attr->map_fd = map_fd;
  attr->key = sys_call_area_user_addr(&area, key_user);
  attr->value = sys_call_area_user_addr(&area, sock_user);

  rc = xdp_sys_bpf(BPF_MAP_UPDATE_ELEM, sys_call_area_user_addr(&area, attr));

  sys_call_area_free(&area);
  return rc;
}

/* Update an element in the XDP socket map (using file pointers) */
static int xdp_map_update(struct efhw_nic_af_xdp* af_xdp, int key,
                          struct file* sock)
{
  int rc, map_fd, sock_fd;

  rc = map_fd = xdp_alloc_fd(af_xdp->map);
  if( rc < 0 )
    return rc;

  rc = sock_fd = xdp_alloc_fd(sock);
  if( rc < 0 )
    goto fail_sock;

  rc = xdp_map_update_fd(map_fd, key, sock_fd);
  if( rc < 0 ) {
    EFHW_ERR("%s: xdp_map_update_fd(%d, %d) returned %d",
             __func__, key, sock_fd, rc);
    goto fail_update_map;
  }


  /* We do not need to roll back xdp_map_update_fd(map_fd) in case of
   * failure, because it rolls back automagically when the socket closes.
   */
fail_update_map:
  ci_close_fd(sock_fd);
fail_sock:
  ci_close_fd(map_fd);
  return rc;
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
static int xdp_set_link(struct net_device* dev, int prog_fd)
{
  if( dev->netdev_ops->ndo_bpf ) {
    struct netdev_bpf bpf = {
      .command = XDP_SETUP_PROG,
      .prog = NULL,
    };

    if( prog_fd > 0 ) {
      struct bpf_prog* prog = bpf_prog_get_type_dev(prog_fd, BPF_PROG_TYPE_XDP, 1);
      ci_close_fd(prog_fd);
      if( IS_ERR(prog) )
        return PTR_ERR(prog);
      bpf.prog = prog;
    }

    return dev->netdev_ops->ndo_bpf(dev, &bpf);
  }
  else {
    char *envp[] = { NULL };
    char *argv[] = {
      NULL,
      dev->name,
      prog_fd > 0 ? XDP_PROG_NAME : NULL,
      NULL
    };

    EFHW_WARN("%s: %s does not support native XDP, using generic mode",
              __FUNCTION__, dev->name);

    if( bpf_link_helper ) {
      argv[0] = strim(bpf_link_helper);
    }
    else {
      EFHW_ERR("%s: bpf_link_helper parameter is not set. Failed to link.",
               __FUNCTION__);
      return -1;
    }

    EFHW_WARN("%s: spawning %s %s %s", __FUNCTION__,
              argv[0], argv[1], argv[2] ? argv[2] : "");

    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
  }
}

/* Fault handler to provide buffer memory pages for our user mapping */
static vm_fault_t xdp_umem_fault(struct vm_fault* vmf) {
  struct efhw_sw_bt* table = vmf->vma->vm_private_data;
  struct page* page;

  if( vmf->pgoff >= oo_iobufset_npages(table->pages) )
    return VM_FAULT_SIGSEGV;

  page = virt_to_page(oo_iobufset_ptr(table->pages, vmf->pgoff << PAGE_SHIFT));

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
static int xdp_register_umem(struct socket* sock, struct efhw_sw_bt* table,
                             int chunk_size, int headroom)
{
  struct vm_area_struct* vma;
  int rc = -EFAULT;

  /* The actual fields present in this struct vary with kernel version, with
   * a flags fields added in 5.4. We don't currently need to set any flags,
   * so just zero everything we don't use.
   */
  struct xdp_umem_reg mr = {
    .len = oo_iobufset_npages(table->pages) << PAGE_SHIFT,
    .chunk_size = chunk_size,
    .headroom = headroom
  };

  mr.addr = vm_mmap(NULL, 0, mr.len, PROT_READ | PROT_WRITE, MAP_SHARED, 0);
  if( offset_in_page(mr.addr) )
    return mr.addr;

  /* linux>=5.8 uses mmap_write_lock() */
  mmap_write_lock(current->mm);
  vma = find_vma(current->mm, mr.addr);
  mmap_write_unlock(current->mm);

  BUG_ON(vma == NULL);
  BUG_ON(vma->vm_start != mr.addr);

  vma->vm_private_data = table;
  vma->vm_ops = &vm_ops;

  rc = sock_ops_setsockopt(sock, SOL_XDP, XDP_UMEM_REG,
                           (char*)&mr, sizeof(mr));

  vm_munmap(mr.addr, mr.len);
  return rc;
}

/* Create the rings for an AF_XDP socket and associated umem */
static int xdp_create_ring(struct socket* sock,
                           struct efhw_page_map* page_map, void* kern_mem_base,
                           int capacity, int desc_size, int sockopt, long pgoff,
                           const struct xdp_ring_offset* xdp_offset,
                           struct efab_af_xdp_offsets_ring* kern_offset,
                           struct efab_af_xdp_offsets_ring* user_offset,
                           struct ring_map* ring_mapping)
{
  int rc;
  unsigned long map_size, addr, pfn, pages = 0;
  int64_t user_base, kern_base;
  struct vm_area_struct* vma;
  void* ring_base = kern_mem_base;

  user_base = page_map->n_pages << PAGE_SHIFT;

  rc = sock_ops_setsockopt(sock, SOL_XDP, sockopt,
                           (char*)&capacity, sizeof(int));
  if( rc < 0 )
    return rc;

  map_size = xdp_offset->desc + (capacity + 1) * desc_size;
  addr = vm_mmap(sock->file, 0, map_size, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_POPULATE, pgoff);
  if( IS_ERR_VALUE(addr) )
      return addr;

  mmap_write_lock(current->mm);

  vma = find_vma(current->mm, addr);
  if( vma == NULL ) {
    rc = -EFAULT;
  }
  else {
    if( rings_are_physically_continuous )
      rc = follow_pfn(vma, addr, &pfn);
    pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
  }
  mmap_write_unlock(current->mm);

  if( ! rings_are_physically_continuous || rc == -EINVAL ) {
    /* Probably the rings were vmalloc'ed, as in linux>=6.3 */

    ring_mapping->pages = kzalloc(sizeof(struct page *) * pages, GFP_KERNEL);
    if( ring_mapping->pages == NULL ) {
      rc = -ENOMEM;
    }
    else {
      mmap_read_lock(current->mm);
      rc = ci_pin_user_pages(addr, pages, FOLL_WRITE, ring_mapping->pages);
      mmap_read_unlock(current->mm);

      if( rc == pages )
        ring_mapping->vmapped_addr = vmap(ring_mapping->pages,
                                          pages, VM_MAP, PAGE_KERNEL);
      else if( rc >= 0 )
        rc = -EFAULT;
    }

    if( rc > 0 ) {
      ring_mapping->n_pages = pages;
      ring_base = ring_mapping->vmapped_addr;
      if( rings_are_physically_continuous )
        rings_are_physically_continuous = false;
    }
  }
  else if( rc >= 0 ) {
    ring_base = phys_to_virt(pfn << PAGE_SHIFT);
  }
  if( rc >= 0 )
    rc = efhw_page_map_add_lump(page_map, ring_base, pages);

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
                            struct efab_af_xdp_offsets_rings* user_offsets,
                            struct ring_map* ring_mapping)
{
  int rc;
  struct sys_call_area rw_area;
  struct xdp_mmap_offsets* mmap_offsets;
  int* optlen;

  EFHW_BUILD_ASSERT(EFAB_AF_XDP_DESC_BYTES == sizeof(struct xdp_desc));

  /* We need a read-write area to call getsockopt().  We unmap it from UL
   * as soon as possible. */
  rc = sys_call_area_alloc(&rw_area);
  if( rc < 0 )
    return rc;

  mmap_offsets = sys_call_area_ptr(&rw_area);
  optlen = (void*)(mmap_offsets + 1);
  *optlen = sizeof(*mmap_offsets);

  /* For linux<=5.7 you can use kernel_getsockopt(),
   * but newer versions does not have this function, so we have all that
   * sys_call_area_*() calls. */
  rc = sock->ops->getsockopt(sock, SOL_XDP, XDP_MMAP_OFFSETS,
                             (void*)sys_call_area_user_addr(&rw_area,
                                                            mmap_offsets),
                             (void*)sys_call_area_user_addr(&rw_area, optlen));

  /* Security consideration: mmap_offsets is located in untrusted user
   * memory.  I.e. the process can overwrite all this data.
   * However this is the process which can create an AF_XDP Onload stack,
   * so it runs with the root account, and it already can do
   * anything bad: reboot, execute arbitrary code, etc.
   *
   * However we do our best: unmap the area from UL ASAP, before use.
   */
  sys_call_area_unmap(&rw_area);
  if( rc < 0 ) {
    EFHW_ERR("%s: getsockopt(XDP_MMAP_OFFSETS) rc=%d", __func__, rc);
    goto out;
  }
  EFHW_ASSERT(*optlen == sizeof(*mmap_offsets));

  rc = xdp_create_ring(sock, page_map, kern_mem_base,
                       rxq_capacity, sizeof(struct xdp_desc),
                       XDP_RX_RING, XDP_PGOFF_RX_RING,
                       &mmap_offsets->rx, &kern_offsets->rx, &user_offsets->rx,
                       ring_mapping++);
  if( rc < 0 )
    goto out;

  rc = xdp_create_ring(sock, page_map, kern_mem_base,
                       txq_capacity, sizeof(struct xdp_desc),
                       XDP_TX_RING, XDP_PGOFF_TX_RING,
                       &mmap_offsets->tx, &kern_offsets->tx, &user_offsets->tx,
                       ring_mapping++);
  if( rc < 0 )
    goto out;

  rc = xdp_create_ring(sock, page_map, kern_mem_base,
                       rxq_capacity, sizeof(uint64_t),
                       XDP_UMEM_FILL_RING, XDP_UMEM_PGOFF_FILL_RING,
                       &mmap_offsets->fr, &kern_offsets->fr, &user_offsets->fr,
                       ring_mapping++);
  if( rc < 0 )
    goto out;

  rc = xdp_create_ring(sock, page_map, kern_mem_base,
                       txq_capacity, sizeof(uint64_t),
                       XDP_UMEM_COMPLETION_RING, XDP_UMEM_PGOFF_COMPLETION_RING,
                       &mmap_offsets->cr, &kern_offsets->cr, &user_offsets->cr,
                       ring_mapping);
  if( rc < 0 )
    goto out;

 out:
  sys_call_area_unpin(&rw_area);
  return rc;
}

static void xdp_release_vi(struct efhw_nic* nic, struct efhw_af_xdp_vi* vi)
{
  int i;

  if( !vi->sock )
    /* We expect uninitialized vi in cases where af_xdp_init()
     * has not been called after enabling evq.
     * This can happen on cleanup from failure of stack allocation */
    return;

  /* Stop from using this socket */
  if( vi->waiter.wait.func != NULL )
    remove_wait_queue(sk_sleep(vi->sock->sk), &vi->waiter.wait);
  fput(vi->sock->file);

#ifdef EFRM_HAS_FLUSH_DELAYED_FPUT
  /* This symbol is exported in linux>=5.4.
   *
   * Practically, as AF_XDP requires linux>=5.3 or RHEL8, it means that on
   * RHEL8 we can't guarantee that the socket is really destroyed (and more
   * importantly, map is updated) before we release the following
   * resources.
   *
   * However we have never seen any issues because of this.
   */
  flush_delayed_fput();
#endif

  /* Release the resources attached to the socket */
  efhw_page_free(&vi->user_offsets_page);

  for( i = 0; i < CI_ARRAY_SIZE(vi->ring_mapping); i++ ) {
    if( vi->ring_mapping[i].n_pages > 0 ) {
      vunmap(vi->ring_mapping[i].vmapped_addr);
      unpin_user_pages(vi->ring_mapping[i].pages, vi->ring_mapping[i].n_pages);
    }
  }

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
  struct efhw_sw_bt* sw_bt;
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
  sw_bt = efhw_sw_bt_by_owner(nic, owner_id);
  if( sw_bt == NULL )
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
    goto fail;
  user_offsets = (void*)efhw_page_ptr(&vi->user_offsets_page);

  rc = efhw_page_map_add_page(page_map, &vi->user_offsets_page);
  if( rc < 0 )
    goto fail;

  rc = xdp_register_umem(sock, sw_bt, chunk_size, headroom);
  if( rc < 0 )
    goto fail;

  rc = xdp_create_rings(sock, page_map, &vi->kernel_offsets,
                        vi->rxq_capacity, vi->txq_capacity,
                        &vi->kernel_offsets.rings, &user_offsets->rings,
                        vi->ring_mapping);
  if( rc < 0 )
    goto fail;

  rc = xdp_map_update(nic->arch_extra, instance, file);
  if( rc < 0 )
    goto fail;

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
#ifdef EFRM_HAVE_WARN_FLUSHING_SYSTEMWIDE_WQ
    /* linux >= 6.6 forbids flushing system global workqueues.
     * flush_scheduled_work() is not available anymore for modules, so we use
     * __flush_workqueue(). */
    __flush_workqueue(system_wq);
#else
    flush_scheduled_work();
#endif
    rc = xdp_bind(sock, nic->net_dev->ifindex, instance, vi->flags);
  }
  if( rc < 0 )
    goto fail;

  if( vi->waiter.wait.func != NULL )
    add_wait_queue(sk_sleep(vi->sock->sk), &vi->waiter.wait);

  user_offsets->mmap_bytes = efhw_page_map_bytes(page_map);
  return 0;

 fail:
  vi->waiter.wait.func = NULL;
  xdp_release_vi(nic, vi);
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
/* Update the efhw_nic struct with the nic's supported RSS hash key length
 * and indirection table length. */
static int
af_xdp_rss_get_support(struct efhw_nic *nic)
{
	struct net_device *dev = nic->net_dev;
	int rc = 0;
	const struct ethtool_ops *ops;

	ASSERT_RTNL();

	ops = dev->ethtool_ops;
	if (!ops->get_rxfh_indir_size) {
		EFHW_WARN("%s: %s does not support `get_rxfh_indir_size` operation",
							__FUNCTION__, dev->name);
		rc = -EOPNOTSUPP;
		goto unlock_out;
	}

	nic->rss_indir_size = ops->get_rxfh_indir_size(dev);

	if (!ops->get_rxfh_key_size) {
		EFHW_WARN("%s: %s does not support `get_rxfh_key_size` operation",
							__FUNCTION__, dev->name);
		rc = -EOPNOTSUPP;
		goto unlock_out;
	}

	nic->rss_key_size = ops->get_rxfh_key_size(dev);

unlock_out:
	return rc;
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
	nic->flags = NIC_FLAG_RX_ZEROCOPY /* TODO AFXDP: hardcoded for now */
		   | NIC_FLAG_RX_FILTER_TYPE_IP_LOCAL /* only wild filters */
	     | NIC_FLAG_USERSPACE_PRIME  /* no explicit priming needed */
		   ;
}

static int af_xdp_vi_allocator_ctor(struct efhw_nic_af_xdp *nic,
                                    unsigned vi_min, unsigned vi_lim) {
  int rc = efhw_buddy_range_ctor(&nic->vi_allocator, vi_min, vi_lim);
  if (rc < 0) {
       EFHW_ERR("%s: efhw_buddy_range_ctor(%d, %d) "
                "failed (%d)",
                __FUNCTION__, vi_min, vi_lim, rc);
  }
  return rc;
}

static void af_xdp_vi_allocator_dtor(struct efhw_nic_af_xdp *nic) {
  efhw_buddy_dtor(&nic->vi_allocator);
}

static int
__af_xdp_nic_init_hardware(struct efhw_nic *nic,
			   struct efhw_ev_handler *ev_handlers,
			   const uint8_t *mac_addr,
			   struct sys_call_area* sys_call_area)
{
	int map_fd, rc;
	struct efhw_nic_af_xdp* xdp;

	xdp = kzalloc(sizeof(*xdp) +
		      nic->vi_lim * sizeof(struct efhw_af_xdp_vi) +
		      EFHW_MAX_SW_BTS * sizeof(struct efhw_sw_bt),
		      GFP_KERNEL);
	if( xdp == NULL )
		return -ENOMEM;

	nic->ev_handlers = ev_handlers;
	xdp->vi = (struct efhw_af_xdp_vi*) (xdp + 1);
	nic->sw_bts = (struct efhw_sw_bt*) (xdp->vi + nic->vi_lim);

	rc = af_xdp_vi_allocator_ctor(xdp, nic->vi_min, nic->vi_lim);
	if( rc < 0 )
		goto fail_map;

	/* Open a pre existing map if it exists, else create one */
	map_fd = xdp_map_lookup(sys_call_area, BPF_FS_PATH "onload_xdp_xsk");
	if( map_fd >= 0 ) {
		EFHW_NOTICE("%s: attaching to existing map", __func__);
		goto has_map_and_bound_prog;
	}

	rc = map_fd = xdp_map_create(sys_call_area, nic->vi_lim);
	if( rc < 0 ) {
		EFHW_ERR("%s: xdp_map_create(%d) returned %d",
				__func__, nic->vi_lim, rc);
		goto fail_map;
	}

	rc = xdp_prog_load(sys_call_area, map_fd);
	if( rc < 0 ) {
		EFHW_ERR("%s: xdp_prog_load(%d) returned %d",
				__func__, map_fd, rc);
		goto fail;
	}

	rc = xdp_set_link(nic->net_dev, rc);
	if( rc < 0 )
		goto fail;

has_map_and_bound_prog:
	xdp->map = fget(map_fd);
	ci_close_fd(map_fd);

	nic->arch_extra = xdp;
	memcpy(nic->mac_addr, mac_addr, ETH_ALEN);

	af_xdp_nic_tweak_hardware(nic);

#ifdef EFRM_NETDEV_HAS_XDP_METADATA_OPS
	if (nic->net_dev->xdp_metadata_ops &&
	    nic->net_dev->xdp_metadata_ops->xmo_rx_timestamp)
		nic->flags |= NIC_FLAG_HW_RX_TIMESTAMPING;
#endif

	rc = af_xdp_rss_get_support(nic);
	return rc;

fail:
	ci_close_fd(map_fd);
fail_map:
	kfree(xdp);
	return rc;
}

static void
af_xdp_nic_sw_ctor(struct efhw_nic *nic,
		   const struct vi_resource_dimensions *res)
{
	/* No restrictions on queue sizes */
	nic->q_sizes[EFHW_EVQ] = ~0;
	nic->q_sizes[EFHW_TXQ] = ~0;
	nic->q_sizes[EFHW_RXQ] = ~0;
	nic->num_evqs = 1;
	nic->num_dmaqs = 1;
	nic->num_timers = 0;
}

static int
af_xdp_nic_init_hardware(struct efhw_nic *nic,
			 struct efhw_ev_handler *ev_handlers,
			 const uint8_t *mac_addr)
{
	int rc;
	struct sys_call_area area;

	rc = sys_call_area_alloc(&area);
	if( rc < 0 )
		return rc;

	rc = __af_xdp_nic_init_hardware(nic, ev_handlers, mac_addr, &area);

	sys_call_area_free(&area);

	return rc;
}
static void
af_xdp_nic_release_hardware(struct efhw_nic* nic)
{
  struct efhw_nic_af_xdp* xdp = nic->arch_extra;
  xdp_set_link(nic->net_dev, -1);
  if( xdp ) {
    af_xdp_vi_allocator_dtor(xdp);
    fput(xdp->map);
    kfree(xdp);
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
  efhw_handle_wakeup_event(w->nic, w->evq, w->budget);
  return 1;
}

/* This function will enable the given event queue with the requested
 * properties.
 */
static int
af_xdp_nic_event_queue_enable(struct efhw_nic *nic, uint32_t client_id,
			      struct efhw_evq_params *params)
{
  struct efhw_af_xdp_vi* vi = vi_by_instance(nic, params->evq);

  if( vi == NULL )
    return -ENODEV;

  init_waitqueue_func_entry(&vi->waiter.wait, wait_callback);
  vi->waiter.nic = nic;
  vi->waiter.evq = params->wakeup_evq;
  /* The budget currently has little relevance as Onload doesn't try to
   * poll AF_XDP from an interrupt context. The value may need some thought
   * if that changes in future. */
  vi->waiter.budget = 64;

  if( vi->sock != NULL )
    add_wait_queue(sk_sleep(vi->sock->sk), &vi->waiter.wait);

  return 0;
}

static void
af_xdp_nic_event_queue_disable(struct efhw_nic *nic, uint32_t client_id,
			     uint evq, int time_sync_events_enabled)
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

static bool af_xdp_accept_vi_constraints(int low,
					 unsigned order, void* arg)
{
	struct efhw_vi_constraints *avc = arg;

	if( avc->channel >= 0 )
		return avc->channel == low;

	return true;
}


static int af_xdp_vi_alloc(struct efhw_nic *nic, struct efhw_vi_constraints *evc,
			     unsigned n_vis) {
  unsigned order = fls(n_vis - 1);
  struct efhw_nic_af_xdp* xdp = nic->arch_extra;
  return efhw_buddy_alloc_special(&xdp->vi_allocator, order,
                                  af_xdp_accept_vi_constraints, evc);
}

static void af_xdp_vi_free(struct efhw_nic *nic, int instance, unsigned n_vis) {
  unsigned order = fls(n_vis - 1);
  struct efhw_nic_af_xdp* xdp = nic->arch_extra;
  efhw_buddy_free(&xdp->vi_allocator, instance, order);
}

/*----------------------------------------------------------------------------
 *
 * DMAQ low-level register interface
 *
 *---------------------------------------------------------------------------*/


static int
af_xdp_dmaq_tx_q_init(struct efhw_nic *nic, uint32_t client_id,
		      struct efhw_dmaq_params *params)
{
  struct efhw_af_xdp_vi* vi = vi_by_instance(nic, params->evq);
  if( vi == NULL )
    return -ENODEV;

  vi->owner_id = params->owner;
  vi->txq_capacity = params->dmaq_size;
  params->qid_out = params->dmaq;

  return 0;
}


static int
af_xdp_dmaq_rx_q_init(struct efhw_nic *nic, uint32_t client_id,
		      struct efhw_dmaq_params *params)
{
  struct efhw_af_xdp_vi* vi = vi_by_instance(nic, params->evq);
  if( vi == NULL )
    return -ENODEV;

  vi->owner_id = params->owner;
  vi->rxq_capacity = params->dmaq_size;
  vi->flags |= (params->flags & EFHW_VI_RX_ZEROCOPY) ? XDP_ZEROCOPY : XDP_COPY;
  params->qid_out = params->dmaq;

  return 0;
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - mid level API
 *
 *--------------------------------------------------------------------*/


static int af_xdp_flush_tx_dma_channel(struct efhw_nic *nic,
		    uint32_t client_id, uint dmaq, uint evq)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return -EOPNOTSUPP;
}


static int af_xdp_flush_rx_dma_channel(struct efhw_nic *nic,
		    uint32_t client_id, uint dmaq)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return -EOPNOTSUPP;
}


static int af_xdp_translate_dma_addrs(struct efhw_nic* nic,
				      const dma_addr_t *src, dma_addr_t *dst,
				      int n)
{
	memmove(dst, src, n * sizeof(src[0]));
	return 0;
}

/*--------------------------------------------------------------------
 *
 * Buffer table - API
 *
 *--------------------------------------------------------------------*/

static const int __af_xdp_nic_buffer_table_get_orders[] = {0,1,2,3,4,5,6,7,8,9,10};

/* Func op implementations are provided by efhw_sw_bt */

/*--------------------------------------------------------------------
 *
 * Filtering
 *
 *--------------------------------------------------------------------*/

static int
af_xdp_ethtool_set_rxfh_context(struct efhw_nic *nic, const u32 *indir,
                                const u8 *key, u8 hfunc, u32 *rss_context,
                                u8 delete)
{
  struct net_device *dev = nic->net_dev;
  const struct ethtool_ops *ops = dev->ethtool_ops;

  EFHW_ASSERT(rss_context);

#ifndef EFRM_HAVE_SET_RXFH_CONTEXT
  /* linux >= 6.8 removes ethtool_ops::set_rxfh_context(). We use set_rxfh(). */

  int rc;
  struct ethtool_rxfh_param rxfh = {
    .hfunc = hfunc,
    .indir_size = nic->rss_indir_size,
    .indir = (u32 *)indir,
    .key_size = nic->rss_key_size,
    .key = (u8 *)key,
    .rss_context = *rss_context,
    .rss_delete = delete,
  };

  if( !ops->set_rxfh ) {
    EFHW_WARN("%s: %s does not support `set_rxfh` operation", __FUNCTION__,
              dev->name);
    return -EOPNOTSUPP;
  }

  rc = ops->set_rxfh(dev, &rxfh, NULL);
  if( rc == 0 )
    *rss_context = rxfh.rss_context;

  return rc;
#else
  if( !ops->set_rxfh_context ) {
    EFHW_WARN("%s: %s does not support `set_rxfh_context` operation",
              __FUNCTION__, dev->name);
    return -EOPNOTSUPP;
  }
  return ops->set_rxfh_context(dev, indir, key, hfunc, rss_context, delete);
#endif
}

static int
af_xdp_rss_alloc(struct efhw_nic *nic, const u32 *indir, const u8 *key,
		 u32 efhw_rss_mode, int num_qs, u32 *rss_context_out)
{
	struct net_device *dev = nic->net_dev;
	int rc = 0;

	EFHW_ASSERT(efhw_rss_mode == EFHW_RSS_MODE_DEFAULT);

	/* We enter the function with rtnl held */
	ASSERT_RTNL();

	/* TODO AF_XDP: Establish whether the RSS hash key can be expanded or
	* contracted while still maintaining favourable properties.
	* For now error out if the NIC has the wrong value.
	*/
	if (nic->rss_key_size != EFRM_RSS_KEY_LEN) {
		EFHW_ERR("%s: ERROR: Onload does not support this device's RSS hash key size.\n"
				"Expecting hash key size of %u, %s's current size = %u",
				__FUNCTION__, EFRM_RSS_KEY_LEN, dev->name, nic->rss_key_size);
		rc = -ENOSYS;
		goto unlock_out;
	}

	/* We want to allocate a context */
	*rss_context_out = ETH_RXFH_CONTEXT_ALLOC;

	/* TODO AF_XDP: We want to check that this device can use a toeplitz hash */
	rc = af_xdp_ethtool_set_rxfh_context(nic, indir, key, /*hfunc*/ 0,
						rss_context_out, false);

	if( rc < 0 ) {
		EFHW_WARN("%s: rc = %d", __FUNCTION__, rc);
	}

unlock_out:
	return rc;
}


static int
af_xdp_rss_free(struct efhw_nic *nic, u32 rss_context)
{
	int rc = 0;

	rtnl_lock();

	rc = af_xdp_ethtool_set_rxfh_context(nic, NULL, NULL, 0, &rss_context, true);

	if (rc < 0) {
		EFHW_WARN("%s: rc = %d", __FUNCTION__, rc);
	}

	rtnl_unlock();
	return rc;
}

static int af_xdp_efx_spec_to_ethtool_flow(struct efx_filter_spec* efx_spec,
					   struct ethtool_rx_flow_spec* fs)
{
	/* In order to support different driver capabilities we need to
	 * always install the same filter type. This means that we will
	 * always use a 3-tuple IP filter, even if a 5-tuple was requested.
	 * Although this can in theory match traffic not destined for us, in
	 * practice common usage means that it's sufficiently specific.
	 *
	 * The ethtool interface does not complain if a duplicate filter is
	 * inserted, and does not reference count such filters. That causes
	 * issues for the case where onload tries to replace a wild match
	 * filter with a full match filter, as it will add the new full match
	 * before removing the original wild. However, we treat both of these
	 * as the same 3-tuple and so the net result is that we remove the
	 * filter entirely. This occurs in two circumstances:
	 * - closing a listening socket with accepted sockets still open
	 * - connecting an already bound UDP socket
	 * We can avoid the first by setting oof_shared_keep_thresh=0 when
	 * using AF_XDP.
	 * The second is a rare case, and the failure mode here is to fall
	 * back to traffic via the kernel, so I'm living with it for now.
	 */

	int rc = efx_spec_to_ethtool_flow(efx_spec, fs);
	if (rc < 0)
		return rc;

	/* FLOW_RSS is not mutually exclusive with the other flow_type options
	* so temporarily ignore it.
	*/
	switch (fs->flow_type & ~(FLOW_RSS)) {
	case UDP_V4_FLOW:
		if (fs->m_u.udp_ip4_spec.tos)
			return -EOPNOTSUPP;
		fs->h_u.udp_ip4_spec.ip4src = 0;
		fs->h_u.udp_ip4_spec.psrc = 0;
		fs->m_u.udp_ip4_spec.ip4src = 0;
		fs->m_u.udp_ip4_spec.psrc = 0;
		break;
	case TCP_V4_FLOW:
		if (fs->m_u.tcp_ip4_spec.tos)
			return -EOPNOTSUPP;
		fs->h_u.tcp_ip4_spec.ip4src = 0;
		fs->h_u.tcp_ip4_spec.psrc = 0;
		fs->m_u.tcp_ip4_spec.ip4src = 0;
		fs->m_u.tcp_ip4_spec.psrc = 0;
		break;
	default:
		/* FIXME AF_XDP need to check whether we can install both IPv6
		 * and IPv4 filters. For now just support IPv4.
		 */
		return -EOPNOTSUPP;
	}

	/* TODO AF_XDP: for now assume dmaq_id matches NIC channel
	 * based on insight into efhw/af_xdp.c */
	fs->ring_cookie = efx_spec->dmaq_id;

	return 0;
}

static int
af_xdp_filter_insert(struct efhw_nic *nic, struct efx_filter_spec *spec,
                     int *rxq, unsigned pd_excl_token, const struct cpumask *mask,
                     unsigned flags)
{
	struct net_device *dev = nic->net_dev;
	int rc;
	struct ethtool_rxnfc info;
	const struct ethtool_ops *ops;
	struct cmd_context ctx;

	if (!enable_af_xdp_flow_filters)
		return AF_XDP_NO_FILTER_MAGIC_ID; /* pretend a filter is installed */
	memset(&info, 0, sizeof(info));
	info.cmd = ETHTOOL_SRXCLSRLINS;
	rc = af_xdp_efx_spec_to_ethtool_flow(spec, &info.fs);
	if ( rc < 0 )
		return rc;

	if (info.fs.flow_type & FLOW_RSS)
		info.rss_context = spec->rss_context;

	rtnl_lock();

	ops = dev->ethtool_ops;
	if (!ops->set_rxnfc) {
		rc = -EOPNOTSUPP;
		goto unlock_out;
	}

	ctx.netdev = dev;
	rc = rmgr_set_location(&ctx, &info.fs);
	if ( rc < 0 )
		goto unlock_out;

	rc = ops->set_rxnfc(dev, &info);
	if ( rc >= 0 )
		rc = info.fs.location;

unlock_out:
	rtnl_unlock();
	return rc;
}

static void
af_xdp_filter_remove(struct efhw_nic *nic, int filter_id)
{
	struct net_device *dev = nic->net_dev;
	struct ethtool_rxnfc info;
	const struct ethtool_ops *ops;

	if (filter_id == AF_XDP_NO_FILTER_MAGIC_ID)
		return;

	memset(&info, 0, sizeof(info));
	info.cmd = ETHTOOL_SRXCLSRLDEL;
	info.fs.location = filter_id;

	rtnl_lock();
	ops = dev->ethtool_ops;
	if (ops->set_rxnfc)
		ops->set_rxnfc(dev, &info);
	rtnl_unlock();
}

static int
af_xdp_filter_redirect(struct efhw_nic *nic, int filter_id,
		       struct efx_filter_spec *spec)
{
	/* This error code is proxied by efrm_filter_redirect() and goes to
	 * oo_hw_filter_set_hwport().  Do not change this value without
	 * looking in there. */
	return -ENODEV;
}


/*--------------------------------------------------------------------
 *
 * Device
 *
 *--------------------------------------------------------------------*/

static int
af_xdp_vi_io_region(struct efhw_nic *nic, int instance, size_t* size_out,
		    resource_size_t* addr_out)
{
	*size_out = 0;
	return 0;
}


/*--------------------------------------------------------------------
 *
 * Abstraction Layer Hooks
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops af_xdp_char_functional_units = {
	.sw_ctor = af_xdp_nic_sw_ctor,
	.init_hardware = af_xdp_nic_init_hardware,
	.post_reset = af_xdp_nic_tweak_hardware,
	.release_hardware = af_xdp_nic_release_hardware,
	.event_queue_enable = af_xdp_nic_event_queue_enable,
	.event_queue_disable = af_xdp_nic_event_queue_disable,
	.wakeup_request = af_xdp_nic_wakeup_request,
	.sw_event = af_xdp_nic_sw_event,
	.vi_alloc = af_xdp_vi_alloc,
	.vi_free = af_xdp_vi_free,
	.dmaq_tx_q_init = af_xdp_dmaq_tx_q_init,
	.dmaq_rx_q_init = af_xdp_dmaq_rx_q_init,
	.flush_tx_dma_channel = af_xdp_flush_tx_dma_channel,
	.flush_rx_dma_channel = af_xdp_flush_rx_dma_channel,
	.translate_dma_addrs = af_xdp_translate_dma_addrs,
	.buffer_table_orders = __af_xdp_nic_buffer_table_get_orders,
	.buffer_table_orders_num = sizeof(__af_xdp_nic_buffer_table_get_orders) /
		sizeof(__af_xdp_nic_buffer_table_get_orders[0]),
	.buffer_table_alloc = efhw_sw_bt_alloc,
	.buffer_table_free = efhw_sw_bt_free,
	.buffer_table_set = efhw_sw_bt_set,
	.buffer_table_clear = efhw_sw_bt_clear,
	.rss_alloc = af_xdp_rss_alloc,
	.rss_free = af_xdp_rss_free,
	.filter_insert = af_xdp_filter_insert,
	.filter_remove = af_xdp_filter_remove,
	.filter_redirect = af_xdp_filter_redirect,
	.dmaq_kick = af_xdp_dmaq_kick,
	.af_xdp_mem = af_xdp_mem,
	.af_xdp_init = af_xdp_init,
	.vi_io_region = af_xdp_vi_io_region,
};

#endif /* EFHW_HAS_AF_XDP */
