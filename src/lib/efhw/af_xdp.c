/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#include <ci/driver/efab/hardware.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/af_xdp.h>

#include <linux/socket.h>

#ifdef AF_XDP

#include <linux/if_xdp.h>
#include <linux/file.h>
#include <linux/bpf.h>
#include <linux/mman.h>

#include <onload/linux_trampoline.h>

#define MAX_SOCKETS 128

struct umem_pages
{
  int chunk_size;
  int headroom;
  long count;   /* Total number of pages */
  long alloc;   /* Pages that have been assigned to allocated buffer tables */
  long ready;   /* Pages that have an address, via buffer_table_set */
  void** addrs; /* Start address of each page in kernel memory, once ready */
};

struct efhw_af_xdp_vi
{
  struct file* sock;
  int owner_id;
  int rxq_capacity;
  int txq_capacity;
  unsigned flags;

  struct umem_pages umem;
};

struct efhw_nic_af_xdp
{
  struct file* map;
  struct efhw_af_xdp_vi vi[MAX_SOCKETS];
};

static int vi_stack_id(struct efhw_nic* nic, struct efhw_af_xdp_vi* vi)
{
  return vi - nic->af_xdp->vi;
}

static struct efhw_af_xdp_vi* vi_by_stack(struct efhw_nic* nic, int stack_id)
{
  struct efhw_nic_af_xdp* xdp = nic->af_xdp;

  if( xdp == NULL || stack_id >= MAX_SOCKETS )
    return NULL;

  return &xdp->vi[stack_id];
}

static struct efhw_af_xdp_vi* vi_by_owner(struct efhw_nic* nic, int owner_id)
{
  int i;
  struct efhw_nic_af_xdp* xdp = nic->af_xdp;

  if( xdp == NULL )
    return NULL;

  for( i = 0; i < MAX_SOCKETS; ++i )
    if( xdp->vi[i].owner_id == owner_id )
      return &xdp->vi[i];

  return NULL;
}

/*----------------------------------------------------------------------------
 *
 * BPF/XDP helper functions
 *
 *---------------------------------------------------------------------------*/

/* Invoke the bpf() syscall args is assumed to be kernel memory */
static int sys_bpf(int cmd, union bpf_attr* attr)
{
#if defined(__NR_bpf) && defined(ONLOAD_SYSCALL_PTREGS)
  struct pt_regs regs;
  static asmlinkage long (*sys_call)(const struct pt_regs*) = NULL;

  if( sys_call == NULL ) {
    void** table = efrm_find_ksym("sys_call_table");
    if( table == NULL || table[__NR_bpf] == NULL )
      return -ENOSYS;

    sys_call = table[__NR_bpf];
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
static int xdp_map_create(void)
{
  int rc;
  union bpf_attr attr = {};

  attr.map_type = BPF_MAP_TYPE_XSKMAP;
  attr.key_size = sizeof(int);
  attr.value_size = sizeof(int);
  attr.max_entries = MAX_SOCKETS;
  strncpy(attr.map_name, "onload_xsks", strlen("onload_xsks"));
  rc = sys_bpf(BPF_MAP_CREATE, &attr);
  return rc;
}

/* Load the BPF program to redirect inbound packets to AF_XDP sockets */
static int xdp_prog_load(int map_fd)
{
  /* This is a simple program which redirects TCP and UDP packets to AF_XDP
   * sockets in the map.
   *
   * TODO: we will want to maintain this in a readable, editable form.
   *
   * It was compiled from the following:
   *
   * // clang -I../../bpf -target bpf -O2 -o xdpprog.o -c xdpprog.c
   * #include <uapi/linux/bpf.h>
   * #include "bpf_helpers.h"
   *
   * struct bpf_map_def SEC("maps") xsks_map = {
   *         .type = BPF_MAP_TYPE_XSKMAP,
   *         .key_size = 4,
   *         .value_size = 4,
   *         .max_entries = 4,
   * };
   *
   * SEC("xdp_sock")
   * int xdp_sock_prog(struct xdp_md *ctx)
   * {
   *   char* data = (char*)(long)ctx->data;
   *   char* end = (char*)(long)ctx->data_end;
   *   if( data + 14 + 20 > end )
   *     return XDP_PASS;
   *   unsigned short ethertype = *(unsigned short*)(data+12);
   *   unsigned char proto;
   *   if( ethertype == 8 )
   *     proto = *(unsigned char*)(data+23);
   *   else if( ethertype == 0xdd86 )
   *     proto = *(unsigned char*)(data+20);
   *   else
   *     return XDP_PASS;
   *   if( proto != 6 && proto != 17 )
   *     return XDP_PASS;
   *   return bpf_redirect_map(&xsks_map, 0, 0);
   * }
   *
   * char _license[] SEC("license") = "GPL";
   */
  const uint64_t prog[] = {
    0x00000002000000b7,0x0000000000041261,0x0000000000001161,0x00000000000013bf,
    0x0000002200000307,0x00000000000e232d,0x00000017000002b7,0x00000000000c1369,
    0x0000000800020315,0x0000dd86000a0355,0x00000014000002b7,0x000000000000210f,
    0x0000000000001171,0x0000001100010115,0x0000000600050155,

    /* This is the instruction to place the map's fd into a register for the
     * call to bpf_redirect_map. The fd is the "immediate value" field of the
     * instruction, which is the upper 32 bits of this representation.
     */
    0x0000000000001118 | ((uint64_t)map_fd << 32),

    0x0000000000000000,0x00000000000002b7,0x00000000000003b7,0x0000003300000085,
    0x0000000000000095
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

/* Update an element in the XDP socket map */
static int xdp_map_update_elem(struct file* map, int key, int value)
{
  int rc;
  union bpf_attr attr = {};

  /* TODO The BPF program is hard-coded to support only one socket, with
   * a key of zero. This resricts us to a single VI per interface for now.
   */
  if( key != 0 )
    return -ENOSPC;

  rc = xdp_alloc_fd(map);
  if( rc < 0 )
    return rc;

  attr.map_fd = rc;
  attr.key = (uintptr_t)(&key);
  attr.value = (uintptr_t)(&value);

  rc = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr);
  __close_fd(current->files, attr.map_fd);
  return rc;
}

/* Delete an element from the XDP socket map */
static int xdp_map_delete_elem(struct file* map, int key)
{
  int rc;
  union bpf_attr attr = {};

  rc = xdp_alloc_fd(map);
  if( rc < 0 )
    return rc;

  attr.map_fd = rc;
  attr.key = (uintptr_t)(&key);

  rc = sys_bpf(BPF_MAP_DELETE_ELEM, &attr);
  __close_fd(current->files, attr.map_fd);
  return rc;
}

/* Bind an AF_XDP socket to an interface */
static int xdp_bind(struct socket* sock, int ifindex, unsigned flags)
{
  struct sockaddr_xdp sxdp = {};

  sxdp.sxdp_family = PF_XDP;
  sxdp.sxdp_ifindex = ifindex;
  sxdp.sxdp_queue_id = 0; // TODO configure?
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

  return op ? op(dev, &bpf) : -ENOSYS;
}

/* Fault handler to provide buffer memory pages for our user mapping */
static vm_fault_t fault(struct vm_fault* vmf) {
  struct umem_pages* pages = vmf->vma->vm_private_data;
  long page = (vmf->address - vmf->vma->vm_start) >> PAGE_SHIFT;

  if( page >= pages->count )
    return VM_FAULT_SIGSEGV;

  get_page(vmf->page = virt_to_page(pages->addrs[page]));
  return 0;
}

static struct vm_operations_struct vm_ops = {
  .fault = fault
};

/* Register user memory with an XDP socket */
static int xdp_register_umem(struct socket* sock, struct umem_pages* pages)
{
  struct vm_area_struct* vma;
  int rc = -EFAULT;

  /* The actual fields present in this struct vary with kernel version, with
   * a flags fields added in 5.4. We don't currently need to set any flags,
   * so just zero everything we don't use.
   */
  struct xdp_umem_reg mr = {
    .len = pages->count << PAGE_SHIFT,
    .chunk_size = pages->chunk_size,
    .headroom = pages->headroom
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
static int xdp_create_ring(struct socket* sock, struct efhw_page_map* page_map,
                           int capacity, int desc_size, int sockopt, long pgoff,
                           const struct xdp_ring_offset* xdp_offset,
                           ef_vi_xdp_offset* offset, ef_vi_xdp_ring* ring)
{
  int rc;
  unsigned long map_size, addr, pfn, pages, offset_base;
  struct vm_area_struct* vma;
  void* ring_base;

  offset_base = page_map->n_pages << PAGE_SHIFT;

  rc = kernel_setsockopt(sock, SOL_XDP, sockopt, (char*)&capacity, sizeof(int));
  if( rc < 0 )
    return rc;

  map_size = xdp_offset->desc + (capacity + 1) * desc_size;
  addr = vm_mmap(sock->file, 0, map_size, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_POPULATE, pgoff);
  if( IS_ERR_VALUE(addr) )
      return addr;

  vma = find_vma(current->mm, addr);
  if( vma == NULL ) {
    rc = -EFAULT;
  }
  else {
    rc = follow_pfn(vma, addr, &pfn);
    pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
  }

  vm_munmap(addr, map_size);
  if( rc < 0 )
    return rc;

  ring_base = phys_to_virt(pfn << PAGE_SHIFT);
  rc = efhw_page_map_add_lump(page_map, ring_base, pages);
  if( rc < 0 )
    return rc;

  ring->producer = ring_base + xdp_offset->producer;
  ring->consumer = ring_base + xdp_offset->consumer;
  ring->desc     = ring_base + xdp_offset->desc;

  offset->producer = offset_base + xdp_offset->producer;
  offset->consumer = offset_base + xdp_offset->consumer;
  offset->desc     = offset_base + xdp_offset->desc;

  return 0;
}

static int xdp_create_rings(struct socket* sock, struct efhw_page_map* page_map,
                            long rxq_capacity, long txq_capacity,
                            struct ef_vi_xdp_offsets* offsets,
                            struct ef_vi_xdp_rings* rings)
{
  int rc, optlen;
  struct xdp_mmap_offsets mmap_offsets;

  optlen = sizeof(mmap_offsets);
  rc = kernel_getsockopt(sock, SOL_XDP, XDP_MMAP_OFFSETS,
                         (char*)&mmap_offsets, &optlen);
  if( rc < 0 )
    return rc;

  rc = xdp_create_ring(sock, page_map, rxq_capacity, sizeof(struct xdp_desc),
                       XDP_RX_RING, XDP_PGOFF_RX_RING,
                       &mmap_offsets.rx, &offsets->rx, &rings->rx);
  if( rc < 0 )
    return rc;

  rc = xdp_create_ring(sock, page_map, txq_capacity, sizeof(struct xdp_desc),
                       XDP_TX_RING, XDP_PGOFF_TX_RING,
                       &mmap_offsets.tx, &offsets->tx, &rings->tx);
  if( rc < 0 )
    return rc;

  rc = xdp_create_ring(sock, page_map, rxq_capacity, sizeof(uint64_t),
                       XDP_UMEM_FILL_RING, XDP_UMEM_PGOFF_FILL_RING,
                       &mmap_offsets.fr, &offsets->fr, &rings->fr);
  if( rc < 0 )
    return rc;

  rc = xdp_create_ring(sock, page_map, txq_capacity, sizeof(uint64_t),
                       XDP_UMEM_COMPLETION_RING, XDP_UMEM_PGOFF_COMPLETION_RING,
                       &mmap_offsets.cr, &offsets->cr, &rings->cr);
  if( rc < 0 )
    return rc;

  offsets->total = efhw_page_map_bytes(page_map);
  return 0;
}

static void xdp_release_vi(struct efhw_nic* nic, struct efhw_af_xdp_vi* vi)
{
  xdp_map_delete_elem(nic->af_xdp->map, vi_stack_id(nic, vi));
  kfree(vi->umem.addrs);
  fput(vi->sock);
  memset(vi, 0, sizeof(*vi));
}
#endif /* AF_XDP */

/*----------------------------------------------------------------------------
 *
 * Temporary bodge to mess around with the AF_XDP socket map
 *
 *---------------------------------------------------------------------------*/
int efhw_nic_bodge_af_xdp_socket(struct efhw_nic* nic, int stack_id,
                                 long buffers, int buffer_size, int headroom,
                                 struct socket** sock_out)
{
#ifdef AF_XDP
  int rc;
  struct socket* sock;
  struct efhw_af_xdp_vi* vi;
  struct file* file;

  long umem_count;
  void** umem_addrs;

  if( buffer_size == 0 ||
      buffer_size < headroom ||
      buffer_size > PAGE_SIZE ||
      PAGE_SIZE % buffer_size != 0 )
    return -EINVAL;

  vi = vi_by_stack(nic, stack_id);
  if( vi == NULL )
    return -ENODEV;

  if( vi->sock != NULL )
    return -EBUSY;

  memset(vi, 0, sizeof(*vi));
  /* We need to use network namespace of network device so that
   * ifindex passed in bpf syscalls makes sense
   * AF_XDP TODO: there is a race here whit device changing netns */
  rc = __sock_create(dev_net(nic->net_dev), AF_XDP, SOCK_RAW, 0, &sock, 0);
  if( rc < 0 )
    return rc;

  file = sock_alloc_file(sock, 0, NULL);
  if( IS_ERR(file) )
    return PTR_ERR(file);

  rc = -ENOMEM;
  umem_count = buffers / (PAGE_SIZE / buffer_size);
  umem_addrs = kzalloc(sizeof(void*) * umem_count, GFP_KERNEL);
  if( umem_addrs == NULL )
    goto fail;

  vi->sock = file;
  vi->umem.chunk_size = buffer_size;
  vi->umem.headroom = headroom;
  vi->umem.count = umem_count;
  vi->umem.addrs = umem_addrs;

  *sock_out = sock;
  return 0;

fail:
  fput(file);
  return rc;
#else
  return -EPROTONOSUPPORT;
#endif
}

int efhw_nic_bodge_af_xdp_ready(struct efhw_nic* nic, int stack_id,
                                struct efhw_page_map* page_map,
                                struct ef_vi_xdp_offsets* offsets,
                                struct ef_vi_xdp_rings* rings)
{
#ifdef AF_XDP
  int rc, fd;
  struct efhw_af_xdp_vi* vi;
  struct socket* sock;

  vi = vi_by_stack(nic, stack_id);
  if( vi == NULL )
    return -ENODEV;

  if( vi->umem.ready != vi->umem.count ) {
    EFHW_ERR("%s: unexpected umem pages %ld != %ld", __FUNCTION__,
             vi->umem.ready, vi->umem.count);
    return -EPROTO;
  }

  sock = sock_from_file(vi->sock, &rc);
  if( sock == NULL )
    return rc;

  rc = xdp_register_umem(sock, &vi->umem);
  if( rc < 0 )
    return rc;

  rc = xdp_create_rings(sock, page_map, vi->rxq_capacity, vi->txq_capacity,
                        offsets, rings);
  if( rc < 0 )
    return rc;

  fd = xdp_alloc_fd(vi->sock);
  if( fd < 0 )
    return fd;

  rc = xdp_map_update_elem(nic->af_xdp->map, stack_id, fd);
  __close_fd(current->files, fd);
  if( rc < 0 )
    return rc;

  rc = xdp_bind(sock, nic->net_dev->ifindex, vi->flags);
  if( rc < 0 )
    xdp_map_delete_elem(nic->af_xdp->map, stack_id);

  return 0;
#else
  return -EPROTONOSUPPORT;
#endif
}

void efhw_nic_bodge_af_xdp_dtor(struct efhw_nic* nic)
{
#ifdef AF_XDP
  xdp_set_link(nic->net_dev, NULL);
  if( nic->af_xdp != NULL ) {
    fput(nic->af_xdp->map);
    kfree(nic->af_xdp);
  }
#endif
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
af_xdp_nic_init_hardware(struct efhw_nic *nic,
		       struct efhw_ev_handler *ev_handlers,
		       const uint8_t *mac_addr)
{
#ifdef AF_XDP
	int map_fd, rc;
	struct bpf_prog* prog;
	struct efhw_nic_af_xdp* xdp;

	xdp = kzalloc(sizeof(*xdp), GFP_KERNEL);
	if( xdp == NULL )
		return -ENOMEM;

	map_fd = xdp_map_create();
	if( map_fd < 0 ) {
		kfree(xdp);
		return map_fd;
	}

	rc = xdp_prog_load(map_fd);
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

	nic->af_xdp = xdp;
	memcpy(nic->mac_addr, mac_addr, ETH_ALEN);

	af_xdp_nic_tweak_hardware(nic);
	return 0;

fail:
	kfree(xdp);
	__close_fd(current->files, map_fd);
	return rc;
#else
	return -EPROTONOSUPPORT;
#endif
}


/*--------------------------------------------------------------------
 *
 * Event Management - and SW event posting
 *
 *--------------------------------------------------------------------*/


/* This function will enable the given event queue with the requested
 * properties.
 */
static int
af_xdp_nic_event_queue_enable(struct efhw_nic *nic, uint evq, uint evq_size,
			    dma_addr_t *dma_addrs,
			    uint n_pages, int interrupting, int enable_dos_p,
			    int wakeup_evq, int flags, int* flags_out)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
	return 0;
}

static void
af_xdp_nic_event_queue_disable(struct efhw_nic *nic, uint evq,
			     int time_sync_events_enabled)
{
	EFHW_ERR("%s: FIXME AF_XDP", __FUNCTION__);
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
#ifdef AF_XDP
  struct efhw_af_xdp_vi* vi = vi_by_stack(nic, stack_id);
  if( vi == NULL )
    return -ENODEV;

  vi->owner_id = own_id;
  vi->txq_capacity = dmaq_size;

  return 0;
#else
  return -EPROTONOSUPPORT;
#endif
}


static int
af_xdp_dmaq_rx_q_init(struct efhw_nic *nic, uint dmaq, uint evq_id, uint own_id,
		    uint tag, uint dmaq_size,
		    dma_addr_t *dma_addrs, int n_dma_addrs,
		    uint vport_id, uint stack_id, uint ps_buf_size, uint flags)
{
#ifdef AF_XDP
  struct efhw_af_xdp_vi* vi = vi_by_stack(nic, stack_id);
  if( vi == NULL )
    return -ENODEV;

  vi->owner_id = own_id;
  vi->rxq_capacity = dmaq_size;
  if( flags & EFHW_VI_RX_ZEROCOPY )
    vi->flags |= XDP_ZEROCOPY;

  return 0;
#else
  return -EPROTONOSUPPORT;
#endif
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

static const int __af_xdp_nic_buffer_table_get_orders[] = {0,4,8,10};


static int
af_xdp_nic_buffer_table_alloc(struct efhw_nic *nic, int owner, int order,
                              struct efhw_buffer_table_block **block_out,
                              int reset_pending)
{
#ifdef AF_XDP
  struct efhw_buffer_table_block* block;
  struct efhw_af_xdp_vi* vi = vi_by_owner(nic, owner);

  if( vi == NULL )
    return -ENODEV;

  if( vi->umem.alloc >= vi->umem.count )
    return -ENOMEM;

  block = kzalloc(sizeof(**block_out), GFP_KERNEL);
  if( block == NULL )
    return -ENOMEM;

  /* We reserve some bits of the handle to store the order, needed later to
   * calculate the address of each entry within the block. This limits the
   * number of owners we can support. Alternatively, we could use the high bits
   * of btb_vaddr (as ef10 does), and mask these out when using the addresses.
   */
  if( owner >= (1 << 24) )
    return -ENOSPC;

  /* TODO use af_xdp-specific data rather than repurposing ef10-specific */
  block->btb_hw.ef10.handle = order | (owner << 8);
  block->btb_vaddr = vi->umem.alloc << PAGE_SHIFT;
  vi->umem.alloc += EFHW_BUFFER_TABLE_BLOCK_SIZE << order;

  *block_out = block;
  return 0;
#else
  return -EPROTONOSUPPORT;
#endif
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
  kfree(block);
}


static int
af_xdp_nic_buffer_table_set(struct efhw_nic *nic,
                            struct efhw_buffer_table_block *block,
                            int first_entry, int n_entries,
                            dma_addr_t *dma_addrs)
{
#ifdef AF_XDP
  int i, j, owner, order;
  long first_page;
  struct efhw_af_xdp_vi* vi;

  owner = block->btb_hw.ef10.handle >> 8;
  order = block->btb_hw.ef10.handle & 0xff;
  vi = vi_by_owner(nic, owner);
  if( vi == NULL )
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

  first_page = (block->btb_vaddr >> PAGE_SHIFT) + (first_entry << order);
  if( first_page + (n_entries << order) > vi->umem.count )
    return -EINVAL;

  for( i = 0; i < n_entries; ++i ) {
    void** addrs = vi->umem.addrs + first_page + (i << order);
    char* dma_addr = (char*)dma_addrs[i];
    for( j = 0; j < (1 << order); ++j )
      addrs[j] = dma_addr + j * PAGE_SIZE;
  }

  vi->umem.ready += (n_entries << order);
  return 0;
#else
  return -EPROTONOSUPPORT;
#endif
}


static void
af_xdp_nic_buffer_table_clear(struct efhw_nic *nic,
                              struct efhw_buffer_table_block *block,
                              int first_entry, int n_entries)
{
#ifdef AF_XDP
  int owner = block->btb_hw.ef10.handle >> 8;
  struct efhw_af_xdp_vi* vi = vi_by_owner(nic, owner);
  if( vi != NULL )
    xdp_release_vi(nic, vi);
#endif
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
};
