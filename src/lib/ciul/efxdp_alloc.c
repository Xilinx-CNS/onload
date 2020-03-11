/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#include "ef_vi_internal.h"

#if CI_HAVE_AF_XDP
#include "logging.h"

#include <limits.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/bpf.h>
#include <linux/rtnetlink.h>
#include <linux/if_xdp.h>

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

/* Helper functions for working with AF_XDP sockets */

/* Open an AF_XDP socket */
static int xdp_socket(void)
{
  int rc = socket(AF_XDP, SOCK_RAW, 0);
  if( rc < 0 ) {
    rc = -errno;
    LOGV(ef_log("%s: socket %d", __FUNCTION__, rc));
  }
  return rc;
}

/* Bind an AF_XDP socket to an interface */
static int xdp_bind(int fd, int ifindex)
{
  int rc;
  struct sockaddr_xdp sxdp = {};

  sxdp.sxdp_family = PF_XDP;
  sxdp.sxdp_ifindex = ifindex;
  sxdp.sxdp_queue_id = 0; // TODO configure?

  rc = bind(fd, (struct sockaddr*)&sxdp, sizeof(sxdp));
  if( rc < 0 ) {
    rc = -errno;
    LOGV(ef_log("%s: bind %d", __FUNCTION__, rc));
  }
  return rc;
}

/* Set an AF_XDP socket option */
static int xdp_setopt(int fd, int opt, const void* val, socklen_t len)
{
  int rc = setsockopt(fd, SOL_XDP, opt, val, len);
  if( rc < 0 ) {
    rc = -errno;
    LOGV(ef_log("%s: setsockopt %d %d", __FUNCTION__, opt, rc));
  }
  return rc;
}

/* Get an AF_XDP socket option */
static int xdp_getopt(int fd, int opt, void* val, socklen_t *len)
{
  int rc = getsockopt(fd, SOL_XDP, opt, val, len);
  if( rc < 0 ) {
    rc = -errno;
    LOGV(ef_log("%s: getsockopt %d %d", __FUNCTION__, opt, rc));
  }
  return rc;
}

/* Get the offsets for the memory-mapped data structures of an AF_XDP socket */
static int xdp_mmap_offsets(int fd, struct xdp_mmap_offsets* off)
{
  socklen_t len = sizeof(*off);
  return xdp_getopt(fd, XDP_MMAP_OFFSETS, off, &len);
}

/* Map an AF_XDP data structure into user memory */
static void* xdp_mmap(int fd, size_t size, uint64_t pgoff)
{
#ifdef __i386__
  /* This version is needed because some offsets overflow a 32-bit off_t */
  return (void*)syscall(SYS_mmap2, NULL, size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, fd, pgoff / 4096);
#else
  /* This version is needed because mmap2 does not exist on 64-bit systems */
  return mmap(NULL, size, PROT_READ | PROT_WRITE,
              MAP_SHARED | MAP_POPULATE, fd, pgoff);
#endif
}

/* Map an AF_XDP socket's ring buffer into user memory */
static int xdp_map_ring(struct ef_vi_xdp_ring* ring, int fd,
                        int capacity, int item_size,
                        struct xdp_ring_offset* off, uint64_t pgoff, int opt)
{
  int rc;
  EF_VI_BUG_ON(! EF_VI_IS_POW2(capacity));

  rc = xdp_setopt(fd, opt, &capacity, sizeof(int));
  if( rc < 0 )
    return rc;

  ring->size = off->desc + capacity * item_size;
  ring->addr = xdp_mmap(fd, ring->size, pgoff);
  if( ring->addr == MAP_FAILED ) {
    rc = -errno;
    LOGV(ef_log("%s: mmap %d", __FUNCTION__, rc));
    ring->addr = NULL;
    return rc;
  }

  ring->desc = ring->addr + off->desc;
  ring->producer = (uint32_t*)(ring->addr + off->producer);
  ring->consumer = (uint32_t*)(ring->addr + off->consumer);
  return 0;
}

/* Map an AF_XDP socket's rx descriptor ring into user memory */
static int xdp_map_rx(ef_vi* vi, int capacity, struct xdp_mmap_offsets* off)
{
  return xdp_map_ring(&vi->xdp_rx, vi->xdp_sock, capacity,
                      sizeof(struct xdp_desc), &off->rx,
                      XDP_PGOFF_RX_RING, XDP_RX_RING);
}

/* Map an AF_XDP socket's tx descriptor ring into user memory */
static int xdp_map_tx(ef_vi* vi, int capacity, struct xdp_mmap_offsets* off)
{
  return xdp_map_ring(&vi->xdp_tx, vi->xdp_sock, capacity,
                      sizeof(struct xdp_desc), &off->tx,
                      XDP_PGOFF_TX_RING, XDP_TX_RING);
}

/* Map an AF_XDP socket's fill ring into user memory */
static int xdp_map_fr(ef_vi* vi, int capacity, struct xdp_mmap_offsets* off)
{
  return xdp_map_ring(&vi->xdp_fr, vi->xdp_sock, capacity,
                      sizeof(uint64_t), &off->fr,
                      XDP_UMEM_PGOFF_FILL_RING, XDP_UMEM_FILL_RING);
}

/* Map an AF_XDP socket's completion ring into user memory */
static int xdp_map_cr(ef_vi* vi, int capacity, struct xdp_mmap_offsets* off)
{
  return xdp_map_ring(&vi->xdp_cr, vi->xdp_sock, capacity,
                      sizeof(uint64_t), &off->cr,
                      XDP_UMEM_PGOFF_COMPLETION_RING, XDP_UMEM_COMPLETION_RING);
}

/* Unmap an AF_XDP ring buffer from user memory */
static int xdp_unmap_ring(struct ef_vi_xdp_ring* ring)
{
  if( ring->addr == NULL || munmap(ring->addr, ring->size) == 0 )
    return 0;

  return -errno;
}

/* Request low-level information an AF_XDP socket's interface */
static int xdp_ifreq(ef_vi* vi, int request, struct ifreq* ifr)
{
  int s, rc = 0;

  if( if_indextoname(vi->xdp_ifindex, ifr->ifr_name) == NULL )
    return -errno;

  /* The AF_XDP socket doesn't seem to be sockety enough for these operations */
  s = socket(AF_UNIX, SOCK_DGRAM, 0);
  if( s < 0 )
    return -errno;

  if( ioctl(s, request, ifr) < 0 )
    rc = -errno;

  close(s);
  return rc;
}

// TODO Mutable globals are evil. These will need to be per-interface I think.
static int xdp_map_fd = -1, xdp_prog_fd = -1;

/* Invoke the bpf system call */
static int xdp_sys_bpf(enum bpf_cmd cmd, union bpf_attr* attr)
{
  return syscall(SYS_bpf, cmd, attr, sizeof(*attr));
}

/* Create the xdp socket map to share with the BPF program */
static int xdp_map_create(void)
{
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.map_type = BPF_MAP_TYPE_XSKMAP;
  attr.key_size = sizeof(int);
  attr.value_size = sizeof(int);
  attr.max_entries = 1; // TODO support more than one socket
  strncpy(attr.map_name, "onload_xsks", BPF_OBJ_NAME_LEN);

  return xdp_sys_bpf(BPF_MAP_CREATE, &attr);
}

/* Load the BPF program to redirect inbound packets to AF_XDP sockets */
static int xdp_prog_load(void)
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
    0x0000000000001118 | ((uint64_t)xdp_map_fd << 32),

    0x0000000000000000,0x00000000000002b7,0x00000000000003b7,0x0000003300000085,
    0x0000000000000095
  };

  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.prog_type = BPF_PROG_TYPE_XDP;
  attr.insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
  attr.insns = (uintptr_t)prog;
  attr.license = (uintptr_t)"GPL";
  strncpy(attr.prog_name, "xdpsock", BPF_OBJ_NAME_LEN);

  return xdp_sys_bpf(BPF_PROG_LOAD, &attr);
}

/* Update an element in the XDP socket map */
static int xdp_map_update_elem(int key, int value)
{
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.map_fd = xdp_map_fd;
  attr.key = (uintptr_t)(&key);
  attr.value = (uintptr_t)(&value);

  return xdp_sys_bpf(BPF_MAP_UPDATE_ELEM, &attr) == 0 ? 0 : -errno;
}

/* Delete an element from the XDP socket map */
static int xdp_map_delete_elem(int key)
{
  union bpf_attr attr;

  memset(&attr, 0, sizeof(attr));
  attr.map_fd = xdp_map_fd;
  attr.key = (uintptr_t)(&key);

  return xdp_sys_bpf(BPF_MAP_DELETE_ELEM, &attr) == 0 ? 0 : -errno;
}

/* Create the XDP resources needed for receiving packets on AF_XDP sockets */
int xdp_create_rx_resources(void)
{
  if( xdp_map_fd >= 0 )
    return 0;

  xdp_map_fd = xdp_map_create();
  if( xdp_map_fd < 0 )
    return -errno;

  xdp_prog_fd = xdp_prog_load();
  if( xdp_prog_fd < 0 ) {
    close(xdp_map_fd);
    xdp_map_fd = -1;
    return -errno;
  }

  return 0;
}

/* Link an XDP program to an interface */
static int xdp_set_link(unsigned ifindex, int prog_fd)
{
  struct sockaddr_nl sa = {};
  socklen_t len = sizeof(sa);
  int sock, rc;
  char buf[4096];

  struct {
    struct nlmsghdr nh;
    struct ifinfomsg ifinfo;
    char buf[64];
  } req = {};
  struct nlattr *nla, *nla_xdp;
  struct nlmsghdr* nh;
  struct nlmsgerr* err;

  sa.nl_family = AF_NETLINK;

  sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if( sock < 0 )
    return -errno;

  rc = bind(sock, (struct sockaddr*)&sa, len);
  if( rc < 0 )
    goto fail;

  rc = getsockname(sock, (struct sockaddr*)&sa, &len);
  if( rc < 0 )
    goto fail;

  req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.nh.nlmsg_type = RTM_SETLINK;
  req.nh.nlmsg_seq = 1;
  req.ifinfo.ifi_family = AF_UNSPEC;
  req.ifinfo.ifi_index = ifindex;

  nla = (struct nlattr*)((char*)&req + NLMSG_ALIGN(req.nh.nlmsg_len));
  nla->nla_type = NLA_F_NESTED | IFLA_XDP;
  nla->nla_len = NLA_HDRLEN;

  nla_xdp = (struct nlattr*)((char*)nla + nla->nla_len);
  nla_xdp->nla_type = IFLA_XDP_FD;
  nla_xdp->nla_len = NLA_HDRLEN + sizeof(int);
  memcpy((char*)nla_xdp + NLA_HDRLEN, &prog_fd, sizeof(int));

  nla->nla_len += nla_xdp->nla_len;
  req.nh.nlmsg_len += NLA_ALIGN(nla->nla_len);

  rc = send(sock, &req, req.nh.nlmsg_len, 0);
  if( rc < 0 )
    goto fail;

  len = recv(sock, buf, sizeof(buf), 0);
  if( len < 0 )
    goto fail;

  rc = 0;
  for( nh = (struct nlmsghdr*)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len) ) {
    if( nh->nlmsg_type == NLMSG_ERROR ) {
      err = (struct nlmsgerr*)NLMSG_DATA(nh);
      if( err->error != 0 )
        rc = err->error;
    }
  }

  close(sock);
  return rc;

fail:
  rc = -errno;
  close(sock);
  return rc;
}

/* Second stage of VI initialisation, once user memory is available */
static int efxdp_vi_bind(ef_vi* vi, ef_pd* pd)
{
  int rc;
  struct xdp_mmap_offsets off;
  struct xdp_umem_reg mr;

  int rxq_capacity = 1 + ef_vi_receive_capacity(vi);
  int txq_capacity = 1 + ef_vi_transmit_capacity(vi);

  if( pd->pd_xdp_umem.iov_base == NULL )
    return -ENOENT;

  rc = xdp_mmap_offsets(vi->xdp_sock, &off);
  if( rc < 0 )
    return rc;

  mr.addr = (uintptr_t)pd->pd_xdp_umem.iov_base;
  mr.len = pd->pd_xdp_umem.iov_len;
  mr.chunk_size = vi->rx_buffer_len;
  mr.headroom = vi->rx_prefix_len;

  rc = xdp_setopt(vi->xdp_sock, XDP_UMEM_REG, &mr, sizeof(mr));
  if( rc < 0 )
    return rc;

  rc = xdp_map_fr(vi, rxq_capacity, &off);
  if( rc < 0 )
    return rc;

  rc = xdp_map_cr(vi, txq_capacity, &off);
  if( rc < 0 )
    goto fail;

  rc = xdp_bind(vi->xdp_sock, vi->xdp_ifindex);
  if( rc < 0 )
    goto fail;

  vi->xdp_sock_key = 0; // TODO support more than one socket
  if( rxq_capacity > 1 ) {
    rc = xdp_map_update_elem(vi->xdp_sock_key, vi->xdp_sock);
    if( rc < 0 )
      goto fail;
  }

  return 0;

fail:
  xdp_unmap_ring(&vi->xdp_fr);
  xdp_unmap_ring(&vi->xdp_cr);
  return rc;
}

/* Round up a requested queue capacity to a power of 2 */
static int q_capacity(int request)
{
  /* Bounds for queue size. The lower bound is somewhat arbitrary to avoid
   * tiny queues. The upper bound is the largest representable power of 2. */
  int min = 256, max = 1 << (sizeof(int) * CHAR_BIT - 2);

  if( request == 0 )
    return 0;
  if( request <= min )
    return min;
  if( request >= max )
    return max;

  return max >> (__builtin_clz(request - 1) - 2);
}

#endif /* CI_HAVE_AF_XDP */

int efxdp_vi_alloc(ef_vi* vi, int rxq_capacity, int txq_capacity,
                   unsigned ifindex, enum ef_vi_flags vi_flags,
                   struct ef_pd* pd)
{
#if CI_HAVE_AF_XDP
  int rc;
  ef_vi_state* state = NULL;
  uint32_t* ids = NULL;
  struct xdp_mmap_offsets off;

  rxq_capacity = q_capacity(rxq_capacity);
  txq_capacity = q_capacity(txq_capacity);

  state = malloc(ef_vi_calc_state_bytes(rxq_capacity, txq_capacity));
  if( state == NULL )
    return -ENOMEM;
  ids = (uint32_t*)(state + 1);

  ef_vi_init(vi, EF_VI_ARCH_AF_XDP, 0, 0, vi_flags, 0, state);

  /* Fake up a single-entry event queue so that ef_eventq_has_event() will
   * return true. The state structure begins with the zero-valued evq_ptr,
   * and is suitably aligned, so if we pretend there's an event there, it
   * will look like it might be valid.
   *
   * This means that the function is safe to use for an AF_XDP VI, without
   * impacting performance of standard VIs. We may want to make this work
   * properly in order to improve AF_XDP performance.
   */
  state->evq.evq_ptr = 0;
  vi->evq_base = (void*)state;
  vi->evq_mask = 0;

  vi->xdp_sock = rc = xdp_socket();
  if( rc < 0 )
    goto fail;

  rc = xdp_mmap_offsets(vi->xdp_sock, &off);
  if( rc < 0 )
    goto fail;

  if( rxq_capacity != 0 ) {
    rc = xdp_create_rx_resources();
    if( rc < 0 )
      goto fail;

    rc = xdp_set_link(ifindex, xdp_prog_fd);
    if( rc < 0 )
      goto fail;

    rc = xdp_map_rx(vi, rxq_capacity, &off);
    if( rc < 0 )
      goto fail;

    ef_vi_init_rxq(vi, rxq_capacity, NULL, ids, 0);
  }

  if( txq_capacity != 0 ) {
    rc = xdp_map_tx(vi, txq_capacity, &off);
    if( rc < 0 )
      goto fail;

    ef_vi_init_txq(vi, txq_capacity, NULL, ids + rxq_capacity);
  }

  ef_vi_init_state(vi);
  vi->xdp_ifindex = ifindex;
  vi->xdp_sock_key = -1;
  vi->rx_buffer_len = 2048;
  vi->rx_prefix_len = 0;

  if( pd->pd_xdp_umem.iov_base == NULL ) {
    vi->xdp_vi_next = pd->pd_xdp_vi_pending;
    pd->pd_xdp_vi_pending = vi;
    return 0;
  }

  return efxdp_vi_bind(vi, pd);

fail:
  xdp_unmap_ring(&vi->xdp_rx);
  xdp_unmap_ring(&vi->xdp_tx);
  if( vi->xdp_sock >= 0 ) close(vi->xdp_sock);
  free(state);
  return rc;
#else
  return -ENOSYS;
#endif
}

int efxdp_vi_free(ef_vi* vi)
{
#if CI_HAVE_AF_XDP
  int rc;

  rc = xdp_map_delete_elem(vi->xdp_sock_key);
  if( rc < 0 )
    return rc;

  rc = xdp_set_link(vi->xdp_ifindex, -1);
  if( rc < 0 )
    return rc;

  rc = xdp_unmap_ring(&vi->xdp_rx);
  if( rc < 0 )
    return rc;

  rc = xdp_unmap_ring(&vi->xdp_tx);
  if( rc < 0 )
    return rc;

  rc = xdp_unmap_ring(&vi->xdp_fr);
  if( rc < 0 )
    return rc;

  rc = xdp_unmap_ring(&vi->xdp_cr);
  if( rc < 0 )
    return rc;

  rc = close(vi->xdp_sock);
  if( rc < 0 )
    return -errno;

  return 0;
#else
  return -ENOSYS;
#endif
}

unsigned efxdp_vi_mtu(ef_vi* vi)
{
#if CI_HAVE_AF_XDP
  struct ifreq ifr;
  int rc = xdp_ifreq(vi, SIOCGIFMTU, &ifr);
  if( rc < 0 ) {
    LOGV(ef_log("%s: SIOCGIFMTU %d", __FUNCTION__, rc));
    return 0;
  }
  return ifr.ifr_mtu;
#else
  return 0;
#endif
}

int efxdp_vi_get_mac(ef_vi* vi, void* mac_out)
{
#if CI_HAVE_AF_XDP
  struct ifreq ifr;
  int rc = xdp_ifreq(vi, SIOCGIFHWADDR, &ifr);
  if( rc < 0 )
    LOGV(ef_log("%s: SIOCGIFHWADDR %d", __FUNCTION__, rc));
  memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
  return rc;
#else
  return -ENOSYS;
#endif
}

int efxdp_umem_alloc(ef_pd* pd, void* base, size_t len)
{
#if CI_HAVE_AF_XDP
  int rc;
  ef_vi* vi;

  if( pd->pd_xdp_umem.iov_base != NULL )
    return -EALREADY;

  pd->pd_xdp_umem.iov_base = base;
  pd->pd_xdp_umem.iov_len = len;

  rc = 0;
  for( vi = pd->pd_xdp_vi_pending; vi != NULL; vi = vi->xdp_vi_next ) {
    int this_rc = efxdp_vi_bind(vi, pd);
    if( this_rc < 0 )
      rc = this_rc;
  }

  return rc;
#else
  return -ENOSYS;
#endif
}
