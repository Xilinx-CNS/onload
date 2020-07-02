/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#include "ef_vi_internal.h"

#if CI_HAVE_AF_XDP
#include "logging.h"

#ifdef __KERNEL__
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/highmem.h>
typedef int socklen_t;
#else /* __KERNEL__ */
#include <limits.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/bpf.h>
#include <linux/rtnetlink.h>
#endif /* __KERNEL__ */

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

/* Get an AF_XDP socket option */
static int xdp_getopt(efxdp_sock_t sock, int opt, void* val, socklen_t *len)
{
  int rc;
#ifdef __KERNEL__
  rc = kernel_getsockopt(sock, SOL_XDP, opt, val, len);
#else
  rc = efxdp_syscall(SYS_getsockopt, sock, SOL_XDP, opt, val, len);
  if( rc < 0 )
    rc = -errno;
#endif
  return rc;
}

/* Get the offsets for the memory-mapped data structures of an AF_XDP socket */
static int xdp_mmap_offsets(efxdp_sock_t sock, struct xdp_mmap_offsets* off)
{
  socklen_t len = sizeof(*off);
  return xdp_getopt(sock, XDP_MMAP_OFFSETS, off, &len);
}

/* Map an AF_XDP socket's ring buffer into user memory */
static int xdp_map_ring(efxdp_sock_t sock, struct ef_vi_xdp_ring* ring,
                        int capacity, int item_size,
                        struct xdp_ring_offset* off, uint64_t pgoff)
{
  if( capacity == 0 )
    return 0;

  ring->size = off->desc + (capacity + 1) * item_size;
  {
#ifdef __KERNEL__
    int rc = 0;
    uint64_t addr;
    struct vm_area_struct* vma;
    unsigned long pfn;

    addr = vm_mmap(sock->file, 0, ring->size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, pgoff);
    if( IS_ERR_VALUE(addr) )
      return addr;

    vma = find_vma(current->mm, addr);
    rc = vma == NULL ? -EFAULT : follow_pfn(vma, addr, &pfn);

    vm_munmap(addr, ring->size);
    if( rc < 0 )
      return rc;

    ring->addr = phys_to_virt(pfn << PAGE_SHIFT);
#else
    void* addr = mmap(NULL, ring->size, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE, sock, pgoff);
    if( addr == MAP_FAILED )
      return -errno;

    ring->addr = addr;
#endif
  }
  ring->desc = ring->addr + off->desc;
  ring->producer = (uint32_t*)(ring->addr + off->producer);
  ring->consumer = (uint32_t*)(ring->addr + off->consumer);
  return 0;
}

/* Unmap an AF_XDP ring buffer from user memory */
static int xdp_unmap_ring(struct ef_vi_xdp_ring* ring)
{
#ifdef __KERNEL__
  return 0;
#else
  if( ring->addr == NULL || munmap(ring->addr, ring->size) == 0 )
    return 0;

  return -errno;
#endif
}
#endif /* CI_HAVE_AF_XDP */

int efxdp_vi_mmap(ef_vi* vi, efxdp_sock_t sock)
{
#if CI_HAVE_AF_XDP
  int rc;
  struct xdp_mmap_offsets off;

  int rx_cap = ef_vi_receive_capacity(vi);
  int tx_cap = ef_vi_transmit_capacity(vi);

  rc = xdp_mmap_offsets(sock, &off);
  if( rc < 0 )
    return rc;

  rc = xdp_map_ring(sock, &vi->xdp_rx, rx_cap, sizeof(struct xdp_desc),
                    &off.rx, XDP_PGOFF_RX_RING);
  if( rc < 0 )
    return rc;

  rc = xdp_map_ring(sock, &vi->xdp_tx, tx_cap, sizeof(struct xdp_desc),
                    &off.tx, XDP_PGOFF_TX_RING);
  if( rc < 0 )
    return rc;

  rc = xdp_map_ring(sock, &vi->xdp_fr, rx_cap, sizeof(uint64_t),
                    &off.fr, XDP_UMEM_PGOFF_FILL_RING);
  if( rc < 0 )
    return rc;

  rc = xdp_map_ring(sock, &vi->xdp_cr, tx_cap, sizeof(uint64_t),
                    &off.cr, XDP_UMEM_PGOFF_COMPLETION_RING);
  if( rc < 0 )
    return rc;

  return 0;
#else
  return -ENOSYS;
#endif
}

void efxdp_vi_munmap(ef_vi* vi)
{
#if CI_HAVE_AF_XDP
  xdp_unmap_ring(&vi->xdp_rx);
  xdp_unmap_ring(&vi->xdp_tx);
  xdp_unmap_ring(&vi->xdp_fr);
  xdp_unmap_ring(&vi->xdp_cr);
#endif
}

#ifndef __KERNEL__
extern long syscall(long nr, ...);
long (*efxdp_syscall)(long nr, ...) = syscall;
#endif

