/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */
#ifndef __ONLOAD_MMAP_H__
#define __ONLOAD_MMAP_H__

#include <onload/mmap_base.h>
#include <cplane/mmap.h>

#ifndef __KERNEL__
# include <sys/mman.h>
#endif

/* OO_MMAP_TYPE_NETIF offsets has following IDs:
 * - CI_NETIF_MMAP_ID_STATE     netif shared state; ep buffers
 * - CI_NETIF_MMAP_ID_TIMESYNC  timesync shared state, read-only
 *                              (could be extended to other global shared
 *                              states)
 * - CI_NETIF_MMAP_ID_IO        VI resource: IO bar.
 * - CI_NETIF_MMAP_ID_IOBUFS    VI resource: queues
 *   + if CI_CFG_PKTS_AS_HUGE_PAGES=1, mmap pkt_shm_id array
 * - CI_NETIF_MMAP_ID_PIO       VI resource: PIO IO BAR
 * - CI_NETIF_MMAP_ID_CTPIO     VI resource: CTPIO IO BAR
 * - CI_NETIF_MMAP_ID_EFCT_SHM  VI resource: EFCT rxq shared state
 * - CI_NETIF_MMAP_ID_PKTS + packet set id
 *   packet sets
 */
#define CI_NETIF_MMAP_ID_STATE    0
#define CI_NETIF_MMAP_ID_TIMESYNC 1
#define CI_NETIF_MMAP_ID_IO       2
#define CI_NETIF_MMAP_ID_IOBUFS   3
#define CI_NETIF_MMAP_ID_PIO      4
#define CI_NETIF_MMAP_ID_CTPIO    5
#define CI_NETIF_MMAP_ID_EFCT_SHM 7
#define CI_NETIF_MMAP_ID_PKTS     8
#define CI_NETIF_MMAP_ID_PKTSET(id) (CI_NETIF_MMAP_ID_PKTS+(id))


/* OO_MMAP_TYPE_DSHM:
 * "Donation" shm mmap IDs encode buffer ID and class. */
#ifdef OO_MMAP_TYPE_DSHM
# define OO_MMAP_DSHM_BUFFER_ID_WIDTH 32
# define OO_MMAP_DSHM_SHM_CLASS_WIDTH 12
# define OO_MMAP_DSHM_BUFFER_ID(map_id) \
    ((map_id) & ((1ull << OO_MMAP_DSHM_BUFFER_ID_WIDTH) - 1))
# define OO_MMAP_DSHM_SHM_CLASS(map_id) \
    (((map_id) >> OO_MMAP_DSHM_BUFFER_ID_WIDTH) & \
     ((1ull << OO_MMAP_DSHM_SHM_CLASS_WIDTH) - 1))
# define OO_MMAP_DSHM_MAKE_ID(shm_class, buffer_id) \
    ((ci_uint64) (buffer_id) | \
     ((ci_uint64) (shm_class) << OO_MMAP_DSHM_BUFFER_ID_WIDTH))
#endif

#define OO_MMAP_UBUF_POST_IX_WIDTH 16
#define OO_MMAP_UBUF_POST_INTF_I_WIDTH 16
#define OO_MMAP_UBUF_POST_IX(map_id) \
  ((map_id) & ((1ull << OO_MMAP_UBUF_POST_IX_WIDTH) - 1))
#define OO_MMAP_UBUF_POST_INTF_I(map_id) \
  (((map_id) >> OO_MMAP_UBUF_POST_IX_WIDTH) & \
   ((1ull << OO_MMAP_UBUF_POST_INTF_I_WIDTH) - 1))
#define OO_MMAP_UBUF_POST_MAKE_ID(ix, intf_i) \
  ((ci_uint64) (ix) | \
   ((ci_uint64) (intf_i) << OO_MMAP_UBUF_POST_IX_WIDTH))

#define VMA_OFFSET(vma)  ((vma)->vm_pgoff << PAGE_SHIFT)

#ifndef __KERNEL__

#define OO_MMAP_FLAG_DEFAULT  0
#define OO_MMAP_FLAG_READONLY 1
#define OO_MMAP_FLAG_FIXED    2
#define OO_MMAP_FLAG_POPULATE 4
ci_inline int
oo_resource_mmap(ci_fd_t fp, ci_uint8 map_type, unsigned long map_id,
                 unsigned bytes, int flags, void** p_out)
{
  int mmap_prot = PROT_READ;
  int mmap_flags = MAP_SHARED;
  int saved_errno = errno;

#ifndef OO_MMAP_TYPE_DSHM
  ci_assert(map_type == OO_MMAP_TYPE_NETIF ||
            map_type == OO_MMAP_TYPE_UBUF_POST);
#endif

  if( ! (flags & OO_MMAP_FLAG_READONLY) )
    mmap_prot |= PROT_WRITE;
  if( flags & OO_MMAP_FLAG_FIXED )
    mmap_flags |= MAP_FIXED;
  if( flags & OO_MMAP_FLAG_POPULATE )
    mmap_flags |= MAP_POPULATE;
  *p_out = mmap((flags & OO_MMAP_FLAG_FIXED) ? *p_out : (void*) 0, bytes,
                mmap_prot, mmap_flags, fp,
                OO_MMAP_MAKE_OFFSET(map_type, map_id));
  if( *p_out == MAP_FAILED ) {
    int rc = -errno;
    errno = saved_errno;
    return rc;
  }
  return 0;
}

ci_inline int
oo_resource_munmap(ci_fd_t fp, void* ptr, int bytes)
{
  if( munmap(ptr, bytes) < 0 )  return -errno;
  return 0;
}

ci_inline int
oo_resource_op(ci_fd_t fp, ci_uint32 cmd, void* io)
{
  int r;
  int saved_errno = errno;
  if( (r = ci_sys_ioctl(fp, cmd, io)) < 0 ) {
    r = -errno;
    errno = saved_errno;
  }
  return r;
}

#else /* ! __KERNEL__ */

int oo_ubuf_post_mmap(struct file *file, struct vm_area_struct *vma);

#endif /* ! __KERNEL__ */

#endif
