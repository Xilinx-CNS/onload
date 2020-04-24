/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: djr
**     Started: 2006/06/16
** Description: TCP helper resource
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_driver_efab */
#include <onload/debug.h>
#include <onload/tcp_driver.h>
#include <onload/cplane_ops.h>
#include <onload/tcp_helper.h>
#include <ci/efch/mmap.h>
#include <onload/mmap.h>


static int tcp_helper_rm_mmap_mem(tcp_helper_resource_t* trs,
                                  unsigned long bytes,
                                  struct vm_area_struct* vma)
{
  int rc = 0;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  rc = ci_shmbuf_mmap(&trs->netif.pages_buf, 0, &bytes, vma,
                           &map_num, &offset);
  if( rc < 0 )  goto out;
  OO_DEBUG_MEMSIZE(ci_log("after mapping page buf have %ld", bytes));

  ci_assert_equal(bytes, 0);

 out:
  return rc;
}


static int tcp_helper_rm_mmap_timesync(tcp_helper_resource_t* trs,
                                       unsigned long bytes,
                                       struct vm_area_struct* vma, int is_writable)
{
  int rc = 0;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  if( is_writable )
    return -EPERM;

  rc = ci_shmbuf_mmap(&efab_tcp_driver.shmbuf, offset, &bytes, vma,
                      &map_num, &offset);
  if( rc < 0 )  return rc;
  ci_assert_equal(bytes, 0);

  return rc;
}


static int tcp_helper_rm_mmap_io(tcp_helper_resource_t* trs,
                                 unsigned long bytes,
                                 struct vm_area_struct* vma)
{
  int rc, intf_i;
  int map_num = 0;
  unsigned long offset = 0;
  ci_netif* ni;

  ni = &trs->netif;
  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    rc = efab_vi_resource_mmap(trs->nic[intf_i].thn_vi_rs, &bytes, vma,
                               &map_num, &offset, EFCH_VI_MMAP_IO);
    if( rc < 0 )
      return rc;

  }
  ci_assert_equal(bytes, 0);

  return 0;
}


#if CI_CFG_PIO
static int tcp_helper_rm_mmap_pio(tcp_helper_resource_t* trs,
                                  unsigned long bytes,
                                  struct vm_area_struct* vma)
{
  int rc, intf_i;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    if( trs->nic[intf_i].thn_pio_io_mmap_bytes != 0 ) {
      rc = efab_vi_resource_mmap(trs->nic[intf_i].thn_vi_rs, &bytes, vma,
                                 &map_num, &offset, EFCH_VI_MMAP_PIO);
      if( rc < 0 )
        return rc;
    }
  }
  ci_assert_equal(bytes, 0);

  return 0;
}
#endif

#if CI_CFG_CTPIO
static int tcp_helper_rm_mmap_ctpio(tcp_helper_resource_t* trs,
                                    unsigned long bytes,
                                    struct vm_area_struct* vma)
{
  int rc, intf_i;
  int map_num = 0;
  unsigned long offset = 0;

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(&trs->netif, intf_i) {
    if( trs->nic[intf_i].thn_ctpio_io_mmap_bytes != 0 ) {
      rc = efab_vi_resource_mmap(trs->nic[intf_i].thn_vi_rs, &bytes, vma,
                                 &map_num, &offset, EFCH_VI_MMAP_CTPIO);
      if( rc < 0 )
        return rc;
    }
  }
  ci_assert_equal(bytes, 0);

  return 0;
}
#endif


static int tcp_helper_rm_mmap_buf(tcp_helper_resource_t* trs,
                                  unsigned long bytes,
                                  struct vm_area_struct* vma)
{
  int intf_i, rc;
  ci_netif* ni;
  int map_num = 0;
  unsigned long offset = 0;

  ni = &trs->netif;
  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx", __func__, trs->id, bytes));

  OO_STACK_FOR_EACH_INTF_I(ni, intf_i ) {
    rc = efab_vi_resource_mmap(trs->nic[intf_i].thn_vi_rs, &bytes, vma,
                               &map_num, &offset, EFCH_VI_MMAP_MEM);
    if( rc < 0 )  return rc;

  }
  ci_assert_equal(bytes, 0);
  return 0;
}

/* fixme: this handler is linux-only */
static int tcp_helper_rm_mmap_pkts(tcp_helper_resource_t* trs,
                                   unsigned long bytes,
                                   struct vm_area_struct* vma, int map_id)
{
  ci_netif* ni;
  ci_netif_state* ns;
  int bufid = map_id - CI_NETIF_MMAP_ID_PKTS;

  if( bytes != CI_CFG_PKT_BUF_SIZE * PKTS_PER_SET )
    return -EINVAL;

  ni = &trs->netif;
  ns = ni->state;
  ci_assert(ns);

  /* Reserve space for packet buffers */
  if( bufid < 0 || bufid > ni->packets->sets_max ||
      ni->pkt_bufs[bufid] == NULL ) {
    OO_DEBUG_ERR(ci_log("%s: %u BAD bufset_id=%d", __FUNCTION__,
                        trs->id, bufid));
    return -EINVAL;
  }
#ifdef OO_DO_HUGE_PAGES
  if( oo_iobufset_get_shmid(ni->pkt_bufs[bufid]) >= 0 ) {
    OO_DEBUG_ERR(ci_log("%s: [%d] WARNING mmapping huge page from bufset=%d "
                        "will split it", __func__, trs->id, bufid));
  }
#endif

  if( oo_iobufset_npages(ni->pkt_bufs[bufid]) == 1 ) {
    /* Avoid nopage handler, mmap it all at once */
    return remap_pfn_range(vma, vma->vm_start,
                           oo_iobufset_pfn(ni->pkt_bufs[bufid], 0), bytes,
                           vma->vm_page_prot);
  }

  return 0;
}


int efab_tcp_helper_rm_mmap(tcp_helper_resource_t* trs, unsigned long bytes,
                            struct vm_area_struct* vma, int map_id, int is_writable)
{
  int rc;

  TCP_HELPER_RESOURCE_ASSERT_VALID(trs, 0);
  ci_assert(bytes > 0);

  OO_DEBUG_VM(ci_log("%s: %u bytes=0x%lx map_id=%x", __func__,
                     trs->id, bytes, map_id));

  switch( map_id ) {
    case CI_NETIF_MMAP_ID_STATE:
      rc = tcp_helper_rm_mmap_mem(trs, bytes, vma);
      break;
    case CI_NETIF_MMAP_ID_TIMESYNC:
      rc = tcp_helper_rm_mmap_timesync(trs, bytes, vma, is_writable);
      break;
    case CI_NETIF_MMAP_ID_IO:
      rc = tcp_helper_rm_mmap_io(trs, bytes, vma);
      break;
#if CI_CFG_PIO
    case CI_NETIF_MMAP_ID_PIO:
      rc = tcp_helper_rm_mmap_pio(trs, bytes, vma);
      break;
#endif
#if CI_CFG_CTPIO
    case CI_NETIF_MMAP_ID_CTPIO:
      rc = tcp_helper_rm_mmap_ctpio(trs, bytes, vma);
      break;
#endif
    case CI_NETIF_MMAP_ID_IOBUFS:
      rc = tcp_helper_rm_mmap_buf(trs, bytes, vma);
      break;
    default:
      /* CI_NETIF_MMAP_ID_PKTS + set_id */
      rc = tcp_helper_rm_mmap_pkts(trs, bytes, vma, map_id);
  }

  if( rc == 0 )  return 0;

  OO_DEBUG_VM(ci_log("%s: failed map_id=%x rc=%d", __FUNCTION__, map_id, rc));
  return rc;
}

/*! \cidoxg_end */
