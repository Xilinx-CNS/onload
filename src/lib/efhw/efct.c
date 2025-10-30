/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#include <ci/driver/kernel_compat.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/ci_aux.h>
#include <ci/driver/ci_efct.h>
#include <ci/efhw/common.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/efct.h>
#include <ci/efhw/efct_filters.h>
#include <ci/efhw/efct_wakeup.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/checks.h>
#include <ci/efhw/mc_driver_pcol.h>
#include <ci/driver/ci_efct.h>
#include <ci/tools/bitfield.h>
#include <ci/net/ipv6.h>
#include <ci/net/ipv4.h>
#include <net/sock.h>
#include <ci/tools/sysdep.h>
#include <ci/tools/bitfield.h>
#include <uapi/linux/ethtool.h>
#include "ethtool_flow.h"
#include <linux/hashtable.h>
#include <etherfabric/internal/internal.h>
#include <kernel_utils/hugetlb.h>
#include <linux/mman.h>
#include "efct.h"
#include "efct_superbuf.h"
#include "mcdi_common.h"

#if CI_HAVE_EFCT_AUX


static void efct_check_for_flushes(struct work_struct *work);
static ssize_t
efct_get_used_hugepages(struct efhw_nic *nic, int qid);

int
efct_nic_rxq_bind(struct efhw_nic *nic, struct efhw_shared_bind_params *params)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  ssize_t used_hugepages;
  int rc;

  struct xlnx_efct_rxq_params qparams = {
    .qid = params->qid,
    .timestamp_req = params->timestamp_req,
    .n_hugepages = params->n_hugepages,
  };

  /* We implicitly lock here by calling `efct_provide_hugetlb_alloc` so that
   * `used_hugepages` does not become invalid between now and binding */
  efct_provide_hugetlb_alloc(params->hugetlb_alloc);
  used_hugepages = efct_get_used_hugepages(nic, params->qid);
  if( used_hugepages < 0 ) {
    efct_unprovide_hugetlb_alloc();
    return used_hugepages;
  }

  EFHW_ASSERT(used_hugepages <= CI_EFCT_MAX_HUGEPAGES);

  if( params->n_hugepages + used_hugepages > CI_EFCT_MAX_HUGEPAGES ) {
    /* Ensure we do not donate more hugepages than we should otherwise
     * sbids > CI_EFCT_MAX_SUPERBUFS will be posted */
    efct_unprovide_hugetlb_alloc();
    return -EINVAL;
  }

  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = __efct_nic_rxq_bind(edev, cli, &qparams, nic->arch_extra,
                           params->n_hugepages, params->shm,
                           params->wakeup_instance, params->rxq);
  EFCT_POST(dev, edev, cli, nic, rc);

  efct_unprovide_hugetlb_alloc();

  params->rxq->uses_shared_evq = true;

  return rc;
}


void
efct_nic_rxq_free(struct efhw_nic *nic, struct efhw_efct_rxq *rxq,
                  efhw_efct_rxq_free_func_t *freer)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc)
  __efct_nic_rxq_free(edev, cli, rxq, freer);
  EFCT_POST(dev, edev, cli, nic, rc);
}

#define REFRESH_BATCH_SIZE  8
#define EFCT_INVALID_PFN   (~0ull)

static int
map_one_superbuf(unsigned long addr, const struct xlnx_efct_hugepage *kern)
{
  unsigned long rc;
  rc = vm_mmap(kern->file, addr, CI_HUGEPAGE_SIZE, PROT_READ, MAP_FIXED |
               MAP_SHARED | MAP_POPULATE | MAP_HUGETLB | MAP_HUGE_2MB,
               oo_hugetlb_page_offset(kern->page));
  if (IS_ERR((void*)rc))
    return PTR_ERR((void*)rc);
  return 0;
}

static int
fixup_superbuf_mapping(unsigned long addr, uint64_t *user,
                       const struct xlnx_efct_hugepage *kern,
                       const struct xlnx_efct_hugepage *spare_page)
{
  uint64_t pfn = kern->page ? __pa(kern->page) : EFCT_INVALID_PFN;
  if (*user == pfn)
    return 0;

  if (pfn == EFCT_INVALID_PFN) {
    /* Rather than actually unmapping the memory, we prefer to map in some
     * random other valid page instead. Ideally we'd use the huge zero
     * page, but we can't get at that so we pick a random other one of our
     * pages instead.
     * The reason for all this is that we promise that
     * ef_eventq_has_event() is safe to call concurrently with
     * ef_eventq_poll(). The latter might call in to this function to
     * unmap the exact page that the former is just about to look at. */
    if (!spare_page->page || map_one_superbuf(addr, spare_page))
      vm_munmap(addr, CI_HUGEPAGE_SIZE);
  }
  else {
    int rc = map_one_superbuf(addr, kern);
    if (rc)
      return rc;
  }
  *user = pfn;
  return 1;
}

int
efct_nic_shared_rxq_refresh(struct efhw_nic *nic, int hwqid,
                            unsigned long superbufs,
                            uint64_t __user *user_current,
                            unsigned max_superbufs)
{
  struct xlnx_efct_hugepage *pages;
  struct xlnx_efct_hugepage spare_page = {};
  size_t i;
  int rc = 0;
  bool is_sbuf_err_logged = false;
  unsigned n_hugepages = CI_MIN(max_superbufs,
                (unsigned)CI_EFCT_MAX_SUPERBUFS) / CI_EFCT_SUPERBUFS_PER_PAGE;

  if (max_superbufs < CI_EFCT_MAX_SUPERBUFS) {
    EFHW_TRACE("max_superbufs: %u passed in by user less than kernel's: %u. "
               "Ensure you do not create enough apps to donate more than %u "
               "superbufs! Alternatively, applications should be compiled with"
               " a newer userspace.", max_superbufs, CI_EFCT_MAX_SUPERBUFS,
               n_hugepages * CI_EFCT_SUPERBUFS_PER_PAGE);
  }

  pages = kmalloc_array(CI_EFCT_MAX_HUGEPAGES, sizeof(pages[0]), GFP_KERNEL);
  if (!pages)
    return -ENOMEM;

  rc = efct_get_hugepages(nic, hwqid, pages, CI_EFCT_MAX_HUGEPAGES);
  if (rc < 0) {
    kfree(pages);
    return rc;
  }
  for (i = 0; i < CI_EFCT_MAX_HUGEPAGES; ++i) {
    if (pages[i].page) {
      /* See commentary in fixup_superbuf_mapping(). It'd be possible to
       * have extensive debates about which is the least-worst page to
       * use for this purpose, but any decision would be crystal ball
       * work: we're trying to avoid wasting memory by having a page
       * mapped which is used for no other purpose other than as our
       * free page filler. */
      spare_page = pages[i];
      break;
    }
  }
  for (i = 0; i < n_hugepages; i += REFRESH_BATCH_SIZE) {
    uint64_t local_current[REFRESH_BATCH_SIZE];
    size_t j;
    size_t n = min((size_t)REFRESH_BATCH_SIZE, n_hugepages - i);
    bool changes = false;

    if (copy_from_user(local_current, user_current + i,
                       n * sizeof(*local_current))) {
      rc = -EFAULT;
      break;
    }

    for (j = 0; j < n; ++j) {
      rc = fixup_superbuf_mapping(superbufs + CI_HUGEPAGE_SIZE * (i + j),
                                  &local_current[j], &pages[i + j],
                                  &spare_page);
      if (rc < 0)
        break;
      if (rc)
        changes = true;
    }

    if (changes)
      if (copy_to_user(user_current + i, local_current,
                       n * sizeof(*local_current)))
        rc = -EFAULT;

    if (rc < 0)
      break;
  }

  for (i = 0; i < CI_EFCT_MAX_HUGEPAGES; i++) {
    if (pages[i].page != NULL) {
      put_page(pages[i].page);
      fput(pages[i].file);
      if (i > n_hugepages && !is_sbuf_err_logged) {
        EFHW_ERR("More than %d superbufs have been donated. User max: %u, "
                 "kernel max: %u. Applications should be recompiled with a "
                 "newer userspace.",
                 n_hugepages * CI_EFCT_SUPERBUFS_PER_PAGE, max_superbufs,
                 CI_EFCT_MAX_SUPERBUFS);
        is_sbuf_err_logged = true;
      }
    }
  }

  kfree(pages);
  return rc;
}

int
efct_nic_shared_rxq_refresh_kernel(struct efhw_nic *nic, int hwqid,
                                   const char** superbufs)
{
  struct xlnx_efct_hugepage *pages;
  size_t i;
  int rc = 0;

  pages = kmalloc_array(CI_EFCT_MAX_HUGEPAGES, sizeof(pages[0]), GFP_KERNEL);
  if (!pages)
    return -ENOMEM;

  rc = efct_get_hugepages(nic, hwqid, pages, CI_EFCT_MAX_HUGEPAGES);
  if (rc < 0) {
    kfree(pages);
    return rc;
  }
  for (i = 0; i < CI_EFCT_MAX_SUPERBUFS; ++i) {
    struct page* page = pages[i / CI_EFCT_SUPERBUFS_PER_PAGE].page;
    superbufs[i] = page_to_virt(page) +
                   EFCT_RX_SUPERBUF_BYTES * (i % CI_EFCT_SUPERBUFS_PER_PAGE);
  }

  for (i = 0; i < CI_EFCT_MAX_HUGEPAGES; ++i) {
    if (pages[i].page != NULL) {
      put_page(pages[i].page);
      fput(pages[i].file);
    }
  }

  kfree(pages);
  return rc;
}

int
efct_nic_shared_rxq_request_wakeup(struct efhw_nic *nic,
                                   struct efhw_efct_rxq *rxq,
                                   unsigned sbseq, unsigned pktix,
                                   bool allow_recursion)
{
  struct efhw_nic_efct* efct = nic->arch_extra;
  return efct_request_wakeup(nic, &efct->rxq[rxq->qid].apps, rxq, sbseq, pktix,
                             allow_recursion);
}


int
efct_get_hugepages(struct efhw_nic *nic, int hwqid,
                   struct xlnx_efct_hugepage *pages, size_t n_pages)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc)
  rc = edev->ops->get_hugepages(cli, hwqid, pages, n_pages);
  EFCT_POST(dev, edev, cli, nic, rc);
  return rc;
}

static int
efct_design_parameters(struct efhw_nic *nic,
                       struct efab_nic_design_parameters *dp)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  union xlnx_efct_param_value val;
  struct xlnx_efct_design_params* xp = &val.design_params;

  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc)
  rc = edev->ops->get_param(cli, XLNX_EFCT_DESIGN_PARAM, &val);
  EFCT_POST(dev, edev, cli, nic, rc);

  if( rc < 0 )
    return rc;

  /* Where older versions of ef_vi make assumptions about parameter values, we
   * must check that either they know about the parameter, or that the value
   * matches the assumption.
   *
   * See documentation of efab_nic_design_parameters for details of
   * compatibility issues.
   */
#define SET(PARAM, VALUE) \
  if( EFAB_NIC_DP_KNOWN(*dp, PARAM) ) \
    dp->PARAM = (VALUE);  \
  else if( (VALUE) != EFAB_NIC_DP_DEFAULT(PARAM) ) \
    return -ENODEV;

  /* Use this with care when ef_vi has never made assumptions about the value,
   * to avoid over-zealous failures if non-default values exist in the wild.
   */
#define SET_NO_CHECK(PARAM, VALUE) \
  if( EFAB_NIC_DP_KNOWN(*dp, PARAM) ) \
    dp->PARAM = (VALUE);

  SET(rx_superbuf_bytes, xp->rx_buffer_len * 4096);
  SET(rx_frame_offset, xp->frame_offset_fixed);
  SET_NO_CHECK(rx_stride, xp->rx_stride);
  SET_NO_CHECK(rx_queues, xp->rx_queues);
  SET(tx_aperture_bytes, xp->tx_aperture_size);
  SET(tx_fifo_bytes, xp->tx_fifo_size);
  SET(timestamp_subnano_bits, xp->ts_subnano_bit);
  SET(unsol_credit_seq_mask, xp->unsol_credit_seq_mask);
  SET(md_location, 0); // should we get the driver to supply this?
  SET(ct_thresh_min, 0);

  return 0;
}

static ssize_t
efct_get_used_hugepages(struct efhw_nic *nic, int qid)
{
  struct xlnx_efct_hugepage *pages;
  ssize_t used;
  int i, rc;

  pages = kvzalloc(sizeof(pages[0]) * CI_EFCT_MAX_HUGEPAGES, GFP_KERNEL);
  if( ! pages )
    return -ENOMEM;

  /* This call will return `EACCES` when `qid` is not bound to by `nic`. This
   * will happen when we have not yet allocated any hugepages with this pair
   * of parameters, so instead of returning an error code,  we validly return
   * that no hugepages are being used. */
  rc = efct_get_hugepages(nic, qid, pages, CI_EFCT_MAX_HUGEPAGES);
  if( rc < 0 ) {
    kfree(pages);
    return (rc != -EACCES) ? rc : 0;
  }

  used = 0;
  for( i = 0; i < CI_EFCT_MAX_HUGEPAGES; i++ ) {
    if( pages[i].page ) {
      used++;
      put_page(pages[i].page);
      fput(pages[i].file);
    }
  }

  kfree(pages);
  return used;
}


static size_t
efct_max_shared_rxqs(struct efhw_nic *nic)
{
  /* TODO ON-16696 this should perhaps return the per-nic limit:
   *
   *  struct efhw_nic_efct* efct = nic->arch_extra;
   *  return efct->rxq_n;
   *
   * However, in practice this is only used to determine the per-vi resources
   * to be allocated in efab_efct_rxq_uk_shm_base, which currently has a fixed
   * limit separate from the per-nic limit.
   *
   * Three ways to resolve this mismatch are:
   *  - modify ef_vi to support an arbitrary limit (defined at run-time),
   *    which can be set to match the per-nic limit;
   *  - implement a separate mechanism to provide the per-vi limit to efrm so
   *    that it can allocate the appropriate resources;
   *  - hack this function so that existing code uses the correct per-vi limit.
   *
   * As we don't yet have the means to test extensive code changes on hardware
   * with different per-nic and per-vi limits, I choose hackery for now.
   */
   return EF_VI_MAX_EFCT_RXQS;
}

/*----------------------------------------------------------------------------
 *
 * Initialisation and configuration discovery
 *
 *---------------------------------------------------------------------------*/


static void
efct_nic_tweak_hardware(struct efhw_nic *nic)
{
  nic->flags |= NIC_FLAG_PHYS_CONTIG_EVQ;
  nic->flags |= NIC_FLAG_EVQ_IRQ;
}


static int
efct_nic_sw_ctor(struct efhw_nic *nic,
                 const struct vi_resource_dimensions *res)
{
  nic->q_sizes[EFHW_EVQ] = 128 | 256 | 512 | 1024 | 2048 | 4096 | 8192;
  /* The TXQ is SW only, but reflects a limited HW resource */
  nic->q_sizes[EFHW_TXQ] = 512;
  /* RXQ is virtual/software-only, but some restrictions
   * Limited by CI_EFCT_MAX_SUPERBUFS and XNET-249 to 131,072
   * Also EF_VI code currently still limited to powers of 2 */
  nic->q_sizes[EFHW_RXQ] = 512 | 1024 | 2048 | 4096 | 8192 | 16384 | 32768 |
                           65536 | 131072;
  return 0;
}


static uint64_t
efct_nic_supported_filter_flags(struct efhw_nic *nic)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  int rc;
  size_t outlen_actual;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_GET_PARSER_DISP_INFO_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMAX);
  struct xlnx_efct_rpc rpc = {
    .cmd = MC_CMD_GET_PARSER_DISP_INFO,
    .inbuf = (u32*)&in,
    .inlen = MC_CMD_GET_PARSER_DISP_INFO_IN_LEN,
    .outbuf = (u32*)&out,
    .outlen = MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMAX,
    .outlen_actual = &outlen_actual,
  };

  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);

  EFHW_MCDI_SET_DWORD(in, GET_PARSER_DISP_INFO_IN_OP,
                   MC_CMD_GET_PARSER_DISP_INFO_IN_OP_GET_SUPPORTED_RX_MATCHES);

  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = edev->ops->fw_rpc(cli, &rpc);
  EFCT_POST(dev, edev, cli, nic, rc);

  if( rc != 0 )
    EFHW_ERR("%s: failed rc=%d", __FUNCTION__, rc);
  else if ( outlen_actual < MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMIN )
    EFHW_ERR("%s: failed, expected response min len %d, got %zd", __FUNCTION__,
             MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMIN, outlen_actual);

  EFHW_ASSERT(EFHW_MCDI_VAR_ARRAY_LEN(outlen_actual,
                GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES) ==
              EFHW_MCDI_DWORD(out,
                GET_PARSER_DISP_INFO_OUT_NUM_SUPPORTED_MATCHES));

  return mcdi_parser_info_to_filter_flags(out);
}

static int
efct_nic_init_hardware(struct efhw_nic *nic,
                       struct efhw_ev_handler *ev_handlers,
                       const uint8_t *mac_addr)
{
  memcpy(nic->mac_addr, mac_addr, ETH_ALEN);
  nic->ev_handlers = ev_handlers;
  nic->flags |= NIC_FLAG_TX_CTPIO | NIC_FLAG_CTPIO_ONLY
             | NIC_FLAG_HW_RX_TIMESTAMPING | NIC_FLAG_HW_TX_TIMESTAMPING
             | NIC_FLAG_RX_SHARED
             | NIC_FLAG_RX_KERNEL_SHARED
             | NIC_FLAG_HW_MULTICAST_REPLICATION
             | NIC_FLAG_SHARED_PD
             | NIC_FLAG_RX_POLL
             | NIC_FLAG_RX_REF
             ;

  nic->filter_flags |= efct_nic_supported_filter_flags(nic);
  nic->filter_flags |= NIC_FILTER_FLAG_IPX_VLAN_SW;
  nic->filter_flags |= NIC_FILTER_FLAG_IP_FULL_SW;
  /* The net driver doesn't install any of its own multicast filters, so on
   * efct a mismatch filter is the same as an all filter */
  if( nic->filter_flags & NIC_FILTER_FLAG_RX_TYPE_MCAST_MISMATCH )
    nic->filter_flags |= NIC_FILTER_FLAG_RX_TYPE_MCAST_ALL;
  efct_nic_tweak_hardware(nic);
  return 0;
}


static void
efct_nic_release_hardware(struct efhw_nic* nic)
{
#ifndef NDEBUG
  struct efhw_nic_efct* efct = nic->arch_extra;
  efct_filter_assert_all_filters_gone(efct->filter_state);
#endif
}

/*--------------------------------------------------------------------
 *
 * Event Management - and SW event posting
 *
 *--------------------------------------------------------------------*/

static bool efct_accept_irq_constraints(int instance, void* arg) {
  return true;
}

static int
efct_nic_irq_alloc(struct efhw_nic *nic, uint32_t *channel, uint32_t *irq)
{
  struct efhw_nic_efct *efct = nic->arch_extra;
  int rc;

  mutex_lock(&efct->irq_allocator.lock);
  rc = efhw_stack_alloc(&efct->irq_allocator.alloc, efct_accept_irq_constraints,
                   NULL);
  if (rc >= 0) {
    *irq = rc;
    /* efct nics don't really use channel properly, so return irq again */
    *channel = rc;
  }
  mutex_unlock(&efct->irq_allocator.lock);

  return rc;
}

static void
efct_nic_irq_free(struct efhw_nic *nic, uint32_t channel, uint32_t irq)
{
  struct efhw_nic_efct *efct = nic->arch_extra;

  /* efct doesn't use channel properly, so channel should equal irq */
  EFHW_ASSERT(channel == irq);

  mutex_lock(&efct->irq_allocator.lock);
  efhw_stack_free(&efct->irq_allocator.alloc, irq);
  mutex_unlock(&efct->irq_allocator.lock);
}

static int
efct_nic_evq_requires_time_sync(struct efhw_nic *nic, uint flags)
{
  return !!(flags & EFHW_VI_TX_TIMESTAMPS);
}


/* This function will enable the given event queue with the requested
 * properties.
 */
static int
efct_nic_event_queue_enable(struct efhw_nic *nic,
                            struct efhw_evq_params *efhw_params)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  int requires_time_sync =
    efct_nic_evq_requires_time_sync(nic, efhw_params->flags);
  struct xlnx_efct_evq_params qparams = {
    .qid = efhw_params->evq,
    .entries = efhw_params->evq_size,
    /* We don't provide a pci_dev to enable queue memory to be mapped for us,
     * so we're given plain physical addresses.
     */
    .q_page = pfn_to_page(efhw_params->dma_addrs[0] >> PAGE_SHIFT),
    .page_offset = 0,
    .q_size = efhw_params->evq_size * sizeof(efhw_event_t),
    .subscribe_time_sync = requires_time_sync,
    .unsol_credit = requires_time_sync ? CI_CFG_TIME_SYNC_EVENT_EVQ_CAPACITY - 1 : 0,
    .irq = efhw_params->wakeup_channel,
  };
  struct efhw_nic_efct *efct = nic->arch_extra;
  struct efhw_nic_efct_evq *efct_evq;
  int rc;
#ifndef NDEBUG
  int i;
#endif

  /* This is a dummy EVQ, so nothing to do. */
  if( efhw_params->evq >= efct->evq_n )
    return 0;

  efct_evq = &efct->evq[efhw_params->evq];

  /* We only look at the first page because this memory should be physically
   * contiguous, but the API provides us with an address per 4K (NIC page)
   * chunk, so sanity check that there are enough pages for the size of queue
   * we're asking for.
   */
  EFHW_ASSERT(efhw_params->n_pages * EFHW_NIC_PAGES_IN_OS_PAGE * CI_PAGE_SIZE
	      >= qparams.q_size);
#ifndef NDEBUG
  /* We should have been provided with physical addresses of physically
   * contiguous memory, so sanity check the addresses look right.
   */
  for( i = 1; i < efhw_params->n_pages; i++ ) {
    EFHW_ASSERT(efhw_params->dma_addrs[i] - efhw_params->dma_addrs[i-1] ==
		EFHW_NIC_PAGE_SIZE);
  }
#endif

  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = edev->ops->init_evq(cli, &qparams);
  EFCT_POST(dev, edev, cli, nic, rc);

  if( rc == 0 ) {
    efct_evq->nic = nic;
    efct_evq->base = efhw_params->virt_base;
    efct_evq->capacity = efhw_params->evq_size;
    atomic_set(&efct_evq->queues_flushing, 0);
    INIT_DELAYED_WORK(&efct_evq->check_flushes, efct_check_for_flushes);

    /* EFCT hardware has no notion of a time-sync without having reqeusted the
     * clock sync status, so always output this result if we use time-sync */
    if( qparams.subscribe_time_sync )
      efhw_params->flags_out = EFHW_VI_CLOCK_SYNC_STATUS;
  }

  return rc;
}

static void
efct_nic_event_queue_disable(struct efhw_nic *nic,
                             uint evq, int time_sync_events_enabled)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  struct efhw_nic_efct *efct = nic->arch_extra;
  struct efhw_nic_efct_evq *efct_evq;
  int rc = 0;

  /* This is a dummy EVQ, so nothing to do. */
  if( evq >= efct->evq_n )
    return;

  efct_evq = &efct->evq[evq];

  /* In the normal case we'll be disabling the queue because all outstanding
   * flushes have completed. However, in the case of a flush timeout there may
   * still be a work item scheduled. We want to avoid it rescheduling if so.
   */
  atomic_set(&efct_evq->queues_flushing, -1);
  cancel_delayed_work_sync(&efct_evq->check_flushes);

  EFCT_PRE(dev, edev, cli, nic, rc);
  edev->ops->free_evq(cli, evq);
  EFCT_POST(dev, edev, cli, nic, rc);
}

static void
efct_nic_wakeup_request(struct efhw_nic *nic, volatile void __iomem* io_page,
                        int vi_id, int rptr)
{
	ci_dword_t dwrptr;

	__DWCHCK(ERF_HZ_READ_IDX);
	__RANGECHCK(rptr, ERF_HZ_READ_IDX_WIDTH);
	__RANGECHCK(vi_id, ERF_HZ_EVQ_ID_WIDTH);

	CI_POPULATE_DWORD_2(dwrptr,
			    ERF_HZ_EVQ_ID, vi_id,
			    ERF_HZ_READ_IDX, rptr);
	writel(dwrptr.u32[0], nic->int_prime_reg);
	mmiowb();
}

static bool efct_accept_tx_vi_constraints(int instance, void* arg)
{
  struct efhw_nic_efct *efct = arg;
  return efct->evq[instance].txq != EFCT_EVQ_NO_TXQ;
}

static bool efct_accept_rx_vi_constraints(int instance, void* arg) {
  return true;
}

static int efct_vi_alloc(struct efhw_nic *nic, struct efhw_vi_constraints *evc,
                         unsigned n_vis)
{
  struct efhw_nic_efct *efct = nic->arch_extra;
  struct xlnx_efct_client* cli;
  int rc = 0;

  if( n_vis != 1 )
    return -EOPNOTSUPP;

  /* Acquire efct device as in EFCT_PRE to protect access to arch_extra which
   * goes away after aux detach. Also aquire an allocation lock so accesses to
   * the vi allocator are synchronised. */
  cli = efhw_nic_acquire_efct_device(nic);
  if( cli == NULL )
    return -ENETDOWN;

  mutex_lock(&efct->vi_allocator.lock);
  if( evc->want_txq )
    rc = efhw_stack_alloc(&efct->vi_allocator.tx,
                             efct_accept_tx_vi_constraints, efct);
  else
    rc = efhw_stack_alloc(&efct->vi_allocator.rx,
                             efct_accept_rx_vi_constraints, efct);
  mutex_unlock(&efct->vi_allocator.lock);

  efhw_nic_release_efct_device(nic, cli);

  return rc;
}

static void efct_vi_free(struct efhw_nic *nic, int instance, unsigned n_vis)
{
  struct efhw_nic_efct* efct = nic->arch_extra;
  struct xlnx_efct_client* cli;

  EFHW_ASSERT(n_vis == 1);
  cli = efhw_nic_acquire_efct_device(nic);
  if( cli != NULL ) {
    /* If this vi is in the range [0..efct->evq_n) it has a txq */
    mutex_lock(&efct->vi_allocator.lock);
    if( instance < efct->evq_n )
      efhw_stack_free(&efct->vi_allocator.tx, instance);
    else
      efhw_stack_free(&efct->vi_allocator.rx, instance);

    mutex_unlock(&efct->vi_allocator.lock);
    efhw_nic_release_efct_device(nic, cli);
  }
}

static bool efct_supports_shared_evq(struct efhw_nic *nic)
{
  return false;
}

/*----------------------------------------------------------------------------
 *
 * DMAQ low-level register interface
 *
 *---------------------------------------------------------------------------*/


static int
efct_dmaq_tx_q_init(struct efhw_nic *nic,
                    struct efhw_dmaq_params *txq_params)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  struct efhw_nic_efct *efct = nic->arch_extra;
  struct efhw_nic_efct_evq *efct_evq = &efct->evq[txq_params->evq];
  struct xlnx_efct_txq_params params = {
    .evq = txq_params->evq,
    .qid = efct_evq->txq,
    .label = txq_params->tag,
  };
  int rc;

  EFHW_ASSERT(txq_params->evq < efct->evq_n);
  EFHW_ASSERT(params.qid != EFCT_EVQ_NO_TXQ);

  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = edev->ops->init_txq(cli, &params);
  EFCT_POST(dev, edev, cli, nic, rc);

  if( rc >= 0 ) {
    txq_params->qid_out = rc;
    rc = 0;
  }

  return 0;
}


static int
efct_dmaq_rx_q_init(struct efhw_nic *nic,
                    struct efhw_dmaq_params *params)
{
  /* efct doesn't do rxqs like this, so nothing to do here */
  params->qid_out = params->dmaq;
  return 0;
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - mid level API
 *
 *--------------------------------------------------------------------*/


static void efct_check_for_flushes(struct work_struct *work)
{
  struct efhw_nic_efct_evq *evq =  container_of(work, struct efhw_nic_efct_evq,
                                                check_flushes.work);
  ci_qword_t *event = evq->base;
  bool found_flush = false;
  int txq;
  int i;

  /* In the case of a flush timeout this may have been rescheduled following
   * evq disable. In which case bail out now.
   */
  if( atomic_read(&evq->queues_flushing) < 0 )
    return;

  for(i = 0; i < evq->capacity; i++) {
    if(CI_QWORD_FIELD(*event, EFCT_EVENT_TYPE) == EFCT_EVENT_TYPE_CONTROL &&
       CI_QWORD_FIELD(*event, EFCT_CTRL_SUBTYPE) == EFCT_CTRL_EV_FLUSH &&
       CI_QWORD_FIELD(*event, EFCT_FLUSH_TYPE) == EFCT_FLUSH_TYPE_TX) {
      found_flush = true;
      txq = CI_QWORD_FIELD(*event, EFCT_FLUSH_QUEUE_ID);
      efhw_handle_txdmaq_flushed(evq->nic, txq);
      break;
    }
    event++;
  }

  if( !found_flush || !atomic_dec_and_test(&evq->queues_flushing) ) {
    EFHW_ERR("%s: WARNING: No TX flush found, scheduling delayed work",
             __FUNCTION__);
    schedule_delayed_work(&evq->check_flushes, 100);
  }
}


static int efct_flush_tx_dma_channel(struct efhw_nic *nic, uint dmaq, uint evq)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  struct efhw_nic_efct *efct = nic->arch_extra;
  struct efhw_nic_efct_evq *efct_evq = &efct->evq[evq];
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc);
  edev->ops->free_txq(cli, dmaq);
  EFCT_POST(dev, edev, cli, nic, rc);

  atomic_inc(&efct_evq->queues_flushing);
  schedule_delayed_work(&efct_evq->check_flushes, 0);

  return 0;
}


static int efct_flush_rx_dma_channel(struct efhw_nic *nic, uint dmaq)
{
  /* rxqs are a software-only concept, no flush required */
  return -EALREADY;
}


static enum efhw_page_map_type efct_queue_map_type(struct efhw_nic *nic)
{
  return EFHW_PAGE_MAP_PHYS;
}

/*--------------------------------------------------------------------
 *
 * Buffer table - API
 *
 *--------------------------------------------------------------------*/

static const int efct_nic_buffer_table_orders[] = {};


static enum efhw_page_map_type efct_buffer_map_type(struct efhw_nic *nic)
{
  return EFHW_PAGE_MAP_NONE;
}


/*--------------------------------------------------------------------
 *
 * Filtering
 *
 *--------------------------------------------------------------------*/

static uint32_t zero_remote_port(uint32_t l4_4_bytes)
{
  return htonl(ntohl(l4_4_bytes) & 0xffff);
}

static int sanitise_ethtool_flow(struct ethtool_rx_flow_spec *dst)
{
  /* Blat out the remote fields: we can soft-filter them even though the
   * hardware can't */
  switch (dst->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) {
  case UDP_V4_FLOW:
  case TCP_V4_FLOW:
    EFHW_ASSERT(&dst->h_u.udp_ip4_spec == &dst->h_u.tcp_ip4_spec);
    if( dst->m_u.udp_ip4_spec.tos )
      return -EPROTONOSUPPORT;
    dst->h_u.udp_ip4_spec.ip4src = 0;
    dst->h_u.udp_ip4_spec.psrc = 0;
    dst->m_u.udp_ip4_spec.ip4src = 0;
    dst->m_u.udp_ip4_spec.psrc = 0;
    break;
  case IPV4_USER_FLOW:
    if( dst->m_u.usr_ip4_spec.tos || dst->m_u.usr_ip4_spec.ip_ver )
      return -EPROTONOSUPPORT;
    dst->h_u.usr_ip4_spec.ip4src = 0;
    dst->m_u.usr_ip4_spec.ip4src = 0;
    dst->h_u.usr_ip4_spec.l4_4_bytes =
                          zero_remote_port(dst->h_u.usr_ip4_spec.l4_4_bytes);
    dst->m_u.usr_ip4_spec.l4_4_bytes =
                          zero_remote_port(dst->m_u.usr_ip4_spec.l4_4_bytes);
    break;
  case UDP_V6_FLOW:
  case TCP_V6_FLOW:
    EFHW_ASSERT(&dst->h_u.udp_ip6_spec == &dst->h_u.tcp_ip6_spec);
    memset(dst->h_u.udp_ip6_spec.ip6src, 0,
           sizeof(dst->h_u.udp_ip6_spec.ip6src));
    dst->h_u.udp_ip6_spec.psrc = 0;
    memset(dst->m_u.udp_ip6_spec.ip6src, 0,
           sizeof(dst->m_u.udp_ip6_spec.ip6src));
    dst->m_u.udp_ip6_spec.psrc = 0;
    break;
  case IPV6_USER_FLOW:
    memset(dst->h_u.usr_ip6_spec.ip6src, 0,
           sizeof(dst->h_u.usr_ip6_spec.ip6src));
    memset(dst->m_u.usr_ip6_spec.ip6src, 0,
           sizeof(dst->m_u.usr_ip6_spec.ip6src));
    dst->h_u.usr_ip6_spec.l4_4_bytes =
                          zero_remote_port(dst->h_u.usr_ip6_spec.l4_4_bytes);
    dst->m_u.usr_ip6_spec.l4_4_bytes =
                          zero_remote_port(dst->m_u.usr_ip6_spec.l4_4_bytes);
    break;
  case ETHER_FLOW:
    dst->h_u.ether_spec.h_proto = 0;
    dst->m_u.ether_spec.h_proto = 0;
    break;
  default:
    return -EPROTONOSUPPORT;
  }

  /* We don't support MAC in combination with IP filters */
  if (dst->flow_type & FLOW_MAC_EXT)
    return -EPROTONOSUPPORT;

  if (dst->flow_type & FLOW_EXT) {
    if (dst->m_ext.vlan_etype || dst->m_ext.vlan_tci != htons(0xfff) ||
        dst->m_ext.data[0] || dst->m_ext.data[1])
      return -EPROTONOSUPPORT;
    /* VLAN tags are only supported with flow_type ETHER_FLOW */
    if ((dst->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) != ETHER_FLOW)
      dst->flow_type &= ~FLOW_EXT;
  }

  return 0;
}

struct filter_insert_params {
  struct efhw_nic *nic;
  struct xlnx_efct_filter_params efct_params;
};

int filter_insert_op(const struct efct_filter_insert_in *in,
                     struct efct_filter_insert_out *out)
{
  struct filter_insert_params *params;
  struct xlnx_efct_filter_params *efct_params;
  struct device *dev;
  struct xlnx_efct_device *edev;
  struct xlnx_efct_client *cli;
  int rc;

  params = (struct filter_insert_params*)in->drv_opaque;
  efct_params = &params->efct_params;
  efct_params->spec = in->filter;

  EFCT_PRE(dev, edev, cli, params->nic, rc);
  rc = edev->ops->filter_insert(cli, efct_params);
  EFCT_POST(dev, edev, cli, params->nic, rc);

  if( rc == 0 ) {
    out->rxq = efct_params->rxq_out;
    out->drv_id = efct_params->filter_id_out;
    out->filter_handle = efct_params->filter_handle;
  }

  return rc;
}

static int
efct_nic_filter_insert(struct efhw_nic *nic,
                       struct efhw_filter_params *efhw_params)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  struct efhw_nic_efct *efct = nic->arch_extra;
  struct filter_insert_params params;
  struct ethtool_rx_flow_spec hw_filter;
  unsigned flags = efhw_params->flags;
  struct efct_filter_params efct_params = {
    .rxq = efhw_params->rxq,
    .pd_excl_token = efhw_params->exclusive_rxq_token,
    .insert_op = filter_insert_op,
    .insert_data = &params,
    .filter_flags = nic->filter_flags,
  };
  int rc;

  if( flags & EFHW_FILTER_F_REPLACE )
    return -EOPNOTSUPP;

  /* rxq_n is based on design param caps, and is used to size various data
   * structs. There may turn out not to actually be the full range of queues
   * available, but we can safely handle queues in that range. */
  if( *efhw_params->rxq >= (int)efct->rxq_n )
    return -EINVAL;

  /* Get the straight translation to ethtool spec of the requested filter.
   * This allows us to make any necessary checks on the actually requested
   * filter before we furtle it later on. */
  rc = efx_spec_to_ethtool_flow(efhw_params->spec, &hw_filter);
  if( rc < 0 )
    return rc;

  params.nic = nic;
  params.efct_params = (struct xlnx_efct_filter_params) {
    .spec = &hw_filter,
    .mask = efhw_params->mask ? efhw_params->mask : cpu_all_mask,
  };
  if( flags & EFHW_FILTER_F_ANY_RXQ )
    params.efct_params.flags |= XLNX_EFCT_FILTER_F_ANYQUEUE_LOOSE;
  if( flags & EFHW_FILTER_F_PREF_RXQ )
    params.efct_params.flags |= XLNX_EFCT_FILTER_F_PREF_QUEUE;

  if( flags & EFHW_FILTER_F_EXCL_RXQ ) {
    params.efct_params.flags |= XLNX_EFCT_FILTER_F_EXCLUSIVE_QUEUE;

    /* For exclusive queues we need to use exactly the filter requested to avoid
     * the need for SW filtering in the app, so check for filter support before
     * furtling the filter. */
    EFCT_PRE(dev, edev, cli, nic, rc);
    rc = edev->ops->is_filter_supported(cli, &hw_filter);
    EFCT_POST(dev, edev, cli, nic, rc);

    if( !rc )
      return -EPERM;

    flags |= EFHW_FILTER_F_USE_HW;
  }
  else {
    /* With non-exclusive queues we can match a superset of the user requested
     * filter, so for some filter types we use wider HW filters to represent a
     * more specific SW filter. This function handles any modifications that are
     * needed to do this. */
    rc = sanitise_ethtool_flow(&hw_filter);
    if( rc < 0 )
      return rc;

    EFCT_PRE(dev, edev, cli, nic, rc);
    rc = edev->ops->is_filter_supported(cli, &hw_filter);
    EFCT_POST(dev, edev, cli, nic, rc);

    /* Some filter types are only supported on certain HW, so querying here lets
     * us tell the common filter management code what we expect. */
    if( rc )
      flags |= EFHW_FILTER_F_USE_HW;

    /* We're not using an exclusive queue, so can allow fallback to SW. */
    flags |= EFHW_FILTER_F_USE_SW;
  }

  efct_params.flags = flags;
  rc = efct_filter_insert(efct->filter_state, efhw_params->spec, &hw_filter,
                          &efct_params);

  /* If we are returning successfully having requested an exclusive queue, that
   * queue should not be shared with the net driver. */
  EFHW_ASSERT((rc < 0) || !(flags & EFHW_FILTER_F_EXCL_RXQ) ||
              (*efhw_params->rxq > 0));

  return rc;
}

static void
efct_nic_filter_remove(struct efhw_nic *nic, int filter_id)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  struct efhw_nic_efct *efct = nic->arch_extra;
  uint64_t drv_id;
  unsigned flags;
  int rc;
  bool remove_drv = efct_filter_remove(efct->filter_state, filter_id,
                                       &drv_id, &flags);

  if( remove_drv ) {
    EFCT_PRE(dev, edev, cli, nic, rc);
    rc = edev->ops->filter_remove(cli, drv_id);
    EFCT_POST(dev, edev, cli, nic, rc);
  }
}

static int
efct_nic_filter_query(struct efhw_nic *nic, int filter_id,
                  struct efhw_filter_info *info)
{
  struct efhw_nic_efct *efct = nic->arch_extra;
  return efct_filter_query(efct->filter_state, filter_id, info);
}

static int
efct_nic_multicast_block(struct efhw_nic *nic, bool block)
{
  struct efhw_nic_efct *efct = nic->arch_extra;
  return efct_multicast_block(efct->filter_state, block);
}

static int
efct_nic_unicast_block(struct efhw_nic *nic, bool block)
{
  struct efhw_nic_efct *efct = nic->arch_extra;
  return efct_unicast_block(efct->filter_state, block);
}


/*--------------------------------------------------------------------
 *
 * Device
 *
 *--------------------------------------------------------------------*/

static int
efct_vi_io_region(struct efhw_nic *nic, int instance, size_t* size_out,
                  resource_size_t* addr_out)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  union xlnx_efct_param_value val;
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc)
  rc = edev->ops->get_param(cli, XLNX_EFCT_EVQ_WINDOW, &val);
  EFCT_POST(dev, edev, cli, nic, rc);

  *size_out = val.evq_window.stride;
  *addr_out = val.evq_window.base;
  *addr_out += (instance - nic->vi_min) * val.evq_window.stride;

  return rc;
}

/*--------------------------------------------------------------------
 *
 * CTPIO
 *
 *--------------------------------------------------------------------*/
static int
efct_ctpio_addr(struct efhw_nic* nic, int instance, resource_size_t* addr)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  size_t region_size;
  int rc;

  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = edev->ops->ctpio_addr(cli, instance, addr, &region_size);
  EFCT_POST(dev, edev, cli, nic, rc);

  /* Currently we assume throughout onload that we have a 4k region */
  if( (rc == 0) && (region_size != 0x1000) )
    return -EOPNOTSUPP;

  return rc;
}

/*--------------------------------------------------------------------
 *
 * Abstraction Layer Hooks
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops efct_char_functional_units = {
  .sw_ctor = efct_nic_sw_ctor,
  .init_hardware = efct_nic_init_hardware,
  .post_reset = efct_nic_tweak_hardware,
  .release_hardware = efct_nic_release_hardware,
  .event_queue_enable = efct_nic_event_queue_enable,
  .event_queue_disable = efct_nic_event_queue_disable,
  .evq_requires_time_sync = efct_nic_evq_requires_time_sync,
  .wakeup_request = efct_nic_wakeup_request,
  .vi_alloc = efct_vi_alloc,
  .vi_free = efct_vi_free,
  .supports_shared_evq = efct_supports_shared_evq,
  .dmaq_tx_q_init = efct_dmaq_tx_q_init,
  .dmaq_rx_q_init = efct_dmaq_rx_q_init,
  .flush_tx_dma_channel = efct_flush_tx_dma_channel,
  .flush_rx_dma_channel = efct_flush_rx_dma_channel,
  .queue_map_type = efct_queue_map_type,
  .buffer_table_orders = efct_nic_buffer_table_orders,
  .buffer_table_orders_num = CI_ARRAY_SIZE(efct_nic_buffer_table_orders),
  .buffer_map_type = efct_buffer_map_type,
  .filter_insert = efct_nic_filter_insert,
  .filter_remove = efct_nic_filter_remove,
  .filter_query = efct_nic_filter_query,
  .multicast_block = efct_nic_multicast_block,
  .unicast_block = efct_nic_unicast_block,
  .vi_io_region = efct_vi_io_region,
  .ctpio_addr = efct_ctpio_addr,
  .design_parameters = efct_design_parameters,
  .max_shared_rxqs = efct_max_shared_rxqs,
  .shared_rxq_bind = efct_nic_rxq_bind,
  .shared_rxq_unbind = efct_nic_rxq_free,
  .shared_rxq_refresh = efct_nic_shared_rxq_refresh,
  .shared_rxq_refresh_kernel = efct_nic_shared_rxq_refresh_kernel,
  .shared_rxq_request_wakeup = efct_nic_shared_rxq_request_wakeup,
  .irq_alloc = efct_nic_irq_alloc,
  .irq_free = efct_nic_irq_free,
};

#endif
