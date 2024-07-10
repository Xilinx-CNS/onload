/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#include <ci/driver/kernel_compat.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/ci_aux.h>
#include <ci/driver/ci_efct.h>
#include <ci/efhw/common.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/efct.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/checks.h>
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
#include "efct.h"
#include "efct_superbuf.h"
#include "efct_filters.h"

#if CI_HAVE_EFCT_AUX


static void efct_check_for_flushes(struct work_struct *work);
static ssize_t
efct_get_used_hugepages(struct efhw_nic *nic, int qid);

int
efct_nic_rxq_bind(struct efhw_nic *nic, int qid, bool timestamp_req,
                  size_t n_hugepages,
                  struct oo_hugetlb_allocator *hugetlb_alloc,
                  struct efab_efct_rxq_uk_shm_q *shm,
                  unsigned wakeup_instance, struct efhw_efct_rxq *rxq)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  ssize_t used_hugepages;
  int rc;

  struct xlnx_efct_rxq_params qparams = {
    .qid = qid,
    .timestamp_req = timestamp_req,
    .n_hugepages = n_hugepages,
  };

  /* We implicitly lock here by calling `efct_provide_hugetlb_alloc` so that
   * `used_hugepages` does not become invalid between now and binding */
  efct_provide_hugetlb_alloc(hugetlb_alloc);
  used_hugepages = efct_get_used_hugepages(nic, qid);
  if( used_hugepages < 0 ) {
    efct_unprovide_hugetlb_alloc();
    return used_hugepages;
  }

  EFHW_ASSERT(used_hugepages <= CI_EFCT_MAX_HUGEPAGES);

  if( n_hugepages + used_hugepages > CI_EFCT_MAX_HUGEPAGES ) {
    /* Ensure we do not donate more hugepages than we should otherwise
     * sbids > CI_EFCT_MAX_SUPERBUFS will be posted */
    efct_unprovide_hugetlb_alloc();
    return -EINVAL;
  }

  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = __efct_nic_rxq_bind(edev, cli, &qparams, nic->arch_extra, n_hugepages, shm, wakeup_instance, rxq);
  EFCT_POST(dev, edev, cli, nic, rc);

  efct_unprovide_hugetlb_alloc();
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
  /* FIXME: this should perhaps return the per-nic limit:
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


static void
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
             | NIC_FLAG_RX_FILTER_TYPE_IP_LOCAL
             | NIC_FLAG_RX_FILTER_TYPE_IP_FULL
             | NIC_FLAG_VLAN_FILTERS
             | NIC_FLAG_RX_FILTER_ETHERTYPE
             | NIC_FLAG_HW_MULTICAST_REPLICATION
             | NIC_FLAG_SHARED_PD
             /* TODO: This will need to be updated to check for nic capabilities. */
             | NIC_FLAG_RX_FILTER_TYPE_ETH_LOCAL
             | NIC_FLAG_RX_FILTER_TYPE_ETH_LOCAL_VLAN
             ;
  efct_nic_tweak_hardware(nic);
  return 0;
}


static void
efct_nic_release_hardware(struct efhw_nic* nic)
{
#ifndef NDEBUG
  struct efhw_nic_efct* efct = nic->arch_extra;

#define ACTION_ASSERT_HASH_TABLE_EMPTY(F) \
    EFHW_ASSERT(efct->filters.F##_n == 0);
  FOR_EACH_FILTER_CLASS(ACTION_ASSERT_HASH_TABLE_EMPTY)
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
efct_nic_event_queue_enable(struct efhw_nic *nic,
                            struct efhw_evq_params *efhw_params)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  struct xlnx_efct_evq_params qparams = {
    .qid = efhw_params->evq,
    .entries = efhw_params->evq_size,
    /* We don't provide a pci_dev to enable queue memory to be mapped for us,
     * so we're given plain physical addresses.
     */
    .q_page = pfn_to_page(efhw_params->dma_addrs[0] >> PAGE_SHIFT),
    .page_offset = 0,
    .q_size = efhw_params->evq_size * sizeof(efhw_event_t),
    .subscribe_time_sync = efhw_params->flags & EFHW_VI_TX_TIMESTAMPS,
    .unsol_credit = efhw_params->flags & EFHW_VI_TX_TIMESTAMPS ? CI_CFG_TIME_SYNC_EVENT_EVQ_CAPACITY  - 1 : 0,
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
    efct_evq->base = phys_to_virt(efhw_params->dma_addrs[0]);
    efct_evq->capacity = efhw_params->evq_size;
    atomic_set(&efct_evq->queues_flushing, 0);
    INIT_DELAYED_WORK(&efct_evq->check_flushes, efct_check_for_flushes);
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
  if(n_vis != 1) {
    return -EOPNOTSUPP;
  }
  if( evc->want_txq ) {
    return efhw_stack_vi_alloc(&efct->vi_allocator.tx, efct_accept_tx_vi_constraints, efct);
  }
  return efhw_stack_vi_alloc(&efct->vi_allocator.rx, efct_accept_rx_vi_constraints, efct);
}

static void efct_vi_free(struct efhw_nic *nic, int instance, unsigned n_vis)
{
  struct efhw_nic_efct* efct = nic->arch_extra;
  EFHW_ASSERT(n_vis == 1);
  /* If this vi is in the range [0..efct->evq_n) it has a txq */
  if( instance < efct->evq_n )
    efhw_stack_vi_free(&efct->vi_allocator.tx, instance);
  else
    efhw_stack_vi_free(&efct->vi_allocator.rx, instance);
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


static int efct_translate_dma_addrs(struct efhw_nic* nic,
                                    const dma_addr_t *src, dma_addr_t *dst,
                                    int n)
{
  /* All efct NICs have 1:1 mappings */
  memmove(dst, src, n * sizeof(src[0]));
  return 0;
}

/*--------------------------------------------------------------------
 *
 * Buffer table - API
 *
 *--------------------------------------------------------------------*/

static const int efct_nic_buffer_table_orders[] = {};


/*--------------------------------------------------------------------
 *
 * Filtering
 *
 *--------------------------------------------------------------------*/


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
  .wakeup_request = efct_nic_wakeup_request,
  .vi_alloc = efct_vi_alloc,
  .vi_free = efct_vi_free,
  .dmaq_tx_q_init = efct_dmaq_tx_q_init,
  .dmaq_rx_q_init = efct_dmaq_rx_q_init,
  .flush_tx_dma_channel = efct_flush_tx_dma_channel,
  .flush_rx_dma_channel = efct_flush_rx_dma_channel,
  .translate_dma_addrs = efct_translate_dma_addrs,
  .buffer_table_orders = efct_nic_buffer_table_orders,
  .buffer_table_orders_num = CI_ARRAY_SIZE(efct_nic_buffer_table_orders),
  .filter_insert = efct_filter_insert,
  .filter_remove = efct_filter_remove,
  .filter_query = efct_filter_query,
  .multicast_block = efct_multicast_block,
  .unicast_block = efct_unicast_block,
  .vi_io_region = efct_vi_io_region,
  .ctpio_addr = efct_ctpio_addr,
  .design_parameters = efct_design_parameters,
  .max_shared_rxqs = efct_max_shared_rxqs,
};

#endif
