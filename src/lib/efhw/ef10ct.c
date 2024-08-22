/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#include <ci/driver/kernel_compat.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efhw/debug.h>
#include <ci/efhw/iopage.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/checks.h>
#include <ci/efhw/efhw_buftable.h>

#include <ci/driver/ci_ef10ct.h>
#include <ci/tools/bitfield.h>
#include <ci/tools/debug.h>

#include <ci/efhw/efct.h>
#include <ci/efhw/ef10ct.h>
#include <ci/efhw/mc_driver_pcol.h>

#include "etherfabric/internal/internal.h"

#include "ef10ct.h"
#include "sw_buffer_table.h"


#if CI_HAVE_EF10CT


/*----------------------------------------------------------------------------
 *
 * MCDI helper
 *
 *---------------------------------------------------------------------------*/
int ef10ct_fw_rpc(struct efhw_nic *nic, struct efx_auxiliary_rpc *cmd)
{
  int rc;
  struct device *dev;
  struct efx_auxiliary_device* edev;
  struct efx_auxiliary_client* cli;

  /* FIXME need to handle reset stuff here */
  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = edev->ops->fw_rpc(cli, cmd);
  EFCT_POST(dev, edev, cli, nic, rc);

  return rc;
}


/*----------------------------------------------------------------------------
 *
 * Initialisation and configuration discovery
 *
 *---------------------------------------------------------------------------*/


static void
ef10ct_nic_sw_ctor(struct efhw_nic *nic,
                   const struct vi_resource_dimensions *res)
{
  nic->q_sizes[EFHW_EVQ] = 128 | 256 | 512 | 1024 | 2048 | 4096 | 8192 |
                           16384 | 32768;
  /* Effective TXQ size is potentially variable, as we can
   * configure how the CTPIO windows are sized. For now assume
   * we're sticking with fixed EFCT equivalent regions. */
  nic->q_sizes[EFHW_TXQ] = 512;
  /* Placeholder values consistent with ef_vi powers of 2 */
  nic->q_sizes[EFHW_RXQ] = 512 | 1024 | 2048 | 4096 | 8192 | 16384 | 32768 |
                           65536 | 131072;
  nic->efhw_func = &ef10ct_char_functional_units;
}


static void
ef10ct_nic_tweak_hardware(struct efhw_nic *nic)
{
}


static int
ef10ct_nic_init_hardware(struct efhw_nic *nic,
                         struct efhw_ev_handler *ev_handlers,
                         const uint8_t *mac_addr)
{
  memcpy(nic->mac_addr, mac_addr, ETH_ALEN);
  nic->ev_handlers = ev_handlers;
  nic->flags |= NIC_FLAG_TX_CTPIO | NIC_FLAG_CTPIO_ONLY
             | NIC_FLAG_HW_RX_TIMESTAMPING | NIC_FLAG_HW_TX_TIMESTAMPING
             | NIC_FLAG_RX_SHARED
             | NIC_FLAG_HW_MULTICAST_REPLICATION
             | NIC_FLAG_SHARED_PD
             | NIC_FLAG_PHYS_CONTIG_EVQ
             | NIC_FLAG_EVQ_IRQ
             | NIC_FLAG_LLCT
             ;
  nic->filter_flags |= NIC_FILTER_FLAG_RX_TYPE_IP_LOCAL
                    | NIC_FILTER_FLAG_RX_TYPE_IP_FULL
                    | NIC_FILTER_FLAG_IPX_VLAN_HW
                    | NIC_FILTER_FLAG_RX_ETHERTYPE
                    /* TODO: This will need to be updated to check for nic capabilities. */
                    | NIC_FILTER_FLAG_RX_TYPE_ETH_LOCAL
                    | NIC_FILTER_FLAG_RX_TYPE_ETH_LOCAL_VLAN
                    ;

  nic->sw_bts = kzalloc(EFHW_MAX_SW_BTS * sizeof(struct efhw_sw_bt),
                        GFP_KERNEL);

  return 0;
}


static void
ef10ct_nic_release_hardware(struct efhw_nic *nic)
{
  EFHW_TRACE("%s:", __FUNCTION__);
}


/*--------------------------------------------------------------------
 *
 * Event Management - and SW event posting
 *
 *--------------------------------------------------------------------*/

static void ef10ct_check_for_flushes(struct work_struct *work)
{
  struct efhw_nic_ef10ct_evq *evq = 
    container_of(work, struct efhw_nic_ef10ct_evq, check_flushes.work);
  unsigned offset = evq->next;
  ci_qword_t *event = evq->base + offset;
  bool found_flush = false;
  int q_id;
  int i;

  /* In the case of a flush timeout this may have been rescheduled following
   * evq disable. In which case bail out now.
   */
  if( atomic_read(&evq->queues_flushing) < 0 )
    return;

  for(i = 0; i < evq->capacity; i++) {
    offset = offset + 1 >= evq->capacity ? 0 : offset + 1;
    if(CI_QWORD_FIELD(*event, EFCT_EVENT_TYPE) == EFCT_EVENT_TYPE_CONTROL &&
       CI_QWORD_FIELD(*event, EFCT_CTRL_SUBTYPE) == EFCT_CTRL_EV_FLUSH) {
      found_flush = true;
      q_id = CI_QWORD_FIELD(*event, EFCT_FLUSH_QUEUE_ID);
      if(CI_QWORD_FIELD(*event, EFCT_FLUSH_TYPE) == EFCT_FLUSH_TYPE_TX) {
        efhw_handle_txdmaq_flushed(evq->nic, q_id);
      } else /* EFCT_FLUSH_TYPE_RX */ {
        struct efhw_nic_ef10ct *ef10ct = evq->nic->arch_extra;
        int hw_rxq = q_id;

        q_id = ef10ct->rxq[hw_rxq].q_id;
        ef10ct->rxq[hw_rxq].q_id = -1;
        efhw_handle_rxdmaq_flushed(evq->nic, q_id, false);
      }
      evq->next = offset;
      /* Clear the event so that we don't see it during the next check. */
      memset(event, 0, sizeof(*event));
      break;
    }
    event = evq->base + offset;
  }

  if( !found_flush || !atomic_dec_and_test(&evq->queues_flushing) ) {
    EFHW_ERR("%s: WARNING: No flush found, scheduling delayed work",
             __FUNCTION__);
    schedule_delayed_work(&evq->check_flushes, 100);
  }
}


/* FIXME EF10CT
 * Need to handle timesync and credits
 * X3 net driver does dma mapping
 */
static int
ef10ct_nic_event_queue_enable(struct efhw_nic *nic,
                              struct efhw_evq_params *efhw_params)
{
  struct efx_auxiliary_evq_params qparams = {
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
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_evq *ef10ct_evq;
  int rc;
#ifndef NDEBUG
  int i;
#endif
  struct efx_auxiliary_rpc dummy;

  /* This is a dummy EVQ, so nothing to do. */
  if( efhw_params->evq >= ef10ct->evq_n )
    return 0;

  ef10ct_evq = &ef10ct->evq[efhw_params->evq];

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

  dummy.cmd = MC_CMD_INIT_EVQ;
  dummy.inlen = sizeof(qparams);
  dummy.inbuf = (void*)&qparams;
  dummy.outlen = 0;
  rc = ef10ct_fw_rpc(nic, &dummy);

  if( rc == 0 ) {
    ef10ct_evq->nic = nic;
    ef10ct_evq->base = phys_to_virt(efhw_params->dma_addrs[0]);
    ef10ct_evq->capacity = efhw_params->evq_size;
    atomic_set(&ef10ct_evq->queues_flushing, 0);
    INIT_DELAYED_WORK(&ef10ct_evq->check_flushes, ef10ct_check_for_flushes);
  }

  return rc;
}

static void
ef10ct_nic_event_queue_disable(struct efhw_nic *nic,
                               uint evq, int time_sync_events_enabled)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_evq *ef10ct_evq;
  struct efx_auxiliary_rpc dummy;

  /* This is a dummy EVQ, so nothing to do. */
  if( evq >= ef10ct->evq_n )
    return;

  ef10ct_evq = &ef10ct->evq[evq];

  /* In the normal case we'll be disabling the queue because all outstanding
   * flushes have completed. However, in the case of a flush timeout there may
   * still be a work item scheduled. We want to avoid it rescheduling if so.
   */
  atomic_set(&ef10ct_evq->queues_flushing, -1);
  cancel_delayed_work_sync(&ef10ct_evq->check_flushes);

  dummy.cmd = MC_CMD_FINI_EVQ;
  dummy.inlen = sizeof(int);
  dummy.inbuf = &evq;
  dummy.outlen = 0;
  ef10ct_fw_rpc(nic, &dummy);
}

static void
ef10ct_nic_wakeup_request(struct efhw_nic *nic, volatile void __iomem* io_page,
                          int vi_id, int rptr)
{
}

static bool ef10ct_accept_tx_vi_constraints(int instance, void* arg)
{
  struct efhw_nic_ef10ct *ef10ct = arg;
  return ef10ct->evq[instance].txq != EF10CT_EVQ_NO_TXQ;
}

static bool ef10ct_accept_rx_vi_constraints(int instance, void* arg) {
  return true;
}

static int ef10ct_vi_alloc(struct efhw_nic *nic, struct efhw_vi_constraints *evc,
                         unsigned n_vis)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  if(n_vis != 1) {
    return -EOPNOTSUPP;
  }
  if( evc->want_txq ) {
    return efhw_stack_vi_alloc(&ef10ct->vi_allocator.tx, ef10ct_accept_tx_vi_constraints, ef10ct);
  }
  return efhw_stack_vi_alloc(&ef10ct->vi_allocator.rx, ef10ct_accept_rx_vi_constraints, ef10ct);
}

static void ef10ct_vi_free(struct efhw_nic *nic, int instance, unsigned n_vis)
{
  struct efhw_nic_ef10ct* ef10ct = nic->arch_extra;
  EFHW_ASSERT(n_vis == 1);
  /* If this vi is in the range [0..ef10ct->evq_n) it has a txq */
  if( instance < ef10ct->evq_n )
    efhw_stack_vi_free(&ef10ct->vi_allocator.tx, instance);
  else
    efhw_stack_vi_free(&ef10ct->vi_allocator.rx, instance);
}

/*----------------------------------------------------------------------------
 *
 * DMAQ low-level register interface
 *
 *---------------------------------------------------------------------------*/


static int
ef10ct_dmaq_tx_q_init(struct efhw_nic *nic,
                      struct efhw_dmaq_params *txq_params)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_evq *ef10ct_evq = &ef10ct->evq[txq_params->evq];
  struct efx_auxiliary_txq_params params = {
    .evq = txq_params->evq,
    .qid = ef10ct_evq->txq,
    .label = txq_params->tag,
  };
  int rc;
  struct efx_auxiliary_rpc dummy;

  EFHW_ASSERT(txq_params->evq < ef10ct->evq_n);
  EFHW_ASSERT(params.qid != EFCT_EVQ_NO_TXQ);

  dummy.cmd = MC_CMD_INIT_TXQ;
  dummy.inlen = sizeof(struct efx_auxiliary_txq_params);
  dummy.inbuf = (void*)&params;
  dummy.outlen = sizeof(struct efx_auxiliary_txq_params);
  dummy.outbuf = (void*)&params;
  rc = ef10ct_fw_rpc(nic, &dummy);

  if( rc >= 0 ) {
    txq_params->qid_out = rc;
    rc = 0;
  }

  return 0;
}

static int
ef10ct_rx_buffer_post_register(struct efhw_nic* nic, int instance,
                               resource_size_t* addr_out)
{
  int rc;
  struct device *dev;
  struct efx_auxiliary_device* edev;
  struct efx_auxiliary_client* cli;
  union efx_auxiliary_param_value val = {.io_addr.qid_in = instance};

  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = edev->ops->get_param(cli, EFX_AUXILIARY_RXQ_POST, &val);
  EFCT_POST(dev, edev, cli, nic, rc);

  if( rc < 0 )
    return rc;

  *addr_out = val.io_addr.base;

  return 0;
}

static int
ef10ct_superbuf_io_region(struct efhw_nic* nic, size_t* size_out,
                          resource_size_t* addr_out)
{
  *size_out = 0x100000; // TODO from design parameters: rx_queues * rx_stride
  return ef10ct_rx_buffer_post_register(nic, 0, addr_out);
}

static int 
ef10ct_dmaq_rx_q_init(struct efhw_nic *nic,
                      struct efhw_dmaq_params *rxq_params)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efx_auxiliary_rxq_params params = {
    .evq = rxq_params->evq,
    .label = rxq_params->tag, /* TODO This will be necessary for shared evqs. */
    .suppress_events = rxq_params->rx.suppress_events,
  };
  int rc, rxq;
  struct efx_auxiliary_rpc dummy;
  resource_size_t register_phys_addr;


  if( rxq_params->evq >= ef10ct->evq_n ) {
    /* We are using a dummy vi, so use a shared kernel evq. */
    /* TODO: Determine the appropriate shared evq to use */
    if( rxq_params->rx.suppress_events ) {
      EFHW_ASSERT(ef10ct->shared_n >= 1 );
      params.evq = ef10ct->shared[0].vi;
    } else {
      /* Not supported for now */
      return -EINVAL;
    }
  }

  dummy.cmd = MC_CMD_INIT_RXQ;
  dummy.inlen = sizeof(struct efx_auxiliary_rxq_params);
  dummy.inbuf = (void*)&params;
  dummy.outlen = sizeof(struct efx_auxiliary_rxq_params);
  dummy.outbuf = (void*)&params;
  rc = ef10ct_fw_rpc(nic, &dummy);
  if( rc < 0 ) {
    EFHW_ERR("%s ef10ct_fw_rpc failed. rc = %d\n", __FUNCTION__, rc);
    return rc;
  }

  rxq_params->qid_out = rc;
  rxq = rc;

  if( rxq < 0 || rxq >= ef10ct->rxq_n ) {
    EFHW_ERR(KERN_INFO "%s rxq outside of expected range. rxq = %d",
             __func__, rxq);
    return -EINVAL;
  }

  rc = ef10ct_rx_buffer_post_register(nic, rxq, &register_phys_addr);
  if( rc < 0 ) {
    EFHW_ERR("%s Failed to get rx post register. rc = %d\n", __FUNCTION__, rc);
    return rc;
  }
  ef10ct->rxq[rxq].post_buffer_addr = phys_to_virt(register_phys_addr);

  flush_delayed_work(&ef10ct->evq[rxq].check_flushes);
  EFHW_ASSERT(ef10ct->rxq[rxq].evq == -1);
  EFHW_ASSERT(ef10ct->rxq[rxq].q_id == -1);

  ef10ct->rxq[rxq].evq = params.evq;
  ef10ct->rxq[rxq].q_id = rxq_params->dmaq;

  return rc;
}

static size_t
ef10ct_max_shared_rxqs(struct efhw_nic *nic)
{
  /* FIXME SCJ efct vi requires this at the moment */
  return 8;
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - mid level API
 *
 *--------------------------------------------------------------------*/


static int
ef10ct_flush_tx_dma_channel(struct efhw_nic *nic,
                            uint dmaq, uint evq)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_evq *ef10ct_evq = &ef10ct->evq[evq];
  int rc = 0;
  struct efx_auxiliary_rpc dummy;

  dummy.cmd = MC_CMD_FINI_TXQ;
  dummy.inlen = sizeof(int);
  dummy.inbuf = &dmaq;
  dummy.outlen = 0;
  rc = ef10ct_fw_rpc(nic, &dummy);

  atomic_inc(&ef10ct_evq->queues_flushing);
  schedule_delayed_work(&ef10ct_evq->check_flushes, 0);

  return rc;
}


static int
ef10ct_flush_rx_dma_channel(struct efhw_nic *nic, uint dmaq)
{
  int rc = 0, evq_id;
  struct efx_auxiliary_rpc dummy;
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_evq *ef10ct_evq;

  dummy.cmd = MC_CMD_FINI_RXQ;
  dummy.inlen = sizeof(int);
  dummy.inbuf = &dmaq;
  dummy.outlen = 0;
  rc = ef10ct_fw_rpc(nic, &dummy);

  evq_id = ef10ct->rxq[dmaq].evq;
  if( evq_id < 0 )
    return -EINVAL;
  ef10ct_evq = &ef10ct->evq[evq_id];

  atomic_inc(&ef10ct_evq->queues_flushing);
  schedule_delayed_work(&ef10ct_evq->check_flushes, 0);

  /* ef10ct->rxq[dmaq].q_id is updated in check_flushes. */
  ef10ct->rxq[dmaq].evq = -1;
  ef10ct->rxq[dmaq].post_buffer_addr = 0;
  return rc;
}


static int
ef10ct_translate_dma_addrs(struct efhw_nic* nic, const dma_addr_t *src,
                           dma_addr_t *dst, int n)
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

/* Buffer table order 9 corresponds to 2MiB hugepages. Currently these are the
 * only sizes supported. */
static const int ef10ct_nic_buffer_table_orders[] = {9};

/* Func op implementations are provided by efhw_sw_bt */

/*--------------------------------------------------------------------
 *
 * Filtering
 *
 *--------------------------------------------------------------------*/


static int
ef10ct_filter_insert(struct efhw_nic *nic, struct efx_filter_spec *spec,
                     int *rxq, unsigned pd_excl_token,
                     const struct cpumask *mask, unsigned flags)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  int i;
  bool found;

  /* We want to find the hw rxq given the dummy vi number in the spec */
  /* For now, just loop over the rxqs to check if the vi is attached
   * TODO: Will this have to handle multiple vis connected to the same rxq? */
  for( i = 0; i < ef10ct->rxq_n; i++ ) {
    if( ef10ct->rxq[i].q_id == spec->dmaq_id ) {
      *rxq = i;
      found = true;
      break;
    }
  }

  if( !found )
    return -EINVAL;
  return 0;
}


static void
ef10ct_filter_remove(struct efhw_nic *nic, int filter_id)
{
}


static int
ef10ct_filter_redirect(struct efhw_nic *nic, int filter_id,
                       struct efx_filter_spec *spec)
{
  return -ENOSYS;
}


static int
ef10ct_filter_query(struct efhw_nic *nic, int filter_id,
                    struct efhw_filter_info *info)
{
  return -EOPNOTSUPP;
}


static int
ef10ct_multicast_block(struct efhw_nic *nic, bool block)
{
  return -ENOSYS;
}


static int
ef10ct_unicast_block(struct efhw_nic *nic, bool block)
{
  return -ENOSYS;
}


/*--------------------------------------------------------------------
 *
 * Device
 *
 *--------------------------------------------------------------------*/

static struct pci_dev*
ef10ct_get_pci_dev(struct efhw_nic* nic)
{
  return NULL;
}


static int
ef10ct_vi_io_region(struct efhw_nic* nic, int instance, size_t* size_out,
                    resource_size_t* addr_out)
{
  struct device *dev;
  struct efx_auxiliary_device* edev;
  struct efx_auxiliary_client* cli;
  union efx_auxiliary_param_value val;
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc)
  rc = edev->ops->get_param(cli, EFX_AUXILIARY_EVQ_WINDOW, &val);
  EFCT_POST(dev, edev, cli, nic, rc);

  *size_out = val.evq_window.stride;
  *addr_out = val.evq_window.base;
  *addr_out += (instance - nic->vi_min) * val.evq_window.stride;

  return rc;
}

static int
ef10ct_design_parameters(struct efhw_nic *nic,
                         struct efab_nic_design_parameters *dp)
{
  struct device *dev;
  struct efx_auxiliary_device* edev;
  struct efx_auxiliary_client* cli;
  union efx_auxiliary_param_value val;
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc)
  rc = edev->ops->get_param(cli, EFX_AUXILIARY_DESIGN_PARAM, &val);
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

  SET(rx_superbuf_bytes, val.design_params.rx_buffer_len);
  if( val.design_params.meta_location == 0 ) {
    SET(rx_frame_offset, EFCT_RX_HEADER_NEXT_FRAME_LOC_0 - 2);
  }
  else if( val.design_params.meta_location == 1 ) {
    SET(rx_frame_offset, EFCT_RX_HEADER_NEXT_FRAME_LOC_1 - 2);
  }
  else {
    EFHW_ERR("%s: Could not determine frame offset from meta_location %u",
             __func__, val.design_params.meta_location);
    return -EOPNOTSUPP;
  }
  SET(rx_stride, val.design_params.rx_stride);
  SET(rx_queues, val.design_params.rx_queues);
  SET(tx_aperture_bytes, val.design_params.tx_aperture_size);
  SET(tx_fifo_bytes, val.design_params.tx_fifo_size);
  SET(timestamp_subnano_bits, val.design_params.ts_subnano_bit);
  SET(unsol_credit_seq_mask, val.design_params.unsol_credit_seq_mask);
  SET(md_location, val.design_params.meta_location);

  return 0;
}


/*--------------------------------------------------------------------
 *
 * CTPIO
 *
 *--------------------------------------------------------------------*/

static int
ef10ct_ctpio_addr(struct efhw_nic* nic, int instance, resource_size_t* addr)
{
  struct device *dev;
  struct efx_auxiliary_device* edev;
  struct efx_auxiliary_client* cli;
  union efx_auxiliary_param_value val;
  int rc;

  val.io_addr.qid_in = instance;
  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = edev->ops->get_param(cli, EFX_AUXILIARY_CTPIO_WINDOW, &val);
  EFCT_POST(dev, edev, cli, nic, rc);

  /* Currently we assume throughout onload that we have a 4k region */
  if( (rc == 0) && (val.io_addr.size != 0x1000) )
    return -EOPNOTSUPP;

  if( rc == 0 )
    *addr = val.io_addr.base;

  return rc;
}

/*--------------------------------------------------------------------
 *
 * Superbuf Management
 *
 *--------------------------------------------------------------------*/

static uint64_t
translate_dma_address(struct efhw_nic *nic, resource_size_t dma_addr,
                      int owner_id)
{
  struct efhw_sw_bt *sw_bt = efhw_sw_bt_by_owner(nic, owner_id);
  uint64_t pfn = efhw_sw_bt_get_pfn(sw_bt, dma_addr >> PAGE_SHIFT);

  return pfn << PAGE_SHIFT;
}

static int ef10ct_rxq_post_superbuf(struct efhw_nic *nic, int instance,
                                    resource_size_t dma_addr,
                                    bool sentinel, bool rollover, int owner_id)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  uint64_t phys_addr;
  ci_qword_t qword;
  volatile uint64_t *reg;

  if( instance < 0 || instance >= ef10ct->rxq_n )
    return -EINVAL;
  reg = ef10ct->rxq[instance].post_buffer_addr;
  if( reg == NULL )
    return -EINVAL;

  phys_addr = translate_dma_address(nic, dma_addr, owner_id) >> CI_PAGE_SHIFT;

  CI_POPULATE_QWORD_3(qword,
                      EFCT_TEST_PAGE_ADDRESS, phys_addr,
                      EFCT_TEST_SENTINEL_VALUE, sentinel,
                      EFCT_TEST_ROLLOVER, rollover);

  /* Due to limitations with the efct_test driver it is possible to write
   * multiple values to RX_BUFFER_POST register before the first one is
   * read. As a crude workaround for the issue the test driver resets the
   * register 0 once it has processed the buffer. We poll the value of the
   * register here in case the test driver hasn't finished yet. */
  /* TODO EFCT_TEST: remove this when no longer using the testdriver */
  while(*reg != 0) {
    msleep(20); /* Ran into softlockups even with reg being declared
                * as volatile. Maybe this is because the test
                * driver is scheduled on the core as the one that
                * is spinning, so can never actually run? */
  }
  *reg = qword.u64[0];

  return 0;
}

/*--------------------------------------------------------------------
 *
 * Abstraction Layer Hooks
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops ef10ct_char_functional_units = {
  .sw_ctor = ef10ct_nic_sw_ctor,
  .init_hardware = ef10ct_nic_init_hardware,
  .post_reset = ef10ct_nic_tweak_hardware,
  .release_hardware = ef10ct_nic_release_hardware,
  .event_queue_enable = ef10ct_nic_event_queue_enable,
  .event_queue_disable = ef10ct_nic_event_queue_disable,
  .wakeup_request = ef10ct_nic_wakeup_request,
  .vi_alloc = ef10ct_vi_alloc,
  .vi_free = ef10ct_vi_free,
  .dmaq_tx_q_init = ef10ct_dmaq_tx_q_init,
  .dmaq_rx_q_init = ef10ct_dmaq_rx_q_init,
  .flush_tx_dma_channel = ef10ct_flush_tx_dma_channel,
  .flush_rx_dma_channel = ef10ct_flush_rx_dma_channel,
  .translate_dma_addrs = ef10ct_translate_dma_addrs,
  .buffer_table_orders = ef10ct_nic_buffer_table_orders,
  .buffer_table_orders_num = CI_ARRAY_SIZE(ef10ct_nic_buffer_table_orders),
  .buffer_table_alloc = efhw_sw_bt_alloc,
  .buffer_table_free = efhw_sw_bt_free,
  .buffer_table_set = efhw_sw_bt_set,
  .buffer_table_clear = efhw_sw_bt_clear,
  .filter_insert = ef10ct_filter_insert,
  .filter_remove = ef10ct_filter_remove,
  .filter_redirect = ef10ct_filter_redirect,
  .filter_query = ef10ct_filter_query,
  .multicast_block = ef10ct_multicast_block,
  .unicast_block = ef10ct_unicast_block,
  .get_pci_dev = ef10ct_get_pci_dev,
  .vi_io_region = ef10ct_vi_io_region,
  .ctpio_addr = ef10ct_ctpio_addr,
  .superbuf_io_region = ef10ct_superbuf_io_region,
  .post_superbuf =  ef10ct_rxq_post_superbuf,
  .design_parameters = ef10ct_design_parameters,
  .max_shared_rxqs = ef10ct_max_shared_rxqs,
};

#endif
