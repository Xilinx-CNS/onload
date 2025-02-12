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
#include <ci/efhw/efct_filters.h>
#include <ci/efhw/ef10ct.h>
#include <ci/efhw/mc_driver_pcol.h>

#include <linux/ethtool.h>
#include <linux/mman.h>

#include "etherfabric/internal/internal.h"

#include "../aux.h"
#include "../ef10ct.h"
#include "../sw_buffer_table.h"
#include "../mcdi_common.h"
#include "../ethtool_flow.h"


#if CI_HAVE_EF10CT


/*----------------------------------------------------------------------------
 *
 * MCDI helper
 *
 *---------------------------------------------------------------------------*/
int ef10ct_fw_rpc(struct efhw_nic *nic, struct efx_auxdev_rpc *cmd)
{
  int rc;
  struct device *dev;
  struct efx_auxdev* edev;
  struct efx_auxdev_client* cli;

  EFHW_WARN("%s", __func__);

  /* FIXME need to handle reset stuff here */
  AUX_PRE(dev, edev, cli, nic, rc);
  rc = edev->llct_ops->base_ops->fw_rpc(cli, cmd);
  AUX_POST(dev, edev, cli, nic, rc);

  return rc;
}


/*----------------------------------------------------------------------------
 *
 * Initialisation and configuration discovery
 *
 *---------------------------------------------------------------------------*/


static int
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
  return 0;
}


static void
ef10ct_nic_tweak_hardware(struct efhw_nic *nic)
{
}

static uint64_t
ef10ct_nic_supported_filter_flags(struct efhw_nic *nic)
{
  int rc;
  int num_matches;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_GET_PARSER_DISP_INFO_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMAX);
  struct efx_auxdev_rpc rpc = {
    .cmd = MC_CMD_GET_PARSER_DISP_INFO,
    .inlen = sizeof(in),
    .inbuf = (void *)in,
    .outlen = sizeof(out),
    .outbuf = (void *)out,
  };

  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);

  EFHW_MCDI_SET_DWORD(in, GET_PARSER_DISP_INFO_IN_OP,
                 MC_CMD_GET_PARSER_DISP_INFO_IN_OP_GET_SUPPORTED_LL_RX_MATCHES);

  rc = ef10ct_fw_rpc(nic, &rpc);

  if( rc < 0 ) {
    EFHW_ERR("%s: failed rc=%d", __FUNCTION__, rc);
    return 0;
  }
  else if ( rpc.outlen_actual < MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMIN ) {
    EFHW_ERR("%s: failed, expected response min len %d, got %zd", __FUNCTION__,
             MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMIN, rpc.outlen_actual);
    return 0;
  }

  num_matches = EFHW_MCDI_VAR_ARRAY_LEN(rpc.outlen_actual,
                                    GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES);

  return mcdi_parser_info_to_filter_flags(out, num_matches);
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
             | NIC_FLAG_RX_REF
             | NIC_FLAG_RX_POLL
             ;
  nic->filter_flags |= ef10ct_nic_supported_filter_flags(nic);

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

static void ef10ct_free_rxq(struct efhw_nic *nic, int qid)
{
  int rc = 0;
  int rxq_num;
  struct device *dev;
  struct efx_auxdev* edev;
  struct efx_auxdev_client* cli;
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;

  EFHW_WARN("%s", __func__);

  rxq_num = ef10ct_get_queue_num(qid);
  mutex_lock(&ef10ct->rxq[rxq_num].bind_lock);
  EFHW_ASSERT(ef10ct->rxq[rxq_num].state == EF10CT_RXQ_STATE_FREEING);

  AUX_PRE(dev, edev, cli, nic, rc);
  edev->llct_ops->rxq_free(cli, qid);
  AUX_POST(dev, edev, cli, nic, rc);

  ef10ct->rxq[rxq_num].state = EF10CT_RXQ_STATE_FREE;
  mutex_unlock(&ef10ct->rxq[rxq_num].bind_lock);
}

static void ef10ct_check_for_flushes(struct work_struct *work)
{
  struct efhw_nic_ef10ct_evq *evq = 
    container_of(work, struct efhw_nic_ef10ct_evq, check_flushes.work);
  unsigned offset = evq->next;
  ci_qword_t *event = &evq->base[offset];
  bool found_flush = false;
  int q_id;
  int i;
  /* Flush complete events only reserve 8 bits for a queue id. This means that
   * in order to free a valid queue handle, we will have to insert the queue
   * type in the upper 8 bits of the handle. */
  uint32_t queue_handle;

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
        queue_handle = ef10ct_reconstruct_queue_handle(q_id,
                                                  EF10CT_QUEUE_HANDLE_TYPE_TXQ);
        efhw_handle_txdmaq_flushed(evq->nic, queue_handle);
      } else /* EFCT_FLUSH_TYPE_RX */ {
        queue_handle = ef10ct_reconstruct_queue_handle(q_id,
                                                  EF10CT_QUEUE_HANDLE_TYPE_RXQ);
        ef10ct_free_rxq(evq->nic, queue_handle);
        /* RXQ flush is not reported upwards. The HW RXQ is managed within
         * efhw. */
      }
      evq->next = offset;
      /* Clear the event so that we don't see it during the next check. */
      memset(event, 0, sizeof(*event));
      break;
    }
    event = &evq->base[offset];
  }

  if( !found_flush || !atomic_dec_and_test(&evq->queues_flushing) ) {
    EFHW_ERR("%s: WARNING: No flush found, scheduling delayed work",
             __FUNCTION__);
    schedule_delayed_work(&evq->check_flushes, 100);
  }
}

static int ef10ct_irq_alloc(struct efhw_nic *nic, uint32_t *channel,
                            uint32_t *irq)
{
  struct efx_auxdev_irq *auxdev_irq;
  struct efhw_nic_ef10ct *ef10ct;
  struct efx_auxdev_client* cli;
  struct efx_auxdev* edev;
  struct device *dev;
  void *xa_res;
  int rc = 0;

  ef10ct = nic->arch_extra;
  mutex_lock(&ef10ct->irq_lock);

  AUX_PRE(dev, edev, cli, nic, rc);
  auxdev_irq = edev->llct_ops->irq_alloc(cli);
  AUX_POST(dev, edev, cli, nic, rc);

  if (rc < 0) /* rc may be updated in AUX_PRE */
    goto out;

  if (IS_ERR(auxdev_irq)) {
    rc = PTR_ERR(auxdev_irq);
    goto out;
  }

  xa_res = xa_store(&ef10ct->irqs, auxdev_irq->os_vector, auxdev_irq, GFP_KERNEL);
  if (xa_is_err(xa_res)) {
    EFHW_ERR("%s: Failed to store auxdev_irq for irq %u. errno = %u",
             __func__, auxdev_irq->os_vector, xa_err(xa_res));
    AUX_PRE(dev, edev, cli, nic, rc);
    edev->llct_ops->irq_free(cli, auxdev_irq);
    AUX_POST(dev, edev, cli, nic, rc);
    rc = xa_err(xa_res);
    goto out;
  }
  EFHW_ASSERT(!xa_res);

  *channel = auxdev_irq->nic_nr;
  *irq = auxdev_irq->os_vector;
  rc = 0;

out:
  mutex_unlock(&ef10ct->irq_lock);
  return rc;
}

static void ef10ct_irq_free(struct efhw_nic *nic, uint32_t channel,
                            uint32_t irq)
{
  struct efx_auxdev_irq *auxdev_irq;
  struct efhw_nic_ef10ct *ef10ct;
  struct efx_auxdev_client* cli;
  struct efx_auxdev* edev;
  struct device *dev;
  int rc = 0;

  ef10ct = nic->arch_extra;
  mutex_lock(&ef10ct->irq_lock);

  auxdev_irq = xa_erase(&ef10ct->irqs, irq);

  if (auxdev_irq == NULL) {
    EFHW_ERR("%s: Failed to retrieve auxdev_irq for irq %u", __func__, irq);
    goto out;
  }

  AUX_PRE(dev, edev, cli, nic, rc);
  edev->llct_ops->irq_free(cli, auxdev_irq);
  AUX_POST(dev, edev, cli, nic, rc);
  EFHW_ASSERT(!rc); /* rc may be updated in AUX_PRE */

out:
  mutex_unlock(&ef10ct->irq_lock);
}


/* FIXME EF10CT
 * Need to handle timesync and credits
 * X3 net driver does dma mapping
 */
static int
ef10ct_nic_event_queue_enable(struct efhw_nic *nic,
                              struct efhw_evq_params *efhw_params)
{
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_INIT_EVQ_V2_OUT_LEN);
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_INIT_EVQ_V2_IN_LEN(1));
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_evq *ef10ct_evq;
  int rc;
#ifndef NDEBUG
  int i;
#endif
  struct efx_auxdev_rpc rpc;
  int evq_num = efhw_params->evq;
  int evq_id = ef10ct_reconstruct_queue_handle(evq_num,
                                               EF10CT_QUEUE_HANDLE_TYPE_EVQ);

  EFHW_WARN("%s: evq 0x%x", __func__, evq_id);

  /* This is a dummy EVQ, so nothing to do. */
  if( evq_num >= ef10ct->evq_n )
    return 0;

  ef10ct_evq = &ef10ct->evq[evq_num];

  /* We only look at the first page because this memory should be physically
   * contiguous, but the API provides us with an address per 4K (NIC page)
   * chunk, so sanity check that there are enough pages for the size of queue
   * we're asking for.
   */
  EFHW_ASSERT(efhw_params->n_pages * EFHW_NIC_PAGES_IN_OS_PAGE * CI_PAGE_SIZE
	      >= efhw_params->evq_size * sizeof(efhw_event_t));
#ifndef NDEBUG
  /* We should have been provided with physical addresses of physically
   * contiguous memory, so sanity check the addresses look right.
   */
  for( i = 1; i < efhw_params->n_pages; i++ ) {
    EFHW_ASSERT(efhw_params->dma_addrs[i] - efhw_params->dma_addrs[i-1] ==
		EFHW_NIC_PAGE_SIZE);
  }
#endif

  EFHW_MCDI_INITIALISE_BUF(in);

  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_V2_IN_SIZE, efhw_params->evq_size);
  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_V2_IN_INSTANCE, evq_id);

  EFHW_MCDI_SET_QWORD(in, INIT_EVQ_V2_IN_DMA_ADDR, efhw_params->dma_addrs[0]);

  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_V2_IN_TMR_MODE,
                      MC_CMD_INIT_EVQ_V2_IN_TMR_MODE_DIS);
  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_V2_IN_TMR_LOAD, 0);
  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_V2_IN_TMR_RELOAD, 0);

  EFHW_MCDI_POPULATE_DWORD_6(in, INIT_EVQ_V2_IN_FLAGS,
                             INIT_EVQ_V2_IN_FLAG_INTERRUPTING, 1,
                             INIT_EVQ_V2_IN_FLAG_RX_MERGE, 1,
                             INIT_EVQ_V2_IN_FLAG_TX_MERGE, 1,
                             INIT_EVQ_V2_IN_FLAG_TYPE,
                             MC_CMD_INIT_EVQ_V2_IN_FLAG_TYPE_MANUAL,
                             INIT_EVQ_V2_IN_FLAG_USE_TIMER, 1,
                             INIT_EVQ_V2_IN_FLAG_CUT_THRU, 0);

  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_V2_IN_COUNT_MODE,
                      MC_CMD_INIT_EVQ_V2_IN_COUNT_MODE_DIS);
  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_V2_IN_COUNT_THRSHLD, 0);

  if( (nic->devtype.variant != 'L') )
    EFHW_MCDI_SET_DWORD(in, INIT_EVQ_V2_IN_IRQ_NUM,
                        efhw_params->wakeup_channel);

  rpc.cmd = MC_CMD_INIT_EVQ;
  rpc.inlen = sizeof(in);
  rpc.inbuf = (void*)in;
  rpc.outlen = sizeof(out);
  rpc.outbuf = (void*)out;
  rc = ef10ct_fw_rpc(nic, &rpc);

  if( rc == 0 ) {
    ef10ct_evq->nic = nic;
    ef10ct_evq->base = efhw_params->virt_base;
    ef10ct_evq->capacity = efhw_params->evq_size;
    atomic_set(&ef10ct_evq->queues_flushing, 0);
    INIT_DELAYED_WORK(&ef10ct_evq->check_flushes, ef10ct_check_for_flushes);
  }

  return rc;
}

static void
ef10ct_nic_event_queue_disable(struct efhw_nic *nic,
                               uint evq_num, int time_sync_events_enabled)
{
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FINI_EVQ_IN_LEN);
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_evq *ef10ct_evq;
  struct efx_auxdev_rpc rpc;
  int evq_id = ef10ct_reconstruct_queue_handle(evq_num,
                                               EF10CT_QUEUE_HANDLE_TYPE_EVQ);

  EFHW_WARN("%s: evq 0x%x", __func__, evq_id);

  /* This is a dummy EVQ, so nothing to do. */
  if( evq_num >= ef10ct->evq_n )
    return;

  ef10ct_evq = &ef10ct->evq[evq_num];

  /* In the normal case we'll be disabling the queue because all outstanding
   * flushes have completed. However, in the case of a flush timeout there may
   * still be a work item scheduled. We want to avoid it rescheduling if so.
   */
  atomic_set(&ef10ct_evq->queues_flushing, -1);
  cancel_delayed_work_sync(&ef10ct_evq->check_flushes);

  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_SET_DWORD(in, FINI_EVQ_IN_INSTANCE, evq_id);

  rpc.cmd = MC_CMD_FINI_EVQ;
  rpc.inlen = sizeof(in);
  rpc.inbuf = (void*)in;
  rpc.outlen = 0;
  rpc.outbuf = NULL;
  ef10ct_fw_rpc(nic, &rpc);
}

static void
ef10ct_nic_wakeup_request(struct efhw_nic *nic, volatile void __iomem* io_page,
                          int vi_id, int rptr)
{
}

int ef10ct_alloc_evq(struct efhw_nic *nic)
{
  struct efx_auxdev_client* cli;
  struct efx_auxdev* edev;
  struct device *dev;
  int evq;

  AUX_PRE(dev, edev, cli, nic, evq);
  evq = edev->llct_ops->channel_alloc(cli);
  AUX_POST(dev, edev, cli, nic, evq);

  return evq;
}

void ef10ct_free_evq(struct efhw_nic *nic, int evq)
{
  struct efx_auxdev_client* cli;
  struct efx_auxdev* edev;
  struct device *dev;
  int rc = 0;

  AUX_PRE(dev, edev, cli, nic, rc);
  edev->llct_ops->channel_free(cli, evq);
  AUX_POST(dev, edev, cli, nic, rc);

  /* Failure here will only occur in the case that the NIC is unavailable.
   * If that's happened there's nothing to do - the queue is already gone and
   * the upper layers will not restore it if the NIC comes back. */
}

static int ef10ct_alloc_txq(struct efhw_nic *nic)
{
  struct efx_auxdev_client* cli;
  struct efx_auxdev* edev;
  struct device *dev;
  int txq;

  AUX_PRE(dev, edev, cli, nic, txq);
  txq = edev->llct_ops->txq_alloc(cli);
  AUX_POST(dev, edev, cli, nic, txq);

  return txq;
}

static void ef10ct_free_txq(struct efhw_nic *nic, int txq)
{
  struct efx_auxdev_client* cli;
  struct efx_auxdev* edev;
  struct device *dev;
  int rc = 0;

  AUX_PRE(dev, edev, cli, nic, rc);
  edev->llct_ops->txq_free(cli, txq);
  AUX_POST(dev, edev, cli, nic, rc);
}

static int ef10ct_alloc_rxq(struct efhw_nic *nic)
{
  struct efx_auxdev_client* cli;
  struct efx_auxdev* edev;
  struct device *dev;
  int rxq;

  AUX_PRE(dev, edev, cli, nic, rxq);
  rxq = edev->llct_ops->rxq_alloc(cli);
  AUX_POST(dev, edev, cli, nic, rxq);

  return rxq;
}

static int ef10ct_vi_alloc_hw(struct efhw_nic *nic,
                              struct efhw_vi_constraints *evc, unsigned n_vis)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  int evq_rc;
  int txq_rc;
  int evq_num;

  if( n_vis != 1 )
    return -EOPNOTSUPP;

  /* FIXME EF10CT re-allocation post reset needs consideration */

  evq_rc = ef10ct_alloc_evq(nic);
  if (evq_rc < 0) {
    EFHW_ERR("%s: rc %d", __func__, evq_rc);
    return evq_rc;
  }

  evq_num = ef10ct_get_queue_num(evq_rc);
  EFHW_ASSERT(ef10ct->evq[evq_num].txq == EF10CT_EVQ_NO_TXQ);

  if( evc->want_txq) {
    txq_rc = ef10ct_alloc_txq(nic);

    if( txq_rc < 0 ) {
      ef10ct_free_evq(nic, evq_rc);
      evq_rc = txq_rc;
    }
    else {
      ef10ct->evq[evq_num].txq = txq_rc;
    }
  }

  if( evq_rc >= 0 ) {
    evq_rc = evq_num;
  }

  EFHW_WARN("%s: rc %d", __func__, evq_rc);

  return evq_rc;
}

static bool ef10ct_accept_rx_vi_constraints(int instance, void* arg) {
  return true;
}

static int ef10ct_vi_alloc_sw(struct efhw_nic *nic,
                              struct efhw_vi_constraints *evc, unsigned n_vis)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  /* Acquire ef10ct device as in AUX_PRE to protect access to arch_extra which
   * goes away after aux detach*/
  struct efx_auxdev_client* cli = efhw_nic_acquire_auxdev(nic);
  int rc;

  if( cli == NULL )
    return -ENETDOWN;

  mutex_lock(&ef10ct->vi_allocator.lock);
  rc = efhw_stack_alloc(&ef10ct->vi_allocator.rx,
                           ef10ct_accept_rx_vi_constraints, ef10ct);
  mutex_unlock(&ef10ct->vi_allocator.lock);

  efhw_nic_release_auxdev(nic, cli);

  EFHW_WARN("%s: rc %d", __func__, rc);

  return rc;
}

static int ef10ct_vi_alloc(struct efhw_nic *nic,
                           struct efhw_vi_constraints *evc, unsigned n_vis)
{
  if( evc->want_txq )
    return ef10ct_vi_alloc_hw(nic, evc, n_vis);
  else
    return ef10ct_vi_alloc_sw(nic, evc, n_vis);
}

static void ef10ct_vi_free_hw(struct efhw_nic *nic, int evq_num)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  int txq = ef10ct->evq[evq_num].txq;
  int evq_id;

  evq_id = ef10ct_reconstruct_queue_handle(evq_num,
                                           EF10CT_QUEUE_HANDLE_TYPE_EVQ);

  EFHW_WARN("%s: q 0x%x", __func__, evq_id);

  ef10ct_free_evq(nic, evq_id);

  if( txq != EF10CT_EVQ_NO_TXQ) {
    ef10ct_free_txq(nic, txq);
  }

  ef10ct->evq[evq_num].txq = EF10CT_EVQ_NO_TXQ;
}

static void ef10ct_vi_free_sw(struct efhw_nic *nic, int evq_num)
{
  struct efx_auxdev_client* cli = efhw_nic_acquire_auxdev(nic);
  if( cli != NULL ) {
    struct efhw_nic_ef10ct* ef10ct = nic->arch_extra;
    /* If this vi is in the range [0..ef10ct->evq_n) it has a txq */
    mutex_lock(&ef10ct->vi_allocator.lock);
    efhw_stack_free(&ef10ct->vi_allocator.rx, evq_num);
    mutex_unlock(&ef10ct->vi_allocator.lock);

    efhw_nic_release_auxdev(nic, cli);
  }
}

static void ef10ct_vi_free(struct efhw_nic *nic, int evq_num, unsigned n_vis)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;

  EFHW_ASSERT(n_vis == 1);

  if( evq_num < ef10ct->evq_n )
    ef10ct_vi_free_hw(nic, evq_num);
  else
    ef10ct_vi_free_sw(nic, evq_num);
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
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_INIT_TXQ_EXT_IN_LEN);
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_evq *ef10ct_evq;
  struct efx_auxdev_rpc rpc;
  int evq_id, evq_num;
  int rc;

  evq_num = txq_params->evq;
  evq_id = ef10ct_reconstruct_queue_handle(evq_num,
                                           EF10CT_QUEUE_HANDLE_TYPE_EVQ);
  ef10ct_evq = &ef10ct->evq[evq_num];
  EFHW_WARN("%s: txq 0x%x evq 0x%x", __func__, ef10ct_evq->txq, evq_id);

  EFHW_ASSERT(evq_num < ef10ct->evq_n);
  EFHW_ASSERT(ef10ct_evq->txq != EFCT_EVQ_NO_TXQ);

  EFHW_MCDI_INITIALISE_BUF(in);

  EFHW_MCDI_SET_DWORD(in, INIT_TXQ_EXT_IN_TARGET_EVQ, evq_id);
  EFHW_MCDI_SET_DWORD(in, INIT_TXQ_EXT_IN_LABEL, txq_params->tag);
  EFHW_MCDI_SET_DWORD(in, INIT_TXQ_EXT_IN_INSTANCE, ef10ct_evq->txq);
  EFHW_MCDI_SET_DWORD(in, INIT_TXQ_EXT_IN_PORT_ID, EVB_PORT_ID_ASSIGNED);

  EFHW_MCDI_POPULATE_DWORD_4(in, INIT_TXQ_EXT_IN_FLAGS,
                             INIT_TXQ_EXT_IN_FLAG_IP_CSUM_DIS, 1,
			     INIT_TXQ_EXT_IN_FLAG_TCP_CSUM_DIS, 1,
			     INIT_TXQ_EXT_IN_FLAG_CTPIO, 1,
			     INIT_TXQ_EXT_IN_FLAG_CTPIO_UTHRESH, 1);

  rpc.cmd = MC_CMD_INIT_TXQ;
  rpc.inlen = sizeof(in);
  rpc.inbuf = (void*)in;
  rpc.outlen = 0;
  rpc.outbuf = NULL;

  rc = ef10ct_fw_rpc(nic, &rpc);
  if( rc == 0 )
    txq_params->qid_out = ef10ct_evq->txq;

  return rc;
}

static int
ef10ct_rx_buffer_post_register(struct efhw_nic* nic, int instance,
                               resource_size_t* addr_out)
{
  int rc;
  struct device *dev;
  struct efx_auxdev* edev;
  struct efx_auxdev_client* cli;
  union efx_auxiliary_param_value val = {0};
  int rxq_handle;

  rxq_handle = ef10ct_reconstruct_queue_handle(instance,
                                               EF10CT_QUEUE_HANDLE_TYPE_RXQ);
  val.queue_io_wnd.qid_in = rxq_handle;

  EFHW_WARN("%s: instance 0x%x", __func__, instance);

  AUX_PRE(dev, edev, cli, nic, rc);
  rc = edev->llct_ops->base_ops->get_param(cli, EFX_AUXILIARY_RXQ_WINDOW, &val);
  AUX_POST(dev, edev, cli, nic, rc);

  if( rc < 0 )
    return rc;

  *addr_out = val.queue_io_wnd.base;

  return 0;
}

static int ef10ct_rx_iomap_buffer_post_register(struct efhw_nic *nic,
                                                int rxq_handle, void **addr_out)
{
  int rc;
  struct device *dev;
  struct efx_auxdev* edev;
  struct efx_auxdev_client* cli;
  union efx_auxiliary_param_value val = {.queue_io_wnd.qid_in = rxq_handle};
  size_t map_size;
  void *io;

  AUX_PRE(dev, edev, cli, nic, rc);
  rc = edev->llct_ops->base_ops->get_param(cli, EFX_AUXILIARY_RXQ_WINDOW, &val);
  AUX_POST(dev, edev, cli, nic, rc);

  if( rc < 0 )
    return rc;

  /* TODO EF10CT The 'L' variant is reported by fake test hardware, which
   * doesn't provide iomem.
  */
  if( (nic->devtype.arch == EFHW_ARCH_EF10CT) &&
      (nic->devtype.variant == 'L') )
  {
    /* The address provided by the test driver is a physical address that has
     * been converted from a virtual address, we can simply convert it back in
     * order to use it. */
    *addr_out = phys_to_virt(val.queue_io_wnd.base);
    return 0;
  }

  map_size = CI_ROUND_UP(val.queue_io_wnd.size, CI_PAGE_SIZE);

  EFHW_ASSERT((val.queue_io_wnd.base & PAGE_MASK) == val.queue_io_wnd.base);
  io = ioremap_uc(val.queue_io_wnd.base, map_size);
  if (io == NULL) {
    EFHW_ERR("%s Failed to iomap! base = %llx, map_size = %lu", __func__,
             val.queue_io_wnd.base, map_size);
    return -EINVAL;
  }

  *addr_out = io;
  return 0;
}

static int ef10ct_fini_rxq(struct efhw_nic *nic, int rxq_num)
{
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FINI_RXQ_IN_LEN);
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_evq *ef10ct_evq;
  struct efx_auxdev_rpc rpc = {
    .cmd = MC_CMD_FINI_RXQ,
    .inlen = sizeof(in),
    .inbuf = (void*)in,
    .outlen = 0,
    .outbuf = NULL,
  };
  int rxq_handle;
  int evq_id;
  int rc;

  rxq_handle = ef10ct_reconstruct_queue_handle(rxq_num,
                                               EF10CT_QUEUE_HANDLE_TYPE_RXQ);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_SET_DWORD(in, FINI_RXQ_IN_INSTANCE, rxq_handle);

  rc = ef10ct_fw_rpc(nic, &rpc);

  evq_id = ef10ct->rxq[rxq_num].evq;
  ef10ct_evq = &ef10ct->evq[ef10ct_get_queue_num(evq_id)];

  atomic_inc(&ef10ct_evq->queues_flushing);
  schedule_delayed_work(&ef10ct_evq->check_flushes, 0);

  return rc;
}

static int
ef10ct_shared_rxq_bind(struct efhw_nic* nic,
                       struct efhw_shared_bind_params *params)
{
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_INIT_RXQ_V5_IN_LEN);
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  int rxq_num = params->qid;
  int rxq_handle;
  int evq;
  int rc;
  struct efx_auxdev_rpc rpc;
  void **post_buffer_addr;
  bool suppress_events = false;

  EFHW_WARN("%s: evq 0x%x, rxq 0x%x", __func__, params->wakeup_instance,
            params->qid);

  mutex_lock(&ef10ct->rxq[rxq_num].bind_lock);

  if( ef10ct->rxq[rxq_num].state == EF10CT_RXQ_STATE_FREEING ||
      ef10ct->rxq[rxq_num].state == EF10CT_RXQ_STATE_FREE ) {
    EFHW_WARN("%s Tried to bind to rxq %d, but it is being freed. Aborting.",
             __func__, rxq_num);
    rc = -EAGAIN;
    goto out_locked;
  }

  if( ef10ct->rxq[rxq_num].ref_count > 0 ) {
    /* Already bound, so should have an associated evq */
    EFHW_ASSERT(ef10ct->rxq[rxq_num].evq >= 0);
    EFHW_ASSERT(ef10ct->rxq[rxq_num].state == EF10CT_RXQ_STATE_INITIALISED);
    goto out_good;
  }

  rxq_handle = ef10ct_reconstruct_queue_handle(rxq_num,
                                               EF10CT_QUEUE_HANDLE_TYPE_RXQ);

  /* FIXME EF10CT the evq used here is not mapped to userspace, so isn't part
   * of the higher level resource management. We need to decide what evq to
   * attach to - a shared queue with rx event suppression, or a dedicated
   * queue. Currently we only support using a single shared queue. When we
   * start supporting onload with interrupts we'll need to be able to alloc
   * and attach to an evq. */
  EFHW_ASSERT(ef10ct->shared_n >= 1 );
  evq = ef10ct->shared[0].evq_id;
  EFHW_WARN("%s: Using shared evq 0x%x", __func__, evq);
  suppress_events = true;

  EFHW_MCDI_INITIALISE_BUF(in);

  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V5_IN_SIZE,
                      roundup_pow_of_two(
                        DIV_ROUND_UP(EFCT_RX_SUPERBUF_BYTES, EFCT_PKT_STRIDE) *
                        CI_EFCT_SUPERBUFS_PER_PAGE * params->n_hugepages
                      ));
  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V5_IN_TARGET_EVQ, evq);
  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V5_IN_LABEL, rxq_num);
  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V5_IN_INSTANCE, rxq_handle);
  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V5_IN_PORT_ID, EVB_PORT_ID_ASSIGNED);

  EFHW_MCDI_POPULATE_DWORD_5(in, INIT_RXQ_V5_IN_FLAGS,
                             INIT_RXQ_V5_IN_DMA_MODE,
			     MC_CMD_INIT_RXQ_V5_IN_EQUAL_STRIDE_SUPER_BUFFER,
			     INIT_RXQ_V5_IN_FLAG_TIMESTAMP, 1,
			     INIT_RXQ_V5_IN_FLAG_PREFIX, 1,
			     INIT_RXQ_V5_IN_FLAG_DISABLE_SCATTER, 1,
			     INIT_RXQ_V5_IN_FLAG_SUPPRESS_RX_EVENTS, suppress_events);

  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V5_IN_ES_PACKET_STRIDE, EFCT_PKT_STRIDE);
  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V5_IN_ES_MAX_DMA_LEN, nic->mtu);
  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V5_IN_ES_PACKET_BUFFERS_PER_BUCKET,
		       DIV_ROUND_UP(EFCT_RX_SUPERBUF_BYTES, EFCT_PKT_STRIDE));

  rpc.cmd = MC_CMD_INIT_RXQ;
  rpc.inlen = sizeof(in);
  rpc.inbuf = (void*)in;
  rpc.outlen = 0;
  rpc.outbuf = NULL;
  rc = ef10ct_fw_rpc(nic, &rpc);
  if( rc < 0 ) {
    EFHW_ERR("%s ef10ct_fw_rpc failed. rc = %d\n", __FUNCTION__, rc);
    goto out_locked;
  }

  if( rxq_num < 0 || rxq_num >= ef10ct->rxq_n ) {
    EFHW_ERR(KERN_INFO "%s rxq outside of expected range. rxq = %d",
             __func__, rxq_num);
    rc = -EINVAL;
    goto out_locked;
  }

  post_buffer_addr = (void **)&ef10ct->rxq[rxq_num].post_buffer_addr;
  rc = ef10ct_rx_iomap_buffer_post_register(nic, rxq_handle, post_buffer_addr);
  if (rc < 0) {
    ef10ct_fini_rxq(nic, rxq_num);
    EFHW_ERR("%s Failed to iomap rx post register. rc = %d", __func__, rc);
    goto out_locked;
  }

  if( params->hugetlb_alloc != NULL && params->n_hugepages != 0 ) {
    int i;
    struct oo_hugetlb_page* pages =
      kzalloc(params->n_hugepages * sizeof(struct oo_hugetlb_page), GFP_KERNEL);

    if( pages == NULL ) {
      EFHW_ERR("%s Failed to allocate buffer page table\n", __FUNCTION__);
      return -ENOMEM;
    }

    for( i = 0; i < params->n_hugepages; ++i ) {
      rc = oo_hugetlb_page_alloc(params->hugetlb_alloc, &pages[i]);
      if( rc < 0 ) {
        EFHW_ERR("%s Failed to allocate buffer page. rc = %d\n", __FUNCTION__, rc);
        while( i > 0 )
          oo_hugetlb_page_free(&pages[--i], false);
        kfree(pages);
        return rc;
      }
    }

    ef10ct->rxq[rxq_num].buffer_pages = pages;
    ef10ct->rxq[rxq_num].n_buffer_pages = params->n_hugepages;
  }
  else {
    ef10ct->rxq[rxq_num].buffer_pages = NULL;
    ef10ct->rxq[rxq_num].n_buffer_pages = 0;
  }

  flush_delayed_work(&ef10ct->evq[ef10ct_get_queue_num(evq)].check_flushes);

  EFHW_ASSERT(ef10ct->rxq[rxq_num].evq == -1);
  ef10ct->rxq[rxq_num].evq = evq;

  EFHW_ASSERT(ef10ct->rxq[rxq_num].state == EF10CT_RXQ_STATE_ALLOCATED);
  ef10ct->rxq[rxq_num].state = EF10CT_RXQ_STATE_INITIALISED;

out_good:
  ef10ct->rxq[rxq_num].ref_count++;
  params->rxq->qid = rxq_num;
out_locked:
  mutex_unlock(&ef10ct->rxq[rxq_num].bind_lock);
  return rc;
}

static void
ef10ct_shared_rxq_unbind(struct efhw_nic* nic, struct efhw_efct_rxq *rxq,
                         efhw_efct_rxq_free_func_t *freer)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  int rxq_num = rxq->qid;
  int rc;

  /* This releases the SW RXQ resource, so is independent of the underlying
   * HW RXQ flush and free. */
  freer(rxq);

  mutex_lock(&ef10ct->rxq[rxq_num].bind_lock);
  EFHW_ASSERT(ef10ct->rxq[rxq_num].ref_count > 0);
  ef10ct->rxq[rxq_num].ref_count--;

  if( ef10ct->rxq[rxq_num].ref_count > 0 ) {
    mutex_unlock(&ef10ct->rxq[rxq_num].bind_lock);
    return;
  }

  EFHW_ASSERT(ef10ct->rxq[rxq_num].state == EF10CT_RXQ_STATE_INITIALISED);
  ef10ct->rxq[rxq_num].state = EF10CT_RXQ_STATE_FREEING;

  if( ef10ct->rxq[rxq_num].buffer_pages != NULL ) {
    int i;
    for( i = 0; i < ef10ct->rxq[rxq_num].n_buffer_pages; ++i )
      oo_hugetlb_page_free(&ef10ct->rxq[rxq_num].buffer_pages[i], false);
    kfree(ef10ct->rxq[rxq_num].buffer_pages);
  }

  rc = ef10ct_fini_rxq(nic, rxq_num);
  if( rc < 0 ) {
    EFHW_ERR("%s: Failed to fini rxq %d rc = %d", __func__, rxq_num, rc);
    mutex_unlock(&ef10ct->rxq[rxq_num].bind_lock);
    return;
  }

  if ( ! ((nic->devtype.arch == EFHW_ARCH_EF10CT) &&
          (nic->devtype.variant == 'L')) )
  {
    iounmap(ef10ct->rxq[rxq_num].post_buffer_addr);
  }
  ef10ct->rxq[rxq_num].evq = -1;
  ef10ct->rxq[rxq_num].post_buffer_addr = NULL;

  mutex_unlock(&ef10ct->rxq[rxq_num].bind_lock);
}

static int
ef10ct_nic_shared_rxq_refresh(struct efhw_nic *nic, int hwqid,
                              unsigned long superbufs,
                              uint64_t __user *user_current,
                              unsigned max_superbufs)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_rxq *rxq = &ef10ct->rxq[hwqid];
  size_t i, n_bufs = rxq->n_buffer_pages * CI_EFCT_SUPERBUFS_PER_PAGE;

  if( max_superbufs < n_bufs ) {
    EFHW_TRACE("max_superbufs: %u passed in by user less than kernel's: %u.",
               max_superbufs, n_bufs);
  }

  for( i = 0; i < rxq->n_buffer_pages; ++i, superbufs += CI_HUGEPAGE_SIZE ) {
    struct oo_hugetlb_page *hpage = &rxq->buffer_pages[i];
    unsigned long rc;

    /* we need write access so that userland can poison buffers when posting */
    rc = vm_mmap(hpage->filp, superbufs, CI_HUGEPAGE_SIZE, PROT_READ | PROT_WRITE,
                 MAP_FIXED | MAP_SHARED | MAP_POPULATE | MAP_HUGETLB | MAP_HUGE_2MB,
                 oo_hugetlb_page_offset(hpage->page));
    if( IS_ERR((void*)rc) )
      return PTR_ERR((void*)rc);
  }

  return 0;
}

static int
ef10ct_nic_shared_rxq_refresh_kernel(struct efhw_nic *nic, int hwqid,
                                     const char** superbufs)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_rxq *rxq = &ef10ct->rxq[hwqid];
  size_t i, n_bufs = rxq->n_buffer_pages * CI_EFCT_SUPERBUFS_PER_PAGE;

  for( i = 0; i < n_bufs; ++i ) {
    struct page *page = rxq->buffer_pages[i / CI_EFCT_SUPERBUFS_PER_PAGE].page;
    superbufs[i] = page_to_virt(page) +
                   EFCT_RX_SUPERBUF_BYTES * (i % CI_EFCT_SUPERBUFS_PER_PAGE);
  }

  return 0;
}

static int
ef10ct_dmaq_rx_q_init(struct efhw_nic *nic,
                      struct efhw_dmaq_params *rxq_params)
{
  /* efct doesn't do rxqs like this, so nothing to do here */
  rxq_params->qid_out = rxq_params->dmaq;
  return 0;
}

static size_t
ef10ct_max_shared_rxqs(struct efhw_nic *nic)
{
  /* FIXME EF10CT this needs to mean exactly one of "needs packet shm"
   * (efct_only) or "attaches to shared rxq resource" (efct and ef10ct). I
   * think at the moment the latter is what we want, but this should be
   * revisited once we've built up more of the RX stuff. */
  return 1;
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - mid level API
 *
 *--------------------------------------------------------------------*/


static int
ef10ct_flush_tx_dma_channel(struct efhw_nic *nic,
                            uint dmaq, uint evq_num)
{
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FINI_TXQ_IN_LEN);
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_evq *ef10ct_evq;
  int rc = 0;
  struct efx_auxdev_rpc rpc;

  ef10ct_evq = &ef10ct->evq[evq_num];

  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_SET_DWORD(in, FINI_TXQ_IN_INSTANCE, dmaq);

  rpc.cmd = MC_CMD_FINI_TXQ;
  rpc.inlen = sizeof(in);
  rpc.inbuf = (void*)in;
  rpc.outlen = 0;
  rpc.outbuf = NULL;
  rc = ef10ct_fw_rpc(nic, &rpc);

  atomic_inc(&ef10ct_evq->queues_flushing);
  schedule_delayed_work(&ef10ct_evq->check_flushes, 0);

  return rc;
}


static int
ef10ct_flush_rx_dma_channel(struct efhw_nic *nic, uint dmaq)
{
  /* Free and flush of RXQs are managed through tracking users, so nothing to
   * do here. */
  return -EALREADY;
}

static enum efhw_page_map_type
ef10ct_queue_map_type(struct efhw_nic *nic)
{
  /* The test driver doesn't support DMA mapping, so fallback to phys addrs
   * in that case. */
  if( nic->devtype.variant == 'L' )
    return EFHW_PAGE_MAP_PHYS;
  else
    return EFHW_PAGE_MAP_DMA;
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

static enum efhw_page_map_type
ef10ct_buffer_map_type(struct efhw_nic *nic)
{
  /* The test driver doesn't support DMA mapping, so fallback to phys addrs
   * in that case. */
  if( nic->devtype.variant == 'L' )
    return EFHW_PAGE_MAP_PHYS;
  else
    return EFHW_PAGE_MAP_DMA;
}

/*--------------------------------------------------------------------
 *
 * Filtering
 *
 *--------------------------------------------------------------------*/


struct filter_insert_params {
  struct efhw_nic *nic;
  const struct cpumask *mask;
  unsigned flags;
};


static int get_rxq_num_from_mask(struct efhw_nic *nic,
                                 const struct cpumask *mask, bool exclusive)
{
  int rc;

  EFHW_WARN("%s", __func__);

  rc = ef10ct_alloc_rxq(nic);

  /* FIXME EF10CT full lifetime management of this RXQ. We do the queue init
   * on demand on first attach, where we have information about the VI user
   * that we need to make decisions such as whether to enable RX event
   * generation and the target EVQ. The flush and release happen on queue
   * detach. There are outstanding bugs to track related work:
   * - permission handling for additional shared users of the queue
   * - resource re-allocation post reset
   */

  /* Update efhw's understanding of the state of this rxq */
  if( rc >= 0 ) {
    struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
    int rxq_num = ef10ct_get_queue_num(rc);

    mutex_lock(&ef10ct->rxq[rxq_num].bind_lock);

    if( rxq_num < ef10ct->rxq_n ) {
      if( ef10ct->rxq[rxq_num].state == EF10CT_RXQ_STATE_FREE )
        ef10ct->rxq[rxq_num].state = EF10CT_RXQ_STATE_ALLOCATED;
      else
        EFHW_WARN("%s Allocated rxq %d but it was not in the FREE state."
                  " state = %u", __func__, rxq_num, ef10ct->rxq[rxq_num].state);
    }

    mutex_unlock(&ef10ct->rxq[rxq_num].bind_lock);

    /* This needs to use queue number as visible to the upper layers rather
     * than the MCDI handle, as it's not going straight to the HW but being
     * used as part of the queue selection process, which operates on host
     * side handles. */
    rc = rxq_num;
  }

  return rc;
}


static int select_rxq(struct filter_insert_params *params, uint64_t rxq_in)
{
  struct efhw_nic_ef10ct *ef10ct = params->nic->arch_extra;
  bool anyqueue, loose, exclusive;
  int rxq_num = -1; /* ignored on failure, but initialised for logging */
  int rc = 0;

  anyqueue = params->flags & EFHW_FILTER_F_ANY_RXQ;
  loose = ((params->flags & EFHW_FILTER_F_PREF_RXQ) ||
           (params->flags & EFHW_FILTER_F_ANY_RXQ));
  exclusive = params->flags & EFHW_FILTER_F_EXCL_RXQ;

  if( !anyqueue ) {
    if( rxq_in >= ef10ct->rxq_n ) {
      EFHW_WARN("%s: Invalid queue id 0x%llx\n", __func__, rxq_in);
      rc = -EINVAL;
      goto out;
    }
    rxq_num = rxq_in;
  }
  else {
    if( params->mask )
      rxq_num = get_rxq_num_from_mask(params->nic, params->mask, exclusive);
  }

  /* Failed to get an rxq matching our cpumask, so allow fallback to any cpu
   * if allowed */
  if( rxq_num < 0 && loose )
    rxq_num = get_rxq_num_from_mask(params->nic, cpu_online_mask, exclusive);

  if( rxq_num < 0 ) {
    EFHW_WARN("%s: Unable to find the queue ID for given mask, flags= %d\n",
              __func__, params->flags);
    rc = rxq_num;
    goto out;
  }

 out:
  EFHW_TRACE("%s: any: %d loose: %d exclusive: %d rxq_in: %llu rc: %d rxq: %x",
             __func__, anyqueue, loose, exclusive, rxq_in, rc, rxq_num);

  return rc < 0 ? rc : rxq_num;
}


static int ef10ct_filter_insert_op(const struct efct_filter_insert_in *in_data,
                                  struct efct_filter_insert_out *out_data)
{
  int rc;
  struct filter_insert_params *params = (struct filter_insert_params*)
                                        in_data->drv_opaque;
  int rxq;
  int rxq_num;

  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FILTER_OP_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_FILTER_OP_OUT_LEN);
  struct efx_auxdev_rpc rpc = {
    .cmd = MC_CMD_FILTER_OP,
    .inbuf = (u32*)&in,
    .inlen = MC_CMD_FILTER_OP_IN_LEN,
    .outbuf = (u32*)&out,
    .outlen = MC_CMD_FILTER_OP_OUT_LEN,
  };
  rxq_num = select_rxq(params, in_data->filter->ring_cookie);
  if( rxq_num < 0 )
    return rxq_num;

  /* Various parts of the efvi user/kernel interface assume that the qid can fit
   * within 8 bits. This precludes us from using the full 32 bit queue handle
   * that we got from firmware without breaking existing apps. Instead, extract
   * the queue number from the handle and reconstruct the queue handle again
   * when it is needed. */
  EFHW_ASSERT(rxq_num < 256);
  rxq = ef10ct_reconstruct_queue_handle(rxq_num, EF10CT_QUEUE_HANDLE_TYPE_RXQ);

  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);
  ethtool_flow_to_mcdi_op(in, rxq, in_data->filter);

  rc = ef10ct_fw_rpc(params->nic, &rpc);

  if( rc == 0 ) {
    uint32_t id_low = EFHW_MCDI_DWORD(out, FILTER_OP_OUT_HANDLE_LO);
    uint32_t id_hi = EFHW_MCDI_DWORD(out, FILTER_OP_OUT_HANDLE_HI);
    out_data->rxq = rxq_num;
    out_data->drv_id = id_low | (uint64_t)id_hi << 32;
    /* Metadata filter_id is the bottom 16 bits of MCDI filter handle */
    out_data->filter_handle = id_low & 0xffff;
  }

  /* Free rxq on filter insert failure */
  if (rc < 0) {
    EFHW_ERR("%s filter insert failed. Freeing rxq = %d", __func__, rxq);
    ef10ct_free_rxq(params->nic, rxq);
  }

  return rc;
}


static int
ef10ct_filter_insert(struct efhw_nic *nic, struct efx_filter_spec *spec,
                     int *rxq, unsigned pd_excl_token,
                     const struct cpumask *mask, unsigned flags)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct ethtool_rx_flow_spec hw_filter;
  struct filter_insert_params params = {
    .nic = nic,
    .mask = mask,
    .flags = flags,
  };
  int rc;


  rc = efx_spec_to_ethtool_flow(spec, &hw_filter);
  if( rc < 0 )
    return rc;

  /* There's no special RXQ 0 here, so don't allow fallback to SW filter */
  flags |= EFHW_FILTER_F_USE_HW;
  return efct_filter_insert(&ef10ct->filter_state, spec, &hw_filter, rxq,
                            pd_excl_token, flags, ef10ct_filter_insert_op,
                            &params, nic->filter_flags);
}


static void
ef10ct_filter_remove(struct efhw_nic *nic, int filter_id)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FILTER_OP_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_FILTER_OP_OUT_LEN);
  struct efx_auxdev_rpc rpc = {
    .cmd = MC_CMD_FILTER_OP,
    .inbuf = (u32*)&in,
    .inlen = MC_CMD_FILTER_OP_IN_LEN,
    .outbuf = (u32*)&out,
    .outlen = MC_CMD_FILTER_OP_OUT_LEN,
  };
  bool remove_drv;
  uint64_t drv_id;
  int rc;

  remove_drv = efct_filter_remove(&ef10ct->filter_state, filter_id, &drv_id);

  if( remove_drv ) {
    EFHW_MCDI_SET_DWORD(in, FILTER_OP_IN_OP, MC_CMD_FILTER_OP_IN_OP_REMOVE);
    EFHW_MCDI_SET_DWORD(in, FILTER_OP_IN_HANDLE_LO, drv_id);
    EFHW_MCDI_SET_DWORD(in, FILTER_OP_IN_HANDLE_HI, drv_id >> 32);

    rc = ef10ct_fw_rpc(nic, &rpc);
    if( rc < 0 )
      EFHW_NOTICE("%s: Failed to remove filter id %d, rc %d",
                  __func__, filter_id, rc);
  }
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
  struct device *dev;
  struct efx_auxdev* edev;
  struct efx_auxdev_client* cli;
  union efx_auxiliary_param_value val;
  int rc = 0;

  AUX_PRE(dev, edev, cli, nic, rc)
  rc = edev->llct_ops->base_ops->get_param(cli, EFX_PCI_DEV, &val);
  /* Ensure auxbus is still present when we increment the refcount to the pci
   * dev. This means it will not be used after free. */
  if( rc >= 0 )
    pci_dev_get(val.pci_dev);

  AUX_POST(dev, edev, cli, nic, rc);

  if( rc < 0 )
    return NULL;
  else
    return val.pci_dev;
}


static int
ef10ct_vi_io_region(struct efhw_nic* nic, int evq_num, size_t* size_out,
                    resource_size_t* addr_out)
{
  struct device *dev;
  struct efx_auxdev* edev;
  struct efx_auxdev_client* cli;
  union efx_auxiliary_param_value val = {
    .queue_io_wnd.qid_in =
      ef10ct_reconstruct_queue_handle(evq_num, EF10CT_QUEUE_HANDLE_TYPE_EVQ)
  };
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  int rc = 0;

  if (evq_num >= ef10ct->evq_n) {
    *size_out = 0;
    *addr_out = 0;
    return rc;
  }

  AUX_PRE(dev, edev, cli, nic, rc)
  rc = edev->llct_ops->base_ops->get_param(cli, EFX_AUXILIARY_EVQ_WINDOW,
                                           &val);
  AUX_POST(dev, edev, cli, nic, rc);

  *size_out = val.queue_io_wnd.size;
  *addr_out = val.queue_io_wnd.base;

  return rc;
}

static int
ef10ct_design_parameters(struct efhw_nic *nic,
                         struct efab_nic_design_parameters *dp)
{
  struct device *dev;
  struct efx_auxdev* edev;
  struct efx_auxdev_client* cli;
  union efx_auxiliary_param_value val;
  struct efx_design_params params;
  int rc = 0;

  val.design_params = &params;
  AUX_PRE(dev, edev, cli, nic, rc)
  rc = edev->llct_ops->base_ops->get_param(cli, EFX_DESIGN_PARAM, &val);
  AUX_POST(dev, edev, cli, nic, rc);

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

  SET(rx_superbuf_bytes, val.design_params->rx_buffer_len);
  if( val.design_params->meta_location == 0 ) {
    SET(rx_frame_offset, EFCT_RX_HEADER_NEXT_FRAME_LOC_0 - 2);
  }
  else if( val.design_params->meta_location == 1 ) {
    SET(rx_frame_offset, EFCT_RX_HEADER_NEXT_FRAME_LOC_1 - 2);
  }
  else {
    EFHW_ERR("%s: Could not determine frame offset from meta_location %u",
             __func__, val.design_params->meta_location);
    return -EOPNOTSUPP;
  }
  SET(rx_stride, val.design_params->rx_stride);
  SET(rx_queues, val.design_params->rx_queues);
  SET(tx_aperture_bytes, val.design_params->tx_aperture_size);
  SET(tx_fifo_bytes, val.design_params->tx_fifo_size);
  SET(timestamp_subnano_bits, val.design_params->ts_subnano_bit);
  SET(unsol_credit_seq_mask, val.design_params->unsol_credit_seq_mask);
  SET(md_location, val.design_params->meta_location);

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
  struct efx_auxdev* edev;
  struct efx_auxdev_client* cli;
  union efx_auxiliary_param_value val;
  int rc;

  val.queue_io_wnd.qid_in = instance;
  AUX_PRE(dev, edev, cli, nic, rc);
  rc = edev->llct_ops->base_ops->get_param(cli, EFX_AUXILIARY_CTPIO_WINDOW,
                                           &val);
  AUX_POST(dev, edev, cli, nic, rc);

  /* Currently we assume throughout onload that we have a 4k region */
  if( (rc == 0) && (val.queue_io_wnd.size != 0x1000) )
    return -EOPNOTSUPP;

  if( rc == 0 )
    *addr = val.queue_io_wnd.base;

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
  int rxq_num = ef10ct_get_queue_num(instance);

  if( rxq_num < 0 || rxq_num >= ef10ct->rxq_n )
    return -EINVAL;
  reg = ef10ct->rxq[rxq_num].post_buffer_addr;
  if( reg == NULL )
    return -EINVAL;

  if( owner_id == -1 )
    phys_addr = virt_to_phys((void*)dma_addr);
  else
    phys_addr = translate_dma_address(nic, dma_addr, owner_id);

  CI_POPULATE_QWORD_3(qword,
                      EFCT_TEST_PAGE_ADDRESS, phys_addr >> CI_PAGE_SHIFT,
                      EFCT_TEST_SENTINEL_VALUE, sentinel,
                      EFCT_TEST_ROLLOVER, rollover);

  if ((nic->devtype.arch == EFHW_ARCH_EF10CT) &&
      (nic->devtype.variant == 'L'))
  {
    EFHW_NOTICE("%s Using the test driver code!", __func__);
    /* Due to limitations with the efct_test driver it is possible to write
     * multiple values to RX_BUFFER_POST register before the first one is
     * read. As a crude workaround for the issue the test driver resets the
     * register 0 once it has processed the buffer. We poll the value of the
     * register here in case the test driver hasn't finished yet. */
    while(*reg != 0) {
      msleep(20); /* Ran into softlockups even with reg being declared
                   * as volatile. Maybe this is because the test
                   * driver is scheduled on the core as the one that
                   * is spinning, so can never actually run? */
    }
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
  .queue_map_type = ef10ct_queue_map_type,
  .buffer_table_orders = ef10ct_nic_buffer_table_orders,
  .buffer_table_orders_num = CI_ARRAY_SIZE(ef10ct_nic_buffer_table_orders),
  .buffer_table_alloc = efhw_sw_bt_alloc,
  .buffer_table_free = efhw_sw_bt_free,
  .buffer_table_set = efhw_sw_bt_set,
  .buffer_table_clear = efhw_sw_bt_clear,
  .buffer_map_type = ef10ct_buffer_map_type,
  .filter_insert = ef10ct_filter_insert,
  .filter_remove = ef10ct_filter_remove,
  .filter_redirect = ef10ct_filter_redirect,
  .filter_query = ef10ct_filter_query,
  .multicast_block = ef10ct_multicast_block,
  .unicast_block = ef10ct_unicast_block,
  .get_pci_dev = ef10ct_get_pci_dev,
  .vi_io_region = ef10ct_vi_io_region,
  .ctpio_addr = ef10ct_ctpio_addr,
  .rxq_window = ef10ct_rx_buffer_post_register,
  .post_superbuf =  ef10ct_rxq_post_superbuf,
  .design_parameters = ef10ct_design_parameters,
  .max_shared_rxqs = ef10ct_max_shared_rxqs,
  .shared_rxq_bind = ef10ct_shared_rxq_bind,
  .shared_rxq_unbind = ef10ct_shared_rxq_unbind,
  .shared_rxq_refresh = ef10ct_nic_shared_rxq_refresh,
  .shared_rxq_refresh_kernel = ef10ct_nic_shared_rxq_refresh_kernel,
  .irq_alloc = ef10ct_irq_alloc,
  .irq_free = ef10ct_irq_free,
};

#endif
