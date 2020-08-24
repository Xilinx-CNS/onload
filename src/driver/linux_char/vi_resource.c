/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2020 Xilinx, Inc. */
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/vi_set.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/efrm_port_sniff.h>
#include <ci/efrm/efrm_filter.h>
#include "efch.h"
#include <ci/driver/efab/hardware.h>
#include <ci/efch/mmap.h>
#include <ci/efch/op_types.h>
#include <ci/driver/kernel_compat.h>
#include "char_internal.h"
#include "filter_list.h"
#include "linux_char_internal.h"


/* Reserved space in evq for a reasonable number of time sync events.
 * They arrive at a rate of 4 per second.  This allows app to get
 * 25s behind...
 */
#define CI_CFG_TIME_SYNC_EVENT_EVQ_CAPACITY (4 * 25)

static const char *q_names[EFHW_N_Q_TYPES] = { "TXQ", "RXQ", "EVQ" };


/*** Resource dumping ****************************************************/

static void
efch_vi_rm_dump_nic(struct efrm_vi* virs, const char *line_prefix)
{
  struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);
  int queue_type;

  ci_log("%s  nic %d EVQ kva=0x%p  dma=0x"DMA_ADDR_T_FMT" capacity=%d",
         line_prefix, nic->index,
         efhw_iopages_ptr(&virs->q[EFHW_EVQ].pages),
         efhw_iopages_dma_addr(&virs->q[EFHW_EVQ].pages, 0),
         virs->q[EFHW_EVQ].capacity);

  for(queue_type=0; queue_type<EFRM_VI_RM_DMA_QUEUE_COUNT; queue_type++) {
    ci_log("%s  nic %d %s kva=0x%p dma=" DMA_ADDR_T_FMT,
           line_prefix, nic->index, q_names[queue_type],
           efhw_iopages_ptr(&virs->q[queue_type].pages),
           efhw_iopages_dma_addr(&virs->q[queue_type].pages, 0));
  }
}


static void efch_vi_rm_dump(struct efrm_resource* rs, ci_resource_table_t *rt,
                            const char *line_prefix) 
{
  struct efrm_vi* virs = efrm_vi(rs);

  ci_log("%sVI resource " EFRM_RESOURCE_FMT,
         line_prefix, EFRM_RESOURCE_PRI_ARG(&virs->rs));

  if (virs->q[EFHW_TXQ].evq_ref != NULL)
    ci_log("%s  txq_evq:" EFRM_RESOURCE_FMT, line_prefix,
           EFRM_RESOURCE_PRI_ARG(&virs->q[EFHW_TXQ].evq_ref->rs));
  if (virs->q[EFHW_RXQ].evq_ref != NULL)
    ci_log("%s  rxq_evq:" EFRM_RESOURCE_FMT, line_prefix,
           EFRM_RESOURCE_PRI_ARG(&virs->q[EFHW_RXQ].evq_ref->rs));

  ci_log("%s  mmap bytes: mem=%d", line_prefix,
         efhw_page_map_bytes(&virs->mem_mmap));

  ci_log("%s  capacity: EVQ=%d TXQ=%d RXQ=%d", line_prefix,
         virs->q[EFHW_EVQ].capacity,
         virs->q[EFHW_TXQ].capacity,
         virs->q[EFHW_RXQ].capacity);

  ci_log("%s  tx_tag=0x%x  rx_tag=0x%x  flags=0x%x", line_prefix,
         virs->q[EFHW_TXQ].tag,
         virs->q[EFHW_RXQ].tag,
         (unsigned) virs->flags);

  ci_log("%s  flush: TX=%d RX=%d time=0x%"CI_PRIx64" count=%d",
         line_prefix, virs->q[EFHW_TXQ].flushing,
         virs->q[EFHW_TXQ].flushing, virs->flush_time, virs->flush_count);

  ci_log("%s  callback: fn=0x%p  arg=0x%p",
         line_prefix, virs->evq_callback_fn, virs->evq_callback_arg);

  ci_log("%s  buffer table: tx_order=0x%x rx_order=0x%x",
         line_prefix,
         virs->q[EFHW_TXQ].page_order,
         virs->q[EFHW_RXQ].page_order);

  efch_vi_rm_dump_nic(virs, line_prefix);
}


/*** Allocation ************************************************/

static int
vi_resource_alloc(struct efrm_vi_attr *attr,
                  struct efrm_client *client,
                  struct efrm_vi *evq_virs,
                  unsigned vi_flags,
                  int evq_capacity, int txq_capacity, int rxq_capacity,
                  int tx_q_tag, int rx_q_tag,
                  struct efrm_vi **virs_out)
{
  struct efrm_vi *virs;
  int rc;

  if (vi_flags & EFHW_VI_RX_PACKED_STREAM)
    efrm_vi_attr_set_packed_stream(attr, 1);

  if ((rc = efrm_vi_alloc(client, attr, 1, NULL, &virs)) < 0)
    goto fail_vi_alloc;

  /* We have to jump through some hoops here:
   * - EF10 needs the event queue allocated before rx and tx queues
   * - Event queue needs to know the size of the rx and tx queues
   *
   * So we first work out the sizes, then create the evq, then create
   * the rx and tx queues.
   */

  rc = efrm_vi_q_alloc_sanitize_size(virs, EFHW_TXQ, txq_capacity);
  if( rc < 0 )
    goto fail_q_alloc;
  txq_capacity = rc;

  rc = efrm_vi_q_alloc_sanitize_size(virs, EFHW_RXQ, rxq_capacity);
  if( rc < 0 )
    goto fail_q_alloc;
  rxq_capacity = rc;

  /* Size EVQ sensibly based on RX and TX Q sizes */
  if (evq_virs == NULL && evq_capacity < 0) {
    if (vi_flags & EFHW_VI_RX_PACKED_STREAM) {
      evq_capacity = 32 * 1024;
    }
    else if (vi_flags & (EFHW_VI_TX_TIMESTAMPS | EFHW_VI_TX_ALT)) {
      if (txq_capacity == 0) {
        rc = -EINVAL;
        goto fail_q_alloc;
      }
      /* Each TX completion is accompanied by 2 timestamp events.
       * Take into account additional capacity to reserve as indicated by
       * evq_capacity.
       */
      evq_capacity = rxq_capacity + 3 * txq_capacity - evq_capacity - 1;

      /* Reserve space for time sync events. */
      if( vi_flags & (EFHW_VI_TX_TIMESTAMPS | EFHW_VI_RX_TIMESTAMPS) )
        evq_capacity += CI_CFG_TIME_SYNC_EVENT_EVQ_CAPACITY;
    }
    else if (vi_flags & EFHW_VI_RX_TIMESTAMPS) {
      evq_capacity = rxq_capacity + txq_capacity - evq_capacity - 1;
      /* Reserve space for time sync events. */
      evq_capacity += CI_CFG_TIME_SYNC_EVENT_EVQ_CAPACITY;
    }
    else {
      evq_capacity = rxq_capacity + txq_capacity - evq_capacity - 1;
    }
    if (evq_capacity == 0)
      evq_capacity = -1;
  }

  /* TODO AF_XDP: allocation order must match the order that ef_vi
   * expects the queues to be mapped into user memory. */
  if ((rc = efrm_vi_q_alloc(virs, EFHW_EVQ, evq_capacity,
                            0, vi_flags, NULL)) < 0)
    goto fail_q_alloc;
  if ((rc = efrm_vi_q_alloc(virs, EFHW_RXQ, rxq_capacity,
                            rx_q_tag, vi_flags, evq_virs)) < 0)
    goto fail_q_alloc;
  if ((rc = efrm_vi_q_alloc(virs, EFHW_TXQ, txq_capacity,
                            tx_q_tag, vi_flags, evq_virs)) < 0)
    goto fail_q_alloc;

  *virs_out = virs;
  return 0;


 fail_q_alloc:
  efrm_vi_resource_release(virs);
 fail_vi_alloc:
  return rc;
}


static int
efch_vi_rm_find(int fd, efch_resource_id_t rs_id, int rs_type,
                struct efrm_resource **rs_out)
{
  return (fd < 0) ? 1 : efch_lookup_rs(fd, rs_id, rs_type, rs_out);
}


static int
efch_vi_rm_alloc(ci_resource_alloc_t* alloc, ci_resource_table_t* rt,
                 efch_resource_t* rs, int intf_ver_id)
{
  const struct efch_vi_alloc_in *alloc_in;
  struct efch_vi_alloc_out *alloc_out;
  struct efrm_resource *vi_set = NULL;
  struct efrm_resource *evq = NULL;
  struct efrm_resource *pd = NULL;
  struct efrm_client *client;
  struct efrm_vi *virs = NULL;
  struct efrm_vi_attr attr;
  struct efhw_nic *nic;
  int rc, ps_buf_size;
  int in_flags;
  struct efrm_pd* rmpd = NULL;

  ci_assert(alloc != NULL);
  ci_assert(rt != NULL);
  ci_assert(rs != NULL);

  alloc_in = &alloc->u.vi_in;

  EFCH_TRACE("%s: evq=%d txq=%d rxq=%d",
             __FUNCTION__, alloc_in->evq_capacity, alloc_in->txq_capacity,
             alloc_in->rxq_capacity);

  efrm_vi_attr_init(&attr);

  if ((rc = efch_vi_rm_find(alloc_in->evq_fd, alloc_in->evq_rs_id,
                            EFRM_RESOURCE_VI, &evq)) < 0) {
    EFCH_ERR("%s: ERROR: EVQ not found fd=%d id=%d rc=%d", __FUNCTION__,
             alloc_in->evq_fd, alloc_in->evq_rs_id.index, rc);
    goto fail1;
  }
  if ((rc = efch_vi_rm_find(alloc_in->pd_or_vi_set_fd,
                            alloc_in->pd_or_vi_set_rs_id,
                            EFRM_RESOURCE_PD, &pd)) < 0)
    if ((rc = efch_vi_rm_find(alloc_in->pd_or_vi_set_fd,
                              alloc_in->pd_or_vi_set_rs_id,
                              EFRM_RESOURCE_VI_SET, &vi_set)) < 0) {
      EFCH_ERR("%s: ERROR: PD or VI_SET not found fd=%d id=%d rc=%d",
               __FUNCTION__, alloc_in->pd_or_vi_set_fd,
               alloc_in->pd_or_vi_set_rs_id.index, rc);
      goto fail2;
    }

  if( vi_set != NULL ) {
    client = NULL;
    efrm_vi_attr_set_instance(&attr, efrm_vi_set_from_resource(vi_set),
                              alloc_in->vi_set_instance);
    rmpd = efrm_vi_set_get_pd(efrm_vi_set_from_resource(vi_set));
  }
  else if( pd != NULL ) {
    client = NULL;
    rmpd = efrm_pd_from_resource(pd);
    efrm_vi_attr_set_pd(&attr, rmpd);
  }
  else {
    rc = efrm_client_get(alloc_in->ifindex, NULL, NULL, &client);
    if( rc != 0 ) {
      EFCH_ERR("%s: ERROR: ifindex=%d not known rc=%d",
               __FUNCTION__, alloc_in->ifindex, rc);
      goto fail3;
    }
  }

  if( alloc_in->ps_buf_size_kb == 0 )
    ps_buf_size = 1024 * 1024;
  else
    ps_buf_size = (int) alloc_in->ps_buf_size_kb * 1024;
  efrm_vi_attr_set_ps_buffer_size(&attr, ps_buf_size);

  in_flags = alloc_in->flags | EFHW_VI_JUMBO_EN;
  if( rmpd != NULL && efrm_pd_stack_id_get(rmpd) > 0 )
    in_flags |= EFHW_VI_TX_LOOPBACK;

  rc = vi_resource_alloc(&attr, client, evq ? efrm_vi(evq) : NULL,
                         in_flags,
                         alloc_in->evq_capacity,
                         alloc_in->txq_capacity, alloc_in->rxq_capacity,
                         alloc_in->tx_q_tag, alloc_in->rx_q_tag,
                         &virs);
  CI_DEBUG(alloc_in = NULL);
  if( client != NULL )
    efrm_client_put(client);
  if (evq != NULL) {
    efrm_resource_release(evq);
    evq = NULL;
  }
  if (vi_set != NULL) {
    efrm_resource_release(vi_set);
    vi_set = NULL;
  }
  if (pd != NULL) {
    efrm_resource_release(pd);
    pd = NULL;
  }
  if (rc != 0)
    goto fail3;

  efch_filter_list_init(&rs->vi.fl);
  rs->vi.sniff_flags = 0;

  /* Initialise the outputs. */
  alloc_out = &alloc->u.vi_out;
  CI_DEBUG(alloc = NULL);
  CI_DEBUG(alloc_in = NULL);

  nic = efrm_client_get_nic(virs->rs.rs_client);
  alloc_out->instance = virs->rs.rs_instance;
  alloc_out->evq_capacity = virs->q[EFHW_EVQ].capacity;
  alloc_out->rxq_capacity = virs->q[EFHW_RXQ].capacity;
  alloc_out->txq_capacity = virs->q[EFHW_TXQ].capacity;
  alloc_out->nic_arch = nic->devtype.arch;
  alloc_out->nic_variant = nic->devtype.variant;
  alloc_out->nic_revision = nic->devtype.revision;
  alloc_out->nic_flags = efhw_vi_nic_flags(nic);
  if (nic->devtype.arch == EFHW_ARCH_AF_XDP)
    alloc_out->io_mmap_bytes = 0;
  else
    alloc_out->io_mmap_bytes = 4096;
  alloc_out->mem_mmap_bytes = efhw_page_map_bytes(&virs->mem_mmap);
  alloc_out->rx_prefix_len = virs->rx_prefix_len;
  alloc_out->out_flags = virs->out_flags;
  alloc_out->out_flags |= EFHW_VI_PS_BUF_SIZE_SET;
  alloc_out->ps_buf_size = virs->ps_buf_size;

  rs->rs_base = &virs->rs;
  EFCH_TRACE("%s: Allocated "EFRM_RESOURCE_FMT" rc=%d", __FUNCTION__,
             EFRM_RESOURCE_PRI_ARG(&virs->rs), rc);
  return 0;

 fail3:
  if (vi_set != NULL)
    efrm_resource_release(vi_set);
  if (pd != NULL)
    efrm_resource_release(pd);
 fail2:
  if (evq != NULL)
    efrm_resource_release(evq);
 fail1:
  return rc;
}


void efch_vi_rm_free(efch_resource_t *rs)
{
  struct efrm_vi *virs = efrm_vi(rs->rs_base);
  if( virs->evq_callback_fn != NULL )
    efrm_eventq_kill_callback(virs);
  efch_filter_list_free(rs->rs_base, efrm_vi_get_pd(virs), &rs->vi.fl);
  /* Remove any sniff config we may have set up. */
  if( rs->vi.sniff_flags & EFCH_RX_SNIFF )
    efrm_port_sniff(rs->rs_base, 0, 0, -1);
  if( rs->vi.sniff_flags & EFCH_TX_SNIFF )
    efrm_tx_port_sniff(rs->rs_base, 0, -1);
  efrm_vi_tx_alt_free(virs);
}


/*** Resource operations *************************************************/

static void
efrm_eventq_put(struct efrm_vi* virs, ci_resource_op_t* op)
{
  struct efhw_nic *nic;
  efhw_event_t ev;
  nic = efrm_client_get_nic(virs->rs.rs_client);

  ev.u64 = op->u.evq_put.ev;
  EFCH_TRACE("efrm_eventq_put: nic "EFRM_RESOURCE_FMT" "EF10_EVENT_FMT,
             EFRM_RESOURCE_PRI_ARG(&virs->rs), EF10_EVENT_PRI_ARG(ev));
  efhw_nic_sw_event(nic, ev.opaque.a, virs->rs.rs_instance);
}


static int efab_vi_get_mtu(struct efrm_vi* virs, unsigned* mtu_out)
{
  struct efhw_nic* nic;
  nic = efrm_client_get_nic(virs->rs.rs_client);
  *mtu_out = nic->mtu;
  return 0;
}


static int efab_vi_get_mac(struct efrm_vi* virs, void* mac_out)
{
  struct efhw_nic* nic;
  nic = efrm_client_get_nic(virs->rs.rs_client);
  memcpy(mac_out, nic->mac_addr, 6);
  return 0;
}


static int efch_vi_get_rx_error_stats(struct efrm_vi* virs,
                                      void* data, size_t data_len,
                                      int do_reset)
{
  return efrm_vi_get_rx_error_stats(virs, data, data_len, do_reset);
}


static int efch_vi_tx_alt_alloc(struct efrm_vi* virs, ci_resource_op_t* op)
{
  int i, rc, num_alts = op->u.vi_tx_alt_alloc_in.num_alts;
  const int max_alts = ( sizeof(op->u.vi_tx_alt_alloc_out.alt_ids) / 
                         sizeof(op->u.vi_tx_alt_alloc_out.alt_ids[0]) );
  if( num_alts > max_alts )
    return -EBUSY;

  rc = efrm_vi_tx_alt_alloc(virs, num_alts,
                            op->u.vi_tx_alt_alloc_in.buf_space_32b);
  if( rc < 0 )
    return rc;

  for( i = 0; i < num_alts; ++i )
    op->u.vi_tx_alt_alloc_out.alt_ids[i] = virs->tx_alt_ids[i];
  return 0;
}

static int efch_vi_tx_alt_free(struct efrm_vi* virs, ci_resource_op_t* op)
{
  return efrm_vi_tx_alt_free(virs);
}


static void efch_vi_flush_complete(void *completion_void)
{
  complete((struct completion *)completion_void);
}


static int
efch_vi_rm_rsops(efch_resource_t* rs, ci_resource_table_t* rt,
                 ci_resource_op_t* op, int* copy_out)
{
  struct efrm_vi *virs = efrm_vi(rs->rs_base);
  struct completion flush_completion;
  ci_timeval_t tv;

  int rc;
  switch(op->op) {
    case CI_RSOP_EVENTQ_PUT:
      efrm_eventq_put(virs, op);
      rc = 0;
      break;

    case CI_RSOP_EVENTQ_WAIT:
      tv.tv_sec = op->u.evq_wait.timeout.tv_sec;
      tv.tv_usec = op->u.evq_wait.timeout.tv_usec;
      rc = efab_vi_rm_eventq_wait(virs, op->u.evq_wait.current_ptr, &tv);
      op->u.evq_wait.timeout.tv_sec = tv.tv_sec;
      op->u.evq_wait.timeout.tv_usec = tv.tv_usec;
      *copy_out = 1;
      break;

    case CI_RSOP_VI_GET_MTU: {
      unsigned mtu;
      rc = efab_vi_get_mtu(virs, &mtu);
      op->u.vi_get_mtu.out_mtu = mtu;
      *copy_out = 1;
      break;
    }

    case CI_RSOP_VI_GET_MAC:
      rc = efab_vi_get_mac(virs, op->u.vi_get_mac.out_mac);
      *copy_out = 1;
      break;

    case CI_RSOP_VI_GET_RX_TS_CORRECTION:
      op->u.vi_rx_ts_correction.out_rx_ts_correction =
        efrm_client_get_nic(virs->rs.rs_client)->rx_ts_correction;
      rc = 0;
      *copy_out = 1;
      break;

    case CI_RSOP_VI_GET_TS_CORRECTION:
      op->u.vi_ts_correction.out_rx_ts_correction =
        efrm_client_get_nic(virs->rs.rs_client)->rx_ts_correction;
      op->u.vi_ts_correction.out_tx_ts_correction =
        efrm_client_get_nic(virs->rs.rs_client)->tx_ts_correction;
      rc = 0;
      *copy_out = 1;
      break;

    case CI_RSOP_PT_ENDPOINT_FLUSH:
      init_completion(&flush_completion);
      efrm_vi_register_flush_callback(virs, &efch_vi_flush_complete,
                                      &flush_completion);
      efrm_pt_flush(virs);
      while(wait_for_completion_timeout(&flush_completion, HZ) == 0)
        ci_log("%s: still waiting for flush to complete", __FUNCTION__);
      rc = 0;
      break;

    case CI_RSOP_PT_SNIFF:
      rc = efrm_port_sniff(rs->rs_base, op->u.pt_sniff.enable,
                           op->u.pt_sniff.promiscuous, -1);
      if( rc == 0 && op->u.pt_sniff.enable )
        rs->vi.sniff_flags |= EFCH_RX_SNIFF;
      else if( rc == 0 && !op->u.pt_sniff.enable )
        rs->vi.sniff_flags &= ~EFCH_RX_SNIFF;
      break;

    case CI_RSOP_TX_PT_SNIFF:
      {
        int enable = op->u.tx_pt_sniff.enable & EFCH_TX_SNIFF_ENABLE;
        rc = efrm_tx_port_sniff(rs->rs_base, enable, -1);
        if( rc == 0 && enable )
          rs->vi.sniff_flags |= EFCH_TX_SNIFF;
        else if( rc == 0 && !enable )
          rs->vi.sniff_flags &= ~EFCH_TX_SNIFF;
      }
      break;

    case CI_RSOP_FILTER_BLOCK_KERNEL:
      rc = efch_filter_list_op_block(rs->rs_base, efrm_vi_get_pd(virs),
                                     &rs->vi.fl, op);
      break;

    case CI_RSOP_FILTER_DEL:
      rc = efch_filter_list_op_del(rs->rs_base, efrm_vi_get_pd(virs),
                                   &rs->vi.fl, op);
      break;

    case CI_RSOP_VI_GET_RX_ERROR_STATS:
      {
        size_t data_len = op->u.vi_stats.data_len;
        void *user_data = (void *)(unsigned long)op->u.vi_stats.data_ptr;
        void *data = kmalloc(data_len, GFP_KERNEL);
    
        if( data == NULL )
          return -ENOMEM;
        memset(data, 0, data_len);
        rc = efch_vi_get_rx_error_stats(virs, data, data_len,
                                        op->u.vi_stats.do_reset);
        if( rc != 0 ) {
          kfree(data);
          break;
        }
        if( copy_to_user(user_data, data, data_len) )
          rc = -EFAULT;
        kfree(data);
        break;
      }

    case CI_RSOP_VI_TX_ALT_ALLOC:
      rc = efch_vi_tx_alt_alloc(virs, op);
      *copy_out = 1;
      break;

    case CI_RSOP_VI_TX_ALT_FREE:
      rc = efch_vi_tx_alt_free(virs, op);
      break;

    case CI_RSOP_VI_GET_TS_FORMAT:
      op->u.vi_ts_format.out_ts_format =
        efrm_client_get_nic(virs->rs.rs_client)->ts_format;
      rc = 0;
      *copy_out = 1;
      break;

    default:
      rc = efch_filter_list_op_add(rs->rs_base, efrm_vi_get_pd(virs),
                                   &rs->vi.fl, op, copy_out, 0u, -1);
      break;
  }
  return rc;
}


/*** Resource manager methods ********************************************/

static int efch_vi_rm_mmap(struct efrm_resource *rs, unsigned long *bytes,
                           struct vm_area_struct *vma, int index)
{
  int map_num = 0;
  unsigned long offset = 0;
  return efab_vi_resource_mmap(efrm_vi(rs), bytes, vma,
                               &map_num, &offset, index);
}


static struct page*
efch_vi_rm_nopage(struct efrm_resource *rs, struct vm_area_struct *vma,
                  unsigned long offset, unsigned long map_size)
{
  return efab_vi_resource_nopage(efrm_vi(rs), vma, offset, map_size);
}


static int efch_vi_rm_mmap_bytes(struct efrm_resource* rs, int map_type)
{
  return efab_vi_resource_mmap_bytes(efrm_vi(rs), map_type);
}


int efch_vi_filter_add(efch_resource_t* rs, ci_filter_add_t* filter_add,
                       int* copy_out)
{
  struct efrm_vi* virs = efrm_vi(rs->rs_base);

  return efch_filter_list_add(rs->rs_base, efrm_vi_get_pd(virs), &rs->vi.fl,
                              filter_add, copy_out);
}


efch_resource_ops efch_vi_ops = {
  .rm_alloc = efch_vi_rm_alloc,
  .rm_free = efch_vi_rm_free,
  .rm_mmap = efch_vi_rm_mmap,
  .rm_nopage = efch_vi_rm_nopage,
  .rm_dump = efch_vi_rm_dump,
  .rm_rsops = efch_vi_rm_rsops,
  .rm_mmap_bytes = efch_vi_rm_mmap_bytes,
};

