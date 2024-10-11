/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */

#include <ci/efrm/efrm_client.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/efct.h>
#include <ci/efhw/eventq.h>
#include <ci/tools/sysdep.h>

#include "linux_resource_internal.h"
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/rwsem.h>
#include <linux/hugetlb.h>
#include <uapi/linux/ip.h>
#include "efrm_internal.h"
#include <ci/driver/kernel_compat.h>
#include <ci/driver/ci_efct.h>
#include <ci/tools/bitfield.h>
#include <kernel_utils/hugetlb.h>

#include "efct_superbuf.h"
#include "debugfs.h"

#if CI_HAVE_EFCT_AUX

/* EFCT TODO: enhance aux API to provide an extra cookie for this stuff so we
 * can get rid of this global variable filth */
static DEFINE_MUTEX(efct_hugetlb_provision_mtx);
static struct oo_hugetlb_allocator *efct_hugetlb_alloc = NULL;

void efct_provide_hugetlb_alloc(struct oo_hugetlb_allocator *hugetlb_alloc)
{
  mutex_lock(&efct_hugetlb_provision_mtx);
  efct_hugetlb_alloc = hugetlb_alloc;
}

void efct_unprovide_hugetlb_alloc(void)
{
  efct_hugetlb_alloc = NULL;
  mutex_unlock(&efct_hugetlb_provision_mtx);
}

static bool seq_lt(uint32_t a, uint32_t b)
{
  return (int32_t)(a - b) < 0;
}

static uint32_t make_pkt_seq(unsigned sbseq, unsigned pktix)
{
  return (sbseq << 16) | pktix;
}

static int do_wakeup(struct efhw_nic_efct *efct, struct efhw_efct_rxq *app,
                     int budget)
{
  return efct->nic->ev_handlers->wakeup_fn(efct->nic, app->wakeup_instance,
                                           budget);
}

static void efct_reset_down(struct efhw_nic_efct *efct)
{
  struct efhw_nic *nic = efct->nic;

  EFRM_NOTICE("%s: %s", __func__, dev_name(nic->dev));

  efrm_nic_reset_suspend(efct->nic);
  ci_atomic32_or(&efct->nic->resetting, NIC_RESETTING_FLAG_RESET);
}

static void efct_reset_up(struct efhw_nic_efct *efct, bool success)
{
  struct efhw_nic *nic = efct->nic;

  EFRM_NOTICE("%s: %s success=%d", __func__, dev_name(nic->dev), success);

  /* TODO EFCT Add support for ef_vi reset injection */
  efrm_nic_flush_all_queues(nic, EFRM_FLUSH_QUEUES_F_NOHW);

  if( success )
    nic->resetting = 0;

  efhw_nic_post_reset(nic);
  efrm_nic_post_reset(nic);
}

static int efct_handle_event(void *driver_data,
                             const struct xlnx_efct_event *event, int budget)
{
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) driver_data;

  /* Check we actually have a nic to act on before proceeding. */
  if( ! efct->nic )
    return 0;

  switch( event->type ) {
    case XLNX_EVENT_WAKEUP: {
      struct efhw_nic_efct_rxq* q = &efct->rxq[event->rxq];
      struct efhw_efct_rxq *app;
      unsigned sbseq = event->value >> 32;
      unsigned pktix = event->value & 0xffffffff;
      uint32_t now = make_pkt_seq(sbseq, pktix);
      int spent = 0;

      CI_WRITE_ONCE(q->now, now);
      ci_mb();
      if( CI_READ_ONCE(q->awaiters) == 0 )
        return 0;

      for( app = q->live_apps; app; app = app->next ) {
        uint32_t wake_at = CI_READ_ONCE(app->wake_at_seqno);
        if( wake_at != EFCT_INVALID_PKT_SEQNO && seq_lt(wake_at, now) ) {
          if( ci_cas32_succeed(&app->wake_at_seqno, wake_at, EFCT_INVALID_PKT_SEQNO) ) {
            int rc;
            ci_atomic32_dec(&q->awaiters);
            rc = do_wakeup(efct, app, budget - spent);
            if( rc >= 0 )
              spent += rc;
          }
        }
      }
      return spent;
    }

    case XLNX_EVENT_TIME_SYNC: {
      struct efhw_nic_efct_rxq* q = &efct->rxq[event->rxq];
      struct efhw_efct_rxq *app;
      int spent = 0;

      q->time_sync = event->value;
      for( app = q->live_apps; app; app = app->next ) {
        CI_WRITE_ONCE(app->shm->time_sync, event->value);
        spent += 1;
      }
      return spent;
    }

    case XLNX_EVENT_RESET_DOWN:
      efct_reset_down(efct);
      break;
    case XLNX_EVENT_RESET_UP:
      efct_reset_up(efct, event->value);
      break;
    case XLNX_EVENT_RX_FLUSH:
      return -ENOSYS;
  }
  return -ENOSYS;
}

int efct_request_wakeup(struct efhw_nic_efct *efct, struct efhw_efct_rxq *app,
                        unsigned sbseq, unsigned pktix, bool allow_recursion)
{
  struct efhw_nic_efct_rxq* q = &efct->rxq[app->qid];
  uint32_t pkt_seqno = make_pkt_seq(sbseq, pktix);
  uint32_t now = CI_READ_ONCE(q->now);

  EFHW_ASSERT(pkt_seqno != EFCT_INVALID_PKT_SEQNO);
  /* Interrupt wakeups are traditionally defined simply by equality, but we
   * need to use proper ordering because apps can run significantly ahead of
   * the net driver due to interrupt coalescing, and it'd be contrary to the
   * goal of being interrupt-driven to spin entering and exiting the kernel
   * for an entire coalesce period */
  if( seq_lt(pkt_seqno, now) ) {
    if( allow_recursion )
      do_wakeup(efct, app, 0);
    return -EAGAIN;
  }

  if( ci_xchg32(&app->wake_at_seqno, pkt_seqno) == EFCT_INVALID_PKT_SEQNO )
    ci_atomic32_inc(&q->awaiters);

  ci_mb();
  now = CI_READ_ONCE(q->now);
  if( ! seq_lt(pkt_seqno, now) )
    return 0;

  if( ci_cas32_succeed(&app->wake_at_seqno, pkt_seqno, EFCT_INVALID_PKT_SEQNO) ) {
    ci_atomic32_dec(&q->awaiters);
    if( allow_recursion )
      do_wakeup(efct, app, 0);
    return -EAGAIN;
  }
  return -EAGAIN;
}

static int efct_alloc_hugepage(void *driver_data,
                               struct xlnx_efct_hugepage *result_out)
{
  /* The rx ring is owned by the net driver, not by us, so it does all
   * DMA handling. We do need to supply it with some memory, though. */
  struct xlnx_efct_hugepage result;
  int rc;

  if( ! efct_hugetlb_alloc ) {
    EFHW_ERR("%s: ERROR: hugetlb allocator not supplied", __func__);
    return -EINVAL;
  }

  rc = oo_hugetlb_page_alloc_raw(efct_hugetlb_alloc,
                                 &result.file, &result.page);
  if( rc ) {
    if( rc != -EINTR )
      EFHW_ERR("%s: ERROR: unable to allocate hugepage for rxq (%d)",
               __func__, rc);
    return rc;
  }

  *result_out = result;

  return 0;
}

static void efct_free_hugepage(void *driver_data,
                               struct xlnx_efct_hugepage *mem)
{
  /* Almost certainly, we are called from the softirq context, e.g. with
   * call_rcu(), so assume the "worst" and disallow non-atomic operations. */
  oo_hugetlb_page_free_raw(mem->file, mem->page, /* atomic_context */ true);
}

static void efct_hugepage_list_changed(void *driver_data, int rxq)
{
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) driver_data;
  struct efhw_nic_efct_rxq *q = &efct->rxq[rxq];
  struct efhw_efct_rxq *app;

  for( app = q->live_apps; app; app = app->next ) {
    if( ! app->destroy ) {
      unsigned new_gen = app->shm->config_generation + 1;
      /* Avoid 0 so that the reader can always use it as a 'not yet initialised'
      * marker. */
      if( new_gen == 0 )
        ++new_gen;
      CI_WRITE_ONCE(app->shm->config_generation, new_gen);
    }
  }
}

bool efct_packet_handled(void *driver_data, int rxq, bool flow_lookup,
                         const void* meta, const void* payload)
{
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) driver_data;
  const unsigned char* pkt = payload;
  const ci_oword_t* header = meta;
  size_t pkt_len = CI_OWORD_FIELD(*header, EFCT_RX_HEADER_PACKET_LENGTH);

  if( pkt_len < ETH_HLEN )
    return false;

  /* This is asserting the next_frame_loc for the wrong packet: we should be
   * looking at the preceeding metadata. Still, having it will probably
   * detect hardware that doesn't use a fixed value fairly rapidly. */
  EFHW_ASSERT(CI_OWORD_FIELD(*header, EFCT_RX_HEADER_NEXT_FRAME_LOC) == 1);
  pkt += EFCT_RX_HEADER_NEXT_FRAME_LOC_1;

  return efct_packet_matches_filter(&efct->filter_state, efct->nic->net_dev, rxq,
                                    pkt, pkt_len);
}

struct xlnx_efct_drvops efct_ops = {
  .name = "sfc_resource",
  .poll = efct_poll,
  .handle_event = efct_handle_event,
  .buffer_start = efct_buffer_start,
  .buffer_end = efct_buffer_end,
  .alloc_hugepage = efct_alloc_hugepage,
  .free_hugepage = efct_free_hugepage,
  .hugepage_list_changed = efct_hugepage_list_changed,
  .packet_handled = efct_packet_handled,
};


static int efct_devtype_init(struct xlnx_efct_device *edev,
                             struct xlnx_efct_client *client,
                             struct efhw_device_type *dev_type)
{
  union xlnx_efct_param_value val;
  int rc;

  dev_type->arch = EFHW_ARCH_EFCT;
  dev_type->function = EFHW_FUNCTION_PF;

  rc = edev->ops->get_param(client, XLNX_EFCT_VARIANT, &val);
  if( rc < 0 )
    return rc;
  dev_type->variant = val.variant;

  rc = edev->ops->get_param(client, XLNX_EFCT_REVISION, &val);
  if( rc < 0 )
    return rc;
  dev_type->revision = val.value;

  return 0;
}

static int efct_resource_init(struct xlnx_efct_device *edev,
                              struct xlnx_efct_client *client,
                              struct efhw_nic_efct *efct,
                              struct vi_resource_dimensions *res_dim)
{
  union xlnx_efct_param_value val;
  int rc;
  int i;
  int n_txqs;

  rc = edev->ops->get_param(client, XLNX_EFCT_DESIGN_PARAM, &val);
  if( rc < 0 )
    return rc;

  rc = efct_filter_state_init(&efct->filter_state, &val.design_params);
  if( rc < 0 )
    return rc;

  efct->rxq_n = val.design_params.rx_queues;
  efct->rxq = vzalloc(sizeof(*efct->rxq) * efct->rxq_n);
  if( ! efct->rxq )
    return -ENOMEM;

  for( i = 0; i < efct->rxq_n; ++i)
    INIT_WORK(&efct->rxq[i].destruct_wq, efct_destruct_apps_work);

  res_dim->efhw_ops = &efct_char_functional_units;

  rc = edev->ops->get_param(client, XLNX_EFCT_NIC_RESOURCES, &val);
  if( rc < 0 )
    return rc;

  efct->evq_n = val.nic_res.evq_lim;
  efct->evq = kzalloc(sizeof(*efct->evq) * efct->evq_n, GFP_KERNEL);
  if( ! efct->evq )
    return -ENOMEM;

  res_dim->vi_min = val.nic_res.evq_min;
  res_dim->vi_lim = CI_EFCT_EVQ_DUMMY_MAX;
  res_dim->mem_bar = VI_RES_MEM_BAR_UNDEFINED;

  for( i = 0; i < efct->evq_n; i++ )
    efct->evq[i].txq = EFCT_EVQ_NO_TXQ;

  n_txqs = val.nic_res.txq_lim - val.nic_res.txq_min;
  for( i = 0; i < n_txqs && val.nic_res.evq_min + i < val.nic_res.evq_lim; ++i )
    efct->evq[val.nic_res.evq_min + i].txq = val.nic_res.txq_min + i;

  rc = edev->ops->get_param(client, XLNX_EFCT_IRQ_RESOURCES, &val);
  if( rc < 0 )
    return rc;

  res_dim->irq_n_ranges = val.irq_res->n_ranges;
  EFRM_ASSERT(res_dim->irq_n_ranges <= IRQ_N_RANGES_MAX);
  for( i = 0; i < res_dim->irq_n_ranges; i++ ) {
      res_dim->irq_ranges[i].irq_base = val.irq_res->irq_ranges[i].vector;
      res_dim->irq_ranges[i].irq_range = val.irq_res->irq_ranges[i].range;
  }

  res_dim->irq_prime_reg = val.irq_res->int_prime;

  return 0;
}

static int efct_vi_allocator_ctor(struct efhw_nic_efct *nic,
                                  struct vi_resource_dimensions *res_dim)
{
  int rc = 0;
  /* tx vis are allocated in the range [res_dim->vi_min,efct->evq_n)
   * The space above this is used for virtual rx vis */
  rc = efhw_stack_vi_allocator_ctor(&nic->vi_allocator.tx, res_dim->vi_min, nic->evq_n);
  if(rc < 0)
    goto fail1;
  rc = efhw_stack_vi_allocator_ctor(&nic->vi_allocator.rx, nic->evq_n, res_dim->vi_lim);
  if(rc < 0)
    goto fail2;
  return rc;

 fail2:
  efhw_stack_vi_allocator_dtor(&nic->vi_allocator.tx);
 fail1:
  if (rc < 0) {
    EFRM_ERR("%s: efct_vi_allocator_ctor(%d, %d) "
              "failed (%d)",
              __FUNCTION__, res_dim->vi_min, res_dim->vi_lim, rc);
  }
  return rc;
}

static void efct_vi_allocator_dtor(struct efhw_nic_efct *nic)
{
  efhw_stack_vi_allocator_dtor(&nic->vi_allocator.tx);
  efhw_stack_vi_allocator_dtor(&nic->vi_allocator.rx);
}

int efct_probe(struct auxiliary_device *auxdev,
               const struct auxiliary_device_id *id)
{
  struct xlnx_efct_device *edev = to_xlnx_efct_device(auxdev);
  struct vi_resource_dimensions res_dim = {};
  struct efhw_device_type dev_type;
  struct xlnx_efct_client *client;
  union xlnx_efct_param_value val;
  struct linux_efhw_nic *lnic = NULL;
  struct net_device *net_dev;
  struct efhw_nic *nic;
  struct efhw_nic_efct *efct = NULL;
  int rc;

  EFRM_NOTICE("%s name %s version %#x", __func__, id->name, edev->version);

  if( edev->version >> 16 != XLNX_EFCT_AUX_VERSION >> 16 ) {
    EFRM_ERR("%s: incompatible efct driver: have %#x want %#x",
             __func__, edev->version, XLNX_EFCT_AUX_VERSION);
    return -EPROTOTYPE;
  }

  efct = vzalloc(sizeof(*efct));
  if( ! efct )
    return -ENOMEM;

  efct->edev = edev;

  /* As soon as we've opened the handle we can start getting callbacks through
   * our supplied efct_ops. Most of these will only occur once we've actually
   * attached to an RXQ, however handle_event can start happening straight
   * away. To avoid trying to use a device we will check in that function
   * whether efct->nic is initted, which is our final step of init. This
   * occurs with the rtnl lock held, which is also held for the suspend/resume
   * ops which require us to use it. */
  client = edev->ops->open(auxdev, &efct_ops, efct);
  if( IS_ERR(client) ) {
    rc = PTR_ERR(client);
    goto fail1;
  }
  efct->client = client;

  rc = edev->ops->get_param(client, XLNX_EFCT_NETDEV, &val);
  if( rc < 0 )
    goto fail2;

  net_dev = val.net_dev;
  EFRM_NOTICE("%s probe of dev %s", __func__, net_dev->name);

  if( efhw_nic_find(net_dev) ) {
    EFRM_TRACE("%s: netdev %s already registered", __func__, net_dev->name);
    rc = -EBUSY;
    goto fail2;
  }

  rc = efct_devtype_init(edev, client, &dev_type);
  if( rc < 0 )
    goto fail2;

  rc = efct_resource_init(edev, client, efct, &res_dim);
  if( rc < 0 )
    goto fail2;

  rc = efct_vi_allocator_ctor(efct, &res_dim);
  if( rc < 0 )
    goto fail2;

  rtnl_lock();
  rc = efrm_nic_add(client, &auxdev->dev, &dev_type, net_dev, &lnic,
                    &res_dim, 0);
  if( rc < 0 )
    goto fail3;

  nic = &lnic->efrm_nic.efhw_nic;
  nic->mtu = net_dev->mtu + ETH_HLEN;
  nic->arch_extra = efct;

  /* Setting the nic here marks the device as ready for use. */
  efct->nic = nic;

  efrm_notify_nic_probe(nic, net_dev);
  rtnl_unlock();

  efhw_init_debugfs_efct(nic);

  return 0;

 fail3:
  rtnl_unlock();
  efct_vi_allocator_dtor(efct);
 fail2:
  edev->ops->close(client);
 fail1:
  efct_filter_state_free(&efct->filter_state);
  if( efct->rxq )
    vfree(efct->rxq);
  if( efct->evq )
    kfree(efct->evq);
  vfree(efct);
  EFRM_ERR("%s rc %d", __func__, rc);
  return rc;
}

void efct_remove(struct auxiliary_device *auxdev)
{
  struct xlnx_efct_device *edev = to_xlnx_efct_device(auxdev);
  struct xlnx_efct_client *client;
  struct linux_efhw_nic *lnic;
  struct efhw_nic* nic;
  struct efhw_nic_efct *efct;
  int i;

  EFRM_TRACE("%s: %s", __func__, dev_name(&auxdev->dev));

  nic = efhw_nic_find_by_dev(&auxdev->dev);
  if( !nic )
    return;

  efhw_fini_debugfs_efct(nic);

  lnic = linux_efhw_nic(nic);
  client = (struct xlnx_efct_client*)lnic->drv_device;
  if( !client )
    return;

  efct = nic->arch_extra;
  for( i = 0; i < efct->rxq_n; ++i ) {
    /* All workqueues should be already shut down by now, but it may happen
     * that the final efct_poll() did not happen.  Do it now. */
    efct_poll(efct, i, 0);
  }
  drain_workqueue(system_wq);

  /* Now any destruct work items we queued as a result of the final poll have
   * been drained, so everything should be gone. */
  for( i = 0; i < efct->rxq_n; ++i ) {
    EFHW_ASSERT(efct->rxq[i].live_apps == NULL);
    EFHW_ASSERT(efct->rxq[i].new_apps == NULL);
  }

  rtnl_lock();
  efrm_notify_nic_remove(nic);

  /* flush all outstanding dma queues */
  efrm_nic_flush_all_queues(nic, 0);

  lnic->drv_device = NULL;
  /* Wait for all in-flight driverlink calls to finish.  Since we
   * have already cleared [lnic->drv_device], no new calls can
   * start. */
  efhw_nic_flush_drv(nic);
  efrm_nic_unplug_hard(nic);

  /* Absent hardware is treated as a protracted reset. */
  efrm_nic_reset_suspend(nic);
  ci_atomic32_or(&nic->resetting, NIC_RESETTING_FLAG_UNPLUGGED);
  rtnl_unlock();

  efct_vi_allocator_dtor(efct);
  /* mind we might still expect callbacks from close() context
   * TODO: rethink where to call close and how to synchronise with
   * the rest. */
  edev->ops->close(client);
  efct_filter_state_free(&efct->filter_state);
  vfree(efct->rxq);
  kfree(efct->evq);
  vfree(efct);
  nic->arch_extra = NULL;
}


static const struct auxiliary_device_id efct_id_table[] = {
  { .name = "xilinx_efct." XLNX_EFCT_DEVNAME, },
  {},
};
MODULE_DEVICE_TABLE(auxiliary, efct_id_table);


struct auxiliary_driver efct_drv = {
  .name = "xilinx_efct",
  .probe = efct_probe,
  .remove = efct_remove,
  .id_table = efct_id_table,
};

#endif
