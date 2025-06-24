/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#include <ci/driver/kernel_compat.h>
#include <ci/driver/ci_ef10ct.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/ef10ct.h>
#include <ci/efhw/efct_filters.h>
#include <ci/efhw/iopage.h>
#include <lib/efhw/aux.h>

#include "linux_resource_internal.h"
#include "efrm_internal.h"
#include "debugfs.h"

#if CI_HAVE_EF10CT

static void ef10ct_reset_suspend(struct efx_auxdev_client * client,
                                 struct efhw_nic *nic)
{
  EFRM_NOTICE("%s: %s", __func__, dev_name(&client->auxdev->auxdev.dev));

  efrm_nic_reset_suspend(nic);
  ci_atomic32_or(&nic->resetting, NIC_RESETTING_FLAG_RESET);
}


static void ef10ct_handle_reset(struct efx_auxdev_client *client,
                                struct efhw_nic *nic, int result)
{
  switch(result) {
    case EFX_IN_RESET:
      ef10ct_reset_suspend(client, nic);
      break;
    case EFX_NOT_IN_RESET:
      EFRM_ERR("%s: WARNING: %s post reset resume not supported", __func__,
               dev_name(&client->auxdev->auxdev.dev));
      break;
    case EFX_HARDWARE_DISABLED:
      /* We treat this in the same way as if the NIC never came back, by
       * just ignoring it. */
      EFRM_ERR("%s: ERROR: %s not available post reset", __func__,
               dev_name(&client->auxdev->auxdev.dev));
      break;
    default:
      EFRM_ERR("%s: ERROR: Unknown result %d for dev %s post reset", __func__,
               result, dev_name(&client->auxdev->auxdev.dev));
      break;
  };
}


static int ef10ct_handler(struct efx_auxdev_client *client,
                          const struct efx_auxdev_event *event)
{
  union efx_auxiliary_param_value val;
  struct efhw_nic *nic;
  int rc;

  rc = client->auxdev->llct_ops->base_ops->get_param(client, EFX_DRIVER_DATA,
                                                     &val);
  if (rc < 0 )
    return rc;

  nic = (struct efhw_nic*)val.driver_data;
  if( !nic )
    return -ENODEV;

  switch(event->type) {
    case EFX_AUXDEV_EVENT_IN_RESET:
      ef10ct_handle_reset(client, nic, event->value);
      break;
    default:
      /* We should only be getting events we asked for. */
      EFRM_ASSERT(false);
      break;
  };

  /* The return from the handler is ignored in all cases other than a poll,
   * which we don't use, so doesn't really matter what we return here. */
  return 0;
}


static int ef10ct_devtype_init(struct efx_auxdev *edev,
                               struct efx_auxdev_client *client,
                               struct efhw_device_type *dev_type)
{
  union efx_auxiliary_param_value val;
  int rc;

  rc = edev->llct_ops->base_ops->get_param(client, EFX_PCI_DEV_DEVICE, &val);
  if( rc < 0 )
    return rc;
  switch( val.value ) {
   case 0x0c03:
    dev_type->variant = 'A';
    dev_type->function = EFHW_FUNCTION_PF;
    break;
   case 0x1c03:
    dev_type->variant = 'A';
    dev_type->function = EFHW_FUNCTION_VF;
    break;
   default:
    EFRM_ERR("%s: Not binding to llct device %s with unknown device id %x",
             __func__, dev_name(&edev->auxdev.dev), val.value);
    return -ENOTSUPP;
  };

  rc = edev->llct_ops->base_ops->get_param(client, EFX_DEVICE_REVISION, &val);
  if( rc < 0 )
    return rc;
  dev_type->revision = val.value;

  dev_type->arch = EFHW_ARCH_EF10CT;

  return 0;
}


static int ef10ct_resource_init(struct efx_auxdev *edev,
                                struct efx_auxdev_client *client,
                                struct efhw_nic_ef10ct *ef10ct,
                                struct vi_resource_dimensions *res_dim)
{
  union efx_auxiliary_param_value val;
  int rc;
  int i;

  val.design_params = &ef10ct->efx_design_params;
  rc = edev->llct_ops->base_ops->get_param(client, EFX_DESIGN_PARAM, &val);
  if( rc < 0 )
    return rc;

  rc = efct_filter_state_init(&ef10ct->filter_state,
                              ef10ct->efx_design_params.num_filters,
                              ef10ct->efx_design_params.rx_queues);

  res_dim->efhw_ops = &ef10ct_char_functional_units;

  ef10ct->evq_n = ef10ct->efx_design_params.ev_queues;
  ef10ct->evq = vzalloc(sizeof(*ef10ct->evq) * ef10ct->evq_n);
  if( ! ef10ct->evq ) {
    rc = -ENOMEM;
    goto fail;
  }

  res_dim->vi_min = 0;
  res_dim->vi_lim = EF10CT_EVQ_DUMMY_MAX;
  res_dim->mem_bar = VI_RES_MEM_BAR_UNDEFINED;

  for( i = 0; i < ef10ct->evq_n; i++ )
    ef10ct->evq[i].txq = EF10CT_EVQ_NO_TXQ;

  ef10ct->rxq_n = ef10ct->efx_design_params.rx_queues;
  ef10ct->rxq = vzalloc(sizeof(*ef10ct->rxq) * ef10ct->rxq_n);
  if( ! ef10ct->rxq ) {
    rc = -ENOMEM;
    goto fail1;
  }
  for( i = 0; i < ef10ct->rxq_n; i++ ) {
    ef10ct->rxq[i].evq = -1;
    mutex_init(&ef10ct->rxq[i].bind_lock);
  }

  /* Claim we have a single IRQ range so that efrm can pre-allocate memory for
   * tracking irq uses. */
  res_dim->irq_n_ranges = 1;
  res_dim->irq_ranges[0].irq_base = 0;
  res_dim->irq_ranges[0].irq_range = EF10CT_EVQ_DUMMY_MAX;
  xa_init(&ef10ct->irqs);
  mutex_init(&ef10ct->irq_lock);
  rc = edev->llct_ops->base_ops->get_param(client, EFX_AUXILIARY_INT_PRIME,
                                           &val);
  if (rc < 0)
    goto fail2;
  res_dim->irq_prime_reg = val.iomem_addr;

  /* Shared evqs for rx vis. Need at least one for suppressed events */
  /* TODO ON-16670 determine how many more to add for interrupt affinity */
  ef10ct->shared_n = 1;
  ef10ct->shared = vzalloc(sizeof(*ef10ct->shared) * ef10ct->shared_n);
  if( ! ef10ct->shared ) {
    rc = -ENOMEM;
    goto fail2;
  }

  return 0;

fail2:
  mutex_destroy(&ef10ct->irq_lock);
  xa_destroy(&ef10ct->irqs);
  vfree(ef10ct->rxq);
fail1:
  vfree(ef10ct->evq);
fail:
  efct_filter_state_free(&ef10ct->filter_state);
  return rc;
}


static int ef10ct_vi_allocator_ctor(struct efhw_nic_ef10ct *nic,
                                  struct vi_resource_dimensions *res_dim)
{
  /* Use allocator for SW VIs only, using the evq range above that supported
   * by the HW. */
  int rc = efhw_stack_vi_allocator_ctor(&nic->vi_allocator.rx, nic->evq_n,
                                        res_dim->vi_lim);
  if (rc < 0) {
    EFRM_ERR("%s: ef10ct_vi_allocator_ctor(%d, %d) "
              "failed (%d)",
              __FUNCTION__, res_dim->vi_min, res_dim->vi_lim, rc);
  }
  mutex_init(&nic->vi_allocator.lock);
  return rc;
}


static void ef10ct_vi_allocator_dtor(struct efhw_nic_ef10ct *nic)
{
  efhw_stack_allocator_dtor(&nic->vi_allocator.rx);
}

static irqreturn_t ef10ct_irq_handler(int irq, void *dev)
{
  struct ef10ct_shared_kernel_evq *shared_evq = dev;
  struct efhw_nic_ef10ct_evq *evq = shared_evq->evq;

  if (shared_evq->irq != irq)
    return IRQ_NONE;

  schedule_delayed_work(&evq->check_flushes_irq, 0);

  return IRQ_HANDLED;
}

static int ef10ct_init_shared_irq(struct ef10ct_shared_kernel_evq *evq)
{
  /* FIXME ON-16187: Better interrupt naming */
  snprintf(evq->name, sizeof(evq->name), "ef10ct-%d",
           ef10ct_get_queue_num(evq->evq_id));

  return request_irq(evq->irq, ef10ct_irq_handler, 0, evq->name, evq);
}

static void ef10ct_fini_shared_irq(struct ef10ct_shared_kernel_evq *evq)
{
  free_irq(evq->irq, evq);
}

static int ef10ct_nic_init_shared_evq(struct efhw_nic *nic, int qid)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_evq *ef10ct_evq;
  uint page_order = 0; /* TODO: What should the size be? */
  struct efhw_evq_params params = {};
  int evq_id, rc, evq_num;
  struct ef10ct_shared_kernel_evq *shared_evq = &ef10ct->shared[qid];

  evq_id = ef10ct_alloc_evq(nic);
  if(evq_id < 0) {
    rc = evq_id;
    goto fail_alloc_evq;
  }
  evq_num = ef10ct_get_queue_num(evq_id);
  EFHW_ASSERT(evq_num <= ef10ct->evq_n);

  ef10ct_evq = &ef10ct->evq[evq_num];

  rc = efhw_nic_irq_alloc(nic, &shared_evq->channel, &shared_evq->irq);
  if (rc < 0)
    goto fail_alloc_irq;

  shared_evq->evq_id = evq_id;
  shared_evq->evq = &ef10ct->evq[evq_num];

  rc = ef10ct_init_shared_irq(shared_evq);
  if (rc < 0)
    goto fail_init_irq;

  rc = efhw_iopages_alloc(nic, &shared_evq->iopages, page_order, 1, 0);
  if( rc )
    goto fail_iopages_alloc;

  params.evq = evq_num;
  params.n_pages = 1 << page_order;
  params.evq_size = (params.n_pages << PAGE_SHIFT) / sizeof(efhw_event_t);
  params.dma_addrs = shared_evq->iopages.dma_addrs;
  params.virt_base = shared_evq->iopages.ptr;
  params.wakeup_channel = shared_evq->channel;
  /* Do we care about flags? */

  rc = efhw_nic_event_queue_enable(nic, &params);
  if( rc < 0 )
    goto fail_evq_enable;

  efhw_nic_wakeup_request(nic, NULL, evq_num, 0);

  return 0;

fail_evq_enable:
  efhw_iopages_free(nic, &shared_evq->iopages);
fail_iopages_alloc:
  ef10ct_fini_shared_irq(shared_evq);
fail_init_irq:
  efhw_nic_irq_free(nic, shared_evq->channel, shared_evq->irq);
fail_alloc_irq:
  ef10ct_free_evq(nic, evq_id);
fail_alloc_evq:
  return rc;
}

static void ef10ct_nic_free_shared_evq(struct efhw_nic *nic, int qid)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct ef10ct_shared_kernel_evq *shared_evq;

  EFHW_ASSERT(qid >= 0);
  EFHW_ASSERT(qid < ef10ct->shared_n);
  shared_evq = &ef10ct->shared[qid];

  /* Neither client_id nor time_sync_events_enabled are used for ef10ct */
  efhw_nic_event_queue_disable(nic, ef10ct_get_queue_num(shared_evq->evq_id),
                               0);

  ef10ct_free_evq(nic, shared_evq->evq_id);
  efhw_iopages_free(nic, &shared_evq->iopages);
  ef10ct_fini_shared_irq(shared_evq);
  efhw_nic_irq_free(nic, shared_evq->channel, shared_evq->irq);

  /* Just to be safe */
  memset(shared_evq, 0, sizeof(*shared_evq));

  return;
}

static int ef10ct_probe(struct auxiliary_device *auxdev,
                        const struct auxiliary_device_id *id)
{
  struct efx_auxdev_client *client;
  struct efx_auxdev *edev = to_efx_auxdev(auxdev);
  struct efhw_device_type dev_type;
  struct linux_efhw_nic *lnic = NULL;
  struct efhw_nic *nic;
  struct efhw_nic_ef10ct *ef10ct = NULL;
  struct vi_resource_dimensions res_dim = {};
  union efx_auxiliary_param_value val;
  struct net_device *net_dev;
  int rc, i, shared_n = 0;

  rc = efhw_check_aux_abi_version(edev, id);
  if( rc )
    return rc;

  ef10ct = vzalloc(sizeof(*ef10ct));
  if( ! ef10ct )
    return -ENOMEM;
  ef10ct->edev = edev;

  client = edev->llct_ops->base_ops->open(auxdev, &ef10ct_handler,
                                          BIT(EFX_AUXDEV_EVENT_IN_RESET));

  if( IS_ERR(client) ) {
    rc = PTR_ERR(client);
    EFRM_ERR("%s: Failed to probe %s.%d (%d)", __func__, id->name,
             auxdev->id, rc);
    goto fail1;
  }

  rc = edev->llct_ops->base_ops->get_param(client, EFX_NETDEV, &val);
  if( rc < 0 )
    goto fail2;

  net_dev = val.net_dev;
  EFRM_NOTICE("%s probe of dev %s as %s.%d ", __func__, net_dev->name,
              id->name, auxdev->id);

  rc = ef10ct_devtype_init(edev, client, &dev_type);
  if( rc < 0 )
    goto fail2;

  rc = ef10ct_resource_init(edev, client, ef10ct, &res_dim);
  if( rc < 0 )
    goto fail2;

  rc = ef10ct_vi_allocator_ctor(ef10ct, &res_dim);
  if( rc < 0 )
    goto fail2;

  rtnl_lock();
  rc = efrm_nic_create(client, &auxdev->dev, &dev_type, net_dev, &lnic,
                       &res_dim, 0);
  if( rc < 0 )
    goto fail3;

  nic = &lnic->efrm_nic.efhw_nic;
  nic->mtu = net_dev->mtu + ETH_HLEN;
  nic->arch_extra = ef10ct;

  /* Init shared evqs for use with rx vis. */
  for( i = 0; i < ef10ct->shared_n; i++ ) {
    rc = ef10ct_nic_init_shared_evq(nic, i);
    if( rc < 0 ) {
      shared_n = i;
      goto fail4;
    }
  }

  shared_n = ef10ct->shared_n;

  rc = efrm_nic_register(lnic);
  if( rc < 0 )
    goto fail4;

  /* Setting the nic here marks the device as ready for use. */
  ef10ct->nic = nic;

  val.driver_data = nic;
  rc = edev->llct_ops->base_ops->set_param(client, EFX_DRIVER_DATA, &val);
  /* The only reason this can fail is if we're using an invalid handle, which
   * we're not. */
  EFRM_ASSERT(rc == 0);

  efrm_notify_nic_probe(nic, net_dev);
  rtnl_unlock();

  efhw_init_debugfs_ef10ct(nic);

  return 0;

 fail4:
  /* Cleanup evqs in range [0..shared_n) where shared_n <= ef10ct->shared_n. */
  for( i = 0; i < shared_n; i++ )
    ef10ct_nic_free_shared_evq(nic, i);

  efrm_nic_destroy(lnic);
 fail3:
  rtnl_unlock();
  ef10ct_vi_allocator_dtor(ef10ct);
 fail2:
  edev->llct_ops->base_ops->close(client);
 fail1:
  vfree(ef10ct);
  EFRM_ERR("%s rc %d", __func__, rc);
  return rc;
}


void ef10ct_remove(struct auxiliary_device *auxdev)
{
  struct efx_auxdev *edev = to_efx_auxdev(auxdev);
  struct efx_auxdev_client *client;
  struct efhw_nic_ef10ct *ef10ct;
  struct efx_auxdev_irq *entry;
  struct linux_efhw_nic *lnic;
  struct efhw_nic* nic;
  unsigned long index;
  int i;

  EFRM_TRACE("%s: %s", __func__, dev_name(&auxdev->dev));

  nic = efhw_nic_find_by_dev(&auxdev->dev);
  if( !nic )
    return;

  efhw_fini_debugfs_ef10ct(nic);

  lnic = linux_efhw_nic(nic);
  client = (struct efx_auxdev_client*)lnic->drv_device;
  if( !client )
    return;

  ef10ct = nic->arch_extra;

  rtnl_lock();
  efrm_notify_nic_remove(nic);

  /* flush all outstanding dma queues */
  efrm_nic_flush_all_queues(nic, 0);

  /* Disable/free all shared evqs. We do this even in the case that the NIC
   * is being reset, as some of the resources here are host side, such as
   * dma mappings and the os irq. */
  for(i = 0; i < ef10ct->shared_n; i++)
    ef10ct_nic_free_shared_evq(nic, i);

  /* Free any remaining irqs */
  xa_for_each(&ef10ct->irqs, index, entry) {
    if (!entry)
      continue;
    edev->llct_ops->irq_free(client, entry);
  }

  xa_destroy(&ef10ct->irqs);
  mutex_destroy(&ef10ct->irq_lock);

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

  ef10ct_vi_allocator_dtor(ef10ct);
  /* mind we might still expect callbacks from close() context
   * TODO ON-16689 rethink where to call close and how to synchronise with
   * the rest. */
  edev->llct_ops->base_ops->close(client);

  efct_filter_state_free(&ef10ct->filter_state);

  /* iounmap the superbuf post registers */
  for (i = 0; i < ef10ct->rxq_n; i++)
    if (ef10ct->rxq[i].post_buffer_addr != NULL)
      iounmap(ef10ct->rxq[i].post_buffer_addr);

  vfree(ef10ct->evq);
  vfree(ef10ct->rxq);
  vfree(ef10ct->shared);
  vfree(ef10ct);
  nic->arch_extra = NULL;
}


static const struct auxiliary_device_id ef10ct_id_table[] = {
  { .name = "sfc." EFX_LLCT_DEVNAME, },
  { .name = "efct_test." EFX_LLCT_DEVNAME ".test", },
  {},
};
MODULE_DEVICE_TABLE(auxiliary, ef10ct_id_table);


struct auxiliary_driver ef10ct_drv = {
  .name = "ef10ct",
  .probe = ef10ct_probe,
  .remove = ef10ct_remove,
  .id_table = ef10ct_id_table,
};

#endif
