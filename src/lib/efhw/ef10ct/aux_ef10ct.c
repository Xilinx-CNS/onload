/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#include <ci/driver/kernel_compat.h>
#include <ci/driver/ci_ef10ct.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/ef10ct.h>
#include <ci/efhw/efct_filters.h>

#include "linux_resource_internal.h"
#include "efrm_internal.h"
#include "debugfs.h"

#if CI_HAVE_EF10CT

static int ef10ct_handler(struct efx_auxdev_client *client,
                        const struct efx_auxdev_event *event)
{
  EFRM_TRACE("%s", __func__);
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
   case 0xffff:
    /* This is the test device provided via the efct_test driver. We use a
     * specific variant for this to avoid trying to do things that the test
     * driver doesn't support, like interrupts. */
    dev_type->variant = 'L';
    dev_type->function = EFHW_FUNCTION_PF;
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
  struct efx_design_params dp;
  int rc;
  int i;

  val.design_params = &dp;
  rc = edev->llct_ops->base_ops->get_param(client, EFX_DESIGN_PARAM, &val);
  if( rc < 0 )
    return rc;

  rc = efct_filter_state_init(&ef10ct->filter_state, dp.num_filters,
                              dp.rx_queues);

  res_dim->efhw_ops = &ef10ct_char_functional_units;

  ef10ct->evq_n = dp.ev_queues;
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

  ef10ct->rxq_n = dp.rx_queues;
  ef10ct->rxq = vzalloc(sizeof(*ef10ct->rxq) * ef10ct->rxq_n);
  if( ! ef10ct->rxq ) {
    rc = -ENOMEM;
    goto fail1;
  }
  for( i = 0; i < ef10ct->rxq_n; i++ )
    ef10ct->rxq[i].evq = -1;

  res_dim->irq_n_ranges = 0;
#if 0
  rc = edev->llct_ops->base_ops->get_param(client, EFX_AUXILIARY_IRQ_RESOURCES,
                                           &val);
  if( rc < 0 )
    return rc;

  res_dim->irq_n_ranges = val.irq_res->n_ranges;
  EFRM_ASSERT(res_dim->irq_n_ranges <= IRQ_N_RANGES_MAX);
  for( i = 0; i < res_dim->irq_n_ranges; i++ ) {
      res_dim->irq_ranges[i].irq_base = val.irq_res->irq_ranges[i].vector;
      res_dim->irq_ranges[i].irq_range = val.irq_res->irq_ranges[i].range;
  }

  res_dim->irq_prime_reg = val.irq_res->int_prime;
#endif

  /* Shared evqs for rx vis. Need at least one for suppressed events */
  /* TODO: determine how many more to add for interrupt affinity */
  ef10ct->shared_n = 1;
  ef10ct->shared = vzalloc(sizeof(*ef10ct->shared) * ef10ct->shared_n);
  if( ! ef10ct->shared ) {
    rc = -ENOMEM;
    goto fail2;
  }

  return 0;

fail2:
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
  efhw_stack_vi_allocator_dtor(&nic->vi_allocator.rx);
}

static int ef10ct_nic_init_shared_evq(struct efhw_nic *nic, int qid)
{
  struct efhw_nic_ef10ct *ef10ct = nic->arch_extra;
  struct efhw_nic_ef10ct_evq *ef10ct_evq;
  uint n_pages = 1; /* TODO: What should the size be? */
  struct page* page;
  dma_addr_t dma_addr;
  dma_addr_t *dma_addrs;
  struct efhw_evq_params params = {};
  int evq_id, rc, evq_num;
  struct ef10ct_shared_kernel_evq *shared_evq = &ef10ct->shared[qid];

  evq_id = ef10ct_alloc_evq(nic);
  if(evq_id < 0) {
    rc = evq_id;
    goto fail1;
  }
  evq_num = ef10ct_get_queue_num(evq_id);
  EFHW_ASSERT(evq_num <= ef10ct->evq_n);

  ef10ct_evq = &ef10ct->evq[evq_num];

  /* TODO: We may want to use alloc_pages_node to get memory on a specific numa
   * node. */
  page = alloc_page(GFP_KERNEL | __GFP_ZERO);

  if( page == NULL ) {
    rc = -ENOMEM;
    goto fail2;
  }

  /* TODO: I think we want to use something like dma_map_single here, however we
   * don't have a pci dev for ef10ct so these function don't currently work.
   * Instead, just get the physical address of the page */
  dma_addr = page_to_phys(page);

  /* Only allocating a single page means that dma_addrs doesn't have to be an
   * an array. */
  EFHW_ASSERT(n_pages == 1);
  dma_addrs = &dma_addr;

  params.evq = evq_id;
  params.evq_size = (n_pages << PAGE_SHIFT) / sizeof(efhw_event_t);
  params.dma_addrs = dma_addrs;
  params.n_pages = n_pages;
  /* Wakeup stuff is ignored */
  /* Do we care about flags? */

  rc = efhw_nic_event_queue_enable(nic, &params);
  if( rc < 0 )
    goto fail3;

  shared_evq->evq_id = evq_id;
  shared_evq->evq = &ef10ct->evq[evq_num];
  shared_evq->page = page;

  return 0;

fail3:
  put_page(page);
fail2:
  ef10ct_free_evq(nic, evq_id);
fail1:
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
  efhw_nic_event_queue_disable(nic, shared_evq->evq_id, 0);

  ef10ct_free_evq(nic, shared_evq->evq_id);
  put_page(shared_evq->page);

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
  int rc, i;

  if ( !efx_aux_abi_version_is_compat(edev->abi_version) ) {
    EFHW_ERR("Auxbus ABI version mismatch. %s requires %u.%u. Auxdev has %u.%u.",
             KBUILD_MODNAME, EFX_AUX_ABI_VERSION_MAJOR_GET(edev->abi_version),
             EFX_AUX_ABI_VERSION_MINOR_GET(edev->abi_version),
             EFX_AUX_ABI_VERSION_MAJOR,
             EFX_AUX_ABI_VERSION_MINOR);
    return -EPROTO;
  }

  ef10ct = vzalloc(sizeof(*ef10ct));
  if( ! ef10ct )
    return -ENOMEM;
  ef10ct->edev = edev;

  client = edev->llct_ops->base_ops->open(auxdev, &ef10ct_handler,
                                          EFX_AUXDEV_ALL_EVENTS);

  EFRM_NOTICE("%s name %s", __func__, id->name);

  if( IS_ERR(client) ) {
    rc = PTR_ERR(client);
    goto fail1;
  }

  rc = edev->llct_ops->base_ops->get_param(client, EFX_NETDEV, &val);
  if( rc < 0 )
    goto fail2;

  EFRM_NOTICE("%s probe of dev %s", __func__, val.net_dev->name);

  rc = ef10ct_devtype_init(edev, client, &dev_type);
  if( rc < 0 )
    goto fail2;

  rc = ef10ct_resource_init(edev, client, ef10ct, &res_dim);
  if( rc < 0 )
    goto fail2;

  rc = ef10ct_vi_allocator_ctor(ef10ct, &res_dim);
  if( rc < 0 )
    goto fail2;

  rc = efrm_nic_add(client, &auxdev->dev, &dev_type, val.net_dev, &lnic,
                    &res_dim, 0);
  if( rc < 0 )
    goto fail3;

  nic = &lnic->efrm_nic.efhw_nic;
  nic->mtu = val.net_dev->mtu + ETH_HLEN;
  nic->arch_extra = ef10ct;

  /* Setting the nic here marks the device as ready for use. */
  ef10ct->nic = nic;

  efrm_notify_nic_probe(nic, val.net_dev);

  /* Init shared evqs for use with rx vis. */
  for( i = 0; i < ef10ct->shared_n; i++ ) {
    rc = ef10ct_nic_init_shared_evq(nic, i);
    if( rc < 0 )
      goto fail4;
  }

  efhw_init_debugfs_ef10ct(nic);

  return 0;

 fail4:
  /* We failed evq reservation at `i`. Cleanup evqs in range [0..i) */
  i--;
  for(; i >= 0; i--)
    ef10ct_nic_free_shared_evq(nic, i);
 fail3:
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
  struct linux_efhw_nic *lnic;
  struct efhw_nic* nic;
  struct efhw_nic_ef10ct *ef10ct;
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

  efrm_notify_nic_remove(nic);

  /* flush all outstanding dma queues */
  efrm_nic_flush_all_queues(nic, 0);

  /* Disable/free all shared evqs */
  for(i = 0; i < ef10ct->shared_n; i++)
    ef10ct_nic_free_shared_evq(nic, i);

  lnic->drv_device = NULL;
  /* Wait for all in-flight driverlink calls to finish.  Since we
   * have already cleared [lnic->drv_device], no new calls can
   * start. */
  efhw_nic_flush_drv(nic);
  efrm_nic_unplug_hard(nic);

  /* Absent hardware is treated as a protracted reset. */
  efrm_nic_reset_suspend(nic);
  ci_atomic32_or(&nic->resetting, NIC_RESETTING_FLAG_UNPLUGGED);

  ef10ct_vi_allocator_dtor(ef10ct);
  /* mind we might still expect callbacks from close() context
   * TODO: rethink where to call close and how to synchronise with
   * the rest. */
  edev->llct_ops->base_ops->close(client);

  efct_filter_state_free(&ef10ct->filter_state);

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
