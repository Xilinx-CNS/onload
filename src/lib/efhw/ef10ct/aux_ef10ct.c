/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#include <ci/driver/kernel_compat.h>
#include <ci/driver/ci_ef10ct.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/ef10ct.h>
#include <ci/efhw/efct_filters.h>

#include "linux_resource_internal.h"
#include "efrm_internal.h"

#if CI_HAVE_EF10CT

static int ef10ct_handler(struct auxiliary_device *auxdev, void *drv_data,
                          struct efx_auxiliary_event *event, int budget)
{
  EFRM_TRACE("%s: %s", __func__, dev_name(&auxdev->dev));
  return 0;
}


static int ef10ct_devtype_init(struct efx_auxiliary_device *edev,
                               struct efx_auxiliary_client *client,
                               struct efhw_device_type *dev_type)
{
  dev_type->arch = EFHW_ARCH_EF10CT;
  dev_type->function = EFHW_FUNCTION_PF;
  dev_type->variant = 'L';
  dev_type->revision = 0;

  return 0;
}


static int ef10ct_resource_init(struct efx_auxiliary_device *edev,
                                struct efx_auxiliary_client *client,
                                struct efhw_nic_ef10ct *ef10ct,
                                struct vi_resource_dimensions *res_dim)
{
  union efx_auxiliary_param_value val;
  int n_txqs;
  int rc;
  int i;

  res_dim->efhw_ops = &ef10ct_char_functional_units;
  rc = edev->ops->get_param(client, EFX_AUXILIARY_NIC_RESOURCES, &val);
  if( rc < 0 )
    return rc;

  ef10ct->evq_n = val.nic_res.evq_lim;
  ef10ct->evq = vzalloc(sizeof(*ef10ct->evq) * ef10ct->evq_n);
  if( ! ef10ct->evq )
    goto fail;

  res_dim->vi_min = val.nic_res.evq_min;
  res_dim->vi_lim = EF10CT_EVQ_DUMMY_MAX;
  res_dim->mem_bar = VI_RES_MEM_BAR_UNDEFINED;

  for( i = 0; i < ef10ct->evq_n; i++ )
    ef10ct->evq[i].txq = EF10CT_EVQ_NO_TXQ;

  n_txqs = val.nic_res.txq_lim - val.nic_res.txq_min;
  for( i = 0; i < n_txqs && val.nic_res.evq_min + i < val.nic_res.evq_lim; ++i )
    ef10ct->evq[val.nic_res.evq_min + i].txq = val.nic_res.txq_min + i;

  ef10ct->rxq_n = val.nic_res.rxq_lim;
  ef10ct->rxq = vzalloc(sizeof(*ef10ct->rxq) * ef10ct->rxq_n);
  if( ! ef10ct->rxq )
    goto fail1;
  for( i = 0; i < ef10ct->rxq_n; i++ ) {
    ef10ct->rxq[i].evq = -1;
    ef10ct->rxq[i].q_id = -1;
  }

  res_dim->irq_n_ranges = 0;
#if 0
  rc = edev->ops->get_param(client, EFX_AUXILIARY_IRQ_RESOURCES, &val);
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
  if( ! ef10ct->shared )
    goto fail2;

  return 0;

fail2:
  vfree(ef10ct->rxq);
fail1:
  vfree(ef10ct->evq);
fail:
  return -ENOMEM;
}


static int ef10ct_vi_allocator_ctor(struct efhw_nic_ef10ct *nic,
                                  struct vi_resource_dimensions *res_dim)
{
  int rc = 0;
  /* tx vis are allocated in the range [res_dim->vi_min,ef10ct->evq_n)
   * The space above this is used for virtual rx vis */
  rc = efhw_stack_vi_allocator_ctor(&nic->vi_allocator.tx, res_dim->vi_min,
                                    nic->evq_n);
  if(rc < 0)
    goto fail1;
  rc = efhw_stack_vi_allocator_ctor(&nic->vi_allocator.rx, nic->evq_n,
                                    res_dim->vi_lim);
  if(rc < 0)
    goto fail2;
  return rc;

 fail2:
  efhw_stack_vi_allocator_dtor(&nic->vi_allocator.tx);
 fail1:
  if (rc < 0) {
    EFRM_ERR("%s: ef10ct_vi_allocator_ctor(%d, %d) "
              "failed (%d)",
              __FUNCTION__, res_dim->vi_min, res_dim->vi_lim, rc);
  }
  return rc;
}


static void ef10ct_vi_allocator_dtor(struct efhw_nic_ef10ct *nic)
{
  efhw_stack_vi_allocator_dtor(&nic->vi_allocator.tx);
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
  int vi, rc;
  struct ef10ct_shared_kernel_evq *shared_evq = &ef10ct->shared[qid];
  struct efhw_vi_constraints evc = {
    .want_txq = true, /* Setting `want_txq` will give us a real evq/vi */
    /* Other fields are ignored for ef10ct */
  };

  vi = efhw_nic_vi_alloc(nic, &evc, 1);
  if(vi < 0) {
    rc = vi;
    goto fail1;
  }
  EFHW_ASSERT(vi <= ef10ct->evq_n);

  ef10ct_evq = &ef10ct->evq[vi];

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

  params.evq = vi;
  params.evq_size = (n_pages << PAGE_SHIFT) / sizeof(efhw_event_t);
  params.dma_addrs = dma_addrs;
  params.n_pages = n_pages;
  /* Wakeup stuff is ignored */
  /* Do we care about flags? */

  rc = efhw_nic_event_queue_enable(nic, &params);
  if( rc < 0 )
    goto fail3;

  shared_evq->vi = vi;
  shared_evq->evq = &ef10ct->evq[vi];
  shared_evq->page = page;

  return 0;

fail3:
  put_page(page);
fail2:
  efhw_nic_vi_free(nic, vi, 1);
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
  efhw_nic_event_queue_disable(nic, shared_evq->vi, 0);

  efhw_nic_vi_free(nic, shared_evq->vi, 1);
  put_page(shared_evq->page);

  /* Just to be safe */
  memset(shared_evq, 0, sizeof(*shared_evq));

  return;
}


static int ef10ct_probe(struct auxiliary_device *auxdev,
                        const struct auxiliary_device_id *id)
{
  struct efx_auxiliary_client *client;
  struct efx_auxiliary_device *edev = to_sfc_aux_device(auxdev);
  struct efhw_device_type dev_type;
  struct linux_efhw_nic *lnic = NULL;
  struct efhw_nic *nic;
  struct efhw_nic_ef10ct *ef10ct = NULL;
  struct vi_resource_dimensions res_dim = {};
  union efx_auxiliary_param_value val;
  int rc, i;

  /* version checking here */

  ef10ct = vzalloc(sizeof(*ef10ct));
  if( ! ef10ct )
    return -ENOMEM;
  ef10ct->edev = edev;

  client = edev->ops->open(auxdev, &ef10ct_handler, EFX_ALL_EVENTS, NULL);

  EFRM_NOTICE("%s name %s", __func__, id->name);

  if( IS_ERR(client) ) {
    rc = PTR_ERR(client);
    goto fail1;
  }

  rc = edev->ops->get_param(client, EFX_AUXILIARY_NETDEV, &val);
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

  return 0;

 fail4:
  /* We failed evq reservation at `i`. Cleanup evqs in range [0..i) */
  i--;
  for(; i >= 0; i--)
    ef10ct_nic_free_shared_evq(nic, i);
 fail3:
  ef10ct_vi_allocator_dtor(ef10ct);
 fail2:
  edev->ops->close(client);
 fail1:
  vfree(ef10ct);
  EFRM_ERR("%s rc %d", __func__, rc);
  return rc;
}


void ef10ct_remove(struct auxiliary_device *auxdev)
{
  struct efx_auxiliary_device *edev = to_sfc_aux_device(auxdev);
  struct efx_auxiliary_client *client;
  struct linux_efhw_nic *lnic;
  struct efhw_nic* nic;
  struct efhw_nic_ef10ct *ef10ct;
  int i;

  EFRM_TRACE("%s: %s", __func__, dev_name(&auxdev->dev));

  nic = efhw_nic_find_by_dev(&auxdev->dev);
  if( !nic )
    return;

  lnic = linux_efhw_nic(nic);
  client = (struct efx_auxiliary_client*)lnic->drv_device;
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
  edev->ops->close(client);
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
