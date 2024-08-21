/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2005-2024, Advanced Micro Devices, Inc. */

#include "linux_resource_internal.h"

#include <ci/driver/ci_ef10.h>

#include "efrm_internal.h"
#include <ci/driver/kernel_compat.h>

#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <net/net_namespace.h>
#include <ci/efrm/nic_table.h>
#include <ci/efhw/ef10.h>
#include <ci/efhw/nic.h>
#include <ci/tools/sysdep.h>
#include <ci/internal/transport_config_opt.h>
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/driver/resource/driverlink.h>


/* Determines whether a known NIC is equivalent to one that would be
 * instantiated according to a [pci_dev] and an [efhw_device_type]. The
 * intended use-case is to check whether a new NIC can step into the shoes of
 * one that went away. */
static inline int
efrm_nic_matches_device(struct efhw_nic* nic, const struct pci_dev* dev,
                        const struct efhw_device_type* dev_type)
{
  int match;
  struct pci_dev* nic_dev = efhw_nic_get_pci_dev(nic);
  if (!nic_dev) {
    /* Rediscovery of non-PCI NICs not currently supported */
    return 0;
  }
  match = nic_dev->devfn == dev->devfn && nic_dev->device == dev->device;
  pci_dev_put(nic_dev);
  if (!match)
    return 0;

  /* Check that the PCI device is of the same type and in the same place. */
  if (nic->domain != pci_domain_nr(dev->bus) ||
      nic->bus_number != dev->bus->number ||
      nic->devtype.arch != dev_type->arch ||
      nic->devtype.revision != dev_type->revision ||
      nic->devtype.variant != dev_type->variant)
    return 0;

  return 1;
}


static inline int
efrm_nic_resources_match(struct efhw_nic* nic,
			 const struct vi_resource_dimensions* res_dim)
{
  struct efrm_nic* efrm_nic = efrm_nic(nic);

  /* Check that we have a compatible set of available VIs. */
  if (nic->vi_min != res_dim->vi_min ||
      /* nic->vi_lim might have been reduced owing to a shortage of
       * IRQs, but that's OK. */
      nic->vi_lim > res_dim->vi_lim ||
      nic->vi_stride != res_dim->vi_stride ||
      efrm_nic->rss_channel_count != res_dim->rss_channel_count)
    return 0;

  return 1;
}


/* Determines whether the control BAR for the device [dev] is where we expect
 * it to be for the NIC [nic]. This is a requirement for hotplug
 * revivification. */
static inline int
efrm_nic_bar_is_good(struct efhw_nic* nic, struct pci_dev* dev)
{
  return !dev || nic->ctr_ap_addr == pci_resource_start(dev, nic->ctr_ap_bar);
}


static struct linux_efhw_nic*
efrm_get_rediscovered_nic(const struct efhw_device_type* dev_type,
			  const struct vi_resource_dimensions* res_dim)
{
  struct linux_efhw_nic* lnic = NULL;
  struct efhw_nic* old_nic;
  int nic_index;

  /* We can't detect hotplug without the pci information to compare */
  if( !res_dim->pci_dev )
    return NULL;

  spin_lock_bh(&efrm_nic_tablep->lock);
  EFRM_FOR_EACH_NIC(nic_index, old_nic) {
    /* We would like to break out of this loop after rediscovering
     * a NIC, but the EFRM_FOR_EACH_NIC construct doesn't allow
     * this, so instead we check explicitly that we haven't set
     * [lnic] yet. */
    if (lnic == NULL && old_nic != NULL &&
        efrm_nic_matches_device(old_nic, res_dim->pci_dev, dev_type)) {
      EFRM_ASSERT(old_nic->resetting);
      if (!efrm_nic_bar_is_good(old_nic, res_dim->pci_dev)) {
        EFRM_WARN("%s: New device matches nic_index %d but has different BAR. "
                  "Existing Onload stacks will not use the new device.",
                  __func__, nic_index);
      }
      else if (!efrm_nic_resources_match(old_nic, res_dim)) {
        EFRM_WARN("%s: New device matches nic_index %d but has different "
                  "resource parameters. Existing Onload stacks will not use "
                  "the new device.", __func__, nic_index);
      }
      else {
        EFRM_NOTICE("%s: Rediscovered nic_index %d", __func__, nic_index);
        lnic = linux_efhw_nic(old_nic);
      }
    }
  }
  spin_unlock_bh(&efrm_nic_tablep->lock);
  /* We can drop the lock now as [lnic] will not go away until the module
   * unloads. */

  return lnic;
}


static int init_resource_info(struct efx_auxdev *edev,
                              struct efx_auxdev_client *client,
                              struct efx_auxdev_dl_vi_resources *vi_res,
                              struct vi_resource_dimensions *rd,
                              unsigned int *tq)
{
  union efx_auxiliary_param_value val;
  int rc;

  rc = edev->ops->get_param(client, EFX_PCI_DEV, &val);
  if( rc < 0 )
    return rc;
  rd->pci_dev = val.pci_dev;

  rc = edev->ops->get_param(client, EFX_MEMBAR, &val);
  if( rc < 0 )
    return rc;
  rd->mem_bar = val.value;

  rc = edev->ops->get_param(client, EFX_TIMER_QUANTUM_NS, &val);
  if( rc < 0 )
    return rc;
  *tq = val.value;

  rd->vi_min = vi_res->vi_min;
  rd->vi_lim = vi_res->vi_lim;
  rd->rss_channel_count = vi_res->rss_channel_count;
  rd->vi_base = vi_res->vi_base;
  rd->vi_shift = vi_res->vi_shift;
  rd->vi_stride = vi_res->vi_stride;

  /* assume all the register STEPS are identical */
  EFRM_BUILD_ASSERT(ER_DZ_EVQ_RPTR_REG_STEP == ER_DZ_EVQ_TMR_REG_STEP);
  EFRM_BUILD_ASSERT(ER_DZ_EVQ_RPTR_REG_STEP == ER_DZ_RX_DESC_UPD_REG_STEP);
  EFRM_BUILD_ASSERT(ER_DZ_EVQ_RPTR_REG_STEP == ER_DZ_TX_DESC_UPD_REG_STEP);

  EFRM_TRACE("Using VI range %d+(%d-%d)<<%d bar %d ws 0x%x", rd->vi_base,
             rd->vi_min, rd->vi_lim, rd->vi_shift, rd->mem_bar, rd->vi_stride);

  /* The net driver manages our interrupts for ef10. */
  rd->irq_n_ranges = 0;
  rd->irq_prime_reg = NULL;

  rd->efhw_ops = &ef10aux_char_functional_units;

  return 0;
}


static void ef10_reset_suspend(struct efx_auxdev_client * client,
                               struct efhw_nic *nic)
{
  EFRM_NOTICE("%s: %s", __func__, dev_name(&client->auxdev->auxdev.dev));

  efrm_nic_reset_suspend(nic);
  ci_atomic32_or(&nic->resetting, NIC_RESETTING_FLAG_RESET);
}


static void ef10_reset_resume(struct efx_auxdev_client * client,
                              struct efhw_nic *nic)
{
  union efx_auxiliary_param_value val;
  struct efx_auxdev_dl_vi_resources *vi_resources =
                        ((struct ef10_aux_arch_extra*)nic->arch_extra)->dl_res;
  int rc;

  EFRM_NOTICE("%s: %s", __func__, dev_name(&client->auxdev->auxdev.dev));

  if( nic->vi_base != vi_resources->vi_base ) {
    EFRM_TRACE("%s: vi_base changed from %d to %d\n",
               __func__, nic->vi_base, vi_resources->vi_base);
  }
  if( nic->vi_shift != vi_resources->vi_shift ) {
    EFRM_TRACE("%s: vi_shift changed from %d to %d\n",
               __func__, nic->vi_shift, vi_resources->vi_shift);
  }
  if( nic->vi_stride != vi_resources->vi_stride ) {
    EFRM_TRACE("%s: vi_stride changed from %d to %d\n",
               __func__, nic->vi_stride, vi_resources->vi_stride);
  }

  rc = client->auxdev->ops->get_param(client, EFX_MEMBAR, &val);
  /* We never expect this to fail, if it does so treat it as the NIC never
   * coming back up. */
  if( rc < 0 ) {
    EFRM_ERR("%s: Failed to obtain BAR information post-reset", __func__);
    return;
  }
  if( nic->ctr_ap_bar != val.value ) {
    EFRM_TRACE("%s: mem_bar changed from %d to %d\n", __func__,
               nic->ctr_ap_bar, val.value);
  }
  nic->ctr_ap_bar = val.value;

  /* Remove record on queue initialization from before a reset
   * No hardware operation will be performed */
  efrm_nic_flush_all_queues(nic, EFRM_FLUSH_QUEUES_F_NOHW |
                                 EFRM_FLUSH_QUEUES_F_INJECT_EV);

  nic->resetting = 0;
  /* Handle re-init at efhw and then efrm level */
  efhw_nic_post_reset(nic);
  efrm_nic_post_reset(nic);
}

static void ef10_post_reset(struct efx_auxdev_client *client,
                           struct efhw_nic *nic, int result)
{
  switch(result) {
    case EFX_IN_RESET:
      ef10_reset_suspend(client, nic);
      break;
    case EFX_NOT_IN_RESET:
      ef10_reset_resume(client, nic);
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

static int ef10_handler(struct efx_auxdev_client *client,
                        const struct efx_auxdev_event *event)
{
  union efx_auxiliary_param_value val;
  struct efhw_nic *nic;
  int rc;

  rc = client->auxdev->ops->get_param(client, EFX_DRIVER_DATA, &val);
  if (rc < 0 )
    return rc;

  nic = (struct efhw_nic*)val.driver_data;
  if( !nic )
    return -ENODEV;

  /* The return from the handler is ignored in all cases other than a poll
   * event, where we return budget consumed, so set a default rc here. */
  rc = 0;

  switch(event->type) {
    case EFX_AUXDEV_EVENT_POLL:
      /* Our polling code handles batches of events, so can exceed the
       * provided budget. If we do so we hide the evidence here, to avoid
       * getting told off by NAPI. */
      rc = efhw_nic_handle_event(nic, event->p_event, event->budget);
      if( rc > event->budget )
        rc = event->budget;
      break;
    case EFX_AUXDEV_EVENT_IN_RESET:
      ef10_post_reset(client, nic, event->value);
      break;
    case EFX_AUXDEV_EVENT_LINK_CHANGE:
      break;
  };

  return rc;
}

static int ef10_probe(struct auxiliary_device *auxdev,
                      const struct auxiliary_device_id *id)
{
  struct efx_auxdev *edev = to_efx_auxdev(auxdev);
  struct efx_auxdev_dl_vi_resources *dl_res;
  struct vi_resource_dimensions res_dim;
  struct efx_auxdev_client *client;
  union efx_auxiliary_param_value val;
  struct efhw_device_type dev_type;
  unsigned timer_quantum_ns;
  struct linux_efhw_nic *lnic;
  struct efhw_nic *nic;
  struct net_device *net_dev;
  int rc;

  EFRM_NOTICE("%s name %s", __func__, id->name);

  if( enable_driverlink == 0 ) {
    EFRM_NOTICE("%s: Ignoring %s as module param enable_driverlink=0",
                __func__, id->name);
    return -EPERM;
  }

  client = edev->ops->open(auxdev, &ef10_handler, EFX_AUXDEV_ALL_EVENTS);

  if( IS_ERR(client) ) {
    rc = PTR_ERR(client);
    goto fail1;
  }

  dl_res = edev->ops->dl_publish(client);
  if( IS_ERR(dl_res) ) {
    rc = PTR_ERR(dl_res);
    goto fail2;
  }

  rc = edev->ops->get_param(client, EFX_NETDEV, &val);
  if( rc < 0 )
    goto fail3;
  net_dev = val.net_dev;

  rc = init_resource_info(edev, client, dl_res, &res_dim, &timer_quantum_ns);
  if( rc < 0 )
    goto fail3;

  rc = efhw_sfc_device_type_init(&dev_type, res_dim.pci_dev);
  if( rc < 0 ) {
    EFRM_ERR("%s: efhw_device_type_init failed %04x:%04x rc %d",
    __func__, (unsigned) res_dim.pci_dev->vendor,
    (unsigned) res_dim.pci_dev->device, rc);
    goto fail3;
  }

  EFRM_NOTICE("%s pci_dev=%04x:%04x(%d) type=%d:%c%d ifindex=%d",
              pci_name(res_dim.pci_dev) ?  pci_name(res_dim.pci_dev) : "?",
              (unsigned) res_dim.pci_dev->vendor,
              (unsigned) res_dim.pci_dev->device, dev_type.revision,
              dev_type.arch, dev_type.variant, dev_type.revision,
              net_dev->ifindex);

  lnic = efrm_get_rediscovered_nic(&dev_type, &res_dim);

  rtnl_lock();
  rc = efrm_nic_add(client, &auxdev->dev, &dev_type,
                    (/*no const*/ struct net_device *)net_dev, &lnic, &res_dim,
                    timer_quantum_ns);
  if( rc < 0 ) {
    rtnl_unlock();
    goto fail3;
  }

  efrm_nic_add_sysfs(net_dev, &auxdev->dev);

  nic = &lnic->efrm_nic.efhw_nic;
  nic->mtu = net_dev->mtu + ETH_HLEN; /* ? + ETH_VLAN_HLEN */
  nic->rss_channel_count = res_dim.rss_channel_count;
  nic->pci_dev = res_dim.pci_dev;
  ((struct ef10_aux_arch_extra*)nic->arch_extra)->dl_res = dl_res;

  val.driver_data = nic;
  rc = edev->ops->set_param(client, EFX_DRIVER_DATA, &val);
  /* The only reason this can fail is if we're using an invalid handle, which
   * we're not. */
  EFRM_ASSERT(rc == 0);

  efrm_notify_nic_probe(nic, net_dev);
  rtnl_unlock();
  return 0;

 fail3:
  edev->ops->dl_unpublish(client);
 fail2:
  edev->ops->close(client);
 fail1:
  return rc;
}

/* When we unregister ourselves on module removal, this function will be
 * called for all the devices we claimed. It will also be called on a single
 * device if that device is unplugged.
 */
void ef10_remove(struct auxiliary_device *auxdev)
{
  struct efx_auxdev *edev = to_efx_auxdev(auxdev);
  struct efx_auxdev_client *client;
  struct linux_efhw_nic *lnic;
  struct efhw_nic *nic;

  EFRM_TRACE("%s: %s", __func__, dev_name(&auxdev->dev));

  nic = efhw_nic_find_by_dev(&auxdev->dev);
  if( !nic )
    return;

  efrm_nic_del_sysfs(&auxdev->dev);
  lnic = linux_efhw_nic(nic);
  client = (struct efx_auxdev_client*)lnic->drv_device;
  if( !client )
    return;

  rtnl_lock();
  efrm_notify_nic_remove(nic);

  /* flush all outstanding dma queues */
  efrm_nic_flush_all_queues(nic, 0);

  lnic->drv_device = NULL;

  /* Wait for all in-flight driverlink calls to finish.  Since we
   * have already cleared [lnic->drv_device], no new calls can
   * start. */
  efhw_nic_flush_drv(nic);
  efrm_nic_unplug(nic);

  /* Absent hardware is treated as a protracted reset. */
  efrm_nic_reset_suspend(nic);
  ci_atomic32_or(&nic->resetting, NIC_RESETTING_FLAG_UNPLUGGED);
  rtnl_unlock();

  edev->ops->dl_unpublish(client);
  edev->ops->close(client);
}


static const struct auxiliary_device_id ef10_id_table[] = {
  { .name = "sfc." EFX_ONLOAD_DEVNAME, },
  {},
};
MODULE_DEVICE_TABLE(auxiliary, ef10_id_table);


struct auxiliary_driver ef10_drv = {
  .name = "ef10",
  .probe = ef10_probe,
  .remove = ef10_remove,
  .id_table = ef10_id_table,
};

