/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */

#include <ci/efrm/efrm_client.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/efct.h>
#include <ci/tools/sysdep.h>

#include "linux_resource_internal.h"
#include <linux/mman.h>
#include "efrm_internal.h"
#include <ci/driver/kernel_compat.h>
#include <ci/driver/ci_efct.h>

#if CI_HAVE_EFCT_AUX

static int efct_handle_event(void *driver_data,
                             const struct xlnx_efct_event *event)
{
  return -ENOSYS;
}

noinline
static long do_sys_mmap(unsigned long addr, unsigned long len,
                        unsigned long prot, unsigned long flags,
                        unsigned long fd, unsigned long off)
{
  return SYSCALL_DISPATCHn(6, mmap, addr, len, prot, flags, fd, off);
}

static int efct_alloc_hugepage(void *driver_data,
                               struct xlnx_efct_hugepage *result_out)
{
  /* The rx ring is owned by the net driver, not by us, so it does all
   * DMA handling. We do need to supply it with some memory, though.
   * We allocate hugepages one by one, rather than a single file with many
   * pages in it, so that freeing of pages can be more granular. */
  const size_t huge_size = HPAGE_PMD_NR * PAGE_SIZE;
  unsigned long addr;
  struct mm_struct *mm = current->mm;
  struct vm_area_struct *vma;
  struct xlnx_efct_hugepage result;
  long rc;

  /* A long dance solely to do, effectively, hugetlb_file_setup(). It's
   * handy that we do the mapping in the correct process context because
   * that means permissions happen correctly, but we don't leave the
   * memory mapping in place because, even though the process is going
   * to want it eventually, it's not going to want it in the random
   * place that we get it here. Where it should be depends on the
   * superbuf IDs, which we don't yet know. */
  addr = do_sys_mmap(0, huge_size, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE |
                     MAP_HUGETLB | MAP_HUGE_2MB, -1, 0);
  if( IS_ERR((void*)addr) ) {
    rc = PTR_ERR((void*)addr);
    EFHW_ERR("%s: ERROR: insufficient hugepage memory for rxq (%ld)",
             __func__, rc);
    return rc;
  }
  /* There's a race here (the window being crowbaropenable with
   * userfaultfd): the app can swiftly munmap and make us grab a
   * different file* to the one we wanted. We already don't trust the
   * contents of the rxq so this isn't super-harmful, but there are
   * definitely ways to use it to exceed resource limits. */
  if( down_write_killable(&mm->mmap_sem) ) {
    rc = -EINTR;
    goto fail1;
  }
  vma = find_vma(mm, addr);
  result.file = vma->vm_file;
  if( result.file )
    get_file(result.file);
  up_write(&mm->mmap_sem);
  if( ! result.file ) {
    EFHW_ERR("%s: ERROR: internal fault:  hugepages not backed by hugetlbfs?",
             __func__);
    rc = -ENOMEM;
    goto fail1;
  }

  /* All pages in a compound page are conjoined (without FOLL_SPLIT) so we
   * only need the first one: */
  rc = pin_user_pages(addr, 1, FOLL_WRITE, &result.page, NULL);
  if( rc < 1 ) {
    EFHW_ERR("%s: ERROR: can't pin rxq memory (%ld)", __func__, rc);
    rc = -EFAULT;
    goto fail2;
  }
  EFHW_ASSERT(PageHuge(result.page));
  EFHW_ASSERT(!PageTail(result.page));
  vm_munmap(addr, huge_size);

  *result_out = result;
  return 0;

 fail2:
  fput(result.file);
 fail1:
  vm_munmap(addr, huge_size);
  return rc;
}

static void efct_free_hugepage(void *driver_data,
                               struct xlnx_efct_hugepage *mem)
{
  unpin_user_page(mem->page);
  fput(mem->file);
}

static void efct_hugepage_list_changed(void *driver_data, int rxq)
{
  struct efhw_nic_efct *efct = driver_data;
  struct efhw_nic_efct_rxq *q = &efct->rxq[rxq];
  struct efhw_efct_rxq *app;

  for( app = q->live_apps; app; app = app->next )
    ++app->shm->config_generation;
}

struct xlnx_efct_drvops efct_ops = {
  .name = "sfc_resource",
  .handle_event = efct_handle_event,
  .alloc_hugepage = efct_alloc_hugepage,
  .free_hugepage = efct_free_hugepage,
  .hugepage_list_changed = efct_hugepage_list_changed,
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
                              struct vi_resource_dimensions *res_dim)
{
  union xlnx_efct_param_value val;
  int rc;

  rc = edev->ops->get_param(client, XLNX_EFCT_NIC_RESOURCES, &val);
  if( rc < 0 )
    return rc;

  res_dim->vi_min = val.nic_res.evq_min;
  res_dim->vi_lim = val.nic_res.evq_lim;
  res_dim->mem_bar = VI_RES_MEM_BAR_UNDEFINED;

  return 0;
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

  EFRM_NOTICE("%s name %s", __func__, id->name);

  efct = vzalloc(sizeof(*efct));
  if( ! efct )
    return -ENOMEM;

  efct->edev = edev;
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

  rc = efct_resource_init(edev, client, &res_dim);
  if( rc < 0 )
    goto fail2;

  rc = efrm_nic_add(client, &auxdev->dev, &dev_type, 0, net_dev, &lnic,
                    &res_dim, 0);
  if( rc < 0 )
    goto fail2;

  nic = &lnic->efrm_nic.efhw_nic;
  nic->mtu = net_dev->mtu + ETH_HLEN;
  nic->arch_extra = efct;

  efrm_notify_nic_probe(net_dev);
  return 0;

 fail2:
  edev->ops->close(client);
 fail1:
  vfree(efct);
  EFRM_ERR("%s rc %d", __func__, rc);
  return rc;
}


void efct_remove(struct auxiliary_device *auxdev)
{
  struct xlnx_efct_device *edev = to_xlnx_efct_device(auxdev);
  struct xlnx_efct_client *client;
  struct linux_efhw_nic *lnic;
  struct net_device *net_dev;
  struct efhw_nic* nic;
  struct efhw_nic_efct *efct;
  int i;

  EFRM_NOTICE("%s", __func__);

  nic = efhw_nic_find_by_dev(&auxdev->dev);
  if( !nic )
    return;

  lnic = linux_efhw_nic(nic);
  client = (struct xlnx_efct_client*)lnic->drv_device;
  if( !client )
    return;

  efct = nic->arch_extra;
  for( i = 0; i < ARRAY_SIZE(efct->rxq); ++i ) {
    EFHW_ASSERT(efct->rxq[i].live_apps == NULL);
    EFHW_ASSERT(efct->rxq[i].new_apps == NULL);
  }

  net_dev = efhw_nic_get_net_dev(nic);
  efrm_notify_nic_remove(net_dev);
  dev_put(net_dev);

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

  vfree(efct);
  edev->ops->close(client);
}


static const struct auxiliary_device_id efct_id_table[] = {
  { .name = "xlnx_efct." XLNX_EFCT_DEVNAME, },
  { .name = "efct_test." XLNX_EFCT_DEVNAME ".test", },
  {},
};
MODULE_DEVICE_TABLE(auxiliary, efct_id_table);


struct auxiliary_driver efct_drv = {
  .name = "efct",
  .probe = efct_probe,
  .remove = efct_remove,
  .id_table = efct_id_table,
};

#endif
