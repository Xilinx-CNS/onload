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

#include "efct_superbuf.h"

#if CI_HAVE_EFCT_AUX

/* EFCT TODO: enhance aux API to provide an extra cookie for this stuff so we
 * can get rid of this global variable filth */
static DEFINE_MUTEX(memfd_provision_mtx);
static struct file* memfd_provided = NULL;
static off_t memfd_provided_off = -1;

void efct_provide_bind_memfd(struct file* memfd, off_t memfd_off)
{
  mutex_lock(&memfd_provision_mtx);
  memfd_provided = memfd;
  memfd_provided_off = memfd_off;
}

void efct_unprovide_bind_memfd(off_t *final_off)
{
  if( final_off )
    *final_off = memfd_provided_off;
  memfd_provided = NULL;
  mutex_unlock(&memfd_provision_mtx);
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

static int efct_handle_event(void *driver_data,
                             const struct xlnx_efct_event *event, int budget)
{
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) driver_data;

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

    case XLNX_EVENT_RESET_UP:
    case XLNX_EVENT_RESET_DOWN:
    case XLNX_EVENT_RX_FLUSH:
      return -ENOSYS;
  }
  return -ENOSYS;
}

int efct_request_wakeup(struct efhw_nic_efct *efct, struct efhw_efct_rxq *app,
                        unsigned sbseq, unsigned pktix)
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
    do_wakeup(efct, app, INT_MAX);
    return 0;
  }

  if( ci_xchg32(&app->wake_at_seqno, pkt_seqno) == EFCT_INVALID_PKT_SEQNO )
    ci_atomic32_inc(&q->awaiters);

  ci_mb();
  now = CI_READ_ONCE(q->now);
  if( ! seq_lt(pkt_seqno, now) )
    return 0;

  if( ci_cas32_succeed(&app->wake_at_seqno, pkt_seqno, EFCT_INVALID_PKT_SEQNO) ) {
    ci_atomic32_dec(&q->awaiters);
    do_wakeup(efct, app, INT_MAX);
    return 0;
  }
  return 0;
}

/* Allocating huge pages which are able to be mapped to userspace is a
 * nightmarish problem: the only thing that mmap() will accept is hugetlbfs
 * files, so we need to get ourselves one of them. And there's no single
 * way. */
static struct file* efct_hugetlb_file_setup(off_t* off)
{
  if( memfd_provided ) {
    get_file(memfd_provided);
    *off = memfd_provided_off;
    memfd_provided_off += CI_HUGEPAGE_SIZE;
    return memfd_provided;
  }

#ifdef ERFM_HAVE_NEW_KALLSYMS
  {
    /* This fallback only exists on old kernels, but that's fine: new kernels
     * all have memfd_create, and there's considerable overlap between 'old'
     * and 'new' (e.g. RHEL8) so we can deal with potential oddballs */
    static __typeof__(hugetlb_file_setup)* fn_hugetlb_file_setup;

    if( ! fn_hugetlb_file_setup )
      fn_hugetlb_file_setup = efrm_find_ksym("hugetlb_file_setup");

    if( fn_hugetlb_file_setup ) {
      struct user_struct* user;
      *off = 0;
      return fn_hugetlb_file_setup(HUGETLB_ANON_FILE, CI_HUGEPAGE_SIZE,
                                   0, &user, HUGETLB_ANONHUGE_INODE,
                                   ilog2(CI_HUGEPAGE_SIZE));
    }
  }
#endif

  EFHW_ERR("%s: ERROR: efct hugepages not possible on this kernel",
            __func__);
  return ERR_PTR(-EOPNOTSUPP);
}

static int efct_alloc_hugepage(void *driver_data,
                               struct xlnx_efct_hugepage *result_out)
{
  /* The rx ring is owned by the net driver, not by us, so it does all
   * DMA handling. We do need to supply it with some memory, though. */
  struct xlnx_efct_hugepage result;
  struct inode* inode;
  struct address_space* mapping;
  long rc;
  off_t off;

  result.file = efct_hugetlb_file_setup(&off);
  if( IS_ERR(result.file) ) {
    rc = PTR_ERR(result.file);
    EFHW_ERR("%s: ERROR: insufficient hugepage memory for rxq (%ld)",
             __func__, rc);
    return rc;
  }

  inode = file_inode(result.file);
  if( i_size_read(inode) < off + CI_HUGEPAGE_SIZE ) {
    rc = vfs_truncate(&result.file->f_path, off + CI_HUGEPAGE_SIZE);
    if( rc < 0 ) {
      EFHW_ERR("%s: ERROR: ftruncate hugepage memory failed for rxq (%ld)",
              __func__, rc);
      goto fail;
    }
  }

  rc = vfs_fallocate(result.file, 0, off, CI_HUGEPAGE_SIZE);
  if( rc < 0 ) {
    EFHW_ERR("%s: ERROR: fallocate hugepage memory failed for rxq (%ld)",
             __func__, rc);
    goto fail;
  }

  inode_lock(inode);
  mapping = inode->i_mapping;
  result.page = find_get_page(mapping, off / CI_HUGEPAGE_SIZE);
  inode_unlock(inode);

  if( ! result.page || ! PageHuge(result.page) || PageTail(result.page) ) {
    /* memfd originated in userspace, so we have to check we actually got what
     * we thought we would */
    EFHW_ERR("%s: ERROR: rxq memfd was badly created (%ld / %d / %d)",
             __func__, off, result.page ? PageHuge(result.page) : -1,
             result.page ? PageTail(result.page) : -1);
    rc = -EINVAL;
    goto fail;
  }

  *result_out = result;
  return 0;

 fail:
  if( memfd_provided )
    memfd_provided_off -= CI_HUGEPAGE_SIZE;
  fput(result.file);
  return rc;
}

static void efct_free_hugepage(void *driver_data,
                               struct xlnx_efct_hugepage *mem)
{
  /* EFCT TODO (minor): When we're using a memfd we could fallocate(PUNCH_HOLE)
   * to free up the memory properly, in case the entire file isn't about to be
   * freed */
  put_page(mem->page);
  fput(mem->file);
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

static bool efct_packet_handled(void *driver_data, int rxq, bool flow_lookup,
                                const void* meta, const void* payload)
{
  /* This is all a massive hack, just to make things mostly work for now. A
   * real implementation would either use the flow_lookup or keep a filter
   * table inside Onload */
  const ci_oword_t* header = meta;
  unsigned len = CI_OWORD_FIELD(*header, EFCT_RX_HEADER_PACKET_LENGTH);
  const struct ethhdr* eth = payload + EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
  const struct iphdr* ip = (const struct iphdr*)(eth + 1);

  if( len < sizeof(*eth) + sizeof(*ip) )
    return false;
  if (eth->h_proto != htons(ETH_P_IP) )
    return false;
  return ip->protocol == IPPROTO_UDP || ip->protocol == IPPROTO_TCP;
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
                              struct vi_resource_dimensions *res_dim)
{
  union xlnx_efct_param_value val;
  int rc;
  int i;

  rc = edev->ops->get_param(client, XLNX_EFCT_NIC_RESOURCES, &val);
  if( rc < 0 )
    return rc;

  res_dim->vi_min = val.nic_res.evq_min;
  res_dim->vi_lim = val.nic_res.evq_lim;
  res_dim->mem_bar = VI_RES_MEM_BAR_UNDEFINED;

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
  int i;

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

  for( i = 0; i < CI_ARRAY_SIZE(efct->rxq); ++i)
    INIT_WORK(&efct->rxq[i].destruct_wq, efct_destruct_apps_work);

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
  efct->nic = nic;

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
  for( i = 0; i < CI_ARRAY_SIZE(efct->rxq); ++i ) {
    /* All workqueues should be already shut down by now, but it may happen
     * that the final efct_poll() did not happen.  Do it now. */
    efct_poll(efct, i, 0);
    EFHW_ASSERT(efct->rxq[i].live_apps == NULL);
    EFHW_ASSERT(efct->rxq[i].new_apps == NULL);
  }
  drain_workqueue(system_wq);

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
