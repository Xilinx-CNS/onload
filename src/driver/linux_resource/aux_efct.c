/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */

#include <ci/efrm/efrm_client.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/efct.h>
#include <ci/tools/sysdep.h>

#include "linux_resource_internal.h"
#include <linux/mman.h>
#include <linux/rwsem.h>
#include <linux/hugetlb.h>
#include <uapi/linux/ip.h>
#include "efrm_internal.h"
#include <ci/driver/kernel_compat.h>
#include <ci/driver/ci_efct.h>
#include <ci/tools/bitfield.h>

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

#define RING_FIFO_ENTRY(q, i)   ((q)[(i) & (ARRAY_SIZE((q)) - 1)])

static bool post_superbuf_to_app(struct efhw_nic_efct_rxq* q, struct efhw_efct_rxq *app);

static void finished_with_superbuf(struct xlnx_efct_device *edev,
                                   struct xlnx_efct_client *client, int qid,
                                   struct efhw_nic_efct_rxq* q,
                                   struct efhw_efct_rxq* app, int sbid)
{
  EFHW_ASSERT(app->current_owned_superbufs > 0);
  EFHW_ASSERT(q->superbuf_refcount[sbid] > 0);
  __clear_bit(sbid, app->owns_superbuf);
  --app->current_owned_superbufs;
  if( --q->superbuf_refcount[sbid] == 0 )
    edev->ops->release_superbuf(client, qid, sbid);

  EFHW_ASSERT(app->current_owned_superbufs < app->max_allowed_superbufs);

  /* perhaps we can feed more buffer(s) to the app */
  post_superbuf_to_app(q, app);
}

static void destruct_apps_work(struct work_struct* work)
{
  struct efhw_nic_efct_rxq *q = container_of(work, struct efhw_nic_efct_rxq,
                                             destruct_wq);
  struct efhw_efct_rxq *app = xchg(&q->destroy_apps, NULL);
  while( app ) {
    struct efhw_efct_rxq *next = app->next;
    EFHW_ASSERT(app->current_owned_superbufs == 0);
    app->freer(app);
    app = next;
  }
}

static void reap_superbufs_from_apps(struct xlnx_efct_device *edev,
                                     struct xlnx_efct_client *client, int qid,
                                     struct efhw_nic_efct_rxq* q)
{
  struct efhw_efct_rxq **pprev;

  for( pprev = &q->live_apps; *pprev; ) {
    struct efhw_efct_rxq *app = *pprev;
    if( app->destroy ) {
      int sbid;
      for_each_set_bit(sbid, app->owns_superbuf, CI_EFCT_MAX_SUPERBUFS)
        finished_with_superbuf(edev, client, qid, q, app, sbid);
      EFHW_ASSERT(app->current_owned_superbufs == 0);
      *pprev = app->next;
      efct_app_list_push(&q->destroy_apps, app);
      schedule_work(&q->destruct_wq);
    }
    else {
      uint32_t added = READ_ONCE(app->shm->freeq.added);
      uint32_t removed = READ_ONCE(app->shm->freeq.removed);
      int maxloop = ARRAY_SIZE(app->shm->freeq.q);
      if( removed != added ) {
        rmb();
        while( removed != added && maxloop-- ) {
          uint16_t id = READ_ONCE(RING_FIFO_ENTRY(app->shm->freeq.q, removed));
          ++removed;

          /* Validate app isn't being malicious: */
          if( id < CI_EFCT_MAX_SUPERBUFS && test_bit(id, app->owns_superbuf) )
            finished_with_superbuf(edev, client, qid, q, app, id);
        }
        smp_store_release(&app->shm->freeq.removed, removed);
      }
      pprev = &(*pprev)->next;
    }
  }
}

static void activate_new_apps(struct efhw_nic_efct_rxq *q)
{
  /* Bolt any newly-added apps on to the live_apps list. The sole reason for
   * this dance is for thread-safety */
  if(unlikely( q->new_apps )) {
    struct efhw_efct_rxq* new_apps = xchg(&q->new_apps, NULL);
    if( new_apps ) {
      struct efhw_efct_rxq* app;
      struct efhw_efct_rxq* last;
      for( app = new_apps; app; app = app->next )
        last = app;
      last->next = q->live_apps;
      q->live_apps = new_apps;
    }
  }
}

static int efct_poll(void *driver_data, int qid, int budget)
{
  struct efhw_nic_efct *efct = driver_data;

  activate_new_apps(&efct->rxq[qid]);
  reap_superbufs_from_apps(efct->edev, efct->client, qid, &efct->rxq[qid]);
  return 0;
}

static int efct_handle_event(void *driver_data,
                             const struct xlnx_efct_event *event)
{
  return -ENOSYS;
}

/* returns true if we can/should squeeze more buffers into the app */
bool post_superbuf_to_app(struct efhw_nic_efct_rxq* q, struct efhw_efct_rxq *app)
{
  uint32_t driver_buf_count;
  uint32_t sbuf_seq;
  uint16_t sbid_sentinel;
  uint16_t sbid;

  uint32_t added;
  uint32_t removed;


  if( app->destroy )
    return false;

  if( app->next_sbuf_seq == q->sbufs.added )
    /* nothing new */
    return false;

  if( app->current_owned_superbufs >= app->max_allowed_superbufs ) {
    ++app->shm->stats.too_many_owned;
    return false;
  }

  added = (uint32_t)READ_ONCE(app->shm->rxq.added);
  removed = READ_ONCE(app->shm->rxq.removed);
  if( (uint32_t)(added - removed) >= ARRAY_SIZE(app->shm->rxq.q) ) {
    /* the shared state is actually corrupted */
    EFHW_ASSERT(app->max_allowed_superbufs <= ARRAY_SIZE(app->shm->rxq.q));
    ++app->shm->stats.no_rxq_space;
    return false;
  }

  driver_buf_count = q->sbufs.added - q->sbufs.removed;
  EFHW_ASSERT(driver_buf_count <= ARRAY_SIZE(q->sbufs.q));

  /* pick the next buffer the app wants ... unless there is something wrong
   * (e.g. the app got stalled) in that case pick the oldest sbuf we have
   */
  if( (uint32_t)(q->sbufs.added - app->next_sbuf_seq) < driver_buf_count &&
      (uint32_t)(app->next_sbuf_seq - q->sbufs.removed) < driver_buf_count )
    sbuf_seq = app->next_sbuf_seq;
  else
    sbuf_seq = q->sbufs.removed;

  sbid_sentinel = q->sbufs.q[sbuf_seq % CI_ARRAY_SIZE(q->sbufs.q)];
  sbid = sbid_sentinel & CI_EFCT_Q_SUPERBUF_ID_MASK;
  app->next_sbuf_seq = sbuf_seq + 1;

  ++q->superbuf_refcount[sbid];
  ++app->current_owned_superbufs;
  __set_bit(sbid, app->owns_superbuf);
  RING_FIFO_ENTRY(app->shm->rxq.q, added) = sbid_sentinel;
  smp_store_release(&app->shm->rxq.added,
                    ((uint64_t)sbuf_seq << 32) | (added + 1));
  return true;
}

static bool post_superbuf_to_apps(struct efhw_nic_efct_rxq* q)
{
  struct efhw_efct_rxq *app;

  for( app = q->live_apps; app; app = app->next ) {
    /* post app to single buffer */
    post_superbuf_to_app(q, app);
  }
  return true;
}


/* net driver finished processing packets from the buffer,
 * check whether we can free the buffer */
static int efct_buffer_end(void *driver_data, int qid, int sbid, bool force)
{
  /* TODO support force flag */
  struct efhw_nic_efct *efct = driver_data;
  struct efhw_nic_efct_rxq *q;
  EFHW_ASSERT(sbid >= 0);
  EFHW_ASSERT(sbid < CI_EFCT_MAX_SUPERBUFS);
  q = &efct->rxq[qid];
  EFHW_ASSERT((uint32_t)(q->sbufs.added - q->sbufs.removed) < ARRAY_SIZE(q->sbufs.q));
  EFHW_ASSERT((q->sbufs.q[q->sbufs.removed % CI_ARRAY_SIZE(q->sbufs.q)] & CI_EFCT_Q_SUPERBUF_ID_MASK) == sbid);
  q->sbufs.removed++;
  EFHW_ASSERT((int)q->superbuf_refcount[sbid] > 0);
  return --q->superbuf_refcount[sbid] == 0;
}


static int efct_buffer_start(void *driver_data, int qid, int sbid,
                             bool sentinel)
{
  struct efhw_nic_efct *efct = driver_data;
  struct efhw_nic_efct_rxq *q;

  EFHW_ASSERT(sbid < CI_EFCT_MAX_SUPERBUFS);
  q = &efct->rxq[qid];

  if( sbid < 0 )
    return -1;

  /* remember buffers owned by x3net */
  ++q->superbuf_refcount[sbid];
  q->sbufs.q[(q->sbufs.added++) % CI_ARRAY_SIZE(q->sbufs.q)] = sbid | (sentinel << 15);

  activate_new_apps(q);
  post_superbuf_to_apps(q);
  return 1; /* always hold on to buffer until efct_buffer_end() is called */
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
  i_mmap_lock_read(mapping);
  result.page = find_get_page(mapping, off / CI_HUGEPAGE_SIZE);
  i_mmap_unlock_read(mapping);
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
  struct efhw_nic_efct *efct = driver_data;
  struct efhw_nic_efct_rxq *q = &efct->rxq[rxq];
  struct efhw_efct_rxq *app;

  for( app = q->live_apps; app; app = app->next ) {
    if( ! app->destroy ) {
      unsigned new_gen = app->shm->config_generation + 1;
      /* Avoid 0 so that the reader can always use it as a 'not yet initialised'
      * marker. */
      if( new_gen == 0 )
        ++new_gen;
      WRITE_ONCE(app->shm->config_generation, new_gen);
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

  for( i = 0; i < ARRAY_SIZE(efct->rxq); ++i)
    INIT_WORK(&efct->rxq[i].destruct_wq, destruct_apps_work);

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
