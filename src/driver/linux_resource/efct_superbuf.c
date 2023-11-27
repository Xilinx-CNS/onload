/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */

#ifdef __KERNEL__
#include <ci/driver/kernel_compat.h>
#include <ci/efhw/debug_linux.h>

#endif

#include <ci/tools/sysdep.h>
#include <ci/efhw/efct.h>
#include <ci/driver/ci_efct.h>
#include <ci/internal/seq.h>
#include "efct_superbuf.h"

#if CI_HAVE_EFCT_AUX

#define RING_FIFO_ENTRY(q, i)   ((q)[(i) & (CI_ARRAY_SIZE((q)) - 1)])

/* returns true if we can/should squeeze more buffers into the app */
static bool post_superbuf_to_app(struct efhw_nic_efct_rxq* q, struct efhw_efct_rxq *app)
{
  uint32_t sbuf_seq;
  struct efab_efct_rxq_uk_shm_rxq_entry sbufs_q_entry;
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

  added = CI_READ_ONCE(app->shm->rxq.added);
  removed = CI_READ_ONCE(app->shm->rxq.removed);
  if( (uint32_t)(added - removed) >= CI_ARRAY_SIZE(app->shm->rxq.q) ) {
    ++app->shm->stats.no_rxq_space;
    return false;
  }

  /* pick the next buffer the app wants ... unless there is something wrong
   * (e.g. the app got stalled) in that case pick the oldest sbuf we have
   */
  if( SEQ_LE(q->sbufs.oldest_app_seq, app->next_sbuf_seq) ) {
    sbuf_seq = app->next_sbuf_seq;
  } else {
    sbuf_seq = q->sbufs.oldest_app_seq;
    app->shm->stats.skipped_bufs += (q->sbufs.oldest_app_seq - app->next_sbuf_seq);
    /* If an app has fallen behind, we should never advance up to added */
    EFHW_ASSERT(SEQ_LT(q->sbufs.oldest_app_seq, q->sbufs.added));
  }

  sbufs_q_entry = q->sbufs.q[sbuf_seq % CI_ARRAY_SIZE(q->sbufs.q)];
  sbid = sbufs_q_entry.sbid;
  app->next_sbuf_seq = sbuf_seq + 1;

  ++q->superbuf_refcount[sbid];
  ++app->current_owned_superbufs;
  EFHW_ASSERT(!ci_bit_test(app->owns_superbuf, sbid));
  __ci_bit_set(app->owns_superbuf, sbid);
  RING_FIFO_ENTRY(app->shm->rxq.q, added) = sbufs_q_entry;
  ci_wmb();
  CI_WRITE_ONCE(app->shm->rxq.added, added + 1);
  return true;
}

static bool drop_sbuf_ref(struct xlnx_efct_device *edev,
                          struct xlnx_efct_client *client, int qid,
                          struct efhw_nic_efct_rxq* q,
                          int sbid)
{
  if( --q->superbuf_refcount[sbid] == 0 ) {
    edev->ops->release_superbuf(client, qid, sbid);
    --q->total_sbufs;
    return true;
  }
  return false;
}

static uint32_t next_app_seq_min(struct efhw_efct_rxq *app,
                         struct efhw_nic_efct_rxq* q,
                         uint32_t min) {
  if( SEQ_LT(app->next_sbuf_seq, q->sbufs.oldest_app_seq) ) {
    app->shm->stats.skipped_bufs += q->sbufs.oldest_app_seq - app->next_sbuf_seq;
    app->next_sbuf_seq = q->sbufs.oldest_app_seq;
  }
  return SEQ_MIN(app->next_sbuf_seq, min);
}

static void advance_oldest_app_seq(struct xlnx_efct_device *edev,
                               struct xlnx_efct_client *client, int qid,
                               struct efhw_nic_efct_rxq* q, uint32_t until) {
  EFHW_ASSERT(SEQ_GE(until, q->sbufs.oldest_app_seq));
  while(q->sbufs.oldest_app_seq != until) {
    uint16_t sbid_to_drop = q->sbufs.q[q->sbufs.oldest_app_seq++ %
                                       CI_ARRAY_SIZE(q->sbufs.q)].sbid;
    drop_sbuf_ref(edev, client, qid, q, sbid_to_drop);
  }
}

static void update_oldest_app_seq(struct xlnx_efct_device *edev,
                              struct xlnx_efct_client *client, int qid,
                              struct efhw_nic_efct_rxq* q)
{
  /* Update the oldest_app_seq pointer. When it advances, drop references
   * to the sbufs it went past. */
  uint32_t min = q->sbufs.added;
  struct efhw_efct_rxq *app;
  for( app = q->live_apps; app; app = app->next ) {
    min = next_app_seq_min(app, q, min);
  }

  advance_oldest_app_seq(edev, client, qid, q, min);
}

static bool post_superbuf_to_apps(struct xlnx_efct_device *edev,
                                  struct xlnx_efct_client *client,
                                  int qid,
                                  struct efhw_nic_efct_rxq* q)
{
  struct efhw_efct_rxq *app;
  bool is_successful_post = false;
  uint32_t min = q->sbufs.added;

  for( app = q->live_apps; app; app = app->next ) {
    /* post app to single buffer */
    is_successful_post |= post_superbuf_to_app(q, app);
    min = next_app_seq_min(app, q, min);
  }
  if( is_successful_post )
    advance_oldest_app_seq(edev, client, qid, q, min);
  return true;
}

static void skip_sbufs(struct xlnx_efct_device *edev,
                       struct xlnx_efct_client *client,
                       int qid,
                       struct efhw_nic_efct_rxq* q)
{
  /* Starting from removed, find and drop superbufs until one is freed
   * or `q->sbufs.oldest_app_seq >= q->sbufs.removed`. There is no point
   * in skipping past bufs the driver hasn't yet removed. */
  uint16_t sbid_to_free;
  do {
    if( SEQ_GE(q->sbufs.oldest_app_seq, q->sbufs.removed) )
      return;
    sbid_to_free = q->sbufs.q[q->sbufs.oldest_app_seq++ % CI_ARRAY_SIZE(q->sbufs.q)].sbid;
  } while(!drop_sbuf_ref(edev, client, qid, q, sbid_to_free));
}

static void finished_with_superbuf(struct xlnx_efct_device *edev,
                                   struct xlnx_efct_client *client, int qid,
                                   struct efhw_nic_efct_rxq* q,
                                   struct efhw_efct_rxq* app, int sbid)
{
  EFHW_ASSERT(app->current_owned_superbufs > 0);
  EFHW_ASSERT(q->superbuf_refcount[sbid] > 0);
  /* check for wrap around, using max number of references <= CI_EFCT_MAX_SUPERBUFS
   * as clients are limited by number of superbufs */
  EFHW_ASSERT(q->superbuf_refcount[sbid] <= CI_EFCT_MAX_SUPERBUFS);
  EFHW_ASSERT(ci_bit_test(app->owns_superbuf, sbid));
  __ci_bit_clear(app->owns_superbuf, sbid);
  --app->current_owned_superbufs;
  drop_sbuf_ref(edev, client, qid, q, sbid);
  EFHW_ASSERT(app->current_owned_superbufs < app->max_allowed_superbufs);
  /* perhaps we can feed more buffer(s) to the app */
  if(post_superbuf_to_app(q, app))
    update_oldest_app_seq(edev, client, qid, q);
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

      ci_bit_for_each_set(sbid, app->owns_superbuf, CI_EFCT_MAX_SUPERBUFS)
        finished_with_superbuf(edev, client, qid, q, app, sbid);
      EFHW_ASSERT(app->current_owned_superbufs == 0);

      /* Now this app is destroyed, its donated sbufs are gone and so
       * we must free sbufs until we have an apropriate amount. */
      *pprev = app->next;
      q->apps_max_sbufs -= app->max_allowed_superbufs;
      while( SEQ_LT(q->sbufs.oldest_app_seq, q->sbufs.removed) &&
             q->total_sbufs > q->apps_max_sbufs )
        skip_sbufs(edev, client, qid, q);
      efct_app_list_push(&q->destroy_apps, app);
      schedule_work(&q->destruct_wq);
    }
    else {
      uint32_t added = CI_READ_ONCE(app->shm->freeq.added);
      uint32_t removed = CI_READ_ONCE(app->shm->freeq.removed);
      int maxloop = CI_ARRAY_SIZE(app->shm->freeq.q);
      if( removed != added ) {
        ci_rmb();
        while( removed != added && maxloop-- ) {
          uint16_t id = CI_READ_ONCE(RING_FIFO_ENTRY(app->shm->freeq.q, removed));
          ++removed;

          /* Validate app isn't being malicious: */
          if( id < CI_EFCT_MAX_SUPERBUFS && ci_bit_test(app->owns_superbuf, id) )
            finished_with_superbuf(edev, client, qid, q, app, id);
        }
        ci_wmb();
        CI_WRITE_ONCE(app->shm->freeq.removed, removed);
      }
      pprev = &(*pprev)->next;
    }
  }
}

static void activate_new_apps(struct efhw_nic_efct_rxq *q)
{
  /* Bolt any newly-added apps on to the live_apps list. The sole reason for
   * this dance is for thread-safety */
  if(CI_UNLIKELY( !! q->new_apps )) {
    struct efhw_efct_rxq* new_apps = (struct efhw_efct_rxq*)
      ci_xchg_uintptr(&q->new_apps, (ci_uintptr_t) (NULL));
    if( new_apps ) {
      struct efhw_efct_rxq* app;
      struct efhw_efct_rxq* last;
      for( app = new_apps; app; app = app->next ) {
        /* Set from which superbuf we want the app to start reading packets.
         * This relies on activate_new_apps being called during or not too long after
         * efct_nic_rxq_bind.
         * Currently, efct_nic_rxq_bind calls x3net's rollover_rxq. And
         * x3net's rollover_rxq calls our efct_buffer_start
         * which calls this function. And we rely on x3net's rollover_rxq behaviour
         * for corner cases. */
        app->next_sbuf_seq = q->sbufs.added;
        app->shm->time_sync = q->time_sync;
        last = app;
        q->apps_max_sbufs += app->max_allowed_superbufs;
      }
      last->next = q->live_apps;
      q->live_apps = new_apps;
    }
  }
}

void efct_destruct_apps_work(struct work_struct* work)
{
  struct efhw_nic_efct_rxq *q = CI_CONTAINER(struct efhw_nic_efct_rxq,
                                             destruct_wq, work);
  struct efhw_efct_rxq *app = (struct efhw_efct_rxq *)
    ci_xchg_uintptr(&q->destroy_apps, (ci_uintptr_t) (NULL));
  while( app ) {
    struct efhw_efct_rxq *next = app->next;
    EFHW_ASSERT(app->current_owned_superbufs == 0);
    app->freer(app);
    app = next;
  }
}

int efct_poll(void *driver_data, int qid, int budget)
{
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) driver_data;

  activate_new_apps(&efct->rxq[qid]);
  reap_superbufs_from_apps(efct->edev, efct->client, qid, &efct->rxq[qid]);
  return 0;
}

/* net driver finished processing packets from the buffer,
 * check whether we can free the buffer */
int efct_buffer_end(void *driver_data, int qid, int sbid, bool force)
{
  /* TODO support force flag */
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) driver_data;

  struct efhw_nic_efct_rxq *q;
  bool free_sbuf;
  EFHW_ASSERT(sbid >= 0);
  EFHW_ASSERT(sbid < CI_EFCT_MAX_SUPERBUFS);
  q = &efct->rxq[qid];
  EFHW_ASSERT((uint32_t)(q->sbufs.added - q->sbufs.removed) <
              CI_ARRAY_SIZE(q->sbufs.q));
  EFHW_ASSERT(q->sbufs.q[q->sbufs.removed % CI_ARRAY_SIZE(q->sbufs.q)].sbid == sbid);
  q->sbufs.removed++;

  EFHW_ASSERT((int)q->superbuf_refcount[sbid] > 0);

  if( q->total_sbufs > q->apps_max_sbufs )
    skip_sbufs(efct->edev, efct->client, qid, q);

  free_sbuf = --q->superbuf_refcount[sbid] == 0;
  q->total_sbufs -= free_sbuf;
  return free_sbuf;
}

int efct_buffer_start(void *driver_data, int qid, unsigned sbseq,
                             int sbid, bool sentinel)
{
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) driver_data;
  struct efhw_nic_efct_rxq *q;
  struct efab_efct_rxq_uk_shm_rxq_entry entry;

  EFHW_ASSERT(sbid < CI_EFCT_MAX_SUPERBUFS);
  q = &efct->rxq[qid];
  if( sbid < 0 )
    return -1;

  activate_new_apps(q);
  EFHW_ASSERT(q->apps_max_sbufs <= CI_EFCT_MAX_SUPERBUFS);
  /* We have taken too many sbufs from x3-net, we need to skip buffers
   * and return the oldest one. */
  if( q->total_sbufs >= q->apps_max_sbufs )
    skip_sbufs(efct->edev, efct->client, qid, q);
  /* buffers owned by x3net, Also add a ref as the sbuf hasn't been
   * removed */
  q->superbuf_refcount[sbid] = 2;
  entry.sbid = sbid;
  entry.sentinel = sentinel;
  entry.sbseq = sbseq;
  q->sbufs.q[(q->sbufs.added++) % CI_ARRAY_SIZE(q->sbufs.q)] = entry;

  ++q->total_sbufs;
  post_superbuf_to_apps(efct->edev, efct->client, qid, q);
  return 1; /* always hold on to buffer until efct_buffer_end() is called */
}

int
__efct_nic_rxq_bind(struct xlnx_efct_device* edev,
                    struct xlnx_efct_client* cli,
                    struct xlnx_efct_rxq_params *rxq_params,
                    struct efhw_nic_efct *efct,
                    int n_hugepages,
                    struct efab_efct_rxq_uk_shm_q *shm,
                    unsigned wakeup_instance,
                    struct efhw_efct_rxq *rxq)
{

  int rc;


  rxq->n_hugepages = n_hugepages;
  rxq->max_allowed_superbufs = n_hugepages * CI_EFCT_SUPERBUFS_PER_PAGE;
  rxq->shm = shm;
  rxq->wakeup_instance = wakeup_instance;
  rxq->wake_at_seqno = EFCT_INVALID_PKT_SEQNO;

  rc = edev->ops->bind_rxq(cli, rxq_params);
  if( rc >= 0 ) {
    struct efhw_nic_efct_rxq *q = &efct->rxq[rc];

    /* Poison the start of each packet buffer with the appropriate value for
     * tcpdirect's packet header detection.
     * EFCT TODO: rationalise other uses of poison (onload, and tcpdirect's
     * partial-packet detection) so they all take the same value.
     */
    union xlnx_efct_param_value poison = {
      .poison = {
        .qid = rc,
        .value = CI_EFCT_DEFAULT_POISON,
        .length = 8
      }
    };
    edev->ops->set_param(cli, XLNX_EFCT_POISON_CONFIG, &poison);

    rxq->qid = rc;
    efct_app_list_push(&q->new_apps, rxq);
    edev->ops->rollover_rxq(cli, rxq->qid);
  }

  if( rc >= 0 ) {
    shm->qid = rc;
    shm->superbuf_pkts = EFCT_RX_SUPERBUF_BYTES / EFCT_PKT_STRIDE;
  }

  return rc;
}

void
__efct_nic_rxq_free(struct xlnx_efct_device* edev,
                    struct xlnx_efct_client* cli,
                    struct efhw_efct_rxq *rxq,
                    efhw_efct_rxq_free_func_t *freer)
{
  rxq->shm->superbuf_pkts = 0;
  rxq->destroy = true;
  rxq->freer = freer;
  edev->ops->free_rxq(cli, rxq->qid, rxq->n_hugepages);
}

#endif
