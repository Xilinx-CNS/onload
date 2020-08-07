/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2019 Xilinx, Inc. */
#include <ci/efrm/vi_resource_manager.h>
#include <ci/efrm/efrm_nic.h>
#include <ci/efrm/efrm_client.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/internal.h>
#include <ci/efrm/driver_private.h> /* FIXME for efrm_rm_table */
#include "char_internal.h"
#include "linux_char_internal.h"


static DEFINE_MUTEX(efch_mutex);


/* The waittable plugin for efrm_vi */
typedef struct eventq_wait_data_s {
  ci_waitable_t    evq_waitable;
  unsigned         evq_wait_current;
  unsigned         evq_wait_request;

  struct efrm_vi   *evq_virs;
} eventq_wait_data_t;

#define efrm_vi_manager \
  ((struct vi_resource_manager *)efrm_rm_table[EFRM_RESOURCE_VI])

static int
eventq_wait_ctor(struct efrm_vi *evq_virs, eventq_wait_data_t **evdata_out)
{
  eventq_wait_data_t *evdata;
  
  ci_assert(evq_virs);
  evdata = kmalloc(sizeof(eventq_wait_data_t), GFP_KERNEL);
  if (evdata == NULL)
    return -ENOMEM;

  ci_waitable_ctor(&evdata->evq_waitable);
  evdata->evq_wait_current = -1;
  evdata->evq_wait_request = -1;
  evdata->evq_virs = evq_virs;

  *evdata_out = evdata;
  return 0;
}

static void
eventq_wait_dtor(eventq_wait_data_t *evdata)
{
  ci_assert(evdata);
  ci_waitable_dtor(&evdata->evq_waitable);
  kfree(evdata);
}

/* This callback is executed in the context of waker */
static int eventq_wait_all(void *arg, int is_timeout,
                           struct efhw_nic *nic, int budget)
{
  eventq_wait_data_t *evdata = (eventq_wait_data_t *)arg;

  ci_assert(evdata);
  if (is_timeout) 
    return 0;
  ci_waitable_wakeup_all(&evdata->evq_waitable);
  return 1;
}


/* This callback is executed in the context of waiter */
ci_inline int
eventq_wait__on_wakeup(ci_waiter_t* waiter, void* opaque_evdata,
                       void* opaque_nic, int rc,
                       ci_waitable_timeout_t timeout)
{
  eventq_wait_data_t *evdata = (eventq_wait_data_t *)opaque_evdata;
  struct efrm_vi* virs = evdata->evq_virs;
  struct efhw_nic* nic = (struct efhw_nic*) opaque_nic;
  unsigned instance;
  struct efrm_nic_per_vi *cb_info;
  unsigned next_i;

  ci_assert(evdata);
  ci_assert(virs);
  ci_assert(efrm_vi_manager);
  instance = virs->rs.rs_instance;
  cb_info = &efrm_nic(nic)->vis[instance];

  next_i = evdata->evq_wait_request;
  if ( rc == 0 && evdata->evq_wait_current != next_i ) {
    int bit;
    /* Post another request and go back to sleep. */
    bit = test_and_set_bit(VI_RESOURCE_EVQ_STATE_WAKEUP_PENDING,
                           &cb_info->state);
    if (bit) {
      /* This indicates that another process is attempting to do a
       * wait. */
      rc = -EBUSY;
    } else {
      ci_waiter_prepare_continue_to_wait(waiter, &evdata->evq_waitable);
      rc = CI_WAITER_CONTINUE_TO_WAIT;

      evdata->evq_wait_current = next_i;
      efrm_eventq_request_wakeup(virs, next_i);
    }
  }

  if ( rc != CI_WAITER_CONTINUE_TO_WAIT )
    ci_waiter_post(waiter, &evdata->evq_waitable);

  return rc;
}


int
efab_vi_rm_eventq_wait(struct efrm_vi* virs, unsigned current_ptr,
                       struct ci_timeval_s* timeout_tv)
{
  /* We write our current read pointer to the hardware, which compares it
  ** with the write pointer.  If they match, it sets the wakeup bit.
  ** Otherwise it sends us a wakeup event straight-away.
  */
  unsigned next_i;
  ci_waiter_t waiter;
  ci_waitable_timeout_t timeout;
  struct efhw_nic* nic;
  struct efrm_nic_per_vi *cb_info;
  eventq_wait_data_t *evdata;
  int rc, instance, bit;

  ci_assert(virs);
  EFRM_RESOURCE_ASSERT_VALID(&virs->rs, 0);

  if ( virs->q[EFHW_EVQ].capacity == 0 ) {
    EFCH_ERR("%s: ERROR: no on this VI", __FUNCTION__);
    return -EINVAL;
  }

  nic = efrm_client_get_nic(virs->rs.rs_client);

  rc = eventq_wait_ctor(virs, &evdata);
  if (rc < 0)
    return rc;

  next_i = current_ptr / sizeof(efhw_event_t);

  ci_waitable_init_timeout(&timeout, timeout_tv);

  ci_assert(efrm_vi_manager);
  instance = virs->rs.rs_instance;
  cb_info = &efrm_nic(nic)->vis[instance];

  rc = efrm_eventq_register_callback(virs, eventq_wait_all, evdata);
  if (rc < 0)
    goto clear_evdata;

  /* Put ourselves on the wait queue to avoid races. */
  rc = ci_waiter_exclusive_pre(&waiter, &evdata->evq_waitable);
  if (rc < 0)
    goto clear_callback;

  /* Check if we've missed the event before ci_waiter_exclusive_pre() was
   * called */
  if( evdata->evq_wait_current != evdata->evq_wait_request ) {
    ci_waiter_dont_wait(&waiter, &evdata->evq_waitable);
    goto clear_callback;
  }

  bit = test_and_set_bit(VI_RESOURCE_EVQ_STATE_WAKEUP_PENDING, &cb_info->state);
  if (!bit) {
    evdata->evq_wait_current = next_i;
    evdata->evq_wait_request = next_i;
    /* Ask hardware to set wakeup bit / or wake us straight away. */
    efrm_eventq_request_wakeup(virs, next_i);
  } else {
    /* There's a pending wakeup.  Just go to sleep.  When the wakeup
     * occurs, we'll check to see whether it's the one we wanted.  */
    if ( evdata->evq_wait_current != next_i )
      EFCH_TRACE("%s: resuming wakeup: evq_wait_current=%d next_i=%d",
                 __FUNCTION__, evdata->evq_wait_current, next_i);
    evdata->evq_wait_request = next_i;
  }

  rc = ci_waiter_wait(&waiter, &evdata->evq_waitable, &timeout,
                      (void*)evdata, (void*)nic, eventq_wait__on_wakeup);

clear_callback:
  efrm_eventq_kill_callback(virs);
clear_evdata:
  eventq_wait_dtor(evdata);
  return rc;
}


static int efab_vi_rm_prime_cb(void *arg, int is_timeout,
                               struct efhw_nic *nic, int budget)
{
  ci_private_char_t* priv = arg;
  priv->cpcp_readable = 1;
  wake_up_interruptible(&priv->cpcp_poll_queue);
  return 1;
}


static int efab_vi_rm_prime(struct efrm_vi* virs, ci_private_char_t* priv,
                            unsigned current_ptr)
{
  struct efhw_nic* nic = efrm_client_get_nic(virs->rs.rs_client);
  struct efrm_nic_per_vi* cb_info = &efrm_nic(nic)->vis[virs->rs.rs_instance];
  int bit;

  priv->cpcp_readable = 0;
  bit = test_and_set_bit(VI_RESOURCE_EVQ_STATE_WAKEUP_PENDING, &cb_info->state);
  if( ! bit )
    efrm_eventq_request_wakeup(virs, current_ptr / sizeof(efhw_event_t));
  return 0;
}


int efch_vi_prime(ci_private_char_t* priv, efch_resource_id_t vi_rs_id,
                  unsigned current_ptr)
{
  int rc = 0;

  if( priv->cpcp_vi == NULL ) {
    /* First time: Find the VI object. */
    mutex_lock(&efch_mutex);
    if( priv->cpcp_vi == NULL ) {
      efch_resource_t* rs;
      rc = efch_resource_id_lookup(vi_rs_id, &priv->rt, &rs);
      if( rc == 0 ) {
        if( rs->rs_base->rs_type == EFRM_RESOURCE_VI ) {
          struct efrm_vi* virs = efrm_vi(rs->rs_base);
          rc = efrm_eventq_register_callback(virs, efab_vi_rm_prime_cb, priv);
          if( rc == 0 )
            priv->cpcp_vi = virs;
        }
        else {
          rc = -EOPNOTSUPP;
        }
      }
    }
    mutex_unlock(&efch_mutex);
  }
  if( rc < 0 )
    return rc;

  return efab_vi_rm_prime(priv->cpcp_vi, priv, current_ptr);
}


unsigned efch_vi_poll(ci_private_char_t* priv, struct file* filp,
                      poll_table* wait)
{
  poll_wait(filp, &priv->cpcp_poll_queue, wait);
  return priv->cpcp_readable ? POLLIN | POLLRDNORM : 0;
}
