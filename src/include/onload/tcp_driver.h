/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: slp
**     Started: 2005/04/22
** Description: Interface for the tcp driver pluggin. This is all the
** stuff, control plane and asynchronous threads which is requried to
** support a ULTCP stack
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */

#ifndef __CI_DRIVER_EFAB_TCP_DRIVER_H__
#define __CI_DRIVER_EFAB_TCP_DRIVER_H__

#include <ci/driver/internal.h>
#include <onload/ipid.h>
#include <onload/id_pool.h>
#include <onload/tcp_helper.h>


/* Table of TCP helpers. Contains all TCP helpers created by the driver.
 * Should be grown  if necessary.
 */
typedef struct {
  /*! Instances of tcp helpers */
  ci_id_pool_t  instances;

  /*! List of all stacks (orphaned or not).
   *  It does not include those being created or destroyed. */
  ci_dllist     all_stacks;

  /*! List of not-yet-created stacks: used to reset them when necessary. */
  ci_dllist     started_stacks;

  /*! Tracks stack count from creation to destruction: used to prevent
   *  interfaces from going down. */
  ci_uint32     stack_count;

  /*! Lock */
  ci_irqlock_t  lock;
} tcp_helpers_table_t;


/*----------------------------------------------------------------------------
 *
 * tcp driver interface
 * \todo FIXME split this structure (and global variable efab_tcp_driver)
 * into separate fields.
 *
 *---------------------------------------------------------------------------*/


struct oo_filter_ns_manager;
typedef struct efab_tcp_driver_s {

  /*! TCP helpers table */
  tcp_helpers_table_t     thr_table;

  /* ID field in the IP header handling */
  efab_ipid_cb_t          ipid;         /* see ipid.h in this dir. */

  /*! Management of per-namespace filter state */
  struct oo_filter_ns_manager *filter_ns_manager;

  /*! work queue */
  struct workqueue_struct      *workqueue;

  /*! Number of pages pinned by all sendpage() users */
  ci_atomic_t sendpage_pinpages_n;
  /*! An overall limit of pinned pages for all sendpage() users */
  int sendpage_pinpages_max;

#if CI_CFG_HANDLE_ICMP
  struct efx_dlfilt_cb_s* dlfilter;
#endif

  /* Dynamic stack list update: flag and wait queue.  Used by tcpdump */
  ci_uint32         stack_list_seq;
  ci_waitq_t        stack_list_wq;

  ci_uint32         load_numa_node;

  /* Timesync object to be mmaped to UL with each netif */
  struct page        *timesync_page;
  struct oo_timesync *timesync;

} efab_tcp_driver_t;


/* Global structure for onload driver */
extern efab_tcp_driver_t efab_tcp_driver;


#define THR_TABLE                (efab_tcp_driver.thr_table)
#define CI_GLOBAL_WORKQUEUE      (efab_tcp_driver.workqueue)


#endif /* __CI_DRIVER_EFAB_TCP_DRIVER_H__ */
/*! \cidoxg_end */
