/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file linux_stats.c OS Interface for reporting network statistics
** <L5_PRIVATE L5_SOURCE>
** \author  Level 5
**  \brief  Package - driver/linux/net	Linux network driver support
**     $Id$
**   \date  2004/09
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */

 
/*--------------------------------------------------------------------
 *
 * Compile time assertions for this file
 *
 *--------------------------------------------------------------------*/

#define __ci_driver_shell__	/* implements driver to kernel interface */

/*--------------------------------------------------------------------
 *
 * CI headers
 *
 *--------------------------------------------------------------------*/

#include "onload_internal.h"
#include <onload/linux_onload_internal.h>
#include <onload/tcp_helper_fns.h>
#include <onload/tcp_driver.h>
#include <ci/internal/ip.h>
#include <ci/internal/ip_log.h>

#include <ci/internal/ip.h>
#include <onload/version.h>
#include <onload/driverlink_filter.h>
#include <onload/nic.h>
#include <onload/oof_onload.h>
#include <onload/oof_interface.h>

#include <net/tcp.h>
#include <net/udp.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include "../linux_resource/kernel_compat.h"

#if 0
#undef LOG_STATS
#define LOG_STATS(x) x
#endif


/*--------------------------------------------------------------------
 *
 * Local constant declarations
 *
 *--------------------------------------------------------------------*/

/* Maximum time in jiffies for which stats from NIC structure is steel up
 * to date */
#define CI_LINUX_STATISTICS_UPDATE_FREQUENCY    1


/** Top level directory for sfc specific stats **/
struct proc_dir_entry *oo_proc_root = NULL;


/*--------------------------------------------------------------------
 *
 * Local function declarations
 *
 *--------------------------------------------------------------------*/

static const struct proc_ops efab_version_fops;
#if CI_CFG_HANDLE_ICMP
static const struct proc_ops efab_dlfilters_fops;
#endif

/*--------------------------------------------------------------------
 *
 * Private proc entries table
 *
 *--------------------------------------------------------------------*/

/* Entries under /proc/drivers/sfc */
typedef struct ci_proc_efab_entry_s {
  char                   *name;  /**< Entry name */
  const struct proc_ops  *fops;  /**< Proc file operations */
} ci_proc_efab_entry_t;
static ci_proc_efab_entry_t ci_proc_efab_table[] = {
    {"version",       &efab_version_fops},
#if CI_CFG_HANDLE_ICMP
    {"dlfilters",     &efab_dlfilters_fops},
#endif
};

#define CI_PROC_EFAB_TABLE_SIZE \
    (sizeof(ci_proc_efab_table) / sizeof(ci_proc_efab_entry_t))


/****************************************************************************
 *
 * /proc/drivers/onload/stacks
 *
 ****************************************************************************/

#if CI_CFG_STATS_NETIF

static void *
efab_stacks_seq_start(struct seq_file *seq, loff_t *ppos)
{
  ci_netif *ni = NULL;
  int i, rc;

  for( i = 0; i <= *ppos; i++) {
    rc = iterate_netifs_unlocked(&ni, 0, 0);
    if( rc != 0 )
      return NULL;
  }
  return ni;
}

static void *
efab_stacks_seq_next(struct seq_file *seq, void *v, loff_t *ppos)
{
  ci_netif *ni = v;
  int rc;
  (*ppos)++;
  rc = iterate_netifs_unlocked(&ni, 0, 0);
  if( rc != 0 )
    return NULL;
  return ni;
}

static void
efab_stacks_seq_stop(struct seq_file *seq, void *v)
{
  if( v )
    iterate_netifs_unlocked_dropref(v);
}

static int
efab_stacks_seq_show(struct seq_file *seq, void *v)
{
  ci_netif *ni = v;
  ci_netif_stats* s = &ni->state->stats;
  tcp_helper_resource_t* thr = netif2tcp_helper_resource(ni);
  int upid;
  uid_t kuid = ci_make_kuid(tcp_helper_get_user_ns(thr), ni->state->uuid);
  uid_t uuid = ci_current_from_kuid_munged(kuid);
  rcu_read_lock();
  upid = pid_vnr(ci_netif_pid_lookup(ni, ni->state->pid));
  rcu_read_unlock();
  seq_printf(seq,
             "%d: %d %d %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",
             NI_ID(ni), upid, uuid,
             s->periodic_polls, s->periodic_evs,
             s->timeout_interrupts, s->interrupts, s->interrupt_polls,
             s->interrupt_wakes, s->interrupt_evs,
             s->interrupt_primes, s->muxer_primes,
             s->sock_wakes_rx + s->sock_wakes_tx +
             s->sock_wakes_rx_os + s->sock_wakes_tx_os,
             s->pkt_wakes, s->unlock_slow,
             s->lock_wakes, s->deferred_work, s->sock_lock_sleeps,
             s->rx_evs, s->tx_evs);
  return 0;
}

static struct seq_operations efab_stacks_seq_ops = {
  .start    = efab_stacks_seq_start,
  .next     = efab_stacks_seq_next,
  .stop     = efab_stacks_seq_stop,
  .show     = efab_stacks_seq_show,
};

static int
efab_stacks_seq_open(struct inode *inode, struct file *file)
{
  return seq_open(file, &efab_stacks_seq_ops);

}
static struct proc_ops efab_stacks_seq_fops = {
  PROC_OPS_SET_OWNER
  .proc_open     = efab_stacks_seq_open,
  .proc_read     = seq_read,
  .proc_lseek    = seq_lseek,
  .proc_release  = seq_release_private,
};


/* /proc/driver/onload/stacks_ul - user-level mapped stacks (excluding
 * orphans/zombies)
 */

static void *
efab_stacks_seq_start_ul(struct seq_file *seq, loff_t *ppos)
{
  ci_netif *ni = NULL;
  int i, rc;

  for( i = 0; i <= *ppos; i++) {
    rc = iterate_netifs_unlocked(&ni, 0, 1);
    if( rc != 0 )
      return NULL;
  }
  return ni;
}

static void *
efab_stacks_seq_next_ul(struct seq_file *seq, void *v, loff_t *ppos)
{
  ci_netif *ni = v;
  int rc;
  (*ppos)++;
  rc = iterate_netifs_unlocked(&ni, 0, 1);
  if( rc != 0 )
    return NULL;
  return ni;
}

static struct seq_operations efab_stacks_ul_seq_ops = {
  .start    = efab_stacks_seq_start_ul,
  .next     = efab_stacks_seq_next_ul,
  .stop     = efab_stacks_seq_stop,
  .show     = efab_stacks_seq_show,
};

static int
efab_stacks_ul_seq_open(struct inode *inode, struct file *file)
{
  return seq_open(file, &efab_stacks_ul_seq_ops);

}
static struct proc_ops efab_stacks_ul_seq_fops = {
  PROC_OPS_SET_OWNER
  .proc_open     = efab_stacks_ul_seq_open,
  .proc_read     = seq_read,
  .proc_lseek    = seq_lseek,
  .proc_release  = seq_release_private,
};


/* /proc/driver/onload/stacks_k - kernel-only stacks (aka orphans/zombies) */

static void *
efab_stacks_seq_start_k(struct seq_file *seq, loff_t *ppos)
{
  ci_netif *ni = NULL;
  int i, rc;

  for( i = 0; i <= *ppos; i++) {
    rc = iterate_netifs_unlocked(&ni, 1, 0);
    if( rc != 0 )
      return NULL;
  }
  return ni;
}

static void *
efab_stacks_seq_next_k(struct seq_file *seq, void *v, loff_t *ppos)
{
  ci_netif *ni = v;
  int rc;
  (*ppos)++;
  rc = iterate_netifs_unlocked(&ni, 1, 0);
  if( rc != 0 )
    return NULL;
  return ni;
}

static struct seq_operations efab_stacks_k_seq_ops = {
  .start    = efab_stacks_seq_start_k,
  .next     = efab_stacks_seq_next_k,
  .stop     = efab_stacks_seq_stop,
  .show     = efab_stacks_seq_show,
};

static int
efab_stacks_k_seq_open(struct inode *inode, struct file *file)
{
  return seq_open(file, &efab_stacks_k_seq_ops);

}
static struct proc_ops efab_stacks_k_seq_fops = {
   PROC_OPS_SET_OWNER
  .proc_open     = efab_stacks_k_seq_open,
  .proc_read     = seq_read,
  .proc_lseek    = seq_lseek,
  .proc_release  = seq_release_private,
};


#endif


/****************************************************************************
 *
 * /proc/driver/onload/version
 *
 ****************************************************************************/

static int 
efab_version_read_proc(struct seq_file *seq, void *s)
{
  seq_printf(seq, "onload_product: %s\n", ONLOAD_PRODUCT);
  seq_printf(seq, "onload_version: %s\n", ONLOAD_VERSION);
  seq_printf(seq, "uk_intf_ver: %s\n", oo_uk_intf_ver);
  return 0;
}
static int efab_version_open_proc(struct inode *inode, struct file *file)
{
    return single_open(file, efab_version_read_proc, 0);
}
static const struct proc_ops efab_version_fops = {
   PROC_OPS_SET_OWNER
    .proc_open    = efab_version_open_proc,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};


#if CI_CFG_HANDLE_ICMP
/****************************************************************************
 *
 * /proc/driver/onload/dlfilters
 *
 ****************************************************************************/

static int 
efab_dlfilters_read_proc(struct seq_file *seq, void *s)
{
  int no_empty, no_tomb, no_used;

  efx_dlfilter_count_stats(efab_tcp_driver.dlfilter,
                           &no_empty, &no_tomb, &no_used);
  seq_printf(seq, "dlfilters: empty=%d, tomb=%d, used=%d\n",
             no_empty, no_tomb, no_used);
  return 0;
}
static int efab_dlfilters_open_proc(struct inode *inode, struct file *file)
{
    return single_open(file, efab_dlfilters_read_proc, 0);
}
static const struct proc_ops efab_dlfilters_fops = {
     PROC_OPS_SET_OWNER
    .proc_open    = efab_dlfilters_open_proc,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};
#endif


/****************************************************************************
 *
 * Install new proc entries
 *
 ****************************************************************************/
/**
 * Install read-only files into /proc/drivers/onload as requested
 * by the table in the argument.
 */
static void
ci_proc_files_install(struct proc_dir_entry *root, char *root_name,
                      ci_proc_efab_entry_t *entries, int num_entries)
{
  int entry_no;

  /* create new etherfabric specific proc entries */
  for (entry_no = 0; entry_no < num_entries; entry_no++) {
    ci_proc_efab_entry_t  *efab_entry = &entries[entry_no];

    OO_DEBUG_STATS(ci_log("Create %s/%s: read_proc=%p",
                      root_name, efab_entry->name, efab_entry->fops));

    if (proc_create(efab_entry->name, 0, root, efab_entry->fops)
        == NULL) {

      ci_log("Unable to create %s/%s: fops=%p",
             root_name, efab_entry->name, efab_entry->fops);

      /* we're not registering any methods off the proc entry so if we
         fail outcome is just that our entry doesn't get put into /proc
      */

    }
  }
}

/**
 * Install read-only files into /proc/drivers/sfc as requested by the table
 * in the argument.
 */
static void
ci_proc_files_uninstall(struct proc_dir_entry *root,
                        ci_proc_efab_entry_t *entries, int num_entries)
{
  int entry_no;

  /* remove etherfabric specific proc entries */
  for (entry_no = 0; entry_no < num_entries; entry_no++)
    remove_proc_entry(entries[entry_no].name, root);
}

static int oo_filter_hwports_read(struct seq_file *seq, void *unused)
{
  return oof_onload_hwports_list(&efab_tcp_driver, seq);
}
static int oo_filter_hwports_open(struct inode *inode, struct file *file)
{
    return single_open(file, oo_filter_hwports_read, PDE_DATA(inode));
}
static const struct proc_ops oo_filter_hwports_fops = {
    PROC_OPS_SET_OWNER
    .proc_open    = oo_filter_hwports_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int oo_filter_ipaddrs_read(struct seq_file *seq, void *unused)
{
  return oof_onload_ipaddrs_list(&efab_tcp_driver, seq);
}
static int oo_filter_ipaddrs_open(struct inode *inode, struct file *file)
{
    return single_open(file, oo_filter_ipaddrs_read, PDE_DATA(inode));
}
static const struct proc_ops oo_filter_ipaddrs_fops = {
    PROC_OPS_SET_OWNER
    .proc_open    = oo_filter_ipaddrs_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static const struct proc_ops oo_cp_stats_fops = {
    PROC_OPS_SET_OWNER
    .proc_open    = cp_proc_stats_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = seq_release,
};

static const struct proc_ops oo_cp_server_pids_fops = {
    PROC_OPS_SET_OWNER
    .proc_open    = cp_server_pids_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = seq_release,
};


int
ci_install_proc_entries(void)
{
  oo_proc_root = proc_mkdir("driver/onload", NULL);
  if( ! oo_proc_root ) {
    ci_log("%s: failed to create driver/onload", __FUNCTION__);
    return -ENOMEM;
  }

  ci_proc_files_install(oo_proc_root, "/proc/driver/onload", 
                        ci_proc_efab_table, CI_PROC_EFAB_TABLE_SIZE);


#if CI_CFG_STATS_NETIF
  proc_create("stacks", 0, oo_proc_root, &efab_stacks_seq_fops);
  proc_create("stacks_ul", 0, oo_proc_root, &efab_stacks_ul_seq_fops);
  proc_create("stacks_k", 0, oo_proc_root, &efab_stacks_k_seq_fops);
#endif

#if CI_MEMLEAK_DEBUG_ALLOC_TABLE
  /* create /proc/driver/sfc/mem */
  if( create_proc_read_entry("mem", 0, oo_proc_root,
                             ci_alloc_memleak_readproc, NULL) == NULL )
    ci_log("%s: failed to create 'mem'", __FUNCTION__);
#endif

  proc_create_data("filter_hwports", 0, oo_proc_root,
                   &oo_filter_hwports_fops,  NULL);
  proc_create_data("filter_ipaddrs", 0, oo_proc_root,
                   &oo_filter_ipaddrs_fops,  NULL);
  proc_create_data("cp_stats", 0, oo_proc_root,
                   &oo_cp_stats_fops,  NULL);
  proc_create_data("cp_server_pids", 0, oo_proc_root,
                   &oo_cp_server_pids_fops,  NULL);

  return 0;
}

/****************************************************************************
 *
 * Uninstall proc entries, return back old proc entries
 *
 ****************************************************************************/

void ci_uninstall_proc_entries(void)
{
  if( oo_proc_root == NULL )
    return;

  ci_proc_files_uninstall(oo_proc_root, ci_proc_efab_table,
                          CI_PROC_EFAB_TABLE_SIZE);
#if CI_CFG_STATS_NETIF
  remove_proc_entry("stacks_ul", oo_proc_root);
  remove_proc_entry("stacks_k", oo_proc_root);
  remove_proc_entry("stacks", oo_proc_root);
#endif
#if CI_MEMLEAK_DEBUG_ALLOC_TABLE
  remove_proc_entry("mem", oo_proc_root);
#endif
  remove_proc_entry("filter_hwports", oo_proc_root);
  remove_proc_entry("filter_ipaddrs", oo_proc_root);
  remove_proc_entry("cp_stats", oo_proc_root);
  remove_proc_entry("cp_server_pids", oo_proc_root);
  remove_proc_entry("driver/onload", NULL);
  oo_proc_root = NULL;
}
