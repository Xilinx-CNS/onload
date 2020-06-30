/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Level 5 Networks Limited.
**      Author: mpb
**     Started: 2019/02/19
** Description: TCP statistics dumping file
** </L5_PRIVATE>
\**************************************************************************/


#include <ci/internal/transport_config_opt.h>

#if ! CI_CFG_UL_INTERRUPT_HELPER
#include <onload_kernel_compat.h>
#include <onload/linux_onload_internal.h>
#include <onload/linux_onload.h>
#include <onload/linux_ip_protocols.h>
#include <ci/efch/mmap.h>
#include <onload/mmap.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/tcp_helper_fns.h>
#include <onload/driverlink_filter.h>
#include <onload/version.h>

#include <etherfabric/timer.h>
#include <etherfabric/internal/internal.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/efhw_types.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/vi_set.h>
#include <ci/driver/efab/hardware.h>
#include <onload/oof_onload.h>
#include <onload/oof_interface.h>
#include <onload/nic.h>
#include <onload/cplane_ops.h>
#include <ci/internal/pio_buddy.h>
#include <onload/tmpl.h>
#include <onload/dshm.h>
#include <ci/net/ipv4.h>
#include <ci/internal/more_stats.h>
#include <ci/internal/stats_dump.h>
#include "tcp_helper_stats_dump.h"



void dump_stack_to_logger(void* netif, oo_dump_log_fn_t logger, void* log_arg)
{
  logger(log_arg,
         "============================================================");
  ci_netif_dump_to_logger(netif, logger, log_arg);
  logger(log_arg,
         "============================================================");
  ci_netif_dump_sockets_to_logger(netif, logger, log_arg);
}


static void netstat_stack_to_logger(void* netif, oo_dump_log_fn_t logger,
                                    void* log_arg)
{
  ci_netif_netstat_sockets_to_logger(netif, logger, log_arg);
}

static void ci_netif_dump_vi_info_stats(ci_netif* ni, int intf_i,
                                        oo_dump_log_fn_t logger, void* log_arg)
{
  ci_netif_state_nic_t* nic = &ni->state->nic[intf_i];
  ef_vi* vi = ci_netif_vi(ni, intf_i);
  tcp_helper_resource_t* thr = NULL;
  struct efhw_nic *efhw_nic = NULL;

  if( intf_i < 0 || intf_i >= CI_CFG_MAX_INTERFACES ||
      ! efrm_nic_set_read(&ni->nic_set, intf_i) ) {
    logger(log_arg, "%s: stack=%d intf=%d ***BAD***",
           __FUNCTION__, NI_ID(ni), intf_i);
    return;
  }
  thr = netif2tcp_helper_resource(ni);
  efhw_nic = efrm_client_get_nic(thr->nic[intf_i].thn_oo_nic->efrm_client);

  logger(log_arg, "%s: stack=%d intf=%d dev=%s hw=%d%c%d", __FUNCTION__,
         NI_ID(ni), intf_i, nic->pci_dev, (int) nic->vi_arch,
         nic->vi_variant, (int) nic->vi_revision);
  logger(log_arg, "  vi=%d  gvi=0x%x  pd_owner=%d channel=%d tcpdump=%s"
         " vi_flags=%x oo_vi_flags=%x", ef_vi_instance(vi),
         (ef_vi_instance(vi) << efhw_nic->vi_shift) + efhw_nic->vi_base,
         nic->pd_owner, (int) nic->vi_channel,
         ni->state->dump_intf[intf_i] == OO_INTF_I_DUMP_ALL ? "all" :
         (ni->state->dump_intf[intf_i] == OO_INTF_I_DUMP_NO_MATCH ?
          "nomatch" : "off"), vi->vi_flags, nic->oo_vi_flags);
}


void full_netif_dump_to_logger(void* netif, oo_dump_log_fn_t logger,
                               void* log_arg)
{
  ci_netif *ni = (ci_netif*) netif;
  logger(log_arg,
         "=================== ORPHAN STACK [%d] ======================",
         NI_ID(ni));
  ci_netif_dump_to_logger(netif, logger, log_arg);
}


void full_netif_dump_extra_to_logger(void* netif, oo_dump_log_fn_t logger,
                                     void* log_arg)
{
  ci_netif_dump_extra_to_logger(netif, logger, log_arg);
}


void full_dump_sockets_to_logger(void* netif, oo_dump_log_fn_t logger,
                                 void* log_arg)
{
  logger(log_arg,
         "--------------------- sockets ------------------------------");
  ci_netif_dump_sockets_to_logger(netif, logger, log_arg);
}


void full_dump_stack_stat_to_logger(void* netif, oo_dump_log_fn_t logger,
                                    void* log_arg)
{
  const void* pstats;
  ci_netif *ni = (ci_netif*) netif;
  pstats = (const void*) &ni->state->stats;
  logger(log_arg,
         "-------------------- ci_netif_stats: %d ---------------------",
         NI_ID(ni));
  ci_dump_stats(netif_stats_fields, N_NETIF_STATS_FIELDS, pstats, 0, logger,
                log_arg);
}


void full_dump_stack_more_stat_to_logger(void* netif, oo_dump_log_fn_t logger,
                                         void* log_arg)
{
  const void* pstats;
  more_stats_t stats;
  ci_netif *ni = (ci_netif*) netif;
  get_more_stats(ni, &stats);
  pstats = (const void*) &stats;
  logger(log_arg,
         "-------------------- more_stats: %d ---------------------",
         NI_ID(ni));
  ci_dump_stats(more_stats_fields, N_MORE_STATS_FIELDS, pstats, 0, logger,
                log_arg);
}


void full_dump_ip_stats_to_logger(void* netif, oo_dump_log_fn_t logger,
                                  void* log_arg)
{
  const void* pstats;
  ci_netif *ni = (ci_netif*) netif;
  pstats = (const void*) &ni->state->stats_snapshot.ip;
  logger(log_arg,
         "--------------------- ci_ip_stats: %d ----------------------",
         NI_ID(ni));
  ci_dump_stats(ip_stats_fields, N_IP_STATS_FIELDS, pstats, 0, logger,
                log_arg);
}


void full_dump_tcp_stats_to_logger(void* netif, oo_dump_log_fn_t logger,
                                   void* log_arg)
{
  const void* pstats;
  ci_netif *ni = (ci_netif*) netif;
  pstats = (const void*) &ni->state->stats_snapshot.tcp;
  logger(log_arg,
         "-------------------- ci_tcp_stats: %d ---------------------",
         NI_ID(ni));
  ci_dump_stats(tcp_stats_fields, N_TCP_STATS_FIELDS, pstats, 0, logger,
                log_arg);
}


void full_dump_tcp_ext_stats_to_logger(void* netif, oo_dump_log_fn_t logger,
                                       void* log_arg)
{
  const void* pstats;
  ci_netif *ni = (ci_netif*) netif;
  pstats = (const void*) &ni->state->stats_snapshot.tcp_ext;
  logger(log_arg,
         "-------------------- ci_tcp_ext_stats: %d ---------------------",
         NI_ID(ni));
  ci_dump_stats(tcp_ext_stats_fields, N_TCP_EXT_STATS_FIELDS, pstats, 0, logger,
                log_arg);
}


void full_dump_udp_stats_to_logger(void* netif, oo_dump_log_fn_t logger,
                                   void* log_arg)
{
  const void* pstats;
  ci_netif *ni = (ci_netif*) netif;
  pstats = (const void*) &ni->state->stats_snapshot.udp;
  logger(log_arg,
         "-------------------- ci_udp_stats: %d ---------------------",
         NI_ID(ni));
  ci_dump_stats(udp_stats_fields, N_UDP_STATS_FIELDS, pstats, 0, logger,
                log_arg);
}


void full_dump_netif_config_opts_to_logger(void* netif, oo_dump_log_fn_t logger,
                                           void* log_arg)
{
  ci_netif *ni = (ci_netif*) netif;
  logger(log_arg,
         "--------------------- config opts --------------------------");
  ci_netif_config_opts_dump(&NI_OPTS(ni), logger, log_arg);
}


void full_dump_stack_time_to_logger(void* netif, oo_dump_log_fn_t logger,
                                    void* log_arg)
{
  ci_netif *ni = (ci_netif*) netif;
  logger(log_arg,
         "--------------------- stack time ---------------------------");
  ci_stack_time_dump(ni, logger, log_arg);
}


void full_dump_vi_info_to_logger(void* netif, oo_dump_log_fn_t logger,
                                        void* log_arg)
{
  int intf_i;
  ci_netif *ni = (ci_netif*) netif;
  logger(log_arg,
         "--------------------- vi_info stats ------------------------");
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i)
    ci_netif_dump_vi_info_stats(ni, intf_i, logger, log_arg);
}


/*! Function to dump specific part of the stack[id] defined in fn function
 * into user buffer. Basic use is to stackdump lots data from  orphaned stack.
  */
static int tcp_helper_full_dump_stack(oo_dump_fn_t fn, unsigned id,
                                      unsigned orphan_only, void* user_buf,
                                      int user_buf_len)
{
  ci_netif* netif = NULL;
  int rc = -ENODEV;

  while( iterate_netifs_unlocked(
                &netif, OO_THR_REF_BASE,
                orphan_only ? OO_THR_REF_APP : OO_THR_REF_INFTY) == 0 ) {
    if( netif->state->stack_id == id ) {
      if ( user_buf != NULL )
        rc = oo_dump_to_user(fn, netif, user_buf, user_buf_len);
      else {
        fn(netif, ci_log_dump_fn, NULL);
        rc = 0;
      }
      iterate_netifs_unlocked_dropref(netif, OO_THR_REF_BASE);
      break;
    }
  }
  return rc;
}


int tcp_helper_dump_stack(unsigned id, unsigned orphan_only, void* user_buf,
                          int user_buf_len, int op)
{
  oo_dump_fn_t fn;

  switch( op ) {
    case __CI_DEBUG_OP_DUMP_STACK__:
      fn = dump_stack_to_logger;
      break;
    case __CI_DEBUG_OP_NETSTAT_STACK__:
      fn = netstat_stack_to_logger;
      break;
    case __CI_DEBUG_OP_NETIF_DUMP__:
      fn = full_netif_dump_to_logger;
      break;
    case __CI_DEBUG_OP_NETIF_DUMP_EXTRA__:
      fn = full_netif_dump_extra_to_logger;
      break;
    case __CI_DEBUG_OP_DUMP_SOCKETS__:
      fn = full_dump_sockets_to_logger;
      break;
    case __CI_DEBUG_OP_STACK_STATS__:
      fn = full_dump_stack_stat_to_logger;
      break;
    case __CI_DEBUG_OP_STACK_MORE_STATS__:
      fn = full_dump_stack_more_stat_to_logger;
      break;
    case __CI_DEBUG_OP_IP_STATS__:
      fn = full_dump_ip_stats_to_logger;
      break;
    case __CI_DEBUG_OP_TCP_STATS__:
      fn = full_dump_tcp_stats_to_logger;
      break;
    case __CI_DEBUG_OP_TCP_EXT_STATS__:
      fn = full_dump_tcp_ext_stats_to_logger;
      break;
    case __CI_DEBUG_OP_UDP_STATS__:
      fn = full_dump_udp_stats_to_logger;
      break;
    case __CI_DEBUG_OP_NETIF_CONFIG_OPTS_DUMP__:
      fn = full_dump_netif_config_opts_to_logger;
      break;
    case __CI_DEBUG_OP_STACK_TIME__:
      fn = full_dump_stack_time_to_logger;
      break;
    case __CI_DEBUG_OP_VI_INFO__:
      fn = full_dump_vi_info_to_logger;
      break;
    default:
      return -ENOPROTOOPT;
  }

  return tcp_helper_full_dump_stack(fn, id, orphan_only, user_buf,
                                    user_buf_len);
}
#endif
