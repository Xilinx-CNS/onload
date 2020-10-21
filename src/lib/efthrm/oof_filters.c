/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2009-2020 Xilinx, Inc. */
/*
** Copyright 2005-2012  Solarflare Communications Inc.
**                      7505 Irvine Center Drive, Irvine, CA 92618, USA
** Copyright 2002-2005  Level 5 Networks Inc.
**
** This program is free software; you can redistribute it and/or modify it
** under the terms of version 2 of the GNU General Public License as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/

/* README!
 *
 * Please do not add any new '#include's here without first talking to
 * David Riddoch.  I want to limit and document dependencies of this module
 * on other parts of Onload.  
 */

#include "onload_kernel_compat.h"

#include "oof_impl.h"
#include <onload/oof_interface.h>
#include <onload/oof_nat.h>
#include <onload/oof_socket.h>
#include <onload/debug.h>
#include "oo_hw_filter.h"
#include "tcp_filters_internal.h"

#define OOF_SRC_FLAGS_DEFAULT 0
#define OOF_SRC_FLAGS_DEFAULT_MCAST (OO_HW_SRC_FLAG_LOOPBACK)

#ifndef NDEBUG

static void oof_mutex_lock_chk_not_atomic(struct mutex* m)
{
  ci_assert(! in_atomic());
  ci_assert(! in_interrupt());
  mutex_lock(m);
  ci_assert(! in_atomic());
  ci_assert(! in_interrupt());
}

# undef mutex_lock
# define mutex_lock  oof_mutex_lock_chk_not_atomic

#endif

/* If the number of sockets sharing a wild-match filter exceeds this value,
 * then the wild-match filter will be kept even after the socket that
 * created the filter is closed.
 *
 * e.g. Create a listening socket, accept 200 connections, close listening
 * socket.  The accepted sockets will continue to share a single wild-match
 * filter until the number of them drops below [oof_shared_keep_thresh], at
 * which point they will each get their own full-match filter and the wild
 * filter will be freed.
 */
int oof_shared_keep_thresh = 100;

/* If the number of sockets sharing a wild-match filter exceeds this value,
 * then the wild-match filter will be kept even when a new wild-match
 * socket needs the filter to point to a different stack.
 *
 * e.g. Create a listening socket, accept 300 connections, close listening
 * socket, create a new listening socket in a separate app.  The accepted
 * sockets will continue to share use the wild-match filter until the
 * number of them drops below [oof_shared_steal_thresh], at which point
 * they will each get their own full-match filter and the wild filter will
 * be pointed at the new wild socket.
 */
int oof_shared_steal_thresh = 200;

/* Module option to handle all local IP addresses. */
int oof_use_all_local_ip_addresses = 0;

#define IPF_LOG(...)  OO_DEBUG_IPF(ci_log(__VA_ARGS__))
#define ERR_LOG(...)  OO_DEBUG_ERR(ci_log(__VA_ARGS__))

#define SK_FMT             "%d:%d"
#define SK_PRI_ARGS(skf)   oof_cb_stack_id(oof_socket_stack_safe(skf)),   \
                           oof_cb_socket_id(skf)
#define SK_PRI_ARGS_SAFE(skf,no_stack) (no_stack ? -1 : \
                                        oof_cb_stack_id(oof_socket_stack_safe(skf))), \
                                       (no_stack ? -1 : \
                                        oof_cb_socket_id(skf))

#define FSK_FMT            "%s: "SK_FMT" "
#define FSK_PRI_ARGS(skf)  __FUNCTION__, SK_PRI_ARGS(skf)
#define FSK_PRI_ARGS_SAFE(skf,no_stack)  __FUNCTION__, SK_PRI_ARGS_SAFE(skf, no_stack)

#define TRIPLE_FMT         "%s "IPPORT_FMT
#define TRIPLE_ARGS(proto, ip, port)                    \
    FMT_PROTOCOL(proto), IPPORT_ARG((ip), (port))

#define QUIN_FMT           "%s "IPPORT_FMT" "IPPORT_FMT
#define QUIN_ARGS(proto, ip1, port1, ip2, port2)                        \
    FMT_PROTOCOL(proto), IPPORT_ARG((ip1), (port1)), IPPORT_ARG((ip2), (port2))

#define IPX_PORT_ARG(ip,p) IPX_ARG(ip), FMT_PORT(p)

#define IPX_TRIPLE_FMT     "%s "IPX_FMT":%d"
#define IPX_TRIPLE_ARGS(proto, ip, port) \
    FMT_PROTOCOL(proto), IPX_PORT_ARG((ip), (port))

#define IPX_QUIN_FMT       "%s "IPX_FMT":%d "IPX_FMT":%d"
#define IPX_QUIN_ARGS(proto, ip1, port1, ip2, port2) \
    FMT_PROTOCOL(proto), IPX_PORT_ARG((ip1), (port1)), \
    IPX_PORT_ARG((ip2), (port2))

#define SK_ADDR_FMT        IPX_QUIN_FMT
#define SK_ADDR_ARGS(skf)                                       \
    IPX_QUIN_ARGS(skf->sf_local_port->lp_protocol,              \
                  AF_IP(skf->sf_laddr),                         \
                  skf->sf_local_port->lp_lport,                 \
                  AF_IP(skf->sf_raddr),                         \
                  skf->sf_rport)

#define SK_WILD_ADDR_FMT   IPX_TRIPLE_FMT
#define SK_WILD_ADDR_ARGS(skf)                                  \
    IPX_TRIPLE_ARGS(skf->sf_local_port->lp_protocol,            \
                    AF_IP(skf->sf_laddr),                       \
                    skf->sf_local_port->lp_lport)

static struct tcp_helper_resource_s*
oof_socket_stack_safe(struct oof_socket* skf);

static void
oof_mcast_filter_list_free(ci_dllist* mcast_filters);

static int
oof_socket_mcast_install(struct oof_manager* fm, struct oof_socket* skf);

static void
oof_socket_mcast_remove(struct oof_manager* fm, struct oof_socket* skf,
                        ci_dllist* mcast_filters);

static int
oof_socket_mcast_remove_sw(struct oof_manager* fm, struct oof_socket* skf);

static void
oof_socket_mcast_del_connected(struct oof_manager* fm,
                               struct oof_socket* skf, int stack_locked);

static unsigned
oof_mcast_filter_duplicate_hwports(struct oof_manager* fm,
                                   struct oof_mcast_filter* mf,
                                   struct oof_mcast_filter* mf2);

static unsigned
oof_mcast_filter_installable_hwports(struct oof_manager* fm,
                                     struct oof_local_port* lp,
                                     struct oof_mcast_filter* mf);

static unsigned
oof_mcast_filter_hwport_mask(struct oof_manager* fm,
                             struct oof_mcast_filter* mf);

static void
__oof_manager_addr_add(struct oof_manager*, int af, ci_addr_t laddr,
                       unsigned ifindex);

static void
__oof_manager_addr_del(struct oof_manager*, int af, ci_addr_t laddr,
                       unsigned ifindex);

static int
__oof_socket_add_wild(struct oof_manager* fm, struct oof_socket* skf,
                      int af_space, struct oo_hw_filter* oofilter,
                      ci_addr_t laddr, ci_uint16 lport, ci_uint16 protocol,
                      int stack_locked);

static struct oof_local_port*
oof_local_port_find(struct oof_manager* fm, int protocol, int lport);

static void
__oof_mcast_update_filters(struct oof_manager* fm, int ifindex);

static void
__oof_manager_update_interface(struct oof_manager* fm,
                               unsigned ifindex,
                               ci_uint16 flags,
                               ci_uint32 hwports_mask,
                               ci_uint16 vlan_id,
                               ci_mac_addr_t mac);

static int
oof_tproxy_filter_update(struct oof_manager* fm, struct oof_tproxy* ft);

static void
__oof_socket_del_wild(struct oof_manager* fm,
                      struct oof_socket* skf,
                      int af_space,
                      struct tcp_helper_resource_s* skf_stack,
                      struct oof_local_port_addr* lpa, ci_addr_t laddr);

extern int scalable_filter_gid;

/**********************************************************************
***********************************************************************
**********************************************************************/

/* Indicates whether oof attempted setting the filters
 * This function does not work with KERNEL_REDIRECT filters
 * (exclusive tproxy case), where
 * both trs and thc fileds can be null and filters still installed */
static int oo_hw_filter_is_empty(struct oo_hw_filter* ft)
{
  return ft->trs == NULL && ft->thc == NULL;
}


/* This function calculates the hwports masks required at the point of
 * installing filters. */
static void
oof_hw_filter_update_hwport_masks(struct oof_manager* fm, int protocol,
                                  int clustered,
                                  unsigned* hwport_mask,
                                  unsigned* drop_hwports_mask)
{
  /* Below TCP and UDP are treated differently.
   *
   * There is a race allowing pkts hit kernel stack after onload removes
   * rx filters when interface goes down.
   *
   * In case of TCP traffic could hit kernel causing RST response.  To avoid
   * this, filters are made to drop traffic to prevent it hitting kernel when
   * interface is down.
   *
   * For UDP the race with filters has no practical issue as the traffic gets
   * handled correctly through kernel by the backing socket.  However, there is
   * an issue with drop filters.  Drop filters would not get necessary flags
   * set and further redirect would create filter without appropriate HW
   * multicast loopback settings.
   */

  if( protocol == IPPROTO_UDP ) {
    *drop_hwports_mask = 0;
    *hwport_mask &= fm->fm_hwports_mcast_update_seen;
  }
  else {
    if( ! clustered ) {
      *drop_hwports_mask = fm->fm_hwports_down & fm->fm_hwports_available;
    }
    else {
      /* In case of clustered TCP sockets we always insert proper filter (as opposite
       * to a DROP one.  The reason is that we cannot redirect DROP filters to rxq/rss,
       * and we would be stuck with DROP filter even when interface went up eventually.
       */
      *drop_hwports_mask = 0;
      *hwport_mask |= fm->fm_hwports_down & fm->fm_hwports_available;
    }
  }
}


static int __oof_hw_filter_set(struct oof_manager* fm,
                               struct oof_socket* skf,
                               struct oo_hw_filter* oofilter,
                               struct tcp_helper_resource_s* trs,
                               struct tcp_helper_cluster_s* thc,
                               int af, int protocol,
                               ci_addr_t saddr, int sport,
                               ci_addr_t daddr, int dport,
                               unsigned hwport_mask,
                               unsigned src_flags,
                               int fail_is_error,
                               const char* caller)
{
  int rc;
  unsigned drop_hwports_mask;
  struct oo_hw_filter_spec oo_filter_spec = {
    .type             = OO_HW_FILTER_TYPE_IP,
    .addr.ip.sport    = sport,
    .addr.ip.dport    = dport,
    .addr.ip.af       = af,
    .addr.ip.protocol = protocol,
    .vlan_id          = OO_HW_VLAN_UNSPEC,
  };
  struct oo_hw_filter old_oofilter;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  /* cannot change filter type from normal to clustered */
  ci_assert(oofilter->thc == NULL || trs == NULL);
  ci_assert(oofilter->trs == NULL || thc == NULL);
  ci_assert(trs == NULL || thc == NULL);

#if CI_CFG_IPV6
  if( IS_AF_INET6(af) ) {
    memcpy(oo_filter_spec.addr.ip.saddr, saddr.ip6,
           sizeof(oo_filter_spec.addr.ip.saddr));
    memcpy(oo_filter_spec.addr.ip.daddr, daddr.ip6,
           sizeof(oo_filter_spec.addr.ip.daddr));
  }
  else
#endif
  {
    oo_filter_spec.addr.ip.saddr[0] = saddr.ip4;
    oo_filter_spec.addr.ip.daddr[0] = daddr.ip4;
  }

  /* The old filter is stored in old_oofilter to free hw filter after unlock.
   * Now, the oofilter can be reinitialised with new stack - this will prevent
   * removal of the socket by oof_socket_del_sw. */
  old_oofilter = *oofilter;
  oo_hw_filter_init2(oofilter, trs, thc);
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  oofilter->plugin_vi = (skf->sf_flags & OOF_SOCKET_SUBVI_MASK) >>
                        OOF_SOCKET_SUBVI_SHIFT;
#endif

  spin_unlock_bh(&fm->fm_inner_lock);
  ci_assert(!in_atomic());
  oo_hw_filter_clear(&old_oofilter);

  oof_hw_filter_update_hwport_masks(fm, protocol, thc != NULL,
                                    &hwport_mask, &drop_hwports_mask);
  rc = oo_hw_filter_set(oofilter, &oo_filter_spec, 0,
                        hwport_mask | drop_hwports_mask,
                        drop_hwports_mask,
                        src_flags);
  spin_lock_bh(&fm->fm_inner_lock);

  if( rc == 0 ) {
    IPF_LOG(FSK_FMT "FILTER "IPX_QUIN_FMT"%s", caller, SK_PRI_ARGS(skf),
            IPX_QUIN_ARGS(protocol, AF_IP(daddr), dport, AF_IP(saddr), sport),
            thc != NULL ? " CLUSTERED" : "");
    oof_dl_filter_set(oofilter,
                      oof_cb_stack_id(oof_cb_socket_stack(skf)),
                      protocol, saddr, sport, daddr, dport);
  }
  else if( rc == -EACCES ) {
    ERR_LOG(FSK_FMT "FILTER "IPX_QUIN_FMT" blocked by firewall", caller,
            SK_PRI_ARGS(skf),
            IPX_QUIN_ARGS(protocol, AF_IP(daddr), dport, AF_IP(saddr), sport));
    /* Replace EACCES error with ERFKILL because EACCES is returned from both
     * oof_filters.c and ip_protocols.c units and should be processed
     * differently. tcp_connect() and tcp_listen() should handover on EACCES
     * from oof_filters.c when EF_NO_FAIL=1 and should return original EACCES
     * errno if retrieved from ip_protocols.c. */
    rc = -ERFKILL;
  }
  else if( fail_is_error ) {
    ERR_LOG(FSK_FMT "ERROR: FILTER "IPX_QUIN_FMT" failed (%d)", caller,
            SK_PRI_ARGS(skf),
            IPX_QUIN_ARGS(protocol, AF_IP(daddr), dport, AF_IP(saddr), sport),
            rc);
  }
  else {
    IPF_LOG(FSK_FMT "ERROR: FILTER "IPX_QUIN_FMT" failed (%d)", caller,
            SK_PRI_ARGS(skf),
            IPX_QUIN_ARGS(protocol, AF_IP(daddr), dport,AF_IP(saddr),sport),
            rc);
  }
  return rc;
}


static void oof_hw_filter_clear_hwports(struct oof_manager* fm,
                                        struct oo_hw_filter* oofilter,
                                        unsigned hwport_mask)
{
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  if( oo_hw_filter_is_empty(oofilter) ) {
    /* we cannot drop lock if oofilter is empty
     * as oofilter and its underlying skf might get removed  */
    return;
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  ci_assert(!in_atomic());
  oo_hw_filter_clear_hwports(oofilter, hwport_mask, 0);
  spin_lock_bh(&fm->fm_inner_lock);
}


static void oof_hw_filter_clear(struct oof_manager* fm,
                                struct oo_hw_filter* oofilter)
{
  oof_hw_filter_clear_hwports(fm, oofilter, -1);
  /* We postpone oo_hw_filter_clear operation to avoid possibility of
   * having the skf (our oofilter belongs to) removed by
   * oo_hw_filter_del_sw.
   *
   * Note: oofilter is empty and can be cleared in atomic context */
  oo_hw_filter_clear(oofilter);
}


static void __oof_hw_filter_clear_full(struct oof_manager* fm,
                                       struct oof_socket* skf,
                                       const char* caller)
{
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  oof_dl_filter_del(&skf->sf_full_match_filter);
  oof_hw_filter_clear(fm, &skf->sf_full_match_filter);
  IPF_LOG(FSK_FMT "CLEAR "SK_ADDR_FMT,
          caller, SK_PRI_ARGS(skf), SK_ADDR_ARGS(skf));
}


static void __oof_hw_filter_clear_wild(struct oof_manager* fm,
                                       struct oof_local_port* lp,
                                       struct oof_local_port_addr* lpa,
                                       ci_addr_t laddr,
                                       const char* caller)
{
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  if( ! oo_hw_filter_is_empty(&lpa->lpa_filter) ) {
    struct oof_nat_table* nat_table = oof_cb_nat_table(fm->fm_owner_private);
    struct oof_nat_filter* nat_filter;
    struct oof_nat_filter* next;

    IPF_LOG("%s: CLEAR "IPX_TRIPLE_FMT" stack=%d", caller,
            IPX_TRIPLE_ARGS(lp->lp_protocol, AF_IP(laddr), lp->lp_lport),
            oof_cb_stack_id(lpa->lpa_filter.trs));

    /* Clear the filter for the real address. */
    oof_dl_filter_del(&lpa->lpa_filter);
    oof_hw_filter_clear(fm, &lpa->lpa_filter);

    /* Clear any NAT filters. */
    CI_DLLIST_FOR_EACH3(struct oof_nat_filter, nat_filter, link,
                        &lpa->lpa_nat_filters, next) {
      ci_dllist_remove(&nat_filter->link);
      oof_dl_filter_del(&nat_filter->natf_hwfilter);
      oof_hw_filter_clear(fm, &nat_filter->natf_hwfilter);
      oof_nat_table_filter_put(nat_table, nat_filter);
    }
  }
}


static int oof_hw_filter_update(struct oof_manager* fm,
                                struct oo_hw_filter* oofilter,
                                struct tcp_helper_resource_s* new_stack,
                                int af, int protocol,
                                ci_addr_t saddr, int sport,
                                ci_addr_t daddr, int dport,
                                ci_uint16 vlan_id,
                                unsigned hwport_mask,
                                unsigned src_flags)
{
  int rc;
  unsigned drop_hwports_mask;
  struct oo_hw_filter_spec oo_filter_spec = {
    .type             = OO_HW_FILTER_TYPE_IP,
    .addr.ip.sport    = sport,
    .addr.ip.dport    = dport,
    .addr.ip.af       = af,
    .addr.ip.protocol = protocol,
    .vlan_id          = vlan_id,
  };

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

#if CI_CFG_IPV6
  if( IS_AF_INET6(af) ) {
    memcpy(oo_filter_spec.addr.ip.saddr, saddr.ip6,
           sizeof(oo_filter_spec.addr.ip.saddr));
    memcpy(oo_filter_spec.addr.ip.daddr, daddr.ip6,
           sizeof(oo_filter_spec.addr.ip.daddr));
  }
  else
#endif
  {
    oo_filter_spec.addr.ip.saddr[0] = saddr.ip4;
    oo_filter_spec.addr.ip.daddr[0] = daddr.ip4;
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  ci_assert(!in_atomic());
  oof_hw_filter_update_hwport_masks(fm, protocol, oofilter->thc != NULL,
                                    &hwport_mask, &drop_hwports_mask);
  rc = oo_hw_filter_update(oofilter, new_stack, &oo_filter_spec,
                           fm->fm_hwports_vlan_filters & hwport_mask,
                           hwport_mask | drop_hwports_mask, drop_hwports_mask,
                           src_flags);
  spin_lock_bh(&fm->fm_inner_lock);
  return rc;
}


static void __oof_hw_filter_move(struct oof_manager* fm,
                                 struct oof_socket* skf,
                                 struct oof_local_port* lp,
                                 struct oof_local_port_addr* lpa,
                                 ci_addr_t laddr, int af,
                                 unsigned hwport_mask,
                                 const char* caller)
{
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));
  ci_assert(! CI_IPX_IS_MULTICAST(laddr));
  ci_assert(lpa->lpa_filter.thc == NULL);

  IPF_LOG(FSK_FMT "MOVE "IPX_TRIPLE_FMT" from stack %d", caller,
          SK_PRI_ARGS(skf),
          IPX_TRIPLE_ARGS(lp->lp_protocol, AF_IP(laddr), lp->lp_lport),
          oof_cb_stack_id(lpa->lpa_filter.trs));

    oof_hw_filter_update(fm, &lpa->lpa_filter, oof_cb_socket_stack(skf), af,
                         lp->lp_protocol, addr_any, 0, laddr, lp->lp_lport,
                         OO_HW_VLAN_UNSPEC, hwport_mask,
                         OOF_SRC_FLAGS_DEFAULT);
}


static void __oof_hw_filter_transfer(struct oof_manager* fm,
                                     struct oof_mcast_member* mm,
                                     struct oof_mcast_filter* mf_new,
                                     unsigned hwport_mask,
                                     const char* caller)
{
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  IPF_LOG(FSK_FMT "TRANSFER "TRIPLE_FMT, caller, SK_PRI_ARGS(mm->mm_socket),
          TRIPLE_ARGS(mm->mm_socket->sf_local_port->lp_protocol, mm->mm_maddr,
          mm->mm_socket->sf_local_port->lp_lport));
  oo_hw_filter_transfer(&mm->mm_filter->mf_filter, &mf_new->mf_filter,
                        hwport_mask);
}


#define oof_hw_filter_set(fm, skf, f, s, t, af, p, sa, sp, da, dp, pp, sf, fie)     \
  __oof_hw_filter_set((fm), (skf), (f), (s), (t), (af), (p), (sa), (sp), (da),  \
                      (dp), (pp), (sf), (fie),  __FUNCTION__)

#define oof_hw_filter_clear_full(fm, skf)                \
  __oof_hw_filter_clear_full((fm), (skf), __FUNCTION__)

#define oof_hw_filter_clear_wild(fm, lp, lpa, laddr)                     \
  __oof_hw_filter_clear_wild((fm), (lp), (lpa), (laddr), __FUNCTION__)

#define oof_hw_filter_move(fm, skf, lp, lpa, laddr, af, hwports)            \
  __oof_hw_filter_move((fm), (skf), (lp), (lpa), (laddr), (af), (hwports),    \
                       __FUNCTION__)

#define oof_hw_filter_transfer(fm, mm, mf, hwports)         \
  __oof_hw_filter_transfer((fm), (mm), (mf), (hwports), __FUNCTION__)


static void oof_sw_insert_fail(struct oof_socket* skf,
                               const char* func, int rc)
{
  /* Currently just log and continue in these cases.  Possible responses:
   * (1) Mark the interface for no further acceleration.  (2) Remove some
   * "non-critical" filters such as UDP to make space.
   */
  ERR_LOG(FSK_FMT "ERROR: "SK_ADDR_FMT" could not add s/w filter (%d)",
          func, SK_PRI_ARGS(skf), SK_ADDR_ARGS(skf), rc);
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static inline int/*af_space*/
oof_addr_to_af_space(ci_addr_t addr)
{
  if( CI_IS_ADDR_IP6(addr) )
    return AF_SPACE_FLAG_IP6;
  else
    return AF_SPACE_FLAG_IP4;
}

static void
oof_local_port_addr_init(struct oof_local_port_addr* lpa, int flags)
{
  oo_hw_filter_init(&lpa->lpa_filter);
  ci_dllist_init(&lpa->lpa_semi_wild_socks);
  ci_dllist_init(&lpa->lpa_full_socks);
  ci_dllist_init(&lpa->lpa_nat_filters);
  lpa->lpa_n_full_sharers = 0;
  lpa->lpa_flags = flags;
}


static int
oof_local_port_addr_valid(struct oof_manager* fm, struct oof_local_port_addr* lpa)
{
  return (lpa->lpa_flags & OOF_LPA_FLAG_REMOVED) == 0;
}


static void
oof_local_port_free(struct oof_manager* fm, struct oof_local_port* lp)
{
  ci_assert(lp->lp_refs == 0);
  ci_assert(ci_dllist_is_empty(&lp->lp_wild_socks));
  ci_assert(ci_dllist_is_empty(&lp->lp_mcast_filters));
  ci_assert(fm->fm_local_addr_n >= 0);

#ifndef NDEBUG
  {
    int la_i;
    spin_lock_bh(&fm->fm_inner_lock);
    for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
      struct oof_local_port_addr* lpa = &lp->lp_addr[la_i];
      ci_assert(oo_hw_filter_is_empty(&lpa->lpa_filter));
      ci_assert(ci_dllist_is_empty(&lpa->lpa_semi_wild_socks));
      ci_assert(ci_dllist_is_empty(&lpa->lpa_full_socks));
    }
    spin_unlock_bh(&fm->fm_inner_lock);
  }
#endif
  ci_free(lp->lp_addr);
  ci_free(lp);
}


static struct oof_local_port*
oof_local_port_alloc(struct oof_manager* fm, int protocol, int lport)
{
  struct oof_local_port* lp;
  struct oof_local_addr* la;
  int la_i, is_active;

  ci_assert(fm->fm_local_addr_n >= 0);

  lp = CI_ALLOC_OBJ(struct oof_local_port);
  if( lp == NULL ) 
    return NULL;

  lp->lp_addr = CI_ALLOC_ARRAY(struct oof_local_port_addr, 
                               fm->fm_local_addr_max);
  if( lp->lp_addr == NULL ) {
    ci_free(lp);
    return NULL;
  }
  
  lp->lp_lport = lport;
  lp->lp_protocol = protocol;
  lp->lp_refs = 0;
  ci_dllist_init(&lp->lp_wild_socks);
  ci_dllist_init(&lp->lp_mcast_filters);
  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    la = &fm->fm_local_addrs[la_i];
    is_active = ci_dllist_not_empty(&la->la_active_ifs);
    oof_local_port_addr_init(&lp->lp_addr[la_i],
                             is_active ? 0 : OOF_LPA_FLAG_REMOVED);
  }
  return lp;
}


static unsigned
oof_local_interface_hwport_mask(struct oof_manager* fm)
{
  struct oof_local_interface_details* lid;
  unsigned hwport_mask = 0;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));

  CI_DLLIST_FOR_EACH2(struct oof_local_interface_details, lid, lid_link,
                      &fm->fm_local_interfaces)
    hwport_mask |= lid->lid_hwport_mask;

  return hwport_mask;
}

static void
oof_local_interface_details_update(struct oof_local_interface_details* lid,
                                   ci_uint16 ifindex, ci_uint16 flags,
                                   ci_uint32 hwport_mask,
                                   ci_uint16 vlan_id, ci_mac_addr_t mac)
{
  lid->lid_ifindex = ifindex;
  lid->lid_flags = flags;
  lid->lid_hwport_mask = hwport_mask;
  lid->lid_vlan_id = vlan_id;
  memcpy(lid->lid_mac, mac, sizeof(lid->lid_mac));
}


static struct oof_local_interface_details*
oof_local_interface_details_find(struct oof_manager* fm, int ifindex)
{
  struct oof_local_interface_details* lid;
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  CI_DLLIST_FOR_EACH2(struct oof_local_interface_details, lid, lid_link,
                      &fm->fm_local_interfaces)
    if( lid->lid_ifindex == ifindex )
      return lid;
  return NULL;
}


static struct oof_local_interface_details*
oof_local_interface_details_alloc(struct oof_manager* fm, int ifindex)
{
  struct oof_local_interface_details* lid;

  ci_assert(oof_local_interface_details_find(fm, ifindex) == NULL);

  lid = CI_ALLOC_OBJ(struct oof_local_interface_details);
  if( lid == NULL )
    return NULL;
  ci_dllist_push_tail(&fm->fm_local_interfaces, &lid->lid_link);
  return lid;
}


static void
oof_local_interface_details_free(struct oof_manager* fm,
                                 struct oof_local_interface_details* lid)
{
  ci_dllist_remove(&lid->lid_link);
  CI_FREE_OBJ(lid);
}

/**********************************************************************
***********************************************************************
**********************************************************************/


static int oof_socket_is_clustered(struct oof_socket* skf)
{
  return (skf->sf_flags & OOF_SOCKET_CLUSTERED) != 0;
}


static int oof_socket_is_dummy(struct oof_socket* skf)
{
  return (skf->sf_flags & OOF_SOCKET_DUMMY) != 0;
}


static int oof_socket_is_stackless(struct oof_socket* skf)
{
  return (skf->sf_flags & OOF_SOCKET_NO_STACK) != 0;
}


static int oof_socket_no_unicast(struct oof_socket* skf)
{
  return (skf->sf_flags & OOF_SOCKET_NO_UCAST) != 0;
}


static struct tcp_helper_resource_s*
oof_socket_stack_safe(struct oof_socket* skf)
{
  return oof_socket_is_stackless(skf) ? NULL : oof_cb_socket_stack(skf);
}


/* Returns cluster associated with socket if there is any.
 * In case socket is not associated with cluster or stack returns NULL.
 */
static struct tcp_helper_cluster_s*
oof_socket_thc_safe(struct oof_socket* skf)
{
  struct tcp_helper_resource_s* skf_stack = oof_socket_stack_safe(skf);
  return skf_stack != NULL ? oof_cb_stack_thc(skf_stack) : NULL;
}


int oof_socket_is_armed(struct oof_socket* skf)
{
  return skf->sf_local_port != NULL && ! oof_socket_is_dummy(skf);
}


static struct tcp_helper_cluster_s*
oof_socket_thc_effective(struct oof_socket* skf)
{
  if( oof_socket_is_clustered(skf) )
    return oof_socket_thc_safe(skf);
  return NULL;
}


static struct tcp_helper_resource_s*
oof_socket_stack_effective(struct oof_socket* skf)
{
  if( oof_socket_is_clustered(skf) )
    return NULL;
  return oof_cb_socket_stack(skf);
}


void
oof_socket_ctor(struct oof_socket* skf)
{
  skf->sf_local_port = NULL;
  skf->sf_flags = 0;
  oo_hw_filter_init(&skf->sf_full_match_filter);
  ci_dllist_init(&skf->sf_mcast_memberships);
  ci_dllink_mark_free(&skf->sf_lp_link);
}


void
oof_socket_dtor(struct oof_socket* skf)
{
  ci_assert(skf->sf_local_port == NULL);
  ci_assert(oo_hw_filter_is_empty(&skf->sf_full_match_filter));
  ci_assert(ci_dllist_is_empty(&skf->sf_mcast_memberships));
  ci_assert(ci_dllink_is_free(&skf->sf_lp_link));
}


void
oof_socket_remove_from_list(struct oof_socket* skf)
{
  ci_assert(! ci_dllink_is_free(&skf->sf_lp_link));
  ci_dllist_remove(&skf->sf_lp_link);
  ci_dllink_mark_free(&skf->sf_lp_link);
}

#if CI_CFG_IPV6
static int/*bool*/
oof_skf_uses_af_space(struct oof_socket* skf, int af_space)
{
  return af_space & skf->af_space;
}
#else
#define oof_skf_uses_af_space(skf, af_space) 1
#endif


static struct oof_socket*
oof_socket_at_head(ci_dllist* list, int no_flags, int want_flags, int af_space)
{
  struct oof_socket* skf;
  CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link, list)
    if( (skf->sf_flags & no_flags) == 0 &&
        (~skf->sf_flags & want_flags) == 0 &&
        oof_skf_uses_af_space(skf, af_space) )
      return skf;
  return NULL;
}


static struct oof_socket*
oof_socket_list_find_matching_stack(ci_dllist* list,
                                    struct tcp_helper_resource_s* stack,
                                    int af_space,
                                    int allow_dummy)
{
  struct oof_socket* skf;
  CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link, list)
    if( ! oof_socket_is_stackless(skf) &&
        oof_skf_uses_af_space(skf, af_space) &&
        (allow_dummy || ! oof_socket_is_dummy(skf)) &&
        ! oof_socket_no_unicast(skf) &&
        oof_cb_socket_stack(skf) == stack )
      return skf;
  return NULL;
}


/* Tells whether this socket deserves a filter */
static int
oof_socket_is_first_in_same_stack(ci_dllist* list, struct oof_socket* skf)
{
  /* Return true if [skf] is non-dummy and  is the first socket in the list,
   * considering only sockets in the same stack as [skf]. */
  if( oof_socket_is_dummy(skf) || oof_socket_no_unicast(skf) )
    return 0;
  return skf ==
         oof_socket_list_find_matching_stack(list, oof_cb_socket_stack(skf),
                                             skf->af_space, 0);
}


/* This is for fixing sw filters, hence cluster is ignored */
static struct oof_socket*
oof_wild_socket_matching_stack(struct oof_local_port* lp,
                               struct oof_local_port_addr* lpa,
                               int af_space,
                               struct tcp_helper_resource_s* stack)
{
  struct oof_socket* skf;
  skf = oof_socket_list_find_matching_stack(&lpa->lpa_semi_wild_socks, stack,
                                            af_space, 0);
  if( skf == NULL )
    skf = oof_socket_list_find_matching_stack(&lp->lp_wild_socks, stack,
                                              af_space, 0);
  return skf;
}

/* Tells whether this socket deserves a filter considering both
 * wild and semi wild lists*/
static int
oof_wild_socket_needs_sw_filter(struct oof_local_port* lp,
                                struct oof_local_port_addr* lpa,
                                struct oof_socket* skf, int af_space)
{
  /* Return true if [skf] is non-dummy and  is the first socket in the list,
   * considering only sockets in the same stack and using the same address
   * family as [skf]. */
  if( oof_socket_is_dummy(skf) || oof_socket_no_unicast(skf) 
      || ! oof_skf_uses_af_space(skf, af_space) )
    return 0;
  return skf ==
         oof_wild_socket_matching_stack(lp, lpa, af_space, oof_cb_socket_stack(skf));
}


/* Finds another socket that belongs to the same cluster */
static struct oof_socket*
__oof_socket_list_find_cluster_sibling(ci_dllist* list,
                                       struct tcp_helper_resource_s* stack,
                                       struct tcp_helper_cluster_s* thc,
                                       int allow_dummy)
{
  struct oof_socket* skf;
  CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link, list)
    if( ! oof_socket_is_stackless(skf) &&
        (allow_dummy || ! oof_socket_is_dummy(skf)) &&
        ! oof_socket_no_unicast(skf) &&
        oof_socket_thc_effective(skf) == thc &&
        oof_cb_socket_stack(skf) != stack )
      return skf;
  return NULL;
}


static struct oof_socket*
oof_socket_list_find_cluster_sibling(ci_dllist* list,
                                     struct oof_socket* skf,
                                     int allow_dummy)
{
  struct tcp_helper_resource_s* stack = oof_cb_socket_stack(skf);
  struct tcp_helper_cluster_s* thc = oof_socket_thc_effective(skf);
  if( thc == NULL )
    return NULL;
  return __oof_socket_list_find_cluster_sibling(list, stack, thc, allow_dummy);
}


static int
oof_socket_has_cluster_sibling(ci_dllist* list, struct oof_socket* skf)
{
  return oof_socket_list_find_cluster_sibling(list, skf, 0) != NULL;
}


/* Verifies whether insertion of given socket is allowed.
 *
 * This is meant for reserving wild or semi-wild proto:port[:ip]
 * tuples for clustered wild sockets.
 *
 * list needs to be either lp_wild_socks or lpa_semi_wild_socks
 * from respectively local_port or local_port_address the socket is being
 * added to.
 *
 * Insertion of socket is allowed when on the list:
 *  * there is no other socket - 0 is returned, or
 *  * there is already a socket belonging to a cluster,
      though the socket must not be present in the same stack, then
      0 is returned and thc_out is populated with the reference
 *    to the cluster.
 *  * no-unicast sockets are ignored in any considerations and
 *    allowed to be intalled as compatible
 * If insertion is not allowed, error (-EADDRINUSE) is returned.
 *
 * Note insertion of second socket from the same stack is not allowed.
 */
static int
oof_socket_insert_probe(ci_dllist* list, struct oof_socket* skf,
                        struct tcp_helper_cluster_s** thc_out)
{
  int has_stack = (skf->sf_flags & OOF_SOCKET_NO_STACK) == 0;
  struct tcp_helper_cluster_s* thc;
  struct oof_socket* skf2;
  if( ci_dllist_is_empty(list) || oof_socket_no_unicast(skf) )
    return 0;
  /* if skf is not clustered any clustered socket blocks its insertion*/
  if( ! oof_socket_is_clustered(skf) )
    return oof_socket_at_head(list, OOF_SOCKET_NO_UCAST, OOF_SOCKET_CLUSTERED,
                              skf->af_space)
           != NULL ? -EADDRINUSE : 0;
  if( has_stack ) {
    /* is there a duplicate socket in our stack. */
    skf2 = oof_socket_list_find_matching_stack(list, oof_cb_socket_stack(skf),
                                               skf->af_space, 1);
    if( skf2 != NULL )
      return -EADDRINUSE;
    /* Foot in the door check: whether our cluster is already allowed */
    skf2 = oof_socket_list_find_cluster_sibling(list, skf, 1);
    if( skf2 != NULL )
      return 0;
    return -EADDRINUSE;
  }

  /* Now, we deal with stackless clustered socket and the list is not empty */

  /* To uphold foot in the door principle, we try to locate cluster first
   * Note: the cluster might have been created by no-ucast socket - that is fine */
  skf2 = oof_socket_at_head(list, 0, OOF_SOCKET_CLUSTERED, skf->af_space);
  if( skf2 == NULL ) {
    /* An existing non clustered socket blocks the insertion */
    return -EADDRINUSE;
  }

  /* We should not have a clustered socked without a stack */
  ci_assert_nflags(skf2->sf_flags, OOF_SOCKET_NO_STACK);

  thc = oof_socket_thc_effective(skf2);

  ci_assert_nequal(thc, NULL);

  /* Client will move skf to cluster but we need to tell the client which one.
   * We allow insertion to book this slot and avoid race with non-clustered
   * sockets.
   * There should be no race with clustered ones as this socket is going
   * to be moved (or revoked) under duration of current cluster lock */
  if( (skf->sf_flags & OOF_SOCKET_NO_STACK) != 0 ) {
    if( thc_out != NULL ) {
      if( thc != NULL )
        oof_cb_thc_ref(thc);
      *thc_out = thc;
      return 0;
    }
  }
  /* Either our space no space in our cluster or another cluster claimed
   * the socket */
  return -EADDRINUSE;
}


/**********************************************************************
***********************************************************************
**********************************************************************/

static int
lp_hash(int protocol, int lport)
{
  return (protocol + lport) & OOF_LOCAL_PORT_TBL_MASK;
}


struct oof_manager*
oof_manager_alloc(unsigned local_addr_max, void* owner_private)
{
  struct oof_manager* fm;
  int hash;
  int i;

  fm = CI_ALLOC_OBJ(struct oof_manager);
  if( fm == NULL )
    return NULL;
  fm->fm_local_addrs = CI_ALLOC_ARRAY(struct oof_local_addr, local_addr_max);
  if( fm->fm_local_addrs == NULL ) {
    ci_free(fm);
    return NULL;
  }

  fm->fm_owner_private = owner_private;
  spin_lock_init(&fm->fm_inner_lock);
  mutex_init(&fm->fm_outer_lock);
  spin_lock_init(&fm->fm_cplane_updates_lock);
  fm->fm_local_addr_n = 0;
  fm->fm_local_addr_max = local_addr_max;
  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    ci_dllist_init(&fm->fm_local_ports[hash]);
  ci_dllist_init(&fm->fm_local_interfaces);
  ci_dllist_init(&fm->fm_mcast_laddr_socks);
  ci_dllist_init(&fm->fm_tproxies);
  for( i = 0; i < OOF_TPROXY_GLOBAL_FILTER_COUNT; ++i )
    fm->fm_tproxy_global_filters[i] = 0;
  fm->fm_hwports_up = 0;
  fm->fm_hwports_up_new = 0;
  fm->fm_hwports_removed = 0;
  fm->fm_hwports_down = 0;
  fm->fm_hwports_down_new = 0;
  fm->fm_hwports_mcast_replicate_capable = 0;
  fm->fm_hwports_mcast_replicate_capable_new = 0;
  fm->fm_hwports_vlan_filters = 0;
  fm->fm_hwports_vlan_filters_new = 0;
  fm->fm_hwports_mcast_update_seen = 0;
  {
    int tag;
    /* Each hwport is available for each tag until we're told otherwise... */
    for( tag = 0; tag < OOF_HWPORT_AVAIL_TAG_NUM; tag++ ) {
      fm->fm_hwports_avail_per_tag[tag] = (unsigned) -1;
      fm->fm_hwports_avail_per_tag_new[tag] = (unsigned) -1;
    }
    /* ...except for namespaces, where each hwport is unavailable until the
     * control plane informs us about it. */
    fm->fm_hwports_avail_per_tag[OOF_HWPORT_AVAIL_TAG_NAMESPACE] = 0;
    fm->fm_hwports_avail_per_tag_new[OOF_HWPORT_AVAIL_TAG_NAMESPACE] = 0;
  }
  fm->fm_hwports_available = 0;
  ci_dllist_init(&fm->fm_cplane_updates);
  return fm;
}


void
oof_manager_free(struct oof_manager* fm)
{
  int hash;
  int la_i;
  struct oof_local_interface_details* lid;
  struct oof_local_interface_details* lid_t;
  struct oof_local_addr* la;
  struct oof_local_interface* li;
  struct oof_local_interface* li_tmp;

  ci_assert(ci_dllist_is_empty(&fm->fm_tproxies));
  ci_assert(ci_dllist_is_empty(&fm->fm_mcast_laddr_socks));
  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    ci_assert(ci_dllist_is_empty(&fm->fm_local_ports[hash]));

  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    la = &fm->fm_local_addrs[la_i];
    CI_DLLIST_FOR_EACH3(struct oof_local_interface, li, li_active_ifs_link,
                        &la->la_active_ifs, li_tmp) {
      ci_dllist_remove(&li->li_active_ifs_link);
      CI_FREE_OBJ(li);
    }
  }

  CI_DLLIST_FOR_EACH3(struct oof_local_interface_details, lid, lid_link,
                      &fm->fm_local_interfaces, lid_t)
    oof_local_interface_details_free(fm, lid);

  mutex_destroy(&fm->fm_outer_lock);
  ci_free(fm->fm_local_addrs);
  ci_free(fm);
}


/**********************************************************************
***********************************************************************
**********************************************************************/

static int
oof_manager_addr_find(struct oof_manager* fm, const ci_addr_t laddr)
{
  int la_i;

  ci_assert_ge(fm->fm_local_addr_n, 0);
  ci_assert(spin_is_locked(&fm->fm_inner_lock));

  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    if( CI_IPX_ADDR_EQ(fm->fm_local_addrs[la_i].la_laddr, laddr) )
      return la_i;
  }
  return -1;
}

/* For a given oof_local_port, find the index of the oof_local_port_addr having
 * a filter for the specified address. */
static int
oof_manager_lport_addr_find(struct oof_manager* fm, struct oof_local_port* lp,
                            const ci_addr_t laddr)
{
  int la_i;

  ci_assert_ge(fm->fm_local_addr_n, 0);
  ci_assert(spin_is_locked(&fm->fm_inner_lock));

  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    struct oof_local_port_addr* lpa = &lp->lp_addr[la_i];
    struct oof_nat_filter* nat_filter;

    if( CI_IPX_ADDR_EQ(fm->fm_local_addrs[la_i].la_laddr, laddr) &&
        ! oo_hw_filter_is_empty(&lpa->lpa_filter) )
      return la_i;
    CI_DLLIST_FOR_EACH2(struct oof_nat_filter, nat_filter, link,
                        &lpa->lpa_nat_filters)
      if( CI_IPX_ADDR_EQ(nat_filter->orig_addr, laddr) )
        return la_i;
  }
  return -1;
}

static int oof_socket_can_share_hw_filter(struct oof_socket* skf,
                                          struct oo_hw_filter* filter)
{
  struct tcp_helper_resource_s* skf_stack = oof_cb_socket_stack(skf);
  struct tcp_helper_cluster_s* skf_thc = oof_socket_thc_safe(skf);

  if( (skf->sf_flags & OOF_SOCKET_NO_SHARING) != 0 )
    return 0;
  return (filter->trs != NULL && filter->trs == skf_stack) ||
         (filter->thc != NULL && filter->thc == skf_thc);
}


/* Obtains a wild socket that can be granted filters,
 * dummy sockets are not taken into account */
static struct oof_socket*
oof_wild_socket(struct oof_local_port* lp, struct oof_local_port_addr* lpa,
                int af_space)
{
  struct oof_socket* skf;
  skf = oof_socket_at_head(&lpa->lpa_semi_wild_socks,
                           OOF_SOCKET_DUMMY | OOF_SOCKET_NO_UCAST, 0,
                           af_space);
  if( skf == NULL ) {
    skf = oof_socket_at_head(&lp->lp_wild_socks,
                             OOF_SOCKET_DUMMY | OOF_SOCKET_NO_UCAST, 0,
                             af_space);
  }
  return skf;
}


static void
oof_manager_sw_filter_insert(struct oof_manager *fm, int af, ci_addr_t laddr,
                             struct oof_local_port* lp, int la_i)
{
  struct oof_local_port_addr* lpa = &lp->lp_addr[la_i];
  struct oof_socket* skf;
  ci_dllist* wild_lists[2] =
      { &lpa->lpa_semi_wild_socks, &lp->lp_wild_socks };
  int i, af_space;

  af_space = OO_AF_FAMILY2SPACE(af);

  /* Add s/w filters for wild sockets. */
  for( i = 0; i < 2; ++i )
    CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link, wild_lists[i]) {
      if( oof_wild_socket_needs_sw_filter(lp, lpa, skf, af_space) ) {
        int rc;

        rc = oof_cb_sw_filter_insert(skf, af_space, laddr, lp->lp_lport,
                                     addr_any, 0, lp->lp_protocol, 0);
        if( rc != 0 ) {
          oof_sw_insert_fail(skf, __FUNCTION__, rc);
          /* Remove the corresponding hardware filters so that traffic
           * continues to reach the socket, albeit without acceleration.
           * BUT don't do that if existing TCP connections are using the
           * hardware filter.
           * With cluster filters there might be sibling cluster stacks
           * using the same hw filter as well.
           */
          if( (lp->lp_protocol == IPPROTO_UDP ||
               lpa->lpa_n_full_sharers == 0 ) &&
              ! oof_socket_has_cluster_sibling(&lp->lp_wild_socks, skf) &&
              ! oof_socket_has_cluster_sibling(&lpa->lpa_semi_wild_socks, skf) )
            oof_hw_filter_clear_wild(fm, lp, lpa, laddr);
        }
      }
    }
}

static void
oof_manager_sw_filter_remove(int af, ci_addr_t laddr, struct oof_local_port* lp,
                             int la_i)
{
  struct oof_local_port_addr* lpa = &lp->lp_addr[la_i];
  struct oof_socket* skf;
  ci_dllist* wild_lists[2] =
      { &lpa->lpa_semi_wild_socks, &lp->lp_wild_socks };
  int i, af_space;

  af_space = OO_AF_FAMILY2SPACE(af);

  /* Remove s/w filters for wild sockets. */
  for( i = 0; i < 2; ++i ) {
    CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link, wild_lists[i])
      if( oof_wild_socket_needs_sw_filter(lp, lpa, skf, af_space) ) {
        oof_cb_sw_filter_remove(skf, af_space, laddr, lp->lp_lport, addr_any, 0,
                                lp->lp_protocol, 0);
      }
    }
}

static void
__oof_manager_addr_add(struct oof_manager *fm, int af, ci_addr_t laddr,
                       unsigned ifindex)
{
  struct oof_local_port_addr* lpa;
  struct oof_local_port* lp;
  struct oof_local_addr* la;
  struct oof_local_interface* li;
  struct oof_socket* skf;
  int hash, la_i, is_new, is_active;
  ci_dllist *la_active_ifs;

  /*  We do not care about crazy local addresses. */
  if( CI_IPX_ADDR_IS_ANY(laddr) || CI_IPX_IS_MULTICAST(laddr) )
    return;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  /* Duplicate? */
  la_i = oof_manager_addr_find(fm, laddr);
  if( la_i >= 0 ) {
    la = &fm->fm_local_addrs[la_i];
    la_active_ifs = &la->la_active_ifs;

    is_active = ci_dllist_not_empty(la_active_ifs);
    CI_DLLIST_FOR_EACH2(struct oof_local_interface, li, li_active_ifs_link, 
                        la_active_ifs)
      if( li->li_ifindex == ifindex )
        break;
    if( li == NULL ) {
      li = CI_ALLOC_OBJ(struct oof_local_interface);
      if( li == NULL ) {
        ERR_LOG("%s: ERROR: " IPX_FMT " couldn't allocate space for ifindex %d",
                __FUNCTION__, IPX_ARG(AF_IP_L3(laddr)), ifindex);
        return; 
      }
      li->li_ifindex = ifindex;
      ci_dllist_push(la_active_ifs, &li->li_active_ifs_link);
    }
    if( is_active )
      /* This local address is already active, nothing further to do. */
      return;
    is_new = 0;
  }
  else {
    /* New entry in local address table. */
    la_i = oof_manager_addr_find(fm, addr_any);
    if( la_i < 0 ) {
      if( fm->fm_local_addr_n == fm->fm_local_addr_max ) {
        ci_log("%s: ERROR: " IPX_FMT " overflows local address table",
               __FUNCTION__, IPX_ARG(AF_IP_L3(laddr)));
        return;
      }
      la_i = fm->fm_local_addr_n;
      ++fm->fm_local_addr_n;
    }

    la = &fm->fm_local_addrs[la_i];
    la->la_laddr = laddr;
    la->la_sockets = 0;
    la_active_ifs = &la->la_active_ifs;

    ci_dllist_init(la_active_ifs);
    li = CI_ALLOC_OBJ(struct oof_local_interface);
    if( li == NULL ) {
      ci_log("%s: ERROR: " IPX_FMT " couldn't allocate space for ifindex %d",
             __FUNCTION__, IPX_ARG(AF_IP_L3(laddr)), ifindex);
      la->la_laddr = addr_any;
      return; 
    }

    li->li_ifindex = ifindex;
    ci_dllist_push(la_active_ifs, &li->li_active_ifs_link);
    is_new = 1;
  }

  /* Mark local_port_addr structures as referring to removed
   * ip address without dropping the spin lock. */
  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      lpa = &lp->lp_addr[la_i];
      if( is_new ) {
        oof_local_port_addr_init(lpa, 0);
      } else {
        /* There are preexisting sockets on the local_port_addr.
         * Let's clear the removed status and enable hw filter sharing */
        ci_assert_flags(lpa->lpa_flags, OOF_LPA_FLAG_REMOVED);
        ci_assert_equal(lpa->lpa_n_full_sharers, 0);
        lpa->lpa_flags &=~ OOF_LPA_FLAG_REMOVED;
      }
      /* Add h/w filter for wild sockets. */
      ci_assert( ! ci_dllist_not_empty(&lpa->lpa_semi_wild_socks) || ! is_new );
    }

  /* Add new filters, and set new filters for wildcard users. */
  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      lpa = &lp->lp_addr[la_i];
      skf = oof_wild_socket(lp, lpa, OO_AF_FAMILY2SPACE(af));
      if( skf != NULL )
        oof_hw_filter_set(fm, skf, &lpa->lpa_filter,
                          oof_socket_stack_effective(skf),
                          oof_socket_thc_effective(skf), af,
                          lp->lp_protocol, addr_any, 0, laddr, lp->lp_lport,
                          fm->fm_hwports_available & fm->fm_hwports_up,
                          OOF_SRC_FLAGS_DEFAULT, 1);
      /* Add h/w filters for full-match sockets. */
      CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                          &lpa->lpa_full_socks) {
        ci_assert(!is_new);
        ci_assert(! oof_socket_is_clustered(skf));
        ci_assert(! oof_socket_is_dummy(skf));
        if( oof_socket_can_share_hw_filter(skf, &lpa->lpa_filter) )
          ++lpa->lpa_n_full_sharers;
        else
          oof_hw_filter_set(fm, skf, &skf->sf_full_match_filter,
                            oof_cb_socket_stack(skf), NULL, af,
                            lp->lp_protocol, skf->sf_raddr, skf->sf_rport,
                            skf->sf_laddr, lp->lp_lport,
                            fm->fm_hwports_available & fm->fm_hwports_up,
                            OOF_SRC_FLAGS_DEFAULT, 1);
      }
      oof_manager_sw_filter_insert(fm, af, laddr, lp, la_i);
    }
}


void
oof_manager_addr_add(struct oof_manager* fm, int af, ci_addr_t laddr,
                     unsigned ifindex)
{
  struct oof_local_interface_details* lid;

#if CI_CFG_IPV6
  if ( af != AF_INET && af != AF_INET6 ) {
#else
  if ( af != AF_INET ) {
#endif
    ERR_LOG("%s: ERROR: bad addreess family %d", __FUNCTION__, af);
    return;
  }

  IPF_LOG("%s: addr=" IPX_FMT " ifindex=%d", __FUNCTION__,
          IPX_ARG(AF_IP_L3(laddr)), ifindex);

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  lid = oof_local_interface_details_find(fm, ifindex);

  if( oof_use_all_local_ip_addresses ||
      (lid != NULL && lid->lid_hwport_mask != 0) )
    __oof_manager_addr_add(fm, af, laddr, ifindex);
  else
    __oof_manager_addr_del(fm, af, laddr, ifindex);

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}


static void
oof_manager_addr_dead(struct oof_manager* fm, struct oof_local_addr* la)
{
  /* Disable/remove table entry.  We can't be bothered to deal with
   * shuffling table entries here, so just mark the entry as free.
   */
  ci_assert(la->la_sockets == 0);
  ci_assert( ci_dllist_is_empty(&la->la_active_ifs) );
  la->la_laddr = addr_any;
}


/* Address removal concerns wild sockets and sockets bound to the
 * address.
 * Primarily, the sockets' (including INADDR_ANY ones)
 * hw/sw filters associated with the removed address are cleared.
 * This stops traffic from coming to and being processd by onload.
 *
 * State relating to removed ip address cannot be removed as long as it
 * is referenced by sockets bound to it.  In particular, the index of an
 * address in the fm_local_addrs array never changes while there are
 * sockets referencing it.
 *
 * One complexity is that when hw filters are cleared then hw filter
 * sharing between filters cannot be determined - so we clear the
 * filter sharing state that is lpa_n_full_sharers counter.  Even more
 * so we disable further local_port_address sharing by setting the
 * per local_port_address flag: OOF_LPA_FLAG_REMOVED.
 *
 * Other function of the flag is to prevent further attempts of adding
 * sw/hw filters in result of adding or removing a socket - mind
 * fixup_wild.
 * We still allow adding the sockets - mostly to allow graceful
 * processing of listenq/acceptq backlogs.
 */
static void
__oof_manager_addr_del(struct oof_manager *fm, int af, ci_addr_t laddr,
                       unsigned ifindex)
{
  struct oof_local_port_addr* lpa;
  struct oof_local_port* lp;
  struct oof_local_addr* la;
  struct oof_local_interface* li;
  struct oof_local_interface* li_tmp;
  struct oof_socket* skf;
  int hash, la_i;
  ci_dllist *la_active_ifs;

  ci_assert(!CI_IPX_ADDR_IS_ANY(laddr));
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  la_i = oof_manager_addr_find(fm, laddr);
  if( la_i < 0 )
    /* We never added this address, possibly due to overflow. */
    return;

  la = &fm->fm_local_addrs[la_i];
  la_active_ifs = &la->la_active_ifs;

  if( ci_dllist_is_empty(la_active_ifs) ) {
    /* Unused, so don't need do anything */
    return;
  }

  CI_DLLIST_FOR_EACH3(struct oof_local_interface, li, li_active_ifs_link, 
                      la_active_ifs, li_tmp)
    if( li->li_ifindex == ifindex ) {
      ci_dllist_remove(&li->li_active_ifs_link);
      ci_free(li);
    }

  if( ci_dllist_not_empty(la_active_ifs) ) {
    /* Not yet, unused, so don't do anything yet */
    return;
  }

  /* Address is disabled; remove filters. */
  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      lpa = &lp->lp_addr[la_i];
      /* Remove h/w filters that use [laddr]. */
      oof_hw_filter_clear_wild(fm, lp, lpa, la->la_laddr);

      CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                          &lpa->lpa_full_socks)
        oof_hw_filter_clear_full(fm, skf);
      /* Mark local_port_addr to indicate address has been removed
       * and filter sharing has been disabled. */
      lpa->lpa_flags |= OOF_LPA_FLAG_REMOVED;
      lpa->lpa_n_full_sharers = 0;
      oof_manager_sw_filter_remove(af, laddr, lp, la_i);
    }

  if( la->la_sockets )
    return;

  /* Address is no longer in use by any socket. */
#ifndef NDEBUG
  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      lpa = &lp->lp_addr[la_i];
      ci_assert(ci_dllist_is_empty(&lpa->lpa_semi_wild_socks));
      ci_assert(ci_dllist_is_empty(&lpa->lpa_full_socks));
      ci_assert(oo_hw_filter_is_empty(&lpa->lpa_filter));
    }
#endif

  oof_manager_addr_dead(fm, la);
}


void
oof_manager_addr_del(struct oof_manager* fm, int af, ci_addr_t laddr,
                     unsigned ifindex)
{
#if CI_CFG_IPV6
  if ( af != AF_INET && af != AF_INET6 ) {
#else
  if ( af != AF_INET ) {
#endif
    ERR_LOG("%s: ERROR: bad addreess family %d", __FUNCTION__, af);
    return;
  }

  IPF_LOG("%s: addr=" IPX_FMT " ifindex=%d", __FUNCTION__,
          IPX_ARG(AF_IP_L3(laddr)), ifindex);

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  __oof_manager_addr_del(fm, af, laddr, ifindex);

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}


int
oof_manager_dnat_add(struct oof_manager* fm, int af, ci_uint16 lp_protocol,
                     const ci_addr_t orig_addr, ci_uint16 orig_port,
                     const ci_addr_t xlated_addr, ci_uint16 xlated_port)
{
  struct oof_local_port_addr* lpa;
  struct oof_local_port* lp;
  struct oof_socket* skf;
  struct oof_nat_filter *nat_filter;
  struct oof_nat_table* nat_table = oof_cb_nat_table(fm->fm_owner_private);
  int la_i, rc;

  rc = 0;
  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  la_i = oof_manager_addr_find(fm, xlated_addr);
  if( la_i < 0 )
    goto out;

  lp = oof_local_port_find(fm, lp_protocol, xlated_port);
  if( lp == NULL )
    goto out;

  lpa = &lp->lp_addr[la_i];
  skf = oof_wild_socket(lp, lpa, OO_AF_FAMILY2SPACE(af));
  if( skf != NULL ) {
    nat_filter = oof_nat_table_filter_get(nat_table);
    ci_assert(nat_filter);
    if( nat_filter == NULL ) {
      rc = -ENOMEM;
    }
    else {
      nat_filter->orig_addr = orig_addr;
      nat_filter->orig_port = orig_port;
      rc = __oof_socket_add_wild(fm, skf, af, &nat_filter->natf_hwfilter,
                                 nat_filter->orig_addr, nat_filter->orig_port,
                                 lp->lp_protocol, 0);
      if( rc == 0 )
        ci_dllist_push(&lpa->lpa_nat_filters, &nat_filter->link);
      else
        oof_nat_table_filter_put(nat_table, nat_filter);
    }
  }

 out:
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  return rc;
}


void
__oof_nat_filter_delete(struct oof_manager* fm,
                        struct oof_nat_filter* nat_filter)
{
  struct oof_nat_table* nat_table = oof_cb_nat_table(fm->fm_owner_private);
  ci_dllist_remove(&nat_filter->link);
  oof_dl_filter_del(&nat_filter->natf_hwfilter);
  oof_hw_filter_clear(fm, &nat_filter->natf_hwfilter);
  oof_nat_table_filter_put(nat_table, nat_filter);
}


void
oof_manager_dnat_del(struct oof_manager* fm, ci_uint16 lp_protocol,
                     const ci_addr_t orig_addr, ci_uint16 orig_port)
{
  struct oof_local_port* lp;
  struct oof_nat_filter* nat_filter;
  struct oof_nat_filter* next;
  int hash, la_i;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash ) {
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      if( lp->lp_protocol != lp_protocol )
        continue;
      for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i )
        CI_DLLIST_FOR_EACH3(struct oof_nat_filter, nat_filter, link,
                            &lp->lp_addr[la_i].lpa_nat_filters, next)
          if( CI_IPX_ADDR_EQ(nat_filter->orig_addr, orig_addr) &&
              nat_filter->orig_port == orig_port )
            __oof_nat_filter_delete(fm, nat_filter);
    }
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}


void
oof_manager_dnat_reset(struct oof_manager* fm, ci_uint16 lp_protocol)
{
  struct oof_local_port* lp;
  struct oof_nat_filter* nat_filter;
  struct oof_nat_filter* next;
  int hash, la_i;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash ) {
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      if( lp->lp_protocol != lp_protocol )
        continue;
      for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i )
        CI_DLLIST_FOR_EACH3(struct oof_nat_filter, nat_filter, link,
                            &lp->lp_addr[la_i].lpa_nat_filters, next)
          __oof_nat_filter_delete(fm, nat_filter);
    }
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}


/**********************************************************************
***********************************************************************
**********************************************************************/

static void
oof_manager_update_all_filters(struct oof_manager* fm)
{
  /* Invoked when physical interfaces come and go.  We add and remove
   * hardware filters to ensure that we don't receive packets through
   * interfaces that are down.  (At time of writing nothing in the net
   * driver or hardware stops packets being delivered when the interface is
   * administratively down).
   */
  struct oof_local_port_addr* lpa;
  struct oof_mcast_filter* mf;
  struct oof_local_port* lp;
  struct oof_tproxy* ft;
  struct oof_socket* skf;
  unsigned hwport_mask;
  ci_addr_t laddr;
  int hash, la_i;

  /* Find all filters potentially affected by a change in the set of
   * hwports, and modify the set of ports filtered as needed.
   */
  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      /* Find and update unicast filters. */
      for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
        lpa = &lp->lp_addr[la_i];
        laddr = fm->fm_local_addrs[la_i].la_laddr;
        if( ! oo_hw_filter_is_empty(&lpa->lpa_filter) )
          oof_hw_filter_update(fm, &lpa->lpa_filter,
                               lpa->lpa_filter.trs,
                               CI_IS_ADDR_IP6(laddr) ? AF_INET6 : AF_INET,
                               lp->lp_protocol, addr_any, 0, laddr, lp->lp_lport,
                               OO_HW_VLAN_UNSPEC,
                               fm->fm_hwports_available & fm->fm_hwports_up,
                               OOF_SRC_FLAGS_DEFAULT);
        CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                            &lpa->lpa_full_socks) {
          ci_assert_equal(skf->sf_full_match_filter.thc, NULL);
          if( ! oo_hw_filter_is_empty(&skf->sf_full_match_filter) )
            oof_hw_filter_update(fm, &skf->sf_full_match_filter,
                                 skf->sf_full_match_filter.trs,
                                 CI_IS_ADDR_IP6(laddr) ? AF_INET6 : AF_INET,
                                 lp->lp_protocol, skf->sf_raddr, skf->sf_rport,
                                 skf->sf_laddr, lp->lp_lport,
                                 OO_HW_VLAN_UNSPEC,
                                 fm->fm_hwports_available & fm->fm_hwports_up,
                                 OOF_SRC_FLAGS_DEFAULT);
        }
      }
      /* Find and update multicast filters. */
      CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                          &lp->lp_mcast_filters) {
        ci_assert_equal(mf->mf_filter.thc, NULL);
        if( ! oo_hw_filter_is_empty(&mf->mf_filter) ) {
          ci_addr_t maddr = CI_ADDR_FROM_IP4(mf->mf_maddr);
          hwport_mask = oof_mcast_filter_installable_hwports(fm, lp, mf);
          hwport_mask &= fm->fm_hwports_up &
              fm->fm_hwports_available;
          oof_hw_filter_update(fm, &mf->mf_filter, mf->mf_filter.trs, AF_INET,
                               lp->lp_protocol, addr_any, 0,
                               maddr, lp->lp_lport,
                               mf->mf_vlan_id, hwport_mask,
                               OOF_SRC_FLAGS_DEFAULT_MCAST);
        }
      }
    }

    /* let us update tproxy filters */
    CI_DLLIST_FOR_EACH2(struct oof_tproxy, ft, ft_manager_link,
                        &fm->fm_tproxies)
      oof_tproxy_filter_update(fm, ft);
}


void oof_hwport_up_down(struct oof_manager* fm, int hwport, int up,
                        int mcast_replicate_capable, int vlan_filters,
                        int sync)
{
  /* A physical interface has gone up or down. */
  if( fm == NULL )
    /* this might be the case in dl_remove on driver unload */
    return;

  spin_lock_bh(&fm->fm_cplane_updates_lock);

  if( up ) {
    /* we allow resetting these flags only when device goes up */
    fm->fm_hwports_mcast_replicate_capable_new &= ~(1 << hwport);
    fm->fm_hwports_vlan_filters_new &= ~(1 << hwport);
  }

  if( mcast_replicate_capable )
    fm->fm_hwports_mcast_replicate_capable_new |= 1 << hwport;
  fm->fm_hwports_vlan_filters_new &= ~(1 << hwport);
  if( vlan_filters )
    fm->fm_hwports_vlan_filters_new |= 1 << hwport;
  if( up ) {
    fm->fm_hwports_up_new |= 1 << hwport;
    fm->fm_hwports_down_new &= ~(1 << hwport);
  }
  else {
    fm->fm_hwports_up_new &= ~(1 << hwport);
    fm->fm_hwports_down_new |= (1 << hwport);
  }
  spin_unlock_bh(&fm->fm_cplane_updates_lock);

  if( sync )
    oof_do_deferred_work(fm);
  else
    oof_cb_defer_work(fm->fm_owner_private);
}


/* This is called when a new interface is probed that is stepping into the
 * shoes of a previous interface.  We trigger the insertion of drop filters
 * for that interface to prevent the kernel from receiving traffic destined for
 * this interface before that interface comes up, lest pre-existing connections
 * get reset. */
void oof_hwport_removed(struct oof_manager* fm, int hwport)
{
  spin_lock_bh(&fm->fm_cplane_updates_lock);
  fm->fm_hwports_removed    |= 1 << hwport;
  fm->fm_hwports_up_new     &= ~(1 << hwport);
  fm->fm_hwports_down_new   |= 1 << hwport;
  spin_unlock_bh(&fm->fm_cplane_updates_lock);

  /* To avoid racing against the kernel, we need to force the filters to be
   * updated right now.  Normally this operation is deferred to a workqueue,
   * but our context is sufficiently friendly that this is safe. */
  ci_assert(! in_atomic());
  oof_do_deferred_work(fm);
}


/* A physical interface is (or isn't) unavailable for the reason indicated by
 * [tag] (for example, if it is a member of an unacceleratable bond).  We
 * should(n't) install filters on this hwport. */
static void
__oof_hwport_un_available(struct oof_manager* fm, ci_hwport_id_t hwport,
                          int available, int tag)
{
  ci_assert(spin_is_locked(&fm->fm_cplane_updates_lock));

  /* Set the updated masks for handling the next time that the OOF workitem
   * runs.  The caller should enqueue this if need be. */
  if( available )
    fm->fm_hwports_avail_per_tag_new[tag] |= 1 << hwport;
  else
    fm->fm_hwports_avail_per_tag_new[tag] &= ~(1 << hwport);
}


void __oof_do_deferred_work(struct oof_manager* fm)
{
  /* Invoked with both outer and inner locks held. */
  unsigned hwports_up_new, hwports_down_new,
           hwports_changed, hwports_removed;
  unsigned hwports_avail_new[OOF_HWPORT_AVAIL_TAG_NUM];
  IPF_LOG("%s:", __FUNCTION__);

  spin_lock_bh(&fm->fm_cplane_updates_lock);

  hwports_changed = fm->fm_hwports_mcast_replicate_capable ^
    fm->fm_hwports_mcast_replicate_capable_new;

  fm->fm_hwports_mcast_replicate_capable =
    fm->fm_hwports_mcast_replicate_capable_new;

  hwports_changed |= fm->fm_hwports_vlan_filters ^
                     fm->fm_hwports_vlan_filters_new;

  fm->fm_hwports_vlan_filters = fm->fm_hwports_vlan_filters_new;

  hwports_removed = fm->fm_hwports_removed;
  hwports_up_new = fm->fm_hwports_up_new;
  hwports_down_new = fm->fm_hwports_down_new;
  memcpy(hwports_avail_new, fm->fm_hwports_avail_per_tag_new,
         sizeof(hwports_avail_new));

  hwports_changed |= hwports_removed |
    (hwports_up_new ^ fm->fm_hwports_up) |
    (hwports_down_new ^ fm->fm_hwports_down);


  /* Restart port change monitoring */
  fm->fm_hwports_removed = 0;

  spin_unlock_bh(&fm->fm_cplane_updates_lock);

  if( hwports_changed ) {
    /* some ports might have changed down then up before we got here.
     * if this was in result of hotplug than we might be seeing a new interface
     * under the same hwport and all filter ids we store are invalid.
     * In such case we make sure we remove all filters first and install new ones.
     * We could do more accurate check by comparing old and new ifindices.
     *
     * The following gives us all ports that are up after previously going down,
     * however oof_do_deferred work had no chance to process the down request
     * separately.
     */
    IPF_LOG("%s: changed=%x, up=%x down=%x removed=%x, new state: up=%x, down=%x "
            "mcast replicate=%x vlan filters=%x",
            __FUNCTION__,
            hwports_changed,
            hwports_up_new &~ fm->fm_hwports_up,
            hwports_down_new &~ fm->fm_hwports_down,
            hwports_removed,
            hwports_up_new, hwports_down_new,
            fm->fm_hwports_mcast_replicate_capable,
            fm->fm_hwports_vlan_filters);

    /* the ports, which went from up -> down -> up might have stale filter ids if
     * up was result of hotplug, lets remove the filters by indicating that
     * the ports are down */
    fm->fm_hwports_up = hwports_up_new & ~hwports_removed;
    fm->fm_hwports_down = hwports_down_new & ~hwports_removed;

    oof_manager_update_all_filters(fm);

    if( hwports_removed ) {
      /* now lets reinstall the filters that we removed earlier from downed ports */
      fm->fm_hwports_up = hwports_up_new;
      fm->fm_hwports_down = hwports_down_new;
      oof_manager_update_all_filters(fm);
    }
  }

  {
    int tag;
    unsigned not_available = 0;
    int changed = 0;

    for( tag = 0; tag < OOF_HWPORT_AVAIL_TAG_NUM; tag++ ) {
      if( fm->fm_hwports_avail_per_tag[tag] != hwports_avail_new[tag] ) {
        IPF_LOG("%s: tag %d: available=%x unavailable=%x", __FUNCTION__, tag,
                hwports_avail_new[tag] &~ fm->fm_hwports_avail_per_tag[tag],
                ~hwports_avail_new[tag] & fm->fm_hwports_avail_per_tag[tag]);
        fm->fm_hwports_avail_per_tag[tag] = hwports_avail_new[tag];
        not_available |= ~fm->fm_hwports_avail_per_tag[tag];
        changed = 1;
      }
    }
    if( changed ) {
      fm->fm_hwports_available = ~not_available;
      oof_manager_update_all_filters(fm);
    }
  }

  BUG_ON(~(fm->fm_hwports_up | fm->fm_hwports_down) &
         fm->fm_hwports_mcast_replicate_capable);
  BUG_ON(~(fm->fm_hwports_up | fm->fm_hwports_down) &
         fm->fm_hwports_vlan_filters);
}

void oof_do_deferred_work(struct oof_manager* fm)
{
  /* Invoked in a non-atomic context (a workitem on Linux) with no locks
   * held.  We handle driverlink updates here.  Reason for deferring to
   * a workitem is so we can grab locks in the right order.
   */
  IPF_LOG("%s:", __FUNCTION__);

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  __oof_do_deferred_work(fm);

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}
/**********************************************************************
***********************************************************************
**********************************************************************/

static struct oof_local_port*
oof_local_port_find(struct oof_manager* fm, int protocol, int lport)
{
  struct oof_local_port* lp;
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                      &fm->fm_local_ports[lp_hash(protocol, lport)])
    if( lp->lp_protocol == protocol && lp->lp_lport == lport )
      return lp;
  return NULL;
}


static struct oof_local_port*
oof_local_port_get(struct oof_manager* fm, int protocol, int lport)
{
  struct oof_local_port* new_lp = NULL;
  struct oof_local_port* lp;

  while( 1 ) {
    spin_lock_bh(&fm->fm_inner_lock);
    lp = oof_local_port_find(fm, protocol, lport);
    if( lp == NULL && new_lp ) {
      lp = new_lp;
      ci_dllist_push_tail(&fm->fm_local_ports[lp_hash(protocol, lport)],
                          &lp->lp_manager_link);
      new_lp = NULL;
    }
    if( lp != NULL )
      ++lp->lp_refs;
    spin_unlock_bh(&fm->fm_inner_lock);

    if( lp != NULL )
      break;

    new_lp = oof_local_port_alloc(fm, protocol, lport);
    if( new_lp == NULL ) {
      ERR_LOG("%s: ERROR: out of memory", __FUNCTION__);
      return NULL;
    }
  }

  if( new_lp != NULL )
    oof_local_port_free(fm, new_lp);

  return lp;
}


static void
oof_full_socks_del_hw_filters(struct oof_manager* fm,
                              struct oof_local_port* lp,
                              struct oof_local_port_addr* lpa)
{
  struct oof_socket* skf;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));
  ci_assert(oof_local_port_addr_valid(fm, lpa));

  CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                      &lpa->lpa_full_socks) {
    if( oo_hw_filter_is_empty(&skf->sf_full_match_filter) )
      continue;
    if( ! oof_socket_can_share_hw_filter(skf, &lpa->lpa_filter) )
      continue;
    ci_assert(oof_local_port_addr_valid(fm, lpa));
    ci_assert_equal(skf->sf_full_match_filter.thc, NULL);
    oof_hw_filter_clear_full(fm, skf);
    ++lpa->lpa_n_full_sharers;
  }
}


static int
oof_full_socks_add_hw_filters(struct oof_manager* fm,
                              struct oof_local_port* lp,
                              struct oof_local_port_addr* lpa,
                              int af)
{
  /* For each full-match socket that is relying on the filter associated
   * with [lpa], try to insert a full-match filter.  Called when the filter
   * associated with [lpa] is about to be removed or pointed at a different
   * stack.
   */
  struct oof_socket* skf;
  int rc = 0;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));
  ci_assert(oof_local_port_addr_valid(fm, lpa));

  if( oo_hw_filter_is_empty(&lpa->lpa_filter) ) {
    ERR_LOG("%s: ERROR: %s:%d has no filter", __FUNCTION__,
            FMT_PROTOCOL(lp->lp_protocol), FMT_PORT(lp->lp_lport));
    return -EINVAL;
  }

  /* oof_hw_filter_set() drops the spin lock, so we need to be
   * extremely careful here.
   * In the loop we are guaranteed that skf is not removed from list
   * as oof_hw_filter_set() marks the socket as having HW filter
   * before dropping the lock. This will prevent oof_socket_del_sw()
   * from full removal of the socket.
   */
  CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                      &lpa->lpa_full_socks) {
    int lport = skf->sf_lport_prenat != 0 ? skf->sf_lport_prenat : lp->lp_lport;
    if( ! oo_hw_filter_is_empty(&skf->sf_full_match_filter) )
      continue;
    if( ! oof_socket_can_share_hw_filter(skf, &lpa->lpa_filter) )
      continue;
    ci_assert(! oof_socket_is_clustered(skf));
    rc = oof_hw_filter_set(fm, skf, &skf->sf_full_match_filter,
                           oof_cb_socket_stack(skf), NULL, af,
                           lp->lp_protocol, skf->sf_raddr, skf->sf_rport,
                           skf->sf_laddr, lport,
                           fm->fm_hwports_available & fm->fm_hwports_up,
                           OOF_SRC_FLAGS_DEFAULT, 1);
    if( rc < 0 ) {
      oof_full_socks_del_hw_filters(fm, lp, lpa);
      break;
    }
    oof_cb_callback_set_filter(skf);
    ci_assert(lpa->lpa_n_full_sharers > 0);
    --lpa->lpa_n_full_sharers;
  }

  return rc;
}


/* Reasons why fixup_wild() is called. */
enum fixup_wild_why {
  fuw_del_full,
  fuw_del_wild,
  fuw_add_wild,
  fuw_udp_connect,
};


static void
oof_local_port_addr_fixup_wild(struct oof_manager* fm,
                               struct oof_local_port* lp,
                               struct oof_local_port_addr* lpa,
                               ci_addr_t laddr, enum fixup_wild_why why)
{
  struct oof_socket* skf;
  int rc, skf_has_filter;
  int unshare_full_match;
  int thresh;
  int af = CI_IS_ADDR_IP6(laddr) ? AF_INET6 : AF_INET;

  if( ! oof_local_port_addr_valid(fm, lpa) ) {
    ci_assert(oo_hw_filter_is_empty(&lpa->lpa_filter));
    /* nothing to do when addr is removed */
    return;
  }
  /* Decide whether we need to insert full-match filters for sockets that
   * are currently sharing a wild filter.
   */
  skf = oof_wild_socket(lp, lpa, oof_addr_to_af_space(laddr));
  unshare_full_match = lpa->lpa_n_full_sharers > 0;
  if( skf == NULL ) {
    thresh = oof_shared_keep_thresh;
  }
  else {
    thresh = oof_shared_steal_thresh;
    if( oof_socket_can_share_hw_filter(skf, &lpa->lpa_filter) )
      /* The existing filter points at the correct stack, so no need to add
       * filters for full-match sockets in that stack.
       */
      unshare_full_match = 0;
  }
  if( unshare_full_match && lpa->lpa_n_full_sharers > thresh ) {
    /* There are lots of sockets still using this wild filter.  We choose
     * not to transfer them all to their own full-match filters, as that
     * would consume lots of h/w resources.  This new socket will have to
     * wait until the filter is freed up.
     *
     * This is not really an error, as user can change
     * oof_shared_[keep|steal]_thresh if they don't like it.  We emit a log
     * message by default (when wild filter is added or removed), as
     * otherwise it can be tricky to see what is going on.
     */
    if( (oo_debug_bits & __OO_DEBUGIPF__) ||
        ((oo_debug_bits & __OO_DEBUGERR__) && why != fuw_del_full) ) {
      ci_log("%s: "IPX_TRIPLE_FMT" shared by %d socks in stack %d "
             "(thresh=%d reason=%d)", __FUNCTION__,
             IPX_TRIPLE_ARGS(lp->lp_protocol, AF_IP(laddr), lp->lp_lport),
             lpa->lpa_n_full_sharers, oof_cb_stack_id(lpa->lpa_filter.trs),
             thresh, (int) why);
      if( skf != NULL )
        ci_log("%s: WARNING: "SK_FMT" "SK_WILD_ADDR_FMT" will not yet receive "
               "traffic", __FUNCTION__, SK_PRI_ARGS(skf),
               SK_WILD_ADDR_ARGS(skf));
    }
    unshare_full_match = 0;
  }

  if( unshare_full_match ) {
    rc = oof_full_socks_add_hw_filters(fm, lp, lpa, af);
    if( rc < 0 ) {
      if( (oo_debug_bits & __OO_DEBUGIPF__) ||
          ((oo_debug_bits & __OO_DEBUGERR__) && why != fuw_del_full) ) {
        ci_log("%s: %s"IPX_TRIPLE_FMT" unable to free wild filter "
               "(%d sharers in stack %d, rc=%d reason=%d)", __FUNCTION__,
               skf == NULL ? "":"ERROR: ",
               IPX_TRIPLE_ARGS(lp->lp_protocol, AF_IP(laddr), lp->lp_lport),
               lpa->lpa_n_full_sharers, oof_cb_stack_id(lpa->lpa_filter.trs),
               rc, (int) why);
        if( skf != NULL )
          ci_log("%s: WARNING: "SK_FMT" "SK_WILD_ADDR_FMT" will not yet "
                 "receive traffic", __FUNCTION__, SK_PRI_ARGS(skf),
                 SK_WILD_ADDR_ARGS(skf));
      }
    }
  }

  if( skf != NULL ) {
    skf_has_filter = 0;
    if( oo_hw_filter_is_empty(&lpa->lpa_filter) ) {
      ci_assert(lpa->lpa_n_full_sharers == 0);
      rc = oof_hw_filter_set(fm, skf, &lpa->lpa_filter,
                             oof_socket_stack_effective(skf),
                             oof_socket_thc_effective(skf), af,
                             lp->lp_protocol, addr_any, 0, laddr, lp->lp_lport,
                             fm->fm_hwports_available & fm->fm_hwports_up,
                             OOF_SRC_FLAGS_DEFAULT, 1);
      skf_has_filter = rc == 0;
    }
    else if( ! oof_socket_can_share_hw_filter(skf, &lpa->lpa_filter) &&
             lpa->lpa_n_full_sharers == 0 ) {
      /* We don't have support for filter re-direct changing the rss context.
       * If either the old or new filter uses rss then we need to remove and
       * re-insert.  Unfortunately that leaves a gap.  However, full match
       * filters are inserted when we unshare, so the sockets that were
       * previously sharing the wild filter that's being replaced will not
       * miss traffic.
       */
      if( lpa->lpa_filter.thc || oof_socket_thc_safe(skf) ) {
        oof_hw_filter_clear_wild(fm, lp, lpa, laddr);
        rc = oof_hw_filter_set(fm, skf, &lpa->lpa_filter,
                               oof_socket_stack_effective(skf),
                               oof_socket_thc_effective(skf), af,
                               lp->lp_protocol, addr_any, 0, laddr, lp->lp_lport,
                               fm->fm_hwports_available & fm->fm_hwports_up,
                               OOF_SRC_FLAGS_DEFAULT, 1);
        skf_has_filter = rc == 0;
      }
      else {
        /* Clustered sockets cannot have hardware filters moved */
        ci_assert_equal(lpa->lpa_filter.thc, NULL);
        oof_hw_filter_move(fm, skf, lp, lpa, laddr, af,
                           fm->fm_hwports_available & fm->fm_hwports_up);
        ci_assert(lpa->lpa_filter.trs == oof_cb_socket_stack(skf));
        skf_has_filter = 1;
      }
    }
    if( skf_has_filter )
      oof_full_socks_del_hw_filters(fm, lp, lpa);
  }
  else if( lpa->lpa_n_full_sharers == 0 ) {
    oof_hw_filter_clear_wild(fm, lp, lpa, laddr);
  }
}


static void
oof_local_port_fixup_wild(struct oof_manager* fm, struct oof_local_port* lp,
                          enum fixup_wild_why why, int af_space)
{
  struct oof_local_addr* la;
  int la_i;
  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    la = &fm->fm_local_addrs[la_i];

    if( ! (oof_addr_to_af_space(la->la_laddr) & af_space) )
      continue;

    if( ci_dllist_not_empty(&la->la_active_ifs) )
      oof_local_port_addr_fixup_wild(fm, lp, &lp->lp_addr[la_i],
                                     la->la_laddr, why);
  }
}


/* Fixme: most callers of oof_cb_sw_filter_insert and
 * oof_socket_add_full_sw do not check rc. */
static int
oof_socket_add_full_sw(struct oof_socket* skf)
{
  struct oof_local_port* lp = skf->sf_local_port;
  int lport = skf->sf_lport_prenat != 0 ? skf->sf_lport_prenat : lp->lp_lport;

  return oof_cb_sw_filter_insert(skf, skf->af_space,
                                 skf->sf_laddr, lport,
                                 skf->sf_raddr, skf->sf_rport,
                                 lp->lp_protocol, 1);
}


static void
oof_socket_del_full_sw(struct oof_socket* skf, int stack_locked)
{
  struct oof_local_port* lp = skf->sf_local_port;
  int lport = skf->sf_lport_prenat != 0 ? skf->sf_lport_prenat : lp->lp_lport;

  oof_cb_sw_filter_remove(skf, skf->af_space,
                          skf->sf_laddr, lport,
                          skf->sf_raddr, skf->sf_rport,
                          lp->lp_protocol, stack_locked);
}


static void
oof_socket_del_wild_sw(struct oof_manager* fm, struct oof_socket* skf,
                       ci_addr_t laddr)
{
  struct oof_local_port* lp = skf->sf_local_port;
  int la_i;

  oof_cb_sw_filter_remove(skf, skf->af_space, laddr, lp->lp_lport, addr_any,
                          0, lp->lp_protocol, 1);

  /* Clear any NAT filters.  Note that we must find these filters by looking
   * at the lpa_nat_filters list rather than by doing a lookup through the NAT
   * table as the latter would be racy. */
  if( lp->lp_protocol == IPPROTO_TCP &&
      (la_i = oof_manager_addr_find(fm, laddr)) >= 0 ) {
    struct oof_local_port_addr* lpa = &lp->lp_addr[la_i];
    struct oof_nat_filter* nat_filter;

    CI_DLLIST_FOR_EACH2(struct oof_nat_filter, nat_filter, link,
                        &lpa->lpa_nat_filters)
      oof_cb_sw_filter_remove(skf, skf->af_space, nat_filter->orig_addr,
                              nat_filter->orig_port, addr_any, 0,
                              lp->lp_protocol, 1);
  }
}


static void
oof_socket_del_full(struct oof_manager* fm, struct oof_socket* skf,
                    struct oof_local_port_addr* lpa)
{
  oof_socket_remove_from_list(skf);
  oof_socket_del_full_sw(skf, 1);
  if( ! oo_hw_filter_is_empty(&skf->sf_full_match_filter) ) {
    oof_hw_filter_clear_full(fm, skf);
  }
  else if( oof_socket_can_share_hw_filter(skf, &lpa->lpa_filter) ) {
    ci_assert(oof_local_port_addr_valid(fm, lpa));
    ci_assert(lpa->lpa_n_full_sharers > 0);
    --lpa->lpa_n_full_sharers;
    oof_local_port_addr_fixup_wild(fm, skf->sf_local_port, lpa,
                                   skf->sf_laddr, fuw_del_full);
  }
}


static int
oof_socket_add_full_hw(struct oof_manager* fm, struct oof_socket* skf,
                       struct oof_local_port_addr* lpa, int af)
{
  int rc;
  ci_assert(! oof_socket_is_clustered(skf));
  ci_assert(! oof_socket_is_dummy(skf));
  ci_assert(oof_local_port_addr_valid(fm, lpa));
  if( ! oof_socket_can_share_hw_filter(skf, &lpa->lpa_filter) ) {
    struct oof_local_port* lp = skf->sf_local_port;
    rc = oof_hw_filter_set(fm, skf, &skf->sf_full_match_filter,
                           oof_cb_socket_stack(skf), NULL, af,
                           lp->lp_protocol, skf->sf_raddr, skf->sf_rport,
                           skf->sf_laddr, lp->lp_lport,
                           fm->fm_hwports_available & fm->fm_hwports_up,
                           OOF_SRC_FLAGS_DEFAULT, 1);
    if( rc < 0 ) {
      /* I think there are the following ways this can fail:
       *
       * - Out of memory (ENOMEM).
       * - Out of space in h/w filter table (EBUSY).
       * - Clash in h/w filter table (EEXIST).
       * - Blocked by Onload iptables (ERFKILL).
       *
       * Is this where we get to if two sockets try to bind/connect to the
       * same 5-tuple?
       *
       * ?? TODO: Handle the various errors elegantly.
       */
      if( rc == -EBUSY || rc == -ERFKILL )
        return rc;
      else
        return -EADDRNOTAVAIL;
    }
  }
  else {
    /* Share the existing wildcard filter for h/w demux. */
    ++lpa->lpa_n_full_sharers;
    IPF_LOG(FSK_FMT "SHARE "SK_ADDR_FMT, FSK_PRI_ARGS(skf), SK_ADDR_ARGS(skf));
  }
  return 0;
}


/* Installs software and (if oofilter is non-NULL) hardware filters on the
 * specified local address and port for a wild or semi-wild socket. */
static int
__oof_socket_add_wild(struct oof_manager* fm, struct oof_socket* skf,
                      int af_space, struct oo_hw_filter* oofilter,
                      ci_addr_t laddr, ci_uint16 lport, ci_uint16 protocol,
                      int stack_locked)
{
  int rc = oof_cb_sw_filter_insert(skf, af_space, laddr, lport,
                                   addr_any, 0, protocol, stack_locked);

  if( rc == 0 && oofilter != NULL ) {
    ci_assert(oo_hw_filter_is_empty(oofilter));
    rc = oof_hw_filter_set(fm, skf, oofilter,
                           oof_socket_stack_effective(skf),
                           oof_socket_thc_effective(skf),
                           IS_AF_SPACE_IP6(af_space) ? AF_INET6 : AF_INET,
                           protocol, addr_any, 0, laddr, lport,
                           fm->fm_hwports_available & fm->fm_hwports_up,
                           OOF_SRC_FLAGS_DEFAULT, 1);
    if( rc != 0 )
      oof_cb_sw_filter_remove(skf, skf->af_space, laddr, lport, addr_any, 0,
                              protocol, stack_locked);
  }

  return rc;
}


/* Installs filters for a wild or semi-wild socket.  Note that the laddr
 * parameter here is the address before any NAT: the function will do NAT
 * lookups on this address and will install filters for extra addresses as
 * required. */
static int
oof_socket_add_wild(struct oof_manager* fm, struct oof_socket* skf,
                    int af_space, struct oof_local_port_addr* lpa,
                    ci_addr_t laddr, int stack_locked)
{
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_socket* other_skf;
  bool already_has_hw_filter = ! oo_hw_filter_is_empty(&lpa->lpa_filter);
  int rc = 0;
  struct oof_nat_table* nat_table = oof_cb_nat_table(fm->fm_owner_private);
  struct oof_nat_lookup_result nat_preimage;
  struct tcp_helper_resource_s* skf_stack;

  ci_assert(! oof_socket_is_dummy(skf));

  if( ! oof_local_port_addr_valid(fm, lpa) )
    return 0;

  /* Find extra address:port pairs that require filters as a result of NAT. */
  if( lp->lp_protocol == IPPROTO_TCP ) {
    rc = oof_nat_table_lookup(nat_table, laddr, lp->lp_lport, &nat_preimage);
    if( rc != 0 )
      return rc;
  }
  else {
    nat_preimage.n_results = 0;
  }

  skf_stack = oof_cb_socket_stack(skf);
  other_skf = oof_wild_socket_matching_stack(lp, lpa, af_space, skf_stack);
  if( other_skf != NULL ) {
    /* Hide sw filter of other socket on the same stack
     *  (likely the wilder one) */
    oof_cb_sw_filter_remove(other_skf, af_space, laddr, lp->lp_lport,
                            addr_any, 0, lp->lp_protocol, stack_locked);
    /* NAT-able sockets should never be hiding each other in the current
     * implementation, becase we apply NAT to TCP only, but socket-hiding of
     * this sort is only possible for UDP (with SO_REUSEADDR). */
    ci_assert_equal(nat_preimage.n_results, 0);
  }

  /* Install software and hardware filters.  If we already have a hardware
   * filter, pass NULL for the argument that would be used to store the state
   * of that filter, so as to prevent us from trying to insert another one. */
  rc = __oof_socket_add_wild(fm, skf, af_space,
                             already_has_hw_filter ? NULL : &lpa->lpa_filter,
                             laddr, lp->lp_lport, lp->lp_protocol, stack_locked);
  if( ! already_has_hw_filter ) {
    int i;
    for( i = 0; rc == 0 && i < nat_preimage.n_results; ++i ) {
      struct oof_nat_filter* nat_filter = oof_nat_table_filter_get(nat_table);
      ci_assert(nat_filter);
      if( nat_filter == NULL ) {
        rc = -ENOMEM;
      }
      else {
        nat_filter->orig_addr = nat_preimage.results[i].orig_addr;
        nat_filter->orig_port = nat_preimage.results[i].orig_port;
        rc = __oof_socket_add_wild(fm, skf, af_space,
                                   &nat_filter->natf_hwfilter,
                                   nat_filter->orig_addr,
                                   nat_filter->orig_port, lp->lp_protocol,
                                   stack_locked);
        if( rc == 0 )
          ci_dllist_push(&lpa->lpa_nat_filters, &nat_filter->link);
        else
          oof_nat_table_filter_put(nat_table, nat_filter);
      }
    }
  }
  else if( ! oof_socket_can_share_hw_filter(skf, &lpa->lpa_filter) ) {
    /* H/w filter already exists but points to a different stack.  This is
     * fixed if necessary in oof_local_port_addr_fixup_wild().
     */
    OO_DEBUG_IPF(other_skf = oof_wild_socket(lp, lpa, skf->af_space);
                 if( other_skf != NULL )
                   ci_log(FSK_FMT "STEAL "IPX_TRIPLE_FMT" from "SK_FMT,
                          FSK_PRI_ARGS(skf),
                          IPX_TRIPLE_ARGS(lp->lp_protocol,
                          AF_IP(laddr), lp->lp_lport),
                          SK_PRI_ARGS(other_skf)));
  }
  if( nat_preimage.n_results > 0 )
    oof_nat_table_lookup_free(&nat_preimage);
  if( rc < 0 )
    __oof_socket_del_wild(fm, skf, af_space, skf_stack, lpa, laddr);
  return rc;
}


static int
oof_socket_steal_or_add_wild(struct oof_manager* fm, struct oof_socket* skf)
{
  struct oof_local_port* lp = skf->sf_local_port;
  struct tcp_helper_resource_s* skf_stack;
  struct oof_local_port_addr* lpa;
  struct oof_local_addr* la;
  int la_i;
  int has_ok = 0;
  int has_fail = 0;
  int rc, saved_rc = 0;
  int af_space;

  ci_assert(CI_IPX_ADDR_IS_ANY(skf->sf_laddr));
  ci_assert(CI_IPX_ADDR_IS_ANY(skf->sf_raddr));

  skf_stack = oof_cb_socket_stack(skf);

  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    la = &fm->fm_local_addrs[la_i];
    af_space = oof_addr_to_af_space(la->la_laddr);

    if( ! oof_skf_uses_af_space(skf, af_space) )
      continue;

    if( ci_dllist_is_empty(&la->la_active_ifs) )
      /* Entry invalid or address disabled. */
      continue;
    lpa = &lp->lp_addr[la_i];

    if( oof_socket_list_find_matching_stack(&lpa->lpa_semi_wild_socks,
                                            skf_stack, af_space, 0) == NULL ) {
      rc = oof_socket_add_wild(fm, skf, af_space, lpa, la->la_laddr, 1);
      if( rc == 0 && ! has_ok )
        has_ok = 1;
      else if( rc != 0 && ! has_fail ) {
        has_fail = 1;
        saved_rc = rc;
      }
    }
  }

  if( ! has_fail )
    return 0;
  else if( has_ok )
    return -EFILTERSSOME;
  else
    return saved_rc;
}


static int oof_are_cluster_compatible(ci_dllist* list, struct oof_socket* skf)
{
  return oof_socket_is_clustered(skf) ?
         oof_socket_at_head(list, OOF_SOCKET_CLUSTERED | OOF_SOCKET_NO_UCAST |
                                  OOF_SOCKET_DUMMY, 0, skf->af_space) == NULL :
         oof_socket_at_head(list, OOF_SOCKET_DUMMY | OOF_SOCKET_NO_UCAST,
                                  OOF_SOCKET_CLUSTERED, skf->af_space) == NULL;
}


static int oof_are_all_addrs_cluster_compatible(struct oof_manager* fm,
                                                struct oof_local_port* lp,
                                                struct oof_socket* skf)
{
  int la_i;
  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    struct oof_local_port_addr* lpa = &lp->lp_addr[la_i];
    if( ! oof_are_cluster_compatible(&lpa->lpa_semi_wild_socks, skf) )
      return 0;
  }
  return 1;
}


static int
__oof_socket_add(struct oof_manager* fm, struct oof_socket* skf, int do_arm_only,
                 int inc_laddr_ref, struct tcp_helper_cluster_s** thc_out)
{
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_local_port_addr* lpa;
  struct oof_local_addr* la;
  int rc = 0;
  int dummy = oof_socket_is_dummy(skf);
  /* helper flags to describe what operations will be done for wild sockets */
  int do_arm = ! dummy && !oof_socket_no_unicast(skf);
  int do_insert = ! do_arm_only;

  ci_assert(ci_dllink_is_free(&skf->sf_lp_link));
  /* we need to do something */
  ci_assert(do_arm || do_insert);
  /* multicast and full match sockets do not support two-stage add, but we
   * use the same path for sockets with no unicast so do allow that.
   */
  ci_assert((do_arm && do_insert) ||
            ! CI_IPX_IS_MULTICAST(skf->sf_laddr) ||
            oof_socket_no_unicast(skf));
  ci_assert((do_arm && do_insert) ||
            CI_IPX_ADDR_IS_ANY(skf->sf_raddr) ||
            oof_socket_no_unicast(skf));

  if( !CI_IPX_ADDR_IS_ANY(skf->sf_laddr) ) {
    skf->sf_la_i = oof_manager_addr_find(fm, skf->sf_laddr);
    if( skf->sf_la_i < 0 ) {
      if( CI_IPX_IS_MULTICAST(skf->sf_laddr) ) {
        /* Local address is bound to multicast address.  We don't insert
         * any filters in this case.  Socket will get accelerated traffic
         * iff it does IP_ADD_MEMBERSHIP.  (NB. In practice this cannot be
         * a full-match add, as that goes via oof_udp_connect()).
         */
        IPF_LOG(FSK_FMT" " IPX_FMT " multicast -- not filtered",
                FSK_PRI_ARGS(skf), IPX_ARG(AF_IP_L3(skf->sf_laddr)));
        ci_dllist_push(&fm->fm_mcast_laddr_socks, &skf->sf_lp_link);
        return 0;
      }
      ERR_LOG(FSK_FMT "ERROR: laddr=" IPX_FMT " not local",
              FSK_PRI_ARGS(skf), IPX_ARG(AF_IP_L3(skf->sf_laddr)));
      return -ENOENT;
    }

    lpa = &lp->lp_addr[skf->sf_la_i];
    la = &fm->fm_local_addrs[skf->sf_la_i];

    if( !CI_IPX_ADDR_IS_ANY(skf->sf_raddr) ) {
      if( oof_socket_is_clustered(skf) ) {
        ci_log("%s: ERROR: Full match filter with reuseport set", __FUNCTION__);
        return -EINVAL;
      }
      if( oof_local_port_addr_valid(fm, lpa) ) {
        if( (rc = oof_socket_add_full_sw(skf)) != 0 )
          return rc;
        if( (rc = oof_socket_add_full_hw(fm, skf, lpa,
                                         IS_AF_SPACE_IP6(skf->af_space) ?
                                         AF_INET6 : AF_INET)) != 0 ) {
          oof_socket_del_full_sw(skf, 1);
          return rc;
        }
      }
      ci_dllist_push(&lpa->lpa_full_socks, &skf->sf_lp_link);
    }
    else {
      if( do_arm ) {
        if( ! oof_are_cluster_compatible(&lp->lp_wild_socks, skf) )
          return -EADDRINUSE;
      }
      if( do_insert ) {
        rc = oof_socket_insert_probe(&lpa->lpa_semi_wild_socks, skf, thc_out);
        if( rc < 0 )
          return rc;
      }
      if( do_arm )
        rc = oof_socket_add_wild(fm, skf, skf->af_space, lpa, skf->sf_laddr, 1);
      if( rc < 0 )
        return rc;
      ci_dllist_push(&lpa->lpa_semi_wild_socks, &skf->sf_lp_link);
      if( do_arm )
        oof_local_port_addr_fixup_wild(fm, lp, lpa, skf->sf_laddr,
                                       fuw_add_wild);
    }
    if( inc_laddr_ref )
      ++la->la_sockets;
  }
  else {
    if( do_arm ) {
      if( ! oof_are_all_addrs_cluster_compatible(fm, lp, skf) )
        return -EADDRINUSE;
    }
    if( do_insert ) {
      rc = oof_socket_insert_probe(&lp->lp_wild_socks, skf, thc_out);
      if( rc < 0 )
        return rc;
    }
    if( do_arm )
      rc = oof_socket_steal_or_add_wild(fm, skf);
    if( rc < 0 && rc != -EFILTERSSOME )
      return rc;
    ci_dllist_push(&lp->lp_wild_socks, &skf->sf_lp_link);
    if( do_arm )
      oof_local_port_fixup_wild(fm, lp, fuw_add_wild, skf->af_space);
  }
  return rc;
}


/* Replaces socket that uses an installed dummy (semi-)wild filter without stack,
 *
 * This is needed when our dummy socket was not backed by socket buffer.
 *
 * Mind target skf should be initialized but not installed.
 *
 * Use oof_socket_dtor on old_skf.
 *
 */
int oof_socket_replace(struct oof_manager* fm,
                       struct oof_socket* old_skf, struct oof_socket* skf)
{
  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  /* skf socket should not be in any list, but if it is, then we just
   * remove it. */
  ci_assert_equal(skf->sf_local_port, NULL);
  if( skf->sf_local_port != NULL )
    oof_socket_remove_from_list(skf);

  ci_assert_nequal(old_skf->sf_local_port, NULL);
  ci_assert(! ci_dllink_is_free(&old_skf->sf_lp_link));
  ci_assert_flags(old_skf->sf_flags, OOF_SOCKET_DUMMY | OOF_SOCKET_NO_STACK);
  ci_assert(oo_hw_filter_is_empty(&old_skf->sf_full_match_filter));
  ci_assert(ci_dllist_is_empty(&old_skf->sf_mcast_memberships));

  ci_assert_equal(skf->sf_local_port, NULL);
  ci_assert(ci_dllink_is_free(&skf->sf_lp_link));
  ci_assert(oo_hw_filter_is_empty(&skf->sf_full_match_filter));
  ci_assert(ci_dllist_is_empty(&skf->sf_mcast_memberships));
  ci_assert_nequal(oof_socket_thc_safe(skf), NULL);

  skf->af_space = old_skf->af_space;
  skf->sf_laddr = old_skf->sf_laddr;
  skf->sf_raddr = old_skf->sf_raddr;
  skf->sf_rport = old_skf->sf_rport;
  skf->sf_lport_prenat = old_skf->sf_lport_prenat;
  skf->sf_local_port = old_skf->sf_local_port;
  skf->sf_la_i = old_skf->sf_la_i;
  skf->sf_flags = old_skf->sf_flags & ~OOF_SOCKET_NO_STACK;

  /* Do the swap in port/portaddr list */
  ci_dllist_insert_after(&old_skf->sf_lp_link, &skf->sf_lp_link);
  oof_socket_remove_from_list(old_skf);

  /* mark old socket as empty */
  old_skf->sf_local_port = NULL;
  old_skf->sf_flags = 0;

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  return 0;
}


/* check that it should be OK to update a stack-less socket
 * with the given stack.
 *
 * Possible collision would be existence of another clustered socket
 * in the same stack, or different cluster holding the stack, or
 * a nonclustered socket.
 * */
int oof_socket_can_update_stack(struct oof_manager* fm, struct oof_socket* skf,
                                struct tcp_helper_resource_s* thr)
{
  int can_add = 0;
  struct oof_local_port* lp;
  ci_dllist* list;

  spin_lock_bh(&fm->fm_inner_lock);

  ci_assert_flags(skf->sf_flags, OOF_SOCKET_DUMMY | OOF_SOCKET_NO_STACK);

  lp = skf->sf_local_port;
  ci_assert_nequal(lp, NULL);
  if( !CI_IPX_ADDR_IS_ANY(skf->sf_laddr) ) {
    ci_assert_ge(skf->sf_la_i, 0);
    list = &lp->lp_addr[skf->sf_la_i].lpa_semi_wild_socks;
  }
  else {
    list = &lp->lp_wild_socks;
  }

  /* no socket of the same stack, even dummy one */
  can_add = oof_socket_list_find_matching_stack(list, thr, skf->af_space, 1) == NULL;

  /* FIXME we could add some assertions to check
   *  * there is no other conflicting socket on list
   */
  spin_unlock_bh(&fm->fm_inner_lock);
  return can_add;
}


/* Adds a socket or arms a dummy socket
 *
 * Before new socket is added some checks are done:
 * If there is an existing socket claiming the same
 * tuple of proto:port[:ip], then -EADDRINUSE is returned,
 * unless both new and existing sockets belong to the same cluster
 * and different stacks.
 *
 * If dummy add is performed no sw or hw filters will be installed,
 * and if the new dummy socket is both clustered and stackless,
 * thc_out might be filled with thc of existing cluster using the tuple
 * when that is the case.
 *
 * In case existing dummy socket is given, its arming will be performed
 * that is its dummy status is lifted with sw and hw filters set as needed.
 *
 * Return values:
 * 0 - socket added successfully
 * <0 - error
 */

int
oof_socket_add(struct oof_manager* fm, struct oof_socket* skf,
               int flags, int protocol, int af_space,
               ci_addr_t laddr, int lport,
               ci_addr_t raddr, int rport,
               struct tcp_helper_cluster_s** thc_out)
{
  struct oof_local_port* lp;
  int rc;
  int clustered = flags & OOF_SOCKET_ADD_FLAG_CLUSTERED;
  int dummy = flags & OOF_SOCKET_ADD_FLAG_DUMMY;
  int no_stack = flags & OOF_SOCKET_ADD_FLAG_NO_STACK;
  int no_ucast = flags & OOF_SOCKET_ADD_FLAG_NO_UCAST;
  int do_arm_only;
  int inc_laddr_ref = 1;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  lp = skf->sf_local_port;
  do_arm_only = lp != NULL && oof_socket_is_dummy(skf);

  IPF_LOG(FSK_FMT IPX_QUIN_FMT"%s%s%s%s", FSK_PRI_ARGS_SAFE(skf, no_stack),
          IPX_QUIN_ARGS(protocol,
                    AF_IP(laddr), lport,
                    AF_IP(raddr), rport),
          clustered ? " CLUSTERED" : "",
          do_arm_only ? " ARMING" : "",
          dummy ? " DUMMY" : "",
          no_ucast ? " NO_UCAST" : "");

  ci_assert_equal(lp == NULL, ci_dllink_is_free(&skf->sf_lp_link));
  ci_assert(! dummy || ! do_arm_only);
  ci_assert(lp == NULL || oof_socket_is_dummy(skf));
  ci_assert(dummy || ! no_stack);

  if( thc_out != NULL )
    *thc_out = NULL;

  rc = -EINVAL;
  if( lport == 0 ||
    /* Both raddr and rport values should be equal to zero or both should not */
    ((!CI_IPX_ADDR_IS_ANY(raddr) || rport != 0) &&
      (CI_IPX_ADDR_IS_ANY(raddr) || rport == 0)) ) {
    ERR_LOG(FSK_FMT "ERROR: bad "IPX_PORT_FMT" "IPX_PORT_FMT,
            FSK_PRI_ARGS_SAFE(skf, no_stack),
            IPX_PORT_ARG(AF_IP(laddr), lport),
            IPX_PORT_ARG(AF_IP(raddr), rport));
    ci_assert(! do_arm_only);
    goto just_unlock;
  }
  if( ! do_arm_only && skf->sf_local_port != NULL ) {
    ERR_LOG(FSK_FMT "ERROR: already bound to "SK_ADDR_FMT,
            FSK_PRI_ARGS(skf), SK_ADDR_ARGS(skf));
    goto just_unlock;
  }

  if( do_arm_only && !no_ucast ) {
    lp = oof_local_port_find(fm, protocol, lport);
    ci_assert_nequal(lp, NULL);
    ci_assert_equal(skf->sf_local_port, lp);

    if( CI_IPX_ADDR_IS_ANY(raddr) ) {
      ci_assert(CI_IPX_ADDR_IS_ANY(skf->sf_raddr));
      ci_assert(CI_IPX_ADDR_EQ(skf->sf_laddr, laddr));
      ci_assert_equal(skf->sf_rport, rport);
      skf->sf_flags &= ~OOF_SOCKET_DUMMY;
      inc_laddr_ref = 0;
    }
    else {
      /* Socket performs connect (inferred from raddr).
       * Lets remove old dummy oofsocket and fallthrough as if we have
       * never installed one...
       * ..almost: we need to make sure socket does not share clustered filter
       * so we set NO SHARING flag.
       */
      ci_assert(!CI_IPX_ADDR_IS_ANY(laddr));
      ci_assert(CI_IPX_ADDR_IS_ANY(skf->sf_laddr) ||
                CI_IPX_ADDR_EQ(skf->sf_laddr, laddr));
      /* increase local addr reference count only
       * when original socket was fully wild */
      inc_laddr_ref = CI_IPX_ADDR_IS_ANY(skf->sf_laddr) ? 1 : 0;
      skf->sf_local_port = NULL;
      skf->sf_flags = OOF_SOCKET_NO_SHARING;
      do_arm_only = 0; /* fall through to socket creation from scratch */
    }
    /* Socket is removed from wild list, it will be readded by __oof_socket_add
     * to either the same list or the full list.
     *
     * In case the socket stays wild and only gets armed, temporary removal
     * from the list will prevent it from being spuriously considered
     * in wild filter resolution.
     **/
    oof_socket_remove_from_list(skf);
  }
  else if( do_arm_only ) {
    /* We hit this case when we've set SO_REUSEPORT on a socket that doesn't
     * want unicast filters.  In this case we don't actually want to arm
     * the socket.  It's currently a dummy, which is the same state as we
     * want a non-unicast filtered socket to be in, so all we need to do
     * is furtle the flags to reflect this.
     */
    rc = 0;
    skf->sf_flags &= ~OOF_SOCKET_DUMMY;
    skf->sf_flags |= OOF_SOCKET_NO_UCAST;
    goto just_unlock;
  }
  else {
    spin_unlock_bh(&fm->fm_inner_lock);
    lp = oof_local_port_get(fm, protocol, lport);
    spin_lock_bh(&fm->fm_inner_lock);
    if( lp == NULL ) {
      ERR_LOG(FSK_FMT "ERROR: out of memory", FSK_PRI_ARGS(skf));
      rc = -ENOMEM;
      goto just_unlock;
    }
    skf->sf_flags = (no_stack ? OOF_SOCKET_NO_STACK : 0) |
                    (dummy ? OOF_SOCKET_DUMMY : 0) |
                    (clustered ? OOF_SOCKET_CLUSTERED : 0) |
                    (no_ucast ? OOF_SOCKET_NO_UCAST : 0);
  }

  {CI_BUILD_ASSERT(
        OOF_SOCKET_ADD_FLAG_SUBVI_MASK >> OOF_SOCKET_ADD_FLAG_SUBVI_SHIFT ==
        OOF_SOCKET_SUBVI_MASK >> OOF_SOCKET_SUBVI_SHIFT);}

  skf->sf_flags = (skf->sf_flags &~ OOF_SOCKET_SUBVI_MASK) |
                  (flags & OOF_SOCKET_ADD_FLAG_SUBVI_MASK) >>
                  OOF_SOCKET_ADD_FLAG_SUBVI_SHIFT << OOF_SOCKET_SUBVI_SHIFT;

  skf->af_space = af_space;
  skf->sf_laddr = laddr;
  skf->sf_raddr = raddr;
  skf->sf_rport = rport;
  skf->sf_lport_prenat = 0;
  skf->sf_local_port = lp;
  skf->sf_la_i = -1;

  rc = __oof_socket_add(fm, skf, do_arm_only, inc_laddr_ref, thc_out);

  if( rc < 0 && rc != -EFILTERSSOME )
    goto unlock_release_lp;

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  if( ci_dllist_not_empty(&skf->sf_mcast_memberships) )
    if( oof_socket_mcast_install(fm, skf) != 0 )
      return -EFILTERSSOME;
  return rc;

 unlock_release_lp:
  skf->sf_local_port = NULL;
  skf->sf_flags = 0;
  if( --lp->lp_refs > 0 )
    lp = NULL;
  else
    ci_dllist_remove(&lp->lp_manager_link);
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  if( lp != NULL )
    oof_local_port_free(fm, lp);
  return rc;

 just_unlock:
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  return rc;
}


/* This function is called to update the remote address and port of a socket.
 * This is needed for sockets which are accepted from the endpoint cache at
 * user level.  These retain the original oof_socket, which should be sharing
 * a wild filter with the listener they were cached on.  However, the raddr
 * and rport on subsequent uses will generally not match that used when the
 * socket was originally added.  This doesn't cause a problem as long as the
 * socket isn't using its own hw filter, but it must be updated before the
 * listening socket's filter is removed.
 */
void
oof_socket_update_sharer_details(struct oof_manager* fm, struct oof_socket* skf,
                                 ci_addr_t raddr, int rport)
{
  /* This must be called while the socket is sharing a wild match filter,
   * otherwise it implies we've been using a hw filter with the wrong details.
   */
#ifndef NDEBUG
  ci_assert(oo_hw_filter_is_empty(&skf->sf_full_match_filter));
#else
  if( ! oo_hw_filter_is_empty(&skf->sf_full_match_filter) ) {
    ci_log("%s: called for socket with full-match filter", __func__);
  }
#endif

  /* We are not modifying any hw filters, or lists here, just the state that is
   * used to determine them, so just take the inner lock, which allows us to be 
   * called from atomic context.
   */
  spin_lock_bh(&fm->fm_inner_lock);

  skf->sf_raddr = raddr;
  skf->sf_rport = rport;

  spin_unlock_bh(&fm->fm_inner_lock);
}



static int
__oof_socket_share(struct oof_manager* fm, struct oof_socket* skf,
                   struct oof_socket* listen_skf, int lport)
{
  struct oof_local_port_addr* lpa;
  struct oof_local_port* lp;
  struct oof_local_addr* la;
  int rc;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));

  ci_assert_equal(skf->sf_local_port == NULL,
                  ci_dllink_is_free(&skf->sf_lp_link));
  ci_assert_impl(skf->sf_local_port == NULL, skf->sf_flags == 0);
  ci_assert_equal(listen_skf->sf_local_port == NULL,
                  ci_dllink_is_free(&listen_skf->sf_lp_link));
  ci_assert_impl(listen_skf->sf_local_port == NULL, listen_skf->sf_flags == 0);

  if( skf->sf_local_port != NULL )
      return -EINVAL;

  if( CI_IPX_ADDR_IS_ANY(skf->sf_laddr) || CI_IPX_ADDR_IS_ANY(skf->sf_raddr))
    return -EINVAL;

  if( (lp = listen_skf->sf_local_port) == NULL )
    return -EINVAL;

  skf->sf_la_i = oof_manager_lport_addr_find(fm, lp, skf->sf_laddr);
  if( skf->sf_la_i < 0 ) {
    ERR_LOG(FSK_FMT "ERROR: laddr=" IPX_FMT " not local", FSK_PRI_ARGS(skf),
            IPX_ARG(AF_IP_L3(skf->sf_laddr)));
    return -EINVAL;
  }

  lpa = &lp->lp_addr[skf->sf_la_i];
  la = &fm->fm_local_addrs[skf->sf_la_i];

  skf->sf_local_port = lp;

  /* If the socket's local port is not equal to the parent-listener's local
   * port, then there must be NAT going on. */
  if( lp->lp_lport != lport )
    skf->sf_lport_prenat = lport;

  /* Socket can be added even after addr has been removed
   * we allow that but cannot install sw filter nor
   * corrupt lpa_n_full_sharers count */
  if( oof_local_port_addr_valid(fm, lpa) ) {
    if( (rc = oof_socket_add_full_sw(skf)) != 0 ) {
      skf->sf_local_port = NULL;
      skf->sf_lport_prenat = 0;
      return rc;
    }
    ++lpa->lpa_n_full_sharers;
  }
  ++lp->lp_refs;
  ci_dllist_push(&lpa->lpa_full_socks, &skf->sf_lp_link);
  ++la->la_sockets;

  return 0;
}


int
oof_socket_share(struct oof_manager* fm, struct oof_socket* skf,
                 struct oof_socket* listen_skf, int af_space,
                 ci_addr_t laddr, ci_addr_t raddr, int lport, int rport)
{
  /* This entry point is used when promoting a syn-recv to a new passively
   * opened socket.  oof_socket_add() actually handles that case just fine,
   * but we need a separate entry point because oof_socket_add() cannot be
   * called in atomic context.
   *
   * Note: This is the only entry-point that doesn't grab [fm_outer_lock],
   * which is because it is invoked in atomic context.
   *
   * It is essential that code reached from here does not insert or remove
   * hardware filters, or free any resources, or remove anything items from
   * lists.
   */
  int rc;

  spin_lock_bh(&fm->fm_inner_lock);

  skf->af_space = af_space;
  skf->sf_laddr = laddr;
  skf->sf_raddr = raddr;
  skf->sf_rport = rport;
  skf->sf_lport_prenat = 0;
  skf->sf_la_i = -1;

  rc = __oof_socket_share(fm, skf, listen_skf, lport);

  spin_unlock_bh(&fm->fm_inner_lock);
  return rc;
}


static void
__oof_socket_del_wild(struct oof_manager* fm,
                      struct oof_socket* skf,
                      int af_space,
                      struct tcp_helper_resource_s* skf_stack,
                      struct oof_local_port_addr* lpa, ci_addr_t laddr)
{
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_socket* other_skf;

  ci_assert(! oof_socket_is_dummy(skf));

  if( ! oof_local_port_addr_valid(fm, lpa) )
    return;

  oof_socket_del_wild_sw(fm, skf, laddr);

  other_skf = oof_wild_socket_matching_stack(lp, lpa, af_space, skf_stack);
  if( other_skf != NULL ) {
    /* Unhide hidden socket on the same stack */
    int rc = oof_cb_sw_filter_insert(other_skf, af_space, laddr,
                                     lp->lp_lport, addr_any, 0,
                                     lp->lp_protocol, 1);
    if( rc != 0 )
      oof_sw_insert_fail(other_skf, __FUNCTION__, rc);
  }
}


static void
oof_socket_del_semi_wild(struct oof_manager* fm, struct oof_socket* skf,
                         struct oof_local_port_addr* lpa)
{
  int hidden;

  hidden = ! oof_socket_is_first_in_same_stack(&lpa->lpa_semi_wild_socks,
                                               skf);

  oof_socket_remove_from_list(skf);
  if( ! hidden ) {
    __oof_socket_del_wild(fm, skf, skf->af_space,
                          oof_cb_socket_stack(skf), lpa, skf->sf_laddr);
    oof_local_port_addr_fixup_wild(fm, skf->sf_local_port, lpa,
                                   skf->sf_laddr, fuw_del_wild);
  }
}


static void
oof_socket_del_wild(struct oof_manager* fm, struct oof_socket* skf)
{
  struct tcp_helper_resource_s* skf_stack;
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_local_port_addr* lpa;
  struct oof_local_addr* la;
  int hidden, la_i;
  int af_space;

  hidden = ! oof_socket_is_first_in_same_stack(&lp->lp_wild_socks, skf);

  oof_socket_remove_from_list(skf);
  if( hidden )
    return;

  skf_stack = oof_cb_socket_stack(skf);
  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    la = &fm->fm_local_addrs[la_i];
    af_space = oof_addr_to_af_space(la->la_laddr);

    if( ! oof_skf_uses_af_space(skf, af_space) )
      continue;

    if( ci_dllist_is_empty(&la->la_active_ifs) )
      /* Entry invalid or address disabled. */
      continue;

    lpa = &lp->lp_addr[la_i];
    if( oof_socket_list_find_matching_stack(&lpa->lpa_semi_wild_socks,
                                            skf_stack, af_space, 0) == NULL )
      __oof_socket_del_wild(fm, skf, af_space, skf_stack, lpa, la->la_laddr);
  }
}


void
oof_socket_del(struct oof_manager* fm, struct oof_socket* skf)
{
  struct oof_local_port* lp;
  struct oof_local_port_addr* lpa;
  struct oof_local_addr* la;
  ci_dllist mcast_filters;
  int dummy;

  ci_dllist_init(&mcast_filters);

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  lp = skf->sf_local_port;
  dummy = oof_socket_is_dummy(skf);

  ci_assert(! dummy || CI_IPX_ADDR_IS_ANY(skf->sf_raddr));
  ci_assert(! dummy || ! CI_IPX_IS_MULTICAST(skf->sf_laddr));
  ci_assert_equal(lp == NULL, ci_dllink_is_free(&skf->sf_lp_link));
  ci_assert_impl(lp == NULL, skf->sf_flags == 0);

  if( lp != NULL ) {
    IPF_LOG(FSK_FMT IPX_QUIN_FMT,
            FSK_PRI_ARGS_SAFE(skf, oof_socket_is_stackless(skf)),
            IPX_QUIN_ARGS(lp->lp_protocol, AF_IP(skf->sf_laddr),
                          lp->lp_lport, AF_IP(skf->sf_raddr),
                          skf->sf_rport));

    oof_socket_mcast_remove(fm, skf, &mcast_filters);

    if( CI_IPX_IS_MULTICAST(skf->sf_laddr) ) {
      oof_socket_remove_from_list(skf);
      if( !CI_IPX_ADDR_IS_ANY(skf->sf_raddr) ) {
        /* Undo path for oof_udp_connect_mcast_laddr().  It's possible we
         * don't actually have either of these filters, if we haven't joined
         * relevant groups, or don't have hwports that need a full match
         * filter.  However, it's safe to remove these even if we don't have
         * them.
         *
         * Any wild match filters will have been removed already, via the
         * standard path.
         */
        oof_socket_del_full_sw(skf, 1);
        skf->sf_flags &= ~OOF_SOCKET_MCAST_FULL_SW_FILTER;
        oof_hw_filter_clear_full(fm, skf);
      }
    }

    else if( !CI_IPX_ADDR_IS_ANY(skf->sf_laddr) ) {
      ci_assert(skf->sf_la_i >= 0 && skf->sf_la_i < fm->fm_local_addr_n);
      lpa = &lp->lp_addr[skf->sf_la_i];
      la = &fm->fm_local_addrs[skf->sf_la_i];
      if( !CI_IPX_ADDR_IS_ANY(skf->sf_raddr) )
        oof_socket_del_full(fm, skf, lpa);
      else
        oof_socket_del_semi_wild(fm, skf, lpa);
      ci_assert(la->la_sockets > 0);
      if( --la->la_sockets == 0 &&  ci_dllist_is_empty(&la->la_active_ifs) )
        oof_manager_addr_dead(fm, la);
    }
    else {
      oof_socket_del_wild(fm, skf);
      if(! dummy )
        oof_local_port_fixup_wild(fm, skf->sf_local_port, fuw_del_wild,
                                  skf->af_space);
    }

    skf->sf_local_port = NULL;
    skf->sf_flags = 0;
  }

  /* The remainder of the cleanup must be performed for a local port even if
   * filters haven't been installed yet. */
  if( lp != NULL ) {
    ci_assert(lp->lp_refs > 0);
    if( --lp->lp_refs == 0 )
      ci_dllist_remove(&lp->lp_manager_link);
    else
      lp = NULL;
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  if( lp != NULL )
    oof_local_port_free(fm, lp);
  oof_mcast_filter_list_free(&mcast_filters);
}


int
oof_socket_del_sw(struct oof_manager* fm, struct oof_socket* skf)
{
  /* This is a subset of oof_socket_del() that can be invoked in atomic
   * context.  It removes all of the socket's software filter entries.
   *
   * If the socket had only sw filters, then this function will return
   * 0 and no other operations are required.  If the socket has hw
   * filters, then the function returns 1.  In which case, a call to
   * oof_socket_del() a little later (in non-atomic context) is
   * required.  That will try to remove the software filters again,
   * which is not maximally efficient, but is otherwise harmless.
   */
  struct oof_local_port* lp;
  struct oof_local_port_addr* lpa;
  struct oof_local_addr* la;
  int la_i, mcast_hw_filter = 0, ucast_hw_filter = 0;

  spin_lock_bh(&fm->fm_inner_lock);

  ci_assert_equal(skf->sf_local_port == NULL,
                  ci_dllink_is_free(&skf->sf_lp_link));
  ci_assert_impl(skf->sf_local_port == NULL,
                 skf->sf_flags == 0);

  if( (lp = skf->sf_local_port) != NULL ) {
    IPF_LOG(FSK_FMT IPX_QUIN_FMT, FSK_PRI_ARGS(skf),
            IPX_QUIN_ARGS(lp->lp_protocol, AF_IP(skf->sf_laddr),
                          lp->lp_lport, AF_IP(skf->sf_raddr),
                          skf->sf_rport));
    ucast_hw_filter = 1;
    mcast_hw_filter = oof_socket_mcast_remove_sw(fm, skf);

    if( CI_IPX_IS_MULTICAST(skf->sf_laddr) ) {
      /* Nothing to do. */
    }
    else if( !CI_IPX_ADDR_IS_ANY(skf->sf_laddr) ) {
      ci_assert(skf->sf_la_i >= 0 && skf->sf_la_i < fm->fm_local_addr_n);
      lpa = &lp->lp_addr[skf->sf_la_i];
      la = &fm->fm_local_addrs[skf->sf_la_i];
      if( skf->sf_raddr.ip4 ) {
        oof_socket_del_full_sw(skf, 1);
          /* If this endpoint only sharing SW filters and is not the
           * last one to be removed, it is safe to remove the filters
           * in an atomic context.
           *
           * When local address has been removed, there is no hadware
           * filters and the socket could be treated as fully removed.
           * However, this would cost cycles on fast path.
           */
        if( oo_hw_filter_is_empty(&skf->sf_full_match_filter) &&
            lp->lp_refs > 1 &&
            lpa->lpa_n_full_sharers > 1 ) {
          oof_socket_remove_from_list(skf);
          ci_assert(la->la_sockets > 0);
          --la->la_sockets;
          --lpa->lpa_n_full_sharers;
          skf->sf_local_port = NULL;
          skf->sf_flags = 0;
          --lp->lp_refs;
         ucast_hw_filter = 0;
        }
      }
      else
        oof_socket_del_wild_sw(fm, skf, skf->sf_laddr);
    }
    else {
      for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i )
        oof_socket_del_wild_sw(fm, skf, fm->fm_local_addrs[la_i].la_laddr);
    }
    if( mcast_hw_filter || ucast_hw_filter )
      skf->sf_flags |= OOF_SOCKET_SW_FILTER_WAS_REMOVED;
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  return mcast_hw_filter || ucast_hw_filter;
}


static int
oof_udp_connect_mcast_laddr(struct oof_manager* fm, struct oof_socket* skf,
                            unsigned laddr, unsigned raddr, int rport)
{
  /* There are two ways to get here:
   * - a socket bound to local mcast addr is being connected
   * - a socket bound to local mcast addr has joined a group with addr laddr
   * 
   * We defer inserting filters for these socket until they actually join a
   * group with addr laddr to avoid receiving packets before we should.
   *
   * For connected mcast sockets the filters we install depend on the
   * capability of the relevant hwports.
   *
   * For hwports that are capable of multicast replication we use normal
   * wild match filters (specifying a vlan if supported).  This may result
   * in the stack getting extra packets, however the software filter will
   * prevent them from being delivered to the socket.  Because of the
   * replication we aren't preventing packets being delivered to other that
   * are interested in them.  This approach means that on multicast replication
   * capable hwports there is no need for chaining between different filter
   * types, as all multicast filters are IP wild (+ vlan).  Similarly we
   * aren't relying on relative priorities of different filter types.
   *
   * For hwports that aren't capable of multicast replication we can't do
   * this, as we need to be as specific as possible in our filters to avoid
   * taking packets that we don't really want from someone that actually
   * wants those packets.  This means that we will just use a full match
   * filter (no vlan).
   *
   * The wild match hw filters are managed in the same way as for unconnected
   * sockets.  The sw filter is added and removed on the connected path.
   */
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_mcast_member* mm;
  unsigned laddr_old, raddr_old, rport_old;
  unsigned hwports = 0;
  unsigned hwports_full;
  int rc = 0;

  IPF_LOG(FSK_FMT "%s "IPX_PORT_FMT" => "IPPORT_FMT" "IPPORT_FMT" multicast",
          FSK_PRI_ARGS(skf), FMT_PROTOCOL(lp->lp_protocol),
          IPX_PORT_ARG(AF_IP(skf->sf_laddr), lp->lp_lport),
          IPPORT_ARG(laddr, lp->lp_lport), IPPORT_ARG(raddr, rport));

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));
  ci_assert(CI_IPX_IS_MULTICAST(skf->sf_laddr));
  ci_assert(CI_IP_IS_MULTICAST(laddr));
  ci_assert(oo_hw_filter_is_empty(&skf->sf_full_match_filter) ||
           (skf->sf_laddr.ip4 == laddr && skf->sf_raddr.ip4 == raddr &&
            skf->sf_rport == rport));

  laddr_old = skf->sf_laddr.ip4;
  raddr_old = skf->sf_raddr.ip4;
  rport_old = skf->sf_rport;
  skf->sf_laddr = CI_ADDR_FROM_IP4(laddr);
  skf->sf_raddr = CI_ADDR_FROM_IP4(raddr);
  skf->sf_rport = rport;

  /* See if we've joined any groups on this laddr, and if so which hwports
   * they're using.
   */
  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships)
    if( mm->mm_maddr == laddr )
      hwports |= mm->mm_hwport_mask;


  /* We come through here each time a new group is joined, but only need to
   * add the sw filter the first time.
   */
  if( hwports != 0 && ! (skf->sf_flags & OOF_SOCKET_MCAST_FULL_SW_FILTER) ) {
    ci_addr_t addr = CI_ADDR_FROM_IP4(laddr);

    /* Remove the wild filter before installing the full-match one to avoid
     * corrupting the filter table.
     */
    oof_socket_del_wild_sw(fm, skf, addr);

    rc = oof_socket_add_full_sw(skf);
    if( rc != 0 ) {
      /* Full-match insertion failed and wild has already gone. If this
       * function was called at connect-time, propagation of this failure will
       * result in handover. Otherwise, we must be adding our first membership
       * to this group, and so there are no hardware filters yet; in this case,
       * in response to this failure, the caller should decline to insert any
       * hardware filters so that traffic can go via the kernel.
       */
      oof_sw_insert_fail(skf, __FUNCTION__, rc);
      goto fail1;
    }

    skf->sf_flags |= OOF_SOCKET_MCAST_FULL_SW_FILTER;
  }

  hwports_full = hwports & ~fm->fm_hwports_mcast_replicate_capable;

  if( hwports_full ) {
    ci_addr_t loc_addr = CI_ADDR_FROM_IP4(laddr);
    ci_addr_t rem_addr = CI_ADDR_FROM_IP4(raddr);
    /* We only install full match mcast filters on ports that don't support
     * multicast replication, so not specifying a vlan makes no
     * difference on current hw, and simplifies things, so that's what we do.
     */
    rc = oof_hw_filter_update(fm, &skf->sf_full_match_filter,
                              oof_cb_socket_stack(skf), AF_INET, lp->lp_protocol,
                              rem_addr, rport, loc_addr, lp->lp_lport,
                              OO_HW_VLAN_UNSPEC, hwports_full,
                              OOF_SRC_FLAGS_DEFAULT);
  }

  return rc;

 fail1:
  skf->sf_laddr = CI_ADDR_FROM_IP4(laddr_old);
  skf->sf_raddr = CI_ADDR_FROM_IP4(raddr_old);
  skf->sf_rport = rport_old;

  return rc;
}


int
oof_udp_connect(struct oof_manager* fm, struct oof_socket* skf, int af_space,
                ci_addr_t laddr, ci_addr_t raddr, int rport)
{
  /* Special case for UDP connect().  We don't want to del() then add(), as
   * there may be an interval when there are no filters installed and
   * packets will go to the wrong place.
   */
  struct oof_local_port_addr* lpa;
  struct oof_local_addr* la;
  struct oof_local_port* lp;
  ci_addr_t laddr_old;
  int la_i_old = skf->sf_la_i;
  int rc, la_i_new;
  int la_i_new_valid;
  int hidden;
  int af_space_old;

  if( CI_IPX_ADDR_IS_ANY(laddr) || CI_IPX_ADDR_IS_ANY(raddr) || rport == 0 ) {
    ERR_LOG(FSK_FMT "ERROR: bad laddr=" IPX_FMT " raddr=" IPX_FMT " rport=%d",
            FSK_PRI_ARGS(skf), IPX_ARG(AF_IP_L3(laddr)), IPX_ARG(AF_IP_L3(raddr)),
            FMT_PORT(rport));
    return -EINVAL;
  }

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  lp = skf->sf_local_port;
  rc = -EINVAL;
  if( lp == NULL ) {
    ERR_LOG(FSK_FMT "ERROR: no local port", FSK_PRI_ARGS(skf));
    goto unlock_out;
  }
  if( lp->lp_protocol != IPPROTO_UDP || !CI_IPX_ADDR_IS_ANY(skf->sf_raddr) ) {
    ERR_LOG(FSK_FMT "ERROR: protocol=%s remote="IPX_PORT_FMT,
            FSK_PRI_ARGS(skf), FMT_PROTOCOL(lp->lp_protocol),
            IPX_PORT_ARG(AF_IP(skf->sf_raddr), skf->sf_rport));
    goto unlock_out;
  }

  la_i_new = oof_manager_addr_find(fm, laddr);
  if( la_i_new < 0 ) {
    if( CI_IPX_IS_MULTICAST(laddr) &&
        CI_IPX_IS_MULTICAST(skf->sf_laddr) ) {

      /* TODO: add IPv6 address support for multicast */
      if( IS_AF_SPACE_IP6(af_space) )
        goto unlock_out;

      rc = oof_udp_connect_mcast_laddr(fm, skf, laddr.ip4, raddr.ip4, rport);
      if( rc < 0 )
        goto unlock_out;
      else
        goto unlock_mcast_out;
    }
    ERR_LOG(FSK_FMT "ERROR: laddr=" IPX_FMT " not local",
            FSK_PRI_ARGS(skf), IPX_ARG(AF_IP_L3(laddr)));
    goto unlock_out;
  }

  /* We don't do connect with a unicast local address for sockets that
   * don't want unicast filters, so the only way we should get here is due
   * to misbehaving userland.
   */
  ci_assert(!oof_socket_no_unicast(skf));
  if( oof_socket_no_unicast(skf) )
    goto unlock_out;

  IPF_LOG(FSK_FMT "%s "IPX_PORT_FMT" => "IPPORT_FMT" "IPPORT_FMT,
          FSK_PRI_ARGS(skf), FMT_PROTOCOL(lp->lp_protocol),
          IPX_PORT_ARG(AF_IP(skf->sf_laddr), lp->lp_lport),
          IPPORT_ARG(laddr, lp->lp_lport), IPPORT_ARG(raddr, rport));

  ci_assert(! oof_socket_is_dummy(skf));
  skf->sf_flags &= ~(OOF_SOCKET_CLUSTERED | OOF_SOCKET_DUMMY);

  la_i_new_valid = oof_local_port_addr_valid(fm, &lp->lp_addr[la_i_new]);

  /* First half of adding as full-match.  May or may not insert full-match
   * h/w filter.  We mustn't install s/w filter until we've removed the
   * existing s/w filter else we can confuse the filter table (which
   * requires that a socket be inserted only once for a given laddr).
   */
  laddr_old = skf->sf_laddr;
  af_space_old = skf->af_space;
  skf->sf_laddr = laddr;
  skf->sf_raddr = raddr;
  skf->sf_rport = rport;
  skf->sf_lport_prenat = 0;
  /* We set sf_la_i even when la_i_new_valid is false, as the socket still
   * counts towards the lpa's socket-total. */
  skf->sf_la_i = la_i_new;
  rc = 0;
  if( la_i_new_valid )
    rc = oof_socket_add_full_hw(fm, skf, &lp->lp_addr[la_i_new],
                                IS_AF_SPACE_IP6(af_space) ? AF_INET6 : AF_INET);
  if( rc < 0 )
    goto fail_reset_skf;

  /* Remove wild s/w filters.  May delete or move wild h/w filters, and may
   * insert new full-match h/w filter.  Must not "fixup" the wildcard
   * filters yet as [skf] does not yet look like a full-match socket, so
   * state is not sufficiently consistent.
   */
  skf->sf_laddr = laddr_old;
  skf->sf_raddr = ip4_addr_any;
  skf->sf_rport = 0;
  if( !CI_IPX_ADDR_IS_ANY(laddr_old) ) {
    ci_assert(la_i_old >= 0 && la_i_old < fm->fm_local_addr_n);
    skf->sf_la_i = la_i_old;
    lpa = &lp->lp_addr[la_i_old];
    hidden = ! oof_socket_is_first_in_same_stack(&lpa->lpa_semi_wild_socks,
                                                 skf);
    oof_socket_remove_from_list(skf);
    if( ! hidden )
      __oof_socket_del_wild(fm, skf, skf->af_space,
                            oof_cb_socket_stack(skf), lpa, laddr);
  }
  else {
    oof_socket_del_wild(fm, skf);
  }

  /* Finish making [skf] into a proper full-match socket. */
  skf->sf_laddr = laddr;
  skf->sf_raddr = raddr;
  skf->sf_rport = rport;
  /* As above, we set sf_la_i even when la_i_new_valid is false. */
  skf->sf_la_i = la_i_new;
  rc = 0;
  if( la_i_new_valid )
    rc = oof_cb_sw_filter_insert(skf, af_space, laddr, lp->lp_lport,
                                 raddr, rport, lp->lp_protocol, 1);
  if( rc != 0 ) {
    /* NB. We haven't reset the socket to its previous state here.  We
     * leave it looking like a full-match, but with all filters missing.
     * Calling code should hand socket over to kernel, so this inconsistent
     * state should not matter much.
     */
    oof_sw_insert_fail(skf, __FUNCTION__, rc);
    oof_hw_filter_clear_full(fm, skf);
    goto unlock_out;
  }
  ci_dllist_push(&lp->lp_addr[la_i_new].lpa_full_socks, &skf->sf_lp_link);
  ++fm->fm_local_addrs[la_i_new].la_sockets;

  /* Sort out of the h/w filter(s).  This step may insert a new full-match
   * h/w filter, and may delete or move the wild h/w filter(s).
   */
  if( !CI_IPX_ADDR_IS_ANY(laddr_old) ) {
    oof_local_port_addr_fixup_wild(fm, lp, &lp->lp_addr[la_i_old],
                                   laddr_old, fuw_udp_connect);
    la = &fm->fm_local_addrs[la_i_old];
    if( --la->la_sockets == 0 && ci_dllist_is_empty(&la->la_active_ifs) )
      oof_manager_addr_dead(fm, la);
  }
  else {
    oof_local_port_fixup_wild(fm, lp, fuw_udp_connect, af_space_old);
  }

 unlock_mcast_out:
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  if( ci_dllist_not_empty(&skf->sf_mcast_memberships) )
    oof_socket_mcast_install(fm, skf);
  return 0;

 fail_reset_skf:
  skf->sf_laddr = laddr_old;
  skf->sf_raddr = ip4_addr_any;
  skf->sf_rport = 0;
  skf->sf_la_i = la_i_old;
 unlock_out:
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  return rc;
}

/**********************************************************************
***********************************************************************
**********************************************************************/

/* If the socket is connected we only need an mcast (wild match) filter
 * if we have ports that support multicast replication.
 *
 * If local address is bound, then the socket can only receive packets
 * addressed to that local address.
 *
 */
#define OOF_NEED_MCAST_FILTER(fm, skf, mm)                             \
  ((((skf)->sf_raddr.ip4 == 0) ||                                          \
   ((mm)->mm_hwport_mask & fm->fm_hwports_mcast_replicate_capable)) && \
   ((skf)->sf_laddr.ip4 == 0 || (skf)->sf_laddr.ip4 == ((mm)->mm_maddr)))


#define OOF_CONNECTED_MCAST(skf, maddr)                         \
  ((skf)->sf_raddr.ip4 != 0 && (skf)->sf_laddr.ip4 == (maddr))


/* Calculate the ports we want to install wild match multicast filters on.
 * For an unconnected socket this is all ports wanted by this oof_mcast_member.
 * For a connected socket we only want wild match on hwports that support
 * multicast replication.
 */
#define OOF_MCAST_WILD_HWPORTS(fm, mm)                                   \
   ( ((mm)->mm_socket->sf_raddr.ip4 == 0) ?                                  \
     ((mm)->mm_hwport_mask) :                                            \
     ((mm)->mm_hwport_mask & (fm)->fm_hwports_mcast_replicate_capable) )


static struct oof_mcast_member*
oof_mcast_member_list_get(ci_dllist* mm_list)
{
  ci_assert(ci_dllist_not_empty(mm_list));
  return CI_CONTAINER(struct oof_mcast_member, mm_socket_link,
                      ci_dllist_pop(mm_list));
}


static void
oof_mcast_member_list_free(ci_dllist* mm_list)
{
  while( ci_dllist_not_empty(mm_list) )
    ci_free(oof_mcast_member_list_get(mm_list));
}


static struct oof_mcast_filter*
oof_mcast_filter_list_get(ci_dllist* mcast_filters)
{
  ci_assert(ci_dllist_not_empty(mcast_filters));
  return CI_CONTAINER(struct oof_mcast_filter, mf_lp_link,
                      ci_dllist_pop(mcast_filters));
}


static void
oof_mcast_filter_list_free(ci_dllist* mcast_filters)
{
  while( ci_dllist_not_empty(mcast_filters) )
    ci_free(oof_mcast_filter_list_get(mcast_filters));
}


static int
oof_socket_has_maddr_filter(struct oof_socket* skf, unsigned maddr)
{
  struct oof_mcast_member* mm;
  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships)
    if( mm->mm_maddr == maddr && mm->mm_filter != NULL )
      return 1;
  return 0;
}


static void
oof_mcast_member_init(struct oof_mcast_member* mm,
                      struct oof_socket* skf, unsigned maddr,
                      int ifindex, unsigned hwport_mask, ci_uint16 vlan_id)
{
  mm->mm_filter = NULL;
  mm->mm_socket = skf;
  mm->mm_maddr = maddr;
  mm->mm_ifindex = ifindex;
  mm->mm_hwport_mask = hwport_mask;
  mm->mm_vlan_id = vlan_id;
}


static const char*
oof_mcast_member_state(struct oof_manager* fm, struct oof_mcast_member* mm)
{
  unsigned hwports_got;
  unsigned hwports_want;
  const char* s;
  struct oof_mcast_filter* mf2;

  hwports_got = oo_hw_filter_hwports(&mm->mm_filter->mf_filter);
  hwports_want = OOF_MCAST_WILD_HWPORTS(fm, mm);

  /* Check whether the filter that this oof_mcast_member wanted was installed
   * via another oof_mcast_filter, which can happen on ports that don't
   * support vlans.
   */
  CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf2, mf_lp_link,
                        &mm->mm_socket->sf_local_port->lp_mcast_filters)
    hwports_got |= oof_mcast_filter_duplicate_hwports(fm, mm->mm_filter, mf2);

  if( hwports_want ) {
    if( (hwports_got & hwports_want) == hwports_want )
      s = "ACCELERATED";
    else if( hwports_got & hwports_want )
      s = "PARTIALLY_ACCELERATED";
    else
      s = "KERNEL";
  }
  else
    s = "NO_ACCELERATABLE_PORTS";
  return s;
}


static void
oof_mcast_filter_init(struct oof_mcast_filter* mf, unsigned maddr,
                      ci_uint16 vlan_id)
{
  oo_hw_filter_init(&mf->mf_filter);
  mf->mf_maddr = maddr;
  mf->mf_vlan_id = vlan_id;
  mf->mf_hwport_mask = 0;
  ci_dllist_init(&mf->mf_memberships);
}


static unsigned
oof_mcast_filter_hwport_mask(struct oof_manager* fm,
                             struct oof_mcast_filter* mf)
{
  struct oof_mcast_member* mm;
  unsigned hwport_mask = 0;
  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_filter_link,
                      &mf->mf_memberships)
    hwport_mask |= OOF_MCAST_WILD_HWPORTS(fm, mm);
  return hwport_mask;
}


static struct oof_mcast_filter*
oof_local_port_find_mcast_filter(struct oof_local_port* lp,
                                 struct tcp_helper_resource_s* stack,
                                 unsigned maddr, ci_uint16 vlan_id)
{
  struct oof_mcast_filter* mf;
  CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                      &lp->lp_mcast_filters)
    if( mf->mf_filter.trs == stack && mf->mf_maddr == maddr
        && mf->mf_vlan_id == vlan_id )
      break;
  return mf;
}


/* This function returns the mask of ports which would conflict with mf if a 
 * new filter was required with the provided settings, on the same local port
 * as mf.
 */
ci_inline unsigned oof_mcast_conflicted_hwports(struct oof_manager* fm,
                                                struct tcp_helper_resource_s* 
                                                       stack,
                                                unsigned maddr,
                                                unsigned hwport_mask,
                                                ci_uint16 vlan_id,
                                                struct oof_mcast_filter* mf)
{
  /* There can only be a conflict is this is for the same address, but a
   * different stack.
   */
  if( maddr == mf->mf_maddr && stack != mf->mf_filter.trs )
    /* Add to conflict mask ports which appear in both hwport masks */
    return hwport_mask & mf->mf_hwport_mask &
           /* remove from conflict mask ports that support mcast replication */
           ~fm->fm_hwports_mcast_replicate_capable &
           /* If vlan id differs then remove from conflict mask ports which
            * understand vlan filters. If vlan id is the same then don't change
            * conflict mask.
            */
           (vlan_id != mf->mf_vlan_id ?
           ~fm->fm_hwports_vlan_filters : (unsigned)-1);
  else
    return 0;
}


static unsigned
oof_mcast_filter_duplicate_hwports(struct oof_manager* fm,
                                   struct oof_mcast_filter* mf,
                                   struct oof_mcast_filter* mf2)
{
  unsigned hwport_mask = 0;

  /* An oof_mcast_filter is unique per maddr/port/vlan.  However, on hwports
   * that don't support vlan filters that means that the exact filter one
   * oof_mcast_filter wants can already be installed via another
   * oof_mcast_filter.
   *
   * An hwport already has an appropriate filter if:
   * - the stack is the same
   * - the maddr is the same
   * - the port is the same
   * - the hwport does not support vlans
   * - mf2 already has installed a filter on that hwport
   */
  if( (mf->mf_filter.trs == mf2->mf_filter.trs) && 
      (mf->mf_maddr == mf2->mf_maddr) )
    /* The filter matches, now check for hwport overlap on non-vlan hwports */
    hwport_mask = oof_mcast_filter_hwport_mask(fm, mf) &
         (oo_hw_filter_hwports(&mf2->mf_filter) & ~fm->fm_hwports_vlan_filters);

  return hwport_mask;
}


/* Find out whether there are any hwports that [mf] can install filters on.
 * ie. We're looking for hwports that support multicast replication or that
 * no other stack wants to install the same multicast filter on.
 */
static unsigned
oof_mcast_filter_installable_hwports(struct oof_manager* fm,
                                     struct oof_local_port* lp,
                                     struct oof_mcast_filter* mf)
{
  unsigned hwport_mask = mf->mf_hwport_mask;
  struct oof_mcast_filter* mf2;

  CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf2, mf_lp_link,
                      &lp->lp_mcast_filters)
    if( mf2 != mf ) {
      hwport_mask &= ~oof_mcast_conflicted_hwports(fm, mf->mf_filter.trs,
                                                   mf->mf_maddr,
                                                   mf->mf_hwport_mask,
                                                   mf->mf_vlan_id, mf2);
      hwport_mask &= ~oof_mcast_filter_duplicate_hwports(fm, mf, mf2);
    }
  return hwport_mask;
}


static int
oof_mcast_install(struct oof_manager* fm, struct oof_mcast_member* mm,
                  ci_dllist* mcast_filters)
{
  struct oof_socket* skf = mm->mm_socket;
  struct tcp_helper_resource_s* skf_stack = oof_cb_socket_stack(skf);
  struct oof_local_port* lp = skf->sf_local_port;
  unsigned install_hwport_mask;
  unsigned conflicted_port_mask;
  struct oof_mcast_filter* mf;
  int rc;
  int mf_pushed = 0;
  struct oof_mcast_filter* old_mm_filter;
  ci_addr_t maddr;

  ci_assert(lp != NULL);
  ci_assert(OOF_NEED_MCAST_FILTER(fm, skf, mm));
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  /* Install a software filter if this socket doesn't already have a filter
   * for this maddr.  (This happens if the socket joins the same group on
   * more than one interface).
   *
   * In the case of connected sockets the connect path is responsible for
   * managing the sw filter.
   */
  if( (! oof_socket_has_maddr_filter(skf, mm->mm_maddr)) &&
      (! OOF_CONNECTED_MCAST(skf, mm->mm_maddr)) ) {
    ci_addr_t laddr_val;

    laddr_val = CI_ADDR_FROM_IP4(mm->mm_maddr);
    rc = oof_cb_sw_filter_insert(skf, AF_SPACE_FLAG_IP4, laddr_val, lp->lp_lport,
                                 addr_any, 0, lp->lp_protocol, 1);
    if( rc != 0 )
      return rc; /* SW filter failed: do not insert HW */
  }


  /* Find filters that conflict with the one we want to install.
   *
   * Only bother checking for conflict if this one has any hwports that don't 
   * support multicast replication and this isn't a connected socket.
   * Multicast replication means we can't conflict.  For connected sockets
   * we will only install mcast (wild match) filters on hwports that
   * support multicast replication.
   *
   * Remove hardware filters that conflict.
   */
  if( (mm->mm_hwport_mask & fm->fm_hwports_mcast_replicate_capable)
      != mm->mm_hwport_mask )  {
    CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                        &lp->lp_mcast_filters) {
     conflicted_port_mask =
       oof_mcast_conflicted_hwports(fm, skf_stack, mm->mm_maddr,
                                    mm->mm_hwport_mask, mm->mm_vlan_id, mf);
     if( conflicted_port_mask ) {
        IPF_LOG(FSK_FMT "CONFLICT: maddr="IPPORT_FMT" if=%d hwports=%x "
                "AND stack=%d hwports=%x AND mcast replicate hwports=%x "
                "AND vlan filter hwports=%x",
                FSK_PRI_ARGS(skf), IPPORT_ARG(mm->mm_maddr, lp->lp_lport),
                mm->mm_ifindex, mm->mm_hwport_mask,
                oof_cb_stack_id(mf->mf_filter.trs), mf->mf_hwport_mask,
                fm->fm_hwports_mcast_replicate_capable,
                fm->fm_hwports_vlan_filters);
        ci_assert(mf->mf_filter.thc == NULL);
      oof_hw_filter_clear_hwports(fm, &mf->mf_filter, conflicted_port_mask);
      }
    }
  }

  mf = oof_local_port_find_mcast_filter(lp, skf_stack, mm->mm_maddr,
                                        mm->mm_vlan_id);
  if( mf == NULL ) {
    mf = oof_mcast_filter_list_get(mcast_filters);
    oof_mcast_filter_init(mf, mm->mm_maddr, mm->mm_vlan_id);
    mf->mf_filter.trs = skf_stack;
    ci_dllist_push(&lp->lp_mcast_filters, &mf->mf_lp_link);
    mf_pushed = 1;
  }

  old_mm_filter = mm->mm_filter;
  mm->mm_filter = mf;
  ci_dllist_push(&mf->mf_memberships, &mm->mm_filter_link);
  mf->mf_hwport_mask |= OOF_MCAST_WILD_HWPORTS(fm, mm);
  install_hwport_mask = oof_mcast_filter_installable_hwports(fm, lp, mf);
  maddr = CI_ADDR_FROM_IP4(mf->mf_maddr);
  rc = oof_hw_filter_update(fm, &mf->mf_filter, skf_stack, AF_INET,
                            lp->lp_protocol, addr_any, 0, maddr, lp->lp_lport,
                            mf->mf_vlan_id, install_hwport_mask,
                            OOF_SRC_FLAGS_DEFAULT_MCAST);
  if( rc != 0 ) {
    ci_addr_t laddr;

    /* We didn't get all of the filters we wanted, but traffic should
     * still get there via the kernel stack.
     */
    ERR_LOG(FSK_FMT "mcast hw filter error: maddr="IPPORT_FMT" if=%d "
            "wanted=%x,%x install=%x got=%x rc=%d", FSK_PRI_ARGS(skf),
            IPPORT_ARG(mm->mm_maddr, lp->lp_lport),
            mm->mm_ifindex, mm->mm_hwport_mask, mf->mf_hwport_mask,
            install_hwport_mask, oo_hw_filter_hwports(&mf->mf_filter), rc);
    mm->mm_filter = old_mm_filter;
    ci_dllist_pop(&mf->mf_memberships);
    if( mf_pushed ) {
      ci_dllist_pop(&lp->lp_mcast_filters);
      ci_dllist_push(mcast_filters, &mf->mf_lp_link);
    }
    laddr = CI_ADDR_FROM_IP4(mm->mm_maddr);
    oof_cb_sw_filter_remove(skf, AF_SPACE_FLAG_IP4, laddr, lp->lp_lport,
                            addr_any, 0, lp->lp_protocol, 1);
  }

  return rc;
}


static int
oof_mcast_remove(struct oof_manager* fm, struct oof_mcast_member* mm,
                 int stack_locked, ci_dllist* mcast_filters)
{
  struct oof_mcast_filter* mf = mm->mm_filter;
  struct oof_socket* skf = mm->mm_socket;
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_mcast_filter* mf2;
  unsigned hwport_mask;
  int rc;
  int filter_removed = 0;

  ci_assert(mm->mm_filter != NULL);
  ci_assert(ci_dllist_not_empty(&mf->mf_memberships));
  ci_assert(mf->mf_maddr == mm->mm_maddr);

  /* It's possible that other oof_mcast_filters may be using a filter
   * installed via this oof_mcast_filter.  That can happen where the
   * oof_mcast_filters differ only in vlan id, and have overlapping hwports
   * that don't support vlan filters.
   *
   * In that case we need to pass ownership of the hwfilter rather than
   * removing it to avoid a gap where there is no filter installed.
   */
  if( mm->mm_hwport_mask & ~fm->fm_hwports_vlan_filters ) {
    CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf2, mf_lp_link,
                        &lp->lp_mcast_filters)
      if( (mf2 != mf) &&
          (hwport_mask = oof_mcast_filter_duplicate_hwports(fm, mf2, mf)) ) {
        /* mf2 is relying on filtering via mf for hwport_mask.  Pass those
         * filters over to mf2.
         */
        oof_hw_filter_transfer(fm, mm, mf2, hwport_mask);
      }
  }

  mm->mm_filter = NULL;
  ci_dllist_remove(&mm->mm_filter_link);
  if( ci_dllist_is_empty(&mf->mf_memberships) ) {
    oof_hw_filter_clear(fm, &mf->mf_filter);
    IPF_LOG(FSK_FMT "CLEAR "IPPORT_FMT, FSK_PRI_ARGS(skf),
            IPPORT_ARG(mm->mm_maddr, lp->lp_lport));
    ci_dllist_remove(&mf->mf_lp_link);
    ci_dllist_push(mcast_filters, &mf->mf_lp_link);
    filter_removed = 1;
  }
  else {
    ci_addr_t maddr = CI_ADDR_FROM_IP4(mf->mf_maddr);
    mf->mf_hwport_mask = oof_mcast_filter_hwport_mask(fm, mf);
    hwport_mask = oof_mcast_filter_installable_hwports(fm, lp, mf);
    oof_hw_filter_update(fm, &mf->mf_filter, mf->mf_filter.trs, AF_INET,
                         lp->lp_protocol, addr_any, 0, maddr, lp->lp_lport,
                         mf->mf_vlan_id, hwport_mask,
                         OOF_SRC_FLAGS_DEFAULT_MCAST);
  }

  /* Is it now possible to insert filters to accelerate this group for
   * another stack?
   */
  CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                      &lp->lp_mcast_filters)
    if( mf->mf_maddr == mm->mm_maddr ) {
      unsigned got_hwport_mask;
      got_hwport_mask = oo_hw_filter_hwports(&mf->mf_filter);
      if( mf->mf_hwport_mask != got_hwport_mask ) {
        hwport_mask = oof_mcast_filter_installable_hwports(fm, lp, mf);
        if( hwport_mask != got_hwport_mask ) {
          ci_addr_t maddr = CI_ADDR_FROM_IP4(mf->mf_maddr);
          IPF_LOG(FSK_FMT "maddr="IPPORT_FMT" if=%d MODIFY stack=%d wanted=%x "
                  "had=%x install=%x", FSK_PRI_ARGS(skf),
                  IPPORT_ARG(mm->mm_maddr, lp->lp_lport), mm->mm_ifindex,
                  oof_cb_stack_id(mf->mf_filter.trs), mf->mf_hwport_mask,
                  got_hwport_mask, hwport_mask);
          rc = oof_hw_filter_update(fm, &mf->mf_filter, mf->mf_filter.trs,
                                    AF_INET, lp->lp_protocol, addr_any, 0, maddr,
                                    lp->lp_lport, mf->mf_vlan_id,
                                    hwport_mask,
                                    OOF_SRC_FLAGS_DEFAULT_MCAST);
          if( rc != 0 )
            ERR_LOG("%s: mcast hw filter error: maddr="IPPORT_FMT" wanted=%x "
                    "install=%x got=%x", __FUNCTION__,
                    IPPORT_ARG(mf->mf_maddr, lp->lp_lport),
                    mf->mf_hwport_mask, hwport_mask,
                    oo_hw_filter_hwports(&mf->mf_filter));
        }
      }
    }

  /* Remove software filter if no filters remain for maddr. */
  if( ! oof_socket_has_maddr_filter(skf, mm->mm_maddr) &&
      ! OOF_CONNECTED_MCAST(skf, mm->mm_maddr) ) {
    ci_addr_t laddr = CI_ADDR_FROM_IP4(mm->mm_maddr);

    oof_cb_sw_filter_remove(skf, AF_SPACE_FLAG_IP4, laddr, lp->lp_lport,
                            addr_any, 0, lp->lp_protocol, stack_locked);
  }
  return filter_removed;
}


static void
oof_mcast_update(struct oof_manager* fm, struct oof_local_port *lp,
                 struct oof_mcast_filter* mf, int ifindex)
{
  unsigned install_hwport_mask, before_hwport_mask;

  before_hwport_mask = oo_hw_filter_hwports(&mf->mf_filter);
  install_hwport_mask = oof_mcast_filter_installable_hwports(fm, lp, mf);
  if( install_hwport_mask != before_hwport_mask ) {
    ci_addr_t maddr = CI_ADDR_FROM_IP4(mf->mf_maddr);
    oof_hw_filter_update(fm, &mf->mf_filter, mf->mf_filter.trs, AF_INET,
                         lp->lp_protocol, addr_any, 0,
                         maddr, lp->lp_lport,
                         mf->mf_vlan_id, install_hwport_mask,
                         OOF_SRC_FLAGS_DEFAULT_MCAST);
    IPF_LOG("%s: UPDATE "IPPORT_FMT" if=%d hwports before=%x wanted=%x "
            "install=%x after=%x", __FUNCTION__,
            IPPORT_ARG(mf->mf_maddr, lp->lp_lport),
            ifindex, before_hwport_mask, mf->mf_hwport_mask,
            install_hwport_mask, oo_hw_filter_hwports(&mf->mf_filter));
  }
}


/* This function is called with both filter-manager locks held, and will take
 * and drop fm_cplane_updates_lock. */
static void
__oof_manager_update_interface(struct oof_manager* fm,
                               unsigned ifindex,
                               ci_uint16 flags,
                               ci_uint32 hwport_mask,
                               ci_uint16 vlan_id,
                               ci_mac_addr_t mac)
{
  int i;
  ci_uint32 old_hwport_mask = 0;
  ci_uint32 in_use_hwport_mask;

  struct oof_local_interface_details* lid =
      oof_local_interface_details_find(fm, ifindex);
  IPF_LOG("%s: UPDATE IF if=%d new %d up %d hwports %x "
          "vlan id %d mac %02X:%02X:%02X:%02X:%02X:%02X", __FUNCTION__,
          ifindex, lid == NULL, flags, hwport_mask, vlan_id,
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  if( lid != NULL )
    old_hwport_mask = lid->lid_hwport_mask;

  if( hwport_mask == 0 ) {
    if( lid != NULL )
      oof_local_interface_details_free(fm, lid);
  }
  else {
    if( lid == NULL )
      lid = oof_local_interface_details_alloc(fm, ifindex);
    if( lid == NULL ) {
      ERR_LOG("%s: couldn't allocate space for if=%d", __FUNCTION__, ifindex);
      return;
    }
    oof_local_interface_details_update(lid, ifindex, flags, hwport_mask, vlan_id, mac);
  }

  /* Now we've updated this interface's hwport usage we need to check what
   * other interfaces may be using to correctly determine hwport availability.
   */
  in_use_hwport_mask = oof_local_interface_hwport_mask(fm);

  /* All interface hwport masks have now been updated, so if this interface
   * is using an hwport it should be present in the in_use mask.
   */
  ci_assert_equal(hwport_mask & in_use_hwport_mask, hwport_mask);

  /* Update the mask of hwports managed by this oof_manager.  This will set the
   * masks in [fm->fm_hwports_avail_per_tag_new], which get propagated to the
   * non-_new field by the deferred work.  We're already in the context of the
   * deferred work, but that's OK; the handling will happen when we eventually
   * return to oof_do_deferred_work(). */
  spin_lock_bh(&fm->fm_cplane_updates_lock);
  for( i = 0; i < CI_CFG_MAX_HWPORTS; ++i )
    if( (1 << i) & (old_hwport_mask ^ hwport_mask) )
      __oof_hwport_un_available(fm, i, (1 << i) & in_use_hwport_mask,
                                OOF_HWPORT_AVAIL_TAG_NAMESPACE);
  spin_unlock_bh(&fm->fm_cplane_updates_lock);
}


/* This function must only be called in response to an LLAP filter-update ioctl
 * from the control plane. */
static void
__oof_mcast_update_filters(struct oof_manager* fm, int ifindex)
{
  struct oof_local_port* lp;
  struct oof_mcast_filter* mf;
  struct oof_mcast_filter* mf_temp;
  struct oof_mcast_member* mm;
  struct oof_mcast_member* mm_temp;
  unsigned hwport_mask;
  int rc, hash, touched;
  ci_dllist mcast_filters;
  int remove;
  int up;
  struct oof_local_interface_details* lid =
      oof_local_interface_details_find(fm, ifindex);

  if( lid == NULL ) {
    /* device is gone, remove all memberships for the ifindex */
    remove = 1;
    hwport_mask = 0;
    up = 0;
  }
  else {
    remove = 0;
    hwport_mask = lid->lid_hwport_mask;
    up = !! lid->lid_flags;
  }

  IPF_LOG("%s: if=%u hwports=%x up %d nodev %d",
          __FUNCTION__, ifindex, hwport_mask, up, remove);

  fm->fm_hwports_mcast_update_seen |= hwport_mask;

  hwport_mask &= fm->fm_hwports_up & fm->fm_hwports_available;

  if( ! up )
    hwport_mask = 0;

  ci_dllist_init(&mcast_filters);

  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash]) {
      /* Need to update mf_hwport_mask in all filters first for
       * oof_mcast_filter_installable_hwports() to give correct results.
       */
      touched = 0;
      CI_DLLIST_FOR_EACH3(struct oof_mcast_filter, mf, mf_lp_link,
                          &lp->lp_mcast_filters, mf_temp)
        CI_DLLIST_FOR_EACH3(struct oof_mcast_member, mm, mm_filter_link,
                            &mf->mf_memberships, mm_temp)
          if( mm->mm_ifindex == ifindex ) {
            touched = 1;
            ci_assert_equal(mm->mm_filter, mf);
            if( remove ) {
              struct oof_socket* skf = mm->mm_socket;
              int maddr = mm->mm_maddr;
              ci_dllist_remove(&mm->mm_socket_link);
              rc = oof_mcast_remove(fm, mm, 0, &mcast_filters);
              ci_free(mm);
              if( OOF_CONNECTED_MCAST(skf, maddr) )
                oof_socket_mcast_del_connected(fm, skf, 0);
              if( rc )
                /* get away: filter got removed,
                 * membership list does not exist any more */
                break;
            }
            else {
              mm->mm_hwport_mask = hwport_mask;
              mf->mf_hwport_mask = oof_mcast_filter_hwport_mask(fm, mf);
            }
          }
      if( touched )
        CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                            &lp->lp_mcast_filters)
          oof_mcast_update(fm, lp, mf, ifindex);
    }

  oof_mcast_filter_list_free(&mcast_filters);
}


void
oof_mcast_update_interface(ci_ifid_t ifindex, ci_uint16 flags,
                           cicp_hwport_mask_t hwports,
                           ci_uint16 vlan_id, ci_mac_addr_t mac, void *arg)
{
  struct oof_manager* fm = arg;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  __oof_manager_update_interface(fm, ifindex, flags, hwports, vlan_id, mac);

  /* Apply changes to fm_hwports_avail_per_tag */
  __oof_do_deferred_work(fm);

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}


void
oof_mcast_update_filters(ci_ifid_t ifindex, void *arg)
{
  struct oof_manager* fm = arg;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  __oof_mcast_update_filters(fm, ifindex);

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}


int
oof_socket_mcast_add(struct oof_manager* fm, struct oof_socket* skf,
                     unsigned maddr, int ifindex)
{
  struct oof_mcast_member* new_mm;
  struct oof_mcast_filter* mf;
  struct oof_mcast_member* mm;
  ci_dllist mcast_filters;
  struct oof_local_interface_details* lid;
  int rc;

  IPF_LOG(FSK_FMT "maddr="IP_FMT" if=%d",
          FSK_PRI_ARGS(skf), IP_ARG(maddr), ifindex);

  ci_dllist_init(&mcast_filters);
  new_mm = NULL;
  if( ! CI_IP_IS_MULTICAST(maddr) ) {
    ERR_LOG(FSK_FMT "ERROR: maddr="IP_FMT, FSK_PRI_ARGS(skf), IP_ARG(maddr));
    rc = -EINVAL;
    goto out;
  }

  if( (new_mm = CI_ALLOC_OBJ(struct oof_mcast_member)) == NULL )
    goto out_of_memory;
  if( (mf = CI_ALLOC_OBJ(struct oof_mcast_filter)) == NULL )
    goto out_of_memory;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  lid = oof_local_interface_details_find(fm, ifindex);
  if( lid == NULL ) {
    IPF_LOG(FSK_FMT "ERROR: no records for if=%d",
            FSK_PRI_ARGS(skf), ifindex);
    rc = -ENODEV;
    ci_free(mf);
    mf = NULL;
    goto out_unlock;
  }

  if( lid->lid_hwport_mask == 0 ) {
    IPF_LOG(FSK_FMT "ERROR: no hwports for if=%d",
            FSK_PRI_ARGS(skf), ifindex);
    /* Carry on -- we may get hwports later due to cplane changes. */
  }

  oof_mcast_member_init(new_mm, skf, maddr, ifindex,
                        lid->lid_hwport_mask, lid->lid_vlan_id);
  ci_dllist_push(&mcast_filters, &mf->mf_lp_link);

  rc = 0;
  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships)
    if( mm->mm_maddr == maddr && mm->mm_ifindex == ifindex )
      break;
  if( mm == NULL ) {  /* NB. Ignore duplicates. */
    mm = new_mm;
    new_mm = NULL;
    ci_dllist_push(&skf->sf_mcast_memberships, &mm->mm_socket_link);
    if( skf->sf_local_port != NULL ) {
      /* For connected sockets we install any full match filters and the sw
       * filter via the connect path first.  Then wild match filters are
       * added for all sockets if needed.  If the connect path fails, we don't
       * install hw filters so that traffic can go via the kernel.
       */
      if( OOF_CONNECTED_MCAST(skf, maddr) )
        rc = oof_udp_connect_mcast_laddr(fm, skf, skf->sf_laddr.ip4,
                                         skf->sf_raddr.ip4, skf->sf_rport);
      if( rc == 0 && OOF_NEED_MCAST_FILTER(fm, skf, mm) ) {
        rc = oof_mcast_install(fm, mm, &mcast_filters);
        if( rc != 0 ) {
          ci_dllist_pop(&skf->sf_mcast_memberships);
          new_mm = mm;
        }
      }
    }
  }

 out_unlock:
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);

 out:
  if( new_mm )
    ci_free(new_mm);
  oof_mcast_filter_list_free(&mcast_filters);
  return rc;

 out_of_memory:
  ERR_LOG(FSK_FMT "ERROR: out of memory", FSK_PRI_ARGS(skf));
  rc = -ENOMEM;
  goto out;
}


static void
oof_socket_mcast_del_connected(struct oof_manager* fm,
                               struct oof_socket* skf, int stack_locked)
{
  struct oof_mcast_member* mm;
  unsigned hwports = 0;
  unsigned hwports_full;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships)
    if( mm->mm_maddr == skf->sf_laddr.ip4 )
      hwports |= mm->mm_hwport_mask;

  hwports_full = hwports & ~fm->fm_hwports_mcast_replicate_capable;

  /* Still need a full match filter, update it with the current hwports */
  if( hwports_full ) {
    oof_hw_filter_update(fm, &skf->sf_full_match_filter,
                         oof_cb_socket_stack(skf), AF_INET,
                         skf->sf_local_port->lp_protocol, skf->sf_raddr,
                         skf->sf_rport, skf->sf_laddr,
                         skf->sf_local_port->lp_lport, OO_HW_VLAN_UNSPEC,
                         hwports_full, OOF_SRC_FLAGS_DEFAULT);
  }
  /* If we have no hwports we don't need any filters. */
  else if( hwports == hwports_full ) {
    if( skf->sf_flags & OOF_SOCKET_MCAST_FULL_SW_FILTER ) {
      oof_socket_del_full_sw(skf, stack_locked);
      skf->sf_flags &= ~OOF_SOCKET_MCAST_FULL_SW_FILTER;
    }
    oof_hw_filter_clear_full(fm, skf);
  }
}


void
oof_socket_mcast_del(struct oof_manager* fm, struct oof_socket* skf,
                     unsigned maddr, int ifindex)
{
  struct oof_mcast_member* mm;
  ci_dllist mcast_filters;

  IPF_LOG(FSK_FMT "maddr="IP_FMT, FSK_PRI_ARGS(skf), IP_ARG(maddr));

  ci_dllist_init(&mcast_filters);

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships)
    if( mm->mm_maddr == maddr && mm->mm_ifindex == ifindex)
      break;
  if( mm != NULL ) {
    ci_dllist_remove(&mm->mm_socket_link);
    if( mm->mm_filter != NULL )
      oof_mcast_remove(fm, mm, 1, &mcast_filters);

    if( OOF_CONNECTED_MCAST(skf, maddr) )
      oof_socket_mcast_del_connected(fm, skf, 1);
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);

  if( mm != NULL )
    ci_free(mm);
  oof_mcast_filter_list_free(&mcast_filters);
}


void
oof_socket_mcast_del_all(struct oof_manager* fm, struct oof_socket* skf)
{
  struct oof_mcast_member* mm;
  ci_dllist mf_list, mm_list;

  ci_dllist_init(&mf_list);
  ci_dllist_init(&mm_list);

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  while( ci_dllist_not_empty(&skf->sf_mcast_memberships) ) {
    mm = CI_CONTAINER(struct oof_mcast_member, mm_socket_link,
                      ci_dllist_pop(&skf->sf_mcast_memberships));
    if( mm->mm_filter != NULL )
      oof_mcast_remove(fm, mm, 1, &mf_list);
    ci_dllist_push(&mm_list, &mm->mm_socket_link);
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);

  oof_mcast_filter_list_free(&mf_list);
  oof_mcast_member_list_free(&mm_list);
}


static int
oof_socket_mcast_install(struct oof_manager* fm, struct oof_socket* skf)
{
  struct tcp_helper_resource_s* skf_stack = oof_cb_socket_stack(skf);
  struct oof_mcast_filter* mf;
  struct oof_mcast_member* mm;
  struct oof_local_port* lp;
  ci_dllist mcast_filters;
  int mf_needed, mf_n, rc, rc1 = 0;

  /* Calculate how many new filters we'll need to install, and allocate
   * that many.  Slightly complex because we want to allocate with lock
   * dropped.
   *
   * TODO: NB. This can be simplified now that we have fm_outer_lock, which
   * allows non-atomic memory allocation and ensures sf_mcast_memberships
   * won't change.
   */
  ci_dllist_init(&mcast_filters);
  mf_n = 0;
  
  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  while( 1 ) {
    mf_needed = 0;
    if( (lp = skf->sf_local_port) != NULL ) {
      CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                          &skf->sf_mcast_memberships) {
        if( mm->mm_filter == NULL &&
            OOF_NEED_MCAST_FILTER(fm, skf, mm) &&
            oof_local_port_find_mcast_filter(lp, skf_stack, mm->mm_maddr,
                                             mm->mm_vlan_id) == NULL )
          ++mf_needed;
      }
    }
    if( mf_n >= mf_needed )
      break;

    spin_unlock_bh(&fm->fm_inner_lock);
    mutex_unlock(&fm->fm_outer_lock);

    do {
      if( (mf = CI_ALLOC_OBJ(struct oof_mcast_filter)) == NULL )
        goto out_of_memory;
      ci_dllist_push(&mcast_filters, &mf->mf_lp_link);
    } while( ++mf_n < mf_needed );

    mutex_lock(&fm->fm_outer_lock);
    spin_lock_bh(&fm->fm_inner_lock);
  }

  if( lp != NULL ) {
    CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                        &skf->sf_mcast_memberships) {
      if( mm->mm_filter == NULL ) {
        if( OOF_NEED_MCAST_FILTER(fm, skf, mm) ) {
          rc = oof_mcast_install(fm, mm, &mcast_filters);
          if( rc != 0 && rc1 == 0 )
            rc1 = rc;
        }
      }
      else {
        if( ! OOF_NEED_MCAST_FILTER(fm, skf, mm) )
          oof_mcast_remove(fm, mm, 1, &mcast_filters);
      }
    }
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);

 out:
  oof_mcast_filter_list_free(&mcast_filters);
  return rc1;

 out_of_memory:
  ERR_LOG(FSK_FMT "ERROR: out of memory", FSK_PRI_ARGS(skf));
  goto out;
}


static void
oof_socket_mcast_remove(struct oof_manager* fm, struct oof_socket* skf,
                        ci_dllist* mcast_filters)
{
  struct oof_mcast_member* mm;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships) {
    ci_assert(mm->mm_socket == skf);
    ci_assert(CI_IP_IS_MULTICAST(mm->mm_maddr));
    if( mm->mm_filter != NULL )
      oof_mcast_remove(fm, mm, 1, mcast_filters);
  }
}


static int
oof_socket_mcast_remove_sw(struct oof_manager* fm, struct oof_socket* skf)
{
  struct oof_mcast_member* mm;
  int needs_cleanup = 0;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));

  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships) {
    needs_cleanup = 1;
    ci_assert(mm->mm_socket == skf);
    ci_assert(CI_IP_IS_MULTICAST(mm->mm_maddr));
    if( mm->mm_filter != NULL ) {
      struct oof_local_port* lp = skf->sf_local_port;
      ci_addr_t laddr = CI_ADDR_FROM_IP4(mm->mm_maddr);

      oof_cb_sw_filter_remove(skf, AF_SPACE_FLAG_IP4, laddr, lp->lp_lport,
                              addr_any, 0, lp->lp_protocol, 1);
    }
  }
  return needs_cleanup;
}


/**********************************************************************
************************** TPROXY *************************************
**********************************************************************/

/* Initializes or updates tproxy filters in response to iface up/down or slave
 * being added or removed from the bond */
static int
oof_tproxy_filter_update(struct oof_manager* fm, struct oof_tproxy* ft)
{
  unsigned short vlan_id = OO_HW_VLAN_UNSPEC;
  unsigned hwport_mask = 0;
  unsigned allowed_hwport_mask;
  unsigned effective_hwport_mask;
  int ifindex;
  ci_mac_addr_t mac = { 0 };
  int rc, rc1;
  struct oo_hw_filter_spec oo_filter_spec;
  struct tcp_helper_resource_s* trs = ft->ft_filter.trs;
  struct oof_local_interface_details* lid;
  int i;

  CI_BUILD_ASSERT(CI_MEMBER_OFFSET(struct oo_hw_filter_spec,
                                   addr.ethertype.mac) ==
                  CI_MEMBER_OFFSET(struct oo_hw_filter_spec,
                                   addr.mac.mac));
  CI_BUILD_ASSERT(CI_MEMBER_OFFSET(struct oo_hw_filter_spec,
                                   addr.ipproto.mac) ==
                  CI_MEMBER_OFFSET(struct oo_hw_filter_spec,
                                   addr.mac.mac));

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));
  ci_assert(ft != NULL);

  ifindex = ft->ft_ifindex;

  ci_assert( ft->ft_filter.trs != NULL ||
             ft->ft_filter.thc != NULL);

  lid = oof_local_interface_details_find(fm, ifindex);

  if( lid == NULL ) {
    IPF_LOG("%s: WARNING: cannot get details of if=%d",
            __FUNCTION__, ifindex);
    /* fall through to delete the filters */
  }
  else {
    hwport_mask = lid->lid_hwport_mask;
    vlan_id = lid->lid_vlan_id;
    if( vlan_id == 0 )
      vlan_id = OO_HW_VLAN_UNSPEC;
    memcpy(mac, lid->lid_mac, sizeof(mac));
  }

  if( (fm->fm_hwports_available & hwport_mask) != hwport_mask ) {
    /* We need accelerated interfaces only
     * FIXME: for now we fall through... most likely not capturing any traffic
     */
    IPF_LOG("%s: ERROR: some of tproxy hwports are not accelerated, "
            "got hwports 0x%x, need 0x%x",
            __FUNCTION__, fm->fm_hwports_available, hwport_mask);
  }

  ft->ft_hwport_mask = hwport_mask;
  ft->ft_vlan_id = vlan_id;
  memcpy(ft->ft_mac, mac, sizeof(ft->ft_mac));

  allowed_hwport_mask = fm->fm_hwports_available &
                        (fm->fm_hwports_up | fm->fm_hwports_down);
  effective_hwport_mask = hwport_mask & allowed_hwport_mask;

  spin_unlock_bh(&fm->fm_inner_lock);

  oo_filter_spec.type = OO_HW_FILTER_TYPE_MAC;
  memcpy(oo_filter_spec.addr.mac.mac, mac, sizeof(oo_filter_spec.addr.mac.mac));
  oo_filter_spec.vlan_id = vlan_id;
  rc = oo_hw_filter_update(&ft->ft_filter, trs, &oo_filter_spec,
                           effective_hwport_mask, effective_hwport_mask, 0,
                           OO_HW_SRC_FLAG_RSS_DST);

#define ETHERTYPE_ARP 0x806
  /* This filter redirects ARP traffic back to kernel. */
  oo_filter_spec.type = OO_HW_FILTER_TYPE_ETHERTYPE;
  oo_filter_spec.addr.ethertype.t = htons(ETHERTYPE_ARP);
  /* [vlan_id] and [mac] are already set. */
  rc1 = oo_hw_filter_update(&ft->ft_filter_arp, trs, &oo_filter_spec,
                            effective_hwport_mask, effective_hwport_mask,
                            0,
                            OO_HW_SRC_FLAG_KERNEL_REDIRECT);
  if( rc1 != 0 )
    ERR_LOG("%s: failed to install filter to steer ARP traffic to kernel "
            "(rc1=%d)", __FUNCTION__, rc1);

  IPF_LOG("%s: if=%u hwports=%x/%x MAC=%02x%02x%02x%02x%02x%02x "
          "vlan=%d rc=%d rc1=%d",
          __FUNCTION__, ifindex, hwport_mask, effective_hwport_mask,
         mac[0], mac[1],mac[2], mac[3], mac[4], mac[5], vlan_id, rc, rc1);

  /* Install the IP-protocol-to-kernel filters. */
  for( i = 0; i < OOF_TPROXY_IPPROTO_FILTER_COUNT; ++i ) {
    oo_filter_spec.type = OO_HW_FILTER_TYPE_IP_PROTO_MAC;
    oo_filter_spec.addr.ipproto.ethertype = htons(oof_tproxy_ipprotos[i][0]);
    oo_filter_spec.addr.ipproto.p = oof_tproxy_ipprotos[i][1];
    oo_filter_spec.vlan_id = vlan_id;

    rc1 = oo_hw_filter_update(&ft->ft_filter_ipproto[i], trs,
                              &oo_filter_spec, effective_hwport_mask,
                              effective_hwport_mask,
                              0,
                              OO_HW_SRC_FLAG_KERNEL_REDIRECT);
    if( rc1 == -EPROTONOSUPPORT ) {
      /* The requested filter-type didn't exist.  This is expected on low-
       * latency firmware, which doesn't support IP-proto + MAC filters, so
       * retry without the MAC.  In this case we can't install the filter
       * ourselves, as we can't see users in other namespaces that might
       * conflict with our usage, so we need arbitration from the layer
       * above.
       */

      /* Add on any ports that we want, but don't currently have filters for */
      unsigned to_add = allowed_hwport_mask & ~fm->fm_tproxy_global_filters[i];
      /* Remove on any ports we currently have filters for, but don't want */
      unsigned to_remove = fm->fm_tproxy_global_filters[i] &
                           ~allowed_hwport_mask;

      IPF_LOG("%s: IP-proto + MAC (+VLAN) filter-insertion failed.  "
              "Retrying without MAC/VLAN.", __FUNCTION__);

      rc1 = 0;

      /* If we loose MAC we need to loose VLAN as well to get as broad filter
       * as possible */
      oo_filter_spec.vlan_id = OO_HW_VLAN_UNSPEC;

      if( to_remove )
        oof_cb_remove_global_tproxy_filter(i, to_remove,
                                           &fm->fm_tproxy_global_filters[i],
                                           fm->fm_owner_private);

      oo_filter_spec.type = OO_HW_FILTER_TYPE_IP_PROTO;
      if( to_add )
        rc1 = oof_cb_add_global_tproxy_filter(&oo_filter_spec, i, to_add,
                                              &fm->fm_tproxy_global_filters[i],
                                              fm->fm_owner_private);
    }

    if( rc1 != 0 )
      ERR_LOG("%s: failed to install filter to steer IP protocol %d to kernel"
              "(rc1=%d)", __FUNCTION__, oo_filter_spec.addr.ipproto.p, rc1);
  }

  spin_lock_bh(&fm->fm_inner_lock);
  return rc;
}


/* Allocate and initialize and add to oof_manager tproxy instance on given if
 */
static int oof_tproxy_alloc(struct oof_manager* fm,
                            struct tcp_helper_resource_s* trs,
                            struct tcp_helper_cluster_s* thc, unsigned ifindex)
{
  struct oof_tproxy* ft;
  int rc;
  int i;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  spin_unlock_bh(&fm->fm_inner_lock);
  ft = CI_ALLOC_OBJ(struct oof_tproxy);
  spin_lock_bh(&fm->fm_inner_lock);

  if( ft == NULL ) {
    OO_DEBUG_ERR(ci_log("%s: ERROR: out of memory", __FUNCTION__));
    return -ENOMEM;
  }

  ft->ft_ifindex = ifindex;
  oo_hw_filter_init2(&ft->ft_filter, trs, thc);
  oo_hw_filter_init2(&ft->ft_filter_arp, trs, thc);
  for( i = 0; i < OOF_TPROXY_IPPROTO_FILTER_COUNT; ++i )
    oo_hw_filter_init2(&ft->ft_filter_ipproto[i], trs, thc);

  rc = oof_tproxy_filter_update(fm, ft);
  if( rc == 0 )
    ci_dllist_push(&fm->fm_tproxies, &ft->ft_manager_link);
  else
    ci_free(ft);
  return rc;
}


static struct oof_tproxy*
oof_tproxy_find(struct oof_manager* fm,
                struct tcp_helper_resource_s* trs,
                struct tcp_helper_cluster_s* thc,
                int ifindex)
{
  struct oof_tproxy* ft;
  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  CI_DLLIST_FOR_EACH2(struct oof_tproxy, ft, ft_manager_link,
                      &fm->fm_tproxies) {
    if( (ifindex < 0 || ft->ft_ifindex == ifindex) &&
        (trs == NULL || ft->ft_filter.trs == trs) &&
        (thc == NULL || ft->ft_filter.thc == thc) )
      return ft;
  }
  return NULL;
}


/* Add tproxy instance
 * rss_idx is index  (0 or 1) of RSS context allocated for vi_set
 */
int
oof_tproxy_install(struct oof_manager* fm,
                   struct tcp_helper_resource_s* trs,
                   struct tcp_helper_cluster_s* thc, int ifindex)
{
  struct oof_tproxy* ft;
  int rc;

  /* If we fail the capability check then need to see if we can allow
   * this user to install the scalable filter.
   */
#ifdef EFRM_NET_HAS_USER_NS
  if( !ns_capable(oof_cb_user_ns(fm->fm_owner_private), CAP_NET_RAW) &&
#else
  if( !capable(CAP_NET_RAW) &&
#endif
      !ci_in_egroup(scalable_filter_gid) )
    return -EPERM;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  ft = oof_tproxy_find(fm, NULL, NULL, ifindex);
  if( ft != NULL ) {
    rc = -EALREADY;
    goto fail1;
  }
  rc = oof_tproxy_alloc(fm, trs, thc, ifindex);

fail1:
  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
  return rc;
}


static int __oof_tproxy_free(struct oof_manager* fm,
                             struct oof_tproxy* ft)
{
  int i;

  ci_assert(ft != NULL);

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  ci_dllist_remove(&ft->ft_manager_link);

  IPF_LOG("%s: if=%u",
          __FUNCTION__, ft->ft_ifindex);
  spin_unlock_bh(&fm->fm_inner_lock);
  /* These IP-protocol filters are safe to clear even if they are unused. */
  for( i = 0; i < OOF_TPROXY_IPPROTO_FILTER_COUNT; ++i )
    oo_hw_filter_clear(&ft->ft_filter_ipproto[i]);
  oo_hw_filter_clear(&ft->ft_filter_arp);
  oo_hw_filter_clear(&ft->ft_filter);
  spin_lock_bh(&fm->fm_inner_lock);

  ci_free(ft);
  return 0;
}


int
oof_tproxy_free(struct oof_manager* fm,
                struct tcp_helper_resource_s* trs,
                struct tcp_helper_cluster_s* thc,
                int ifindex)
{
  struct oof_tproxy* ft;
  int rc;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  ft = oof_tproxy_find(fm, trs, thc, ifindex);
  if( ft == NULL ) {
    rc = -ENOENT;
    spin_unlock_bh(&fm->fm_inner_lock);
    goto fail1;
  }
  rc = __oof_tproxy_free(fm, ft);

  spin_unlock_bh(&fm->fm_inner_lock);

  if( ci_dllist_is_empty(&fm->fm_tproxies) ) {
    /* Last tproxy has gone, so clear global filters. */
    int i;
    for( i = 0; i < OOF_TPROXY_GLOBAL_FILTER_COUNT; ++i )
      oof_cb_remove_global_tproxy_filter(i, fm->fm_tproxy_global_filters[i],
                                         &fm->fm_tproxy_global_filters[i],
                                         fm->fm_owner_private);
  }

fail1:
  mutex_unlock(&fm->fm_outer_lock);
  return rc;
}


/**********************************************************************
***********************************************************************
**********************************************************************/

int
oof_is_onloaded(struct oof_manager* fm, int ifindex)
{
  struct oof_local_interface_details* lid;
  int v = 0;
  spin_lock_bh(&fm->fm_inner_lock);
  lid = oof_local_interface_details_find(fm, ifindex);
  if( lid != NULL )
    v = lid->lid_hwport_mask != 0;
  spin_unlock_bh(&fm->fm_inner_lock);
  return v;
}


static void
oof_socket_dump_w_lp(const char* pf, struct oof_manager* fm,
                     struct oof_socket* skf,
                     void (*log)(void* opaque, const char* fmt, ...),
                     void* loga)
{
  struct tcp_helper_resource_s* skf_stack = oof_socket_stack_safe(skf);
  struct oof_local_port* lp = skf->sf_local_port;
  struct oof_local_port_addr* lpa;
  struct oof_mcast_filter* mf, *mf2;
  const char* state = NULL;
  int n_laddr, n_filter, n_mine;
  int la_i;

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));
  ci_assert(skf->sf_local_port != NULL);

  /* Work out whether the socket can receive any packets. */
  if( ! oo_hw_filter_is_empty(&skf->sf_full_match_filter) ) {
    state = "ACCELERATED (full)";
  }
  else if( CI_IPX_IS_MULTICAST(skf->sf_laddr) ) {
    CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                        &lp->lp_mcast_filters)
      if( mf->mf_maddr == skf->sf_laddr.ip4 && mf->mf_filter.trs == skf_stack ) {
        if( oo_hw_filter_hwports(&mf->mf_filter) )
          state = "ACCELERATED (multicast laddr)";
        else {
          /* See if there's another filter that we're sharing. */
          CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf2, mf_lp_link,
                              &lp->lp_mcast_filters)
            if( (mf != mf2) && (oof_mcast_filter_duplicate_hwports(fm, mf,
                                                                   mf2)) ) {
              state = "ACCELERATED (multicast laddr)";
              break;
            }
          if ( state == NULL )
            state = "KERNEL (multicast laddr)";
        }
        break;
      }
    if( state == NULL )
      /* Not done IP_ADD_MEMBERSHIP, so won't get packets. */
      state = "UNREACHABLE (need IP_ADD_MEMBERSHIP)";
  }
  else if( !CI_IPX_ADDR_IS_ANY(skf->sf_laddr) ) {
    ci_assert(skf->sf_la_i >= 0 && skf->sf_la_i < fm->fm_local_addr_n);
    lpa = &lp->lp_addr[skf->sf_la_i];
    if( !CI_IPX_ADDR_IS_ANY(skf->sf_raddr) ) {
      if( oo_hw_filter_is_empty(&lpa->lpa_filter) )
        state = "ORPHANED (no filter)";
      else if( oof_socket_can_share_hw_filter(skf, &lpa->lpa_filter) )
        state = "ACCELERATED (sharing wild)";
      else
        state = "ORPHANED (filter points elsewhere)";
    }
    else {
      struct oof_socket* wskf = oof_wild_socket(lp, lpa, skf->af_space);
      if( wskf == skf ) {
        if( oo_hw_filter_is_empty(&lpa->lpa_filter) )
          state = "FILTER_MISSING (not accelerated)";
        else if( oof_socket_can_share_hw_filter(skf, &lpa->lpa_filter) ) {
          if( lpa->lpa_filter.thc != NULL )
            state = "ACCELERATED CLUSTERED-MASTER (wild)";
          else
            state = "ACCELERATED (wild)";
        }
        else
          state = "!! BAD_FILTER !!";
      }
      else {
        if( oof_socket_is_dummy(skf) )
          state = "CLUSTERED (not activated)";
        else if( oof_socket_can_share_hw_filter(skf, &lpa->lpa_filter) )
          state = "ACCELERATED CLUSTERED-SLAVE (wild)";
        else
          state = "HIDDEN";
      }
    }
  }
  else {
    n_laddr = n_filter = n_mine = 0;
    for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i )
      if( ci_dllist_not_empty(&fm->fm_local_addrs[la_i].la_active_ifs) ) {
        ++n_laddr;
        lpa = &lp->lp_addr[la_i];
        if( oof_wild_socket(lp, lpa, skf->af_space) == skf )
          ++n_mine;
        if( oof_socket_can_share_hw_filter(skf, &lpa->lpa_filter) )
          ++n_filter;
      }
    if( n_laddr == 0 )
      state = "NO_LOCAL_ADDR";
    else if( n_filter < n_mine )
      state = "FILTERS_MISSING (may not be accelerated)";
    else if( n_mine == 0 )
      state = oof_socket_is_dummy(skf)   ? "CLUSTERED (not activated)" :
              oof_socket_no_unicast(skf) ? "NO UNICAST" :
                                           "HIDDEN";
    else if( n_mine < n_laddr )
      state = "PARTIALLY_HIDDEN";
    else
      state = "ACCELERATED";
  }

  log(loga, "%s: "SK_FMT" "SK_ADDR_FMT" lport_prenat=%d %s %s", pf,
      SK_PRI_ARGS(skf), SK_ADDR_ARGS(skf), FMT_PORT(skf->sf_lport_prenat),
      state,
      oof_socket_thc_safe(skf) ? oof_cb_thc_name(oof_socket_thc_safe(skf)) : "");
}


void
oof_socket_dump(struct oof_manager* fm, struct oof_socket* skf,
                void (*log)(void* opaque, const char* fmt, ...),
                void* loga)
{
  struct oof_mcast_member* mm;
  struct oof_mcast_filter* mf;
  unsigned hwports_got;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  if( skf->sf_local_port != NULL )
    oof_socket_dump_w_lp(__FUNCTION__, fm, skf, log, loga);
  CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_socket_link,
                      &skf->sf_mcast_memberships) {
    if( (mf = mm->mm_filter) == NULL ) {
      log(loga, "%s:   maddr="IP_FMT" if=%d hwports=%x NOT_BOUND",
          __FUNCTION__, IP_ARG(mm->mm_maddr), mm->mm_ifindex,
          mm->mm_hwport_mask);
    }
    else {
      hwports_got = oo_hw_filter_hwports(&mf->mf_filter);
      log(loga, "%s:   maddr="IP_FMT" if=%d hwports=%x,%x,%x %s", __FUNCTION__,
          IP_ARG(mm->mm_maddr), mm->mm_ifindex, mm->mm_hwport_mask,
          oof_mcast_filter_installable_hwports(fm, skf->sf_local_port, mf) &
            mm->mm_hwport_mask,
          hwports_got & mm->mm_hwport_mask, oof_mcast_member_state(fm, mm));
    }
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}


static void
oof_local_port_dump(struct oof_manager* fm, struct oof_local_port* lp,
                    void (*log)(void* opaque, const char* fmt, ...),
                    void* loga)
{
  unsigned hwports_got, hwports_uc;
  struct oof_local_port_addr* lpa;
  struct oof_mcast_filter* mf;
  struct oof_nat_filter* natf;
  struct oof_mcast_member* mm;
  struct oof_local_addr* la;
  struct oof_socket* skf;
  int la_i;

  log(loga, "%s: %s:%d n_refs=%d", __FUNCTION__,
      FMT_PROTOCOL(lp->lp_protocol), FMT_PORT(lp->lp_lport), lp->lp_refs);

  ci_assert(spin_is_locked(&fm->fm_inner_lock));
  ci_assert(mutex_is_locked(&fm->fm_outer_lock));

  if( ci_dllist_not_empty(&lp->lp_wild_socks) ) {
    log(loga, "  wild sockets:");
    CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link, &lp->lp_wild_socks)
      oof_socket_dump_w_lp("    ", fm, skf, log, loga);
  }

  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    la = &fm->fm_local_addrs[la_i];
    lpa = &lp->lp_addr[la_i];

    if( ! oo_hw_filter_is_empty(&lpa->lpa_filter) )
      log(loga, "  FILTER " IPX_FMT ":%d hwports=%x stack=%d",
          IPX_ARG(AF_IP(la->la_laddr)), FMT_PORT(lp->lp_lport),
          oo_hw_filter_hwports(&lpa->lpa_filter),
          oof_cb_stack_id(lpa->lpa_filter.trs));
    if( ci_dllist_not_empty(&lpa->lpa_semi_wild_socks) ) {
      log(loga, "  semi-wild sockets:");
      CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                          &lpa->lpa_semi_wild_socks)
        oof_socket_dump_w_lp("    ", fm, skf, log, loga);
    }
    if( ci_dllist_not_empty(&lpa->lpa_nat_filters) ) {
      log(loga, "    NAT filters:");
      CI_DLLIST_FOR_EACH2(struct oof_nat_filter, natf, link,
                          &lpa->lpa_nat_filters) {
        log(loga, "      service_addr "IPX_FMT":%d",
            IPX_ARG(AF_IP(natf->orig_addr)),
            FMT_PORT(natf->orig_port));
      }
    }
    if( ci_dllist_not_empty(&lpa->lpa_full_socks) ) {
      log(loga, "  full-match sockets:");
      CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                          &lpa->lpa_full_socks)
        oof_socket_dump_w_lp("    ", fm, skf, log, loga);
    }
  }

  if( ci_dllist_not_empty(&lp->lp_mcast_filters) ) {
    log(loga, "  mcast filters:");
    CI_DLLIST_FOR_EACH2(struct oof_mcast_filter, mf, mf_lp_link,
                        &lp->lp_mcast_filters) {
      hwports_got = oo_hw_filter_hwports(&mf->mf_filter);
      hwports_uc = oof_mcast_filter_installable_hwports(fm, lp, mf);
      log(loga, "    maddr="IPPORT_FMT" stack=%d hwports=%x,%x,%x",
          IPPORT_ARG(mf->mf_maddr, lp->lp_lport),
          oof_cb_stack_id(mf->mf_filter.trs), mf->mf_hwport_mask,
          hwports_uc, hwports_got);
      CI_DLLIST_FOR_EACH2(struct oof_mcast_member, mm, mm_filter_link,
                          &mf->mf_memberships)
        log(loga, "      "SK_FMT" "SK_ADDR_FMT" if=%d hwports=%x,%x,%x %s",
            SK_PRI_ARGS(mm->mm_socket), SK_ADDR_ARGS(mm->mm_socket),
            mm->mm_ifindex, mm->mm_hwport_mask,
            hwports_uc & mm->mm_hwport_mask, hwports_got & mm->mm_hwport_mask,
            oof_mcast_member_state(fm, mm));
    }
  }
}


static void
oof_tproxy_dump(struct oof_manager* fm, struct oof_tproxy* ft,
                    void (*log)(void* opaque, const char* fmt, ...),
                    void* loga)
{
  ci_uint8* m = ft->ft_mac;
  log(loga, "  if=%d hwports=%x,%x mac=%02x:%02x:%02x:%02x:%02x:%02x "
            "vlan_id=%d stack=%d cluster=%s",
      ft->ft_ifindex, ft->ft_hwport_mask, oo_hw_filter_hwports(&ft->ft_filter),
      m[0], m[1], m[2], m[3], m[4], m[5], ft->ft_vlan_id,
      oof_cb_stack_id(ft->ft_filter.trs),
      ft->ft_filter.thc != NULL ? oof_cb_thc_name(ft->ft_filter.thc) : "None");
}


void
oof_manager_dump(struct oof_manager* fm,
                void (*log)(void* opaque, const char* fmt, ...),
                void* loga)
{
  struct oof_local_port* lp;
  struct oof_tproxy* ft;
  struct oof_socket* skf;
  struct oof_local_addr* la;
  int la_i, hash;
  int i;

  mutex_lock(&fm->fm_outer_lock);
  spin_lock_bh(&fm->fm_inner_lock);

  log(loga, "%s: hwports up=%x down=%x unavailable=%x update_seen=%x "
            "local_addr_n=%d",
      __FUNCTION__, fm->fm_hwports_up,fm->fm_hwports_down,
      ~fm->fm_hwports_available, fm->fm_hwports_mcast_update_seen,
      fm->fm_local_addr_n);

  for( la_i = 0; la_i < fm->fm_local_addr_n; ++la_i ) {
    la = &fm->fm_local_addrs[la_i];

    if( CI_IPX_ADDR_IS_ANY(la->la_laddr) )
      continue;

    log(loga, "  " IPX_FMT " active=%d sockets=%d",
        IPX_ARG(AF_IP_L3(la->la_laddr)),
        ci_dllist_not_empty(&la->la_active_ifs), la->la_sockets);
  }

  if( ci_dllist_not_empty(&fm->fm_mcast_laddr_socks) ) {
    log(loga, "%s: sockets with laddr bound to multicast address:",
        __FUNCTION__);
    CI_DLLIST_FOR_EACH2(struct oof_socket, skf, sf_lp_link,
                        &fm->fm_mcast_laddr_socks)
      oof_socket_dump_w_lp("  ", fm, skf, log, loga);
  }

  for( hash = 0; hash < OOF_LOCAL_PORT_TBL_SIZE; ++hash )
    CI_DLLIST_FOR_EACH2(struct oof_local_port, lp, lp_manager_link,
                        &fm->fm_local_ports[hash])
      oof_local_port_dump(fm, lp, log, loga);

  log(loga, "%s: scalable interfaces and MAC filters",
      __FUNCTION__);
  CI_DLLIST_FOR_EACH2(struct oof_tproxy, ft, ft_manager_link,
                      &fm->fm_tproxies)
    oof_tproxy_dump(fm, ft, log, loga);

  for( i = 0; i < OOF_TPROXY_GLOBAL_FILTER_COUNT; ++i ) {
    if( fm->fm_tproxy_global_filters[i] != 0 )
      log(loga, "Global filter %d: hwports=%x", i,
          fm->fm_tproxy_global_filters[i]);
  }

  spin_unlock_bh(&fm->fm_inner_lock);
  mutex_unlock(&fm->fm_outer_lock);
}


int oof_hwports_list(struct oof_manager* fm, struct seq_file* seq)
{
  int i;

  for( i = 0; i < 32; i++ ) {
    unsigned portmask = 1 << i;
    if( portmask &
        (fm->fm_hwports_up | fm->fm_hwports_down | fm->fm_hwports_removed) ) {
      seq_printf(seq, "port %d%s%s%s\t%s%s%s\tcapable of%s%s\n", i,
                 (portmask & fm->fm_hwports_up) ? " up" : "",
                 (portmask & fm->fm_hwports_down) ? " down" : "",
                 (portmask & fm->fm_hwports_removed) ? " removed" : "",
                 (portmask & fm->fm_hwports_available) ?
                 "\t\t" : "forbidden by",
                 (portmask &
                  fm->fm_hwports_avail_per_tag[OOF_HWPORT_AVAIL_TAG_BOND]) ?
                 "" : " bond",
                 (portmask &
                  fm->fm_hwports_avail_per_tag[OOF_HWPORT_AVAIL_TAG_NAMESPACE])?
                 "" : " namespace",
                 (portmask & fm->fm_hwports_mcast_replicate_capable) ?
                 " macst_replicate" : "",
                 (portmask & fm->fm_hwports_vlan_filters) ?
                 " vlan_filters" : "");
    }
  }
  return 0;
}
int oof_ipaddrs_list(struct oof_manager* fm, struct seq_file* seq)
{
  int i;

  for( i = 0; i < fm->fm_local_addr_n; i++ ) {
    seq_printf(seq, IPX_FMT": in use by %d sockets\n",
               IPX_ARG(AF_IP_L3(fm->fm_local_addrs[i].la_laddr)),
               fm->fm_local_addrs[i].la_sockets);
  }
  return 0;
}
