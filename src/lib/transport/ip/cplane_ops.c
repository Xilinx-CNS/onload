/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  Control Plane kernel code
**   \date  2005/07/15
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/



/*! The code in this file is available both in the kernel and from the
 *  user-mode libraries.
 *
 *  This code could be split among a number of different files but is divided
 *  instead into the following sections:
 *
 *      ACM  - Functions on Abstract Cacheable MIBs
 *             (which hide use of CM and support protocols)
 *      CM   - Functions on Cacheable MIBs
 *             (which hide use of SYN)
 *      SYN  - Functions on local MIB caches required for O/S synchronization
 *
 *  These divisions are documented in L5-CGG/1-SD 'IP "Control Plane" Design
 *  Notes'
 *
 *  Within each section code supporting each of the following Management
 *  Information Bases (MIBs) potentially occur.
 *
 *  User and kernel visible information
 *
 *      cicp_mac_kmib_t    - IP address resolution table
 *
 *      cicp_fwdinfo_t     - cache of kernel forwarding information table
 *
 *  The information is related as follows:
 *
 *   * the IP address resolution table provides link layer addresses usable at
 *     a given link layer access point that identify IP entities directly
 *     connected to IP interfaces the access point supports
 *
 *   * the cache of forwarding information remembers a complete set of the
 *     data that needs to be known when transmitting to a destination
 *     IP address - including the first hop and its link layer access point
 *     for example
 *
 */




/*****************************************************************************
 *                                                                           *
 *          Headers                                                          *
 *          =======							     *
 *                                                                           *
 *****************************************************************************/





#include <onload/cplane_ops.h>




#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif



/*****************************************************************************
 *                                                                           *
 *          Debugging                                                        *
 *          =========							     *
 *                                                                           *
 *****************************************************************************/



#define DPRINTF ci_log

#define CODEID "cplane(onload)"








#if OO_DO_STACK_POLL




ci_inline int
ci_ip_cache_is_onloadable(ci_netif* ni, ci_ip_cached_hdrs* ipcache)
{
  /* Return true if [ipcache->hwport] can be accelerated by [ni], and also
   * sets [ipcache->intf_i] in that case.
   *
   * [ipcache->hwport] must have a legal value here.
   */
  ci_hwport_id_t hwport = ipcache->hwport;
  ci_assert(hwport == CI_HWPORT_ID_BAD ||
            (unsigned) hwport < CI_CFG_MAX_HWPORTS);
  return (unsigned) hwport < CI_CFG_MAX_HWPORTS &&
    (ipcache->intf_i = __ci_hwport_to_intf_i(ni, hwport)) >= 0;
}

#if CI_CFG_TEAMING
static int
cicp_user_bond_hash_get_hwport(ci_netif* ni, ci_ip_cached_hdrs* ipcache,
                               cicp_hwport_mask_t hwports,
                               ci_uint16 src_port_be16,
                               ci_addr_t daddr)
{
  /* For an active-active bond that uses hashing, choose the appropriate
   * interface to send out of.
   */
  struct cicp_hash_state hs;

  if( src_port_be16 != 0 || ipcache->dport_be16 != 0)
    hs.flags = CICP_HASH_STATE_FLAGS_IS_TCP_UDP | 
      CICP_HASH_STATE_FLAGS_IS_IP;
  else
    hs.flags = CICP_HASH_STATE_FLAGS_IS_IP;
  memcpy(&hs.dst_mac, ci_ip_cache_ether_dhost(ipcache), ETH_ALEN);
  memcpy(&hs.src_mac, ci_ip_cache_ether_shost(ipcache), ETH_ALEN);
  hs.src_addr_be32 = onload_addr_xor(ipcache_laddr(ipcache));
  hs.dst_addr_be32 = onload_addr_xor(daddr);
  hs.src_port_be16 = src_port_be16;
  hs.dst_port_be16 = ipcache->dport_be16;
  ipcache->hwport = oo_cp_hwport_bond_get(ipcache->encap.type, hwports, &hs);
  return ! ci_ip_cache_is_onloadable(ni, ipcache);
}
#endif


static int
__cicp_user_resolve(ci_netif* ni, struct oo_cplane_handle* cp,
                    cicp_verinfo_t* verinfo, struct cp_fwd_key* key,
                    struct cp_fwd_data* data)
{
  /* Note that, for the fwd-table ID, we always pass the ID of the _local_
   * control plane.  This is exactly what we want: if we're speaking to our
   * own control plane, then we want to store the result of the lookup in the
   * local table, and if we're speaking to init_net's control plane, we want
   * the result to go in the table that _we_ have mapped. */
  int rc = __oo_cp_route_resolve(cp, verinfo, key, 1/*ask_server*/, data,
                                 ci_ni_fwd_table_id(ni));

#ifdef __KERNEL__
  ci_assert_impl(ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT,
                 ! (key->flag & CP_FWD_KEY_REQ_WAIT));
  if( !(key->flag & CP_FWD_KEY_REQ_WAIT) && rc < 0 ) {
    /* We've scheduled an addition of this route to the route cache, but we
     * can't sleep for the time when it really happens.  Let's use more
     * direct way to resolve a route. */
    cicp_kernel_resolve(ni, cp, key, data);
    return 0;
  }
#else
  /* There is no reason to call this in UL without WAIT; so we don't. */
  ci_assert(key->flag & CP_FWD_KEY_REQ_WAIT);
#endif
  if( rc < 0 )
    data->base.ifindex = CI_IFID_BAD;
  return rc;
}


int cicp_user_resolve(ci_netif* ni, struct oo_cplane_handle* cp,
                      cicp_verinfo_t* verinfo, ci_uint8 sock_cp_flags,
                      struct cp_fwd_key* key, struct cp_fwd_data* data)
{
  int rc;

  rc = __cicp_user_resolve(ni, cp, verinfo, key, data);
  if( rc != 0 )
    return rc;

  /* Find out the real source address. */
  if( !CI_IPX_ADDR_IS_ANY(key->src) ) {
    /* We MUST use the source address we've asked for.
     * data.base.src and key.src MAY differ if the route cache has
     * the source like 127.0.0.8/29. */
    data->base.src = key->src;
  }
  else if( ! (key->flag & CP_FWD_KEY_SOURCELESS) ) {
    key->src = data->base.src;
    rc = __cicp_user_resolve(ni, cp, verinfo, key, data);
    data->base.src = key->src;
  }
  return rc;
}


int
cicp_user_build_fwd_key(ci_netif* ni, const ci_ip_cached_hdrs* ipcache,
                        const struct oo_sock_cplane* sock_cp, ci_addr_t daddr,
                        int af, struct cp_fwd_key* key)
{
  key->dst = CI_ADDR_SH_FROM_ADDR(daddr);
  key->iif_ifindex = CI_IFID_BAD;
  /* Pass 0 IPv6 tclass value into cp_fwd_key tos field because Linux policy
   * based routing doesn't consider tclass when performing route lookup
   * for TCP and UDP connected send. Though, tclass is considered for UDP
   * unconnected send. As a result, there would be a single fwd entry for all
   * IPv6 tclass values. */
  key->tos = IS_AF_INET6(af) ? 0 : sock_cp->ip_tos;
  key->flag = 0;

  key->ifindex = sock_cp->so_bindtodevice;
  key->src = CI_ADDR_SH_FROM_ADDR(sock_cp->laddr);
  if( CI_IPX_IS_MULTICAST(daddr) ) {
    if( IS_AF_INET6(af) || sock_cp->sock_cp_flags & OO_SCP_NO_MULTICAST )
      return -EHOSTUNREACH;

    /* In linux, SO_BINDTODEVICE has the priority over IP_MULTICAST_IF */
    if( key->ifindex == 0 )
      key->ifindex = sock_cp->ip_multicast_if;
    if( CI_IPX_ADDR_IS_ANY(key->src) )
       key->src = CI_ADDR_SH_FROM_IP4(sock_cp->ip_multicast_if_laddr_be32);
  }
  else {
#if CI_CFG_IPV6
    if( ! IS_AF_INET6(af) && CI_IPX_ADDR_EQ(key->src, addr_sh_any) )
      key->src = ip4_addr_sh_any;
#endif
    if( sock_cp->sock_cp_flags & OO_SCP_TPROXY )
      key->flag |= CP_FWD_KEY_TRANSPARENT;
  }

  /* Source policy routing works differently for IPv6 and IPv4.
   * In IPv4, the source address is used unless OO_SCP_UDP_WILD.
   * In IPv6, the source address is used if OO_SCP_BOUND_ADDR. */
  if( IS_AF_INET6(af) && ! (sock_cp->sock_cp_flags & OO_SCP_BOUND_ADDR) ) {
    key->src = addr_sh_any;
    key->flag |= CP_FWD_KEY_SOURCELESS;
  }
  else if( CI_IPX_ADDR_IS_ANY(key->src) &&
           (sock_cp->sock_cp_flags & OO_SCP_UDP_WILD) ) {
    key->flag |= CP_FWD_KEY_SOURCELESS;
  }

#ifdef __KERNEL__
  if( ! (ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT) )
#endif
    key->flag |= CP_FWD_KEY_REQ_WAIT;

  return 0;
}


void
cicp_user_retrieve(ci_netif*                    ni,
                   ci_ip_cached_hdrs*           ipcache,
                   const struct oo_sock_cplane* sock_cp)
{
  struct cp_fwd_key key;
  struct cp_fwd_data data;
  ci_addr_t daddr = ipcache_raddr(ipcache);
  int af;
  /* Initialise to placate compiler. */
  ci_addr_sh_t pre_nat_laddr = addr_sh_any;
  int /*bool*/ nat_applied = 0;

  /* This function must be called when "the route is unusable".  I.e. when
   * the route is invalid or if there is no ARP.  In the second case, we
   * can expedite ARP resolution by explicit request just now. */
  if( oo_cp_ipcache_is_valid(ni, ipcache) ) {
    ci_assert_equal(ipcache->status, retrrc_nomac);
    oo_cp_arp_resolve(ni->cplane, &ipcache->fwd_ver, ci_ni_fwd_table_id(ni));

    /* Re-check the version of the fwd entry after ARP resolution.
     * Return if nothing changed; otherwise handle the case when ARP has
     * already been resolved. */
    if( oo_cp_ipcache_is_valid(ni, ipcache) )
      return;
  }

  af = CI_IS_ADDR_IP6(daddr) ? AF_INET6 : AF_INET;

  if( cicp_user_build_fwd_key(ni, ipcache, sock_cp, daddr, af, &key) != 0 )
    goto alien_route;

  if( ni->cplane_init_net != NULL &&
      ipcache_protocol(ipcache) == IPPROTO_TCP ) {
    ci_uint16 lport = sock_cp->lport_be16;
    pre_nat_laddr = key.src;
    /* We ignore failure returns from cp_svc_check_dnat().  In the event that
     * it fails, it leaves the address untranslated, which is the best that
     * we can do. */
    nat_applied = cp_svc_check_dnat(ni->cplane_init_net, &key.src, &lport) > 0;
  }
  if( cicp_user_resolve(ni, ni->cplane, &ipcache->fwd_ver,
                        sock_cp->sock_cp_flags, &key, &data) != 0 )
    goto alien_route;

  /* Look at main namespace if this route is across veth. */
  if( data.encap.type & CICP_LLAP_TYPE_ROUTE_ACROSS_NS ) {
    if( ni->cplane_init_net == NULL )
      goto alien_route;
    /* Use the source address from the local namespace data (i.e.
     * data.base.src) in the routing request in the main namespace.  This in
     * turn requires setting RTA_IIF to the incoming veth interface. */
    key.src = data.base.src;
    key.iif_ifindex = data.encap.link_ifindex;
    ipcache->iif_ifindex = key.iif_ifindex;
    /* Note that we do want BAD here, rather than UNUSED.  In the typical case
     * cicp_user_resolve() will set the id field to the row in init_net's fwd
     * table, but if we look up the route by querying the kernel rather than
     * the cplane server, then the field will not be touched. */
    ipcache->fwd_ver_init_net.id = CICP_MAC_ROWID_BAD;
    if( cicp_user_resolve(ni, ni->cplane_init_net, &ipcache->fwd_ver_init_net,
                          sock_cp->sock_cp_flags, &key, &data) != 0 )
      goto alien_route;
  }
  else {
    ipcache->fwd_ver_init_net.id = CICP_MAC_ROWID_UNUSED;
    ipcache->iif_ifindex = CI_IFID_BAD;
  }

  /* IPv6 + !OO_SCP_BOUND_ADDR: set the source address back */
  if( IS_AF_INET6(af) && ! (sock_cp->sock_cp_flags & OO_SCP_BOUND_ADDR) &&
      ! CI_IPX_ADDR_IS_ANY(sock_cp->laddr) )
    data.base.src = CI_ADDR_SH_FROM_ADDR(sock_cp->laddr);

  switch( data.base.ifindex ) {
    case CI_IFID_LOOP:
      ipcache->status = retrrc_localroute;
      ipcache->encap.type = CICP_LLAP_TYPE_NONE;
      ipcache->ether_offset = 4;
      ipcache->intf_i = OO_INTF_I_LOOPBACK;
      ci_ipcache_set_saddr(ipcache, CI_ADDR_FROM_ADDR_SH(data.base.src));
      return;
    case CI_IFID_BAD:
      goto alien_route;
    default:
    {
      cicp_hwport_mask_t hwports = 0;
      /* Can we accelerate interface in this stack ? */
      if( (data.encap.type & CICP_LLAP_TYPE_BOND) == 0 &&
          (data.hwports & ~(ci_netif_get_hwport_mask(ni))) == 0 )
        break;
      /* Check bond */
      if( cicp_user_get_fwd_rx_hwports(ni, &data, &hwports) != 0 ||
          (hwports & ~(ci_netif_get_hwport_mask(ni))) )
        goto alien_route;
      break;
    }
  }

  ipcache->encap = data.encap;
  cicp_ipcache_vlan_set(ipcache);
#if CI_CFG_TEAMING
  if( ipcache->encap.type & CICP_LLAP_TYPE_USES_HASH ) {
    if( cicp_user_bond_hash_get_hwport(ni, ipcache, data.hwports,
                                       sock_cp->lport_be16, daddr) != 0 )
      goto alien_route;
  }
  else
#endif
    ipcache->hwport = cp_hwport_mask_first(data.hwports);

  if( is_sock_cp_pmtu_probe_set(sock_cp, af) ) {
    int rc = oo_cp_find_llap(ni->cplane, data.base.ifindex, &data.base.mtu,
                             NULL, NULL, NULL, NULL);
    if( rc != 0 )
      goto alien_route;
  }
  ipcache->mtu = data.base.mtu;
  /* Use the local address returned by the control plane if we're not doing
   * NAT, but if we are doing NAT, then use the pre-NAT source address.  This
   * doesn't lose any information, as the route lookup only returns a different
   * source address from the key if the latter address in INADDR_ANY or
   * multicast, neither of which can apply if we're NAT-ing. */
  ci_ipcache_set_saddr(ipcache,
                       nat_applied ? CI_ADDR_FROM_ADDR_SH(pre_nat_laddr) :
                                     CI_ADDR_FROM_ADDR_SH(data.base.src));
  ipcache->ifindex = data.base.ifindex;
  ipcache->nexthop = CI_ADDR_FROM_ADDR_SH(data.base.next_hop);
  if( ! ci_ip_cache_is_onloadable(ni, ipcache))
    goto alien_route;

  /* Layout the Ethernet header, and set the source mac.
   * Route resolution already issues ARP request, so there is no need to
   * call oo_cp_arp_resolve() explicitly in case of retrrc_nomac. */
  ipcache->status = (data.flags & CICP_FWD_DATA_FLAG_ARP_VALID) ?
                                        retrrc_success : retrrc_nomac;
  memcpy(ci_ip_cache_ether_shost(ipcache), &data.src_mac, ETH_ALEN);
  if( data.flags & CICP_FWD_DATA_FLAG_ARP_VALID )
    memcpy(ci_ip_cache_ether_dhost(ipcache), &data.dst_mac, ETH_ALEN);

  if( CI_IPX_IS_MULTICAST(daddr) ) {
    ipcache_ttl(ipcache) = IS_AF_INET6(af) ? CI_IPV6_DFLT_MCASTHOPS :
                           sock_cp->ip_mcast_ttl;
  }
  else {
    ci_int16 hlim = sock_cp_ttl_hoplimit(af, sock_cp);
    if( hlim == -1 )
      hlim = data.base.hop_limit;
    ipcache_ttl(ipcache) = hlim;
  }
  return;

 alien_route:
  ipcache->status = retrrc_alienroute;
  ipcache->hwport = CI_HWPORT_ID_BAD;
  ipcache->intf_i = -1;
  return;
}


void
cicp_ip_cache_update_from(ci_netif* ni, ci_ip_cached_hdrs* ipcache,
                          const ci_ip_cached_hdrs* from_ipcache)
{
  /* We can't check the inputs that come from oo_sock_cplane, but this at
   * least gives us a little checking...
   */
  ci_assert_equal(ipcache->dport_be16, from_ipcache->dport_be16);
  ci_assert_addrs_equal(ipcache_raddr(ipcache), ipcache_raddr(from_ipcache));
  ci_assert_addrs_equal(ipcache_laddr(ipcache), ipcache_laddr(from_ipcache));
  ci_assert_equal(ipcache->dport_be16, from_ipcache->dport_be16);
  ci_assert_equal(ipcache_af(ipcache), ipcache_af(from_ipcache));
 
  ipcache_ttl(ipcache) = ipcache_ttl(from_ipcache);
  ipcache->fwd_ver = from_ipcache->fwd_ver;
  ipcache->fwd_ver_init_net = from_ipcache->fwd_ver_init_net;
  ipcache->status = from_ipcache->status;
  ipcache->flags = from_ipcache->flags;
  ipcache->nexthop = from_ipcache->nexthop;
  /* ipcache->pmtus = something; */
  ipcache->mtu = from_ipcache->mtu;
  ipcache->ifindex = from_ipcache->ifindex;
  ipcache->iif_ifindex = from_ipcache->iif_ifindex;
  ipcache->encap = from_ipcache->encap;
  ipcache->intf_i = from_ipcache->intf_i;
  ipcache->hwport = from_ipcache->hwport;
  ipcache->ether_offset = from_ipcache->ether_offset;
  memcpy(ipcache->ether_header, from_ipcache->ether_header,
         sizeof(ipcache->ether_header));
}


int
cicp_ipif_check_ok(struct oo_cplane_handle* cp,
                   ci_ifid_t ifindex, uint8_t scope, void* data)
{
  return 1;
}

int
cicp_ipif_check_scope(struct oo_cplane_handle* cp,
                      ci_ifid_t ifindex, uint8_t scope, void* data)
{
  struct cicp_ipif_check_scope_data* check_scope = data;
  ci_assert_equal(check_scope->op, CICP_IPIF_CHECK_SCOPE_LT);
  return scope < check_scope->scope;
}

int
cicp_llap_check_onloaded(struct oo_cplane_handle* cp,
                         cicp_llap_row_t* llap, void* data)
{
  ci_netif* ni = data;
  return llap->rx_hwports != 0 &&
         (llap->rx_hwports & ~ci_netif_get_hwport_mask(ni)) == 0;
}

/* Call this when ARP resolution failed */
static void
oo_deferred_arp_failed(ci_netif *ni, int af, ci_ip_pkt_fmt* pkt)
{
  CITP_STATS_NETIF_INC(ni, tx_defer_pkt_drop_arp_failed);

  if( pkt->flags & CI_PKT_FLAG_UDP ) {
    ci_udp_state* us = SP_TO_UDP(ni, pkt->pf.udp.tx_sock_id);
    if( is_sockopt_flag_ip_recverr_set(&us->s, af) )
      CI_SET_UDP_SO_ERROR(us, EHOSTUNREACH);
  }
  else if( (TX_PKT_IPX_TCP(af, pkt)->tcp_flags & CI_TCP_FLAG_SYN) &&
           OO_SP_NOT_NULL(pkt->pf.tcp_tx.sock_id) ) {
    citp_waitable_obj* wo = SP_TO_WAITABLE_OBJ(ni, pkt->pf.tcp_tx.sock_id);
    /* For TCP SYN_SENT, we drop the connection */
    if( wo->waitable.state == CI_TCP_SYN_SENT )
      ci_tcp_drop(ni, &wo->tcp, EHOSTUNREACH);
  }

  cicp_pkt_complete_fake(ni, pkt);
}

/* Try to send one deferrred packet.  Returns TRUE if sent. */
int oo_deferred_send_one(ci_netif *ni, struct oo_deferred_pkt* dpkt)
{
  struct oo_cplane_handle *cp =
    dpkt->iif_ifindex == CI_IFID_BAD ? ni->cplane : ni->cplane_init_net;
  struct cp_fwd_data data;
  ci_ip_pkt_fmt* pkt = PKT_CHK(ni, dpkt->pkt_id);
  int rc;

  /* Has anything changed? */
  if( ! (dpkt->flag & OO_DEFERRED_FLAG_FIRST) &&
      oo_cp_verinfo_is_valid(cp, &dpkt->ver, ci_ni_fwd_table_id(ni)) )
    return 0;

  if( ! CICP_MAC_ROWID_IS_VALID(dpkt->ver.id) ) {
    /* The only way to get here is when sending TCP reply from in-kernel
     * code (in the most cases it is about sending SYN-ACK for incoming
     * SYN).  In all the other cases we have a valid verinfo, with policy
     * routing properly applied.
     *
     * In the TCP case and complicated source routing we can do the wrong
     * thing here - but TCP is resistant to packet loss. */
    struct cp_fwd_key key;

    key.dst = CI_ADDR_SH_FROM_ADDR(dpkt->nexthop);
    key.src = CI_ADDR_SH_FROM_ADDR(dpkt->src);
    key.ifindex = dpkt->ifindex;
    /* We just need the MAC address for the nexthop via the ifindex.
     * In case of IPv6, Linux also wants us to provide the source address.
     * Everything else is not meaningful for our purpose: resolve the
     * destination MAC for this next hop. */
    key.iif_ifindex = dpkt->iif_ifindex;
    key.tos = 0;
    key.flag = CP_FWD_KEY_SOURCELESS;
#ifdef __KERNEL__
    if( ! (ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT) )
#endif
      key.flag |= CP_FWD_KEY_REQ_WAIT;

    rc = __oo_cp_route_resolve(cp, &dpkt->ver, &key, 1/*ask_server*/,
                               &data, ci_ni_fwd_table_id(ni));
    if( rc != 0 ) {
      if( key.flag & CP_FWD_KEY_REQ_WAIT ) {
        /* cplane failed to resolve - drop the packet. */
        CITP_STATS_NETIF_INC(ni, tx_defer_pkt_drop_failed);
        cicp_pkt_complete_fake(ni, pkt);
        return 1;
      }
      dpkt->flag &=~ OO_DEFERRED_FLAG_FIRST;
      return 0;
    }
  }
  else {
    /* Update the route data.
     * Unlike the previous branch, nobody is calling `oo_cp_arp_resolve()`
     * again.  We rely on ARP resolution initiated when
     * __oo_cp_route_resolve() was called for the first time. */
    struct cp_fwd_row* fwd = cp_get_fwd_by_id(
                                oo_cp_get_fwd_table(cp, ci_ni_fwd_table_id(ni)),
                                dpkt->ver.id);
    do {
      dpkt->ver.version = OO_ACCESS_ONCE(*cp_fwd_version(fwd));
      data = *cp_get_fwd_data_current(fwd);
      if( !(fwd->flags & CICP_FWD_FLAG_OCCUPIED) ) {
        /* Mark data as invalid and break out */
        data.base.ifindex = 0;
        break;
      }
    } while( dpkt->ver.version != OO_ACCESS_ONCE(*cp_fwd_version(fwd)) );
  }

  /* Check next hop and ifindex, drop dpkt if they have changed.
   * We do not check the source address because we do not really care;
   * we need it to for correct key.src above only. */
  if( data.base.ifindex != dpkt->ifindex || data.hwports == 0 ||
      ! CI_IPX_ADDR_EQ(dpkt->nexthop,
                       CI_ADDR_FROM_ADDR_SH(data.base.next_hop)) ) {
    CITP_STATS_NETIF_INC(ni, tx_defer_pkt_drop_failed);
    cicp_pkt_complete_fake(ni, pkt);
    return 1;
  }

  if( data.flags & CICP_FWD_DATA_FLAG_ARP_FAILED ) {
    if( dpkt->flag & OO_DEFERRED_FLAG_FIRST ) {
      /* Do not trust ARP_FAILED without re-resolving.  We've already
       * kicked the ARP resolution via __oo_cp_route_resolve(); we should
       * wait for it.
       * In the worst case we'll fail to re-resolve without any visible
       * transition in the fwd entry, and will drop this packet because of
       * timeout. */
      dpkt->flag &=~ OO_DEFERRED_FLAG_FIRST;
      return 0;
    }
    oo_deferred_arp_failed(ni,
                           dpkt->flag & OO_DEFERRED_FLAG_IS_IPV6 ?
                                                        AF_INET6 : AF_INET,
                           pkt);
    return 1;
  }
  if( ! (data.flags & CICP_FWD_DATA_FLAG_ARP_VALID) ) {
    dpkt->flag &=~ OO_DEFERRED_FLAG_FIRST;
    return 0;
  }

  /* Move all that header to the packet */
  memcpy(oo_tx_ether_hdr(pkt)->ether_dhost, data.dst_mac, ETH_ALEN);
  memcpy(oo_tx_ether_hdr(pkt)->ether_shost, data.src_mac, ETH_ALEN);
  /* And send! */
  __ci_netif_send(ni, pkt);
  CITP_STATS_NETIF_INC(ni, tx_defer_pkt_sent);
  return 1;
}

/* Try to send all deferrred packets.  Returns TRUE if all sent. */
int oo_deferred_send(ci_netif *ni)
{
  int ret = 1;
  struct oo_p_dllink_state deferred_list =
                    oo_p_dllink_ptr(ni, &ni->state->deferred_list);
  struct oo_p_dllink_state l, tmp;

  ci_assert(ci_netif_is_locked(ni));

  oo_p_dllink_for_each_safe(ni, l, tmp, deferred_list) {
    struct oo_deferred_pkt* dpkt = CI_CONTAINER(struct oo_deferred_pkt,
                                                link, l.l);
    int handled = oo_deferred_send_one(ni, dpkt);

    if( handled ||
        TIME_GT(ci_ip_time_now(ni),
                dpkt->ts + NI_CONF(ni).tconst_defer_arp) ) {
      if( ! handled ) {
        /* Not handled, but timed out.  Call TX complete callback. */
        CITP_STATS_NETIF_INC(ni, tx_defer_pkt_drop_timeout);
        cicp_pkt_complete_fake(ni, PKT_CHK(ni, dpkt->pkt_id));
      }
      oo_p_dllink_del(ni, l);
      oo_p_dllink_add(ni, oo_p_dllink_ptr(ni,
                                &ni->state->deferred_list_free), l);
    }
    else {
      ret = 0;
    }
  }

  return ret;
}

#endif
