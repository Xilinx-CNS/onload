/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2016-2020 Xilinx, Inc. */
/* Cplane related functions which are part of Onload */
#ifndef __ONLOAD_CPLANE_OPS_H__
#define __ONLOAD_CPLANE_OPS_H__

#include <ci/internal/ip.h>

#ifndef __KERNEL__
#include <onload/unix_intf.h>
#endif

#ifdef __KERNEL__

#include <onload/cplane_modparam.h>

#define CICP_HANDLE(netif) (&CI_GLOBAL_CPLANE)

#else

#define CICP_HANDLE(netif) ((netif)->cplane)

#endif

#ifdef CI_USE_GCC_VISIBILITY
#pragma GCC visibility push(default)
#endif

/*!
 * Establish forwarding information.
 *
 * \param ni       The Onload stack
 * \param ipcache  The cached forwarding state
 * \param sock_cp  Per-socket inputs to the lookup
 *
 * Return value is in [ipcache->status], which will either be a value from
 * [cicpos_retrieve_rc_t], or -ve, in which case it is an error code.  The
 * -ve errors relate to the mac lookup, so imply that the route can be
 * accelerated.
 *
 *    retrrc_success: Can accelerate, and all forwarding info was valid
 *                    just before return.
 *
 *      retrrc_nomac: Can accelerate route, but do not currently have
 *                    destination MAC.  Per-route info other than the
 *                    outgoing interface is valid.
 *
 *    retrrc_noroute: No route to destination.
 *
 * retrrc_alienroute: Can't be accelerated.
 */
extern void
cicp_user_retrieve(ci_netif*                    ni,
                   ci_ip_cached_hdrs*           ipcache,
                   const struct oo_sock_cplane* sock_cp) CI_HF;

extern int
cicp_user_resolve(ci_netif* ni, struct oo_cplane_handle* cp,
                  cicp_verinfo_t* verinfo, ci_uint8 sock_cp_flags,
                  struct cp_fwd_key* key, struct cp_fwd_data* data) CI_HF;

/*! Update forwarding and mac info of [ipcache] from [from_ipcache].
 *
 * NB. This function does not take a complete copy of [from_ipcache].  It
 * only takes the fields that are updated by control plane lookup.  These
 * include:
 *
 * - fwd_ver
 * - freshness (invalidated)
 * - ip_saddr_be32
 * - status
 * - pmtus (invalidated)
 * - mtu
 * - ifindex
 * - intf_i
 * - hwport
 * - ether_offset
 * - mac addresses + vlan header
 */
extern void
cicp_ip_cache_update_from(ci_netif* ni, ci_ip_cached_hdrs* ipcache,
                          const ci_ip_cached_hdrs* from_ipcache);



ci_inline void
cicp_ipcache_vlan_set(ci_ip_cached_hdrs*  ipcache)
{
  if( ipcache->encap.type & CICP_LLAP_TYPE_VLAN ) {
    ci_uint16* vlan_tag = (ci_uint16*) ipcache->ether_header + 6;
    vlan_tag[0] = CI_ETHERTYPE_8021Q;
    vlan_tag[1] = CI_BSWAP_BE16(ipcache->encap.vlan_id);
    ipcache->ether_offset = 0;
  }
  else {
    ipcache->ether_offset = ETH_VLAN_HLEN;
  }
}

extern int
cicp_ipif_check_ok(struct oo_cplane_handle* cp,
                   ci_ifid_t ifindex, uint8_t scope, void* data);

extern int
cicp_llap_check_onloaded(struct oo_cplane_handle* cp,
                         cicp_llap_row_t* llap, void* data);
/*! Checks if the given ip address is both local and etherfabric.
 *  Returns 1 if it is, 0 if it isn't.
 *  If the address isn't found, it returns 0
 */
ci_inline int
cicp_user_addr_is_local_efab(ci_netif* ni, ci_addr_t ip)
{ 
#if CI_CFG_IPV6
  if( CI_IS_ADDR_IP6(ip) ) {
    return oo_cp_find_llap_by_ip6(ni->cplane, ip.ip6,
                                  cicp_ipif_check_ok, NULL,
                                  cicp_llap_check_onloaded, ni);
  }
  else
#endif
  return oo_cp_find_llap_by_ip(ni->cplane, ip.ip4,
                               cicp_ipif_check_ok, NULL,
                               cicp_llap_check_onloaded, ni);
}


static inline int/*bool*/
cicp_find_ifindex_by_ip(struct oo_cplane_handle* cp, ci_addr_t ip,
                        oo_cp_ifindex_check check, void* data)
{
#if CI_CFG_IPV6
  if( CI_IS_ADDR_IP6(ip) )
    return oo_cp_find_ipif_by_ip6(cp, ip.ip6, check, data);
#endif
  return oo_cp_find_ipif_by_ip(cp, ip.ip4, check, data);
}


ci_inline int /* bool */
cicp_user_is_local_addr(struct oo_cplane_handle *cplane, ci_addr_t ip)
{
  return cicp_find_ifindex_by_ip(cplane, ip, cicp_ipif_check_ok, NULL);
}


/* Try to send one deferred packet.  Returns TRUE if sent. */
extern int oo_deferred_send_one(ci_netif *ni, struct oo_deferred_pkt* dpkt);
/* Try to send all deferred packets.  Returns TRUE if all sent. */
extern int oo_deferred_send(ci_netif *ni);


extern int
cicp_user_build_fwd_key(ci_netif* ni, const ci_ip_cached_hdrs* ipcache,
                        const struct oo_sock_cplane* sock_cp, ci_addr_t daddr,
                        int af, struct cp_fwd_key* key);

/* Given the result of a route lookup, find the _RX_ hwports associated with
 * the egress interface.  This is a bizarre thing to want to know on the face
 * of it, but there are two use-cases:
 *   - bonds with no active slaves are still acceleratable iff they have a
 *     non-empty set of RX hwports, and
 *   - joining a multicast group by doing a route-lookup requires a map to the
 *     RX hwports as the final step.
 */
static inline int
cicp_user_get_fwd_rx_hwports(ci_netif* ni, const struct cp_fwd_data* data,
                             cicp_hwport_mask_t* hwports_out)
{
  return oo_cp_find_llap(ni->cplane, data->base.ifindex, NULL /*mtu*/,
                         NULL /*tx_hwports*/, hwports_out /*rx_hwports*/,
                         NULL /*mac*/, NULL /*encap*/);
}


/*----------------------------------------------------------------------------
 * Control Plane initialization/termination 
 *---------------------------------------------------------------------------*/


#ifdef __ci_driver__

/*! Send IP packet via RAW socket.  Computes TCP/UDP checksum if possible */
extern int cicp_raw_ip_send(struct oo_cplane_handle* cp, int af,
                            ci_ipx_hdr_t* ipx, int len, ci_ifid_t ifindex,
                            ci_addr_t next_hop);

#ifdef CI_USE_GCC_VISIBILITY
#pragma GCC visibility pop
#endif

#endif
#endif /* __ONLOAD_CPLANE_OPS_H__ */
