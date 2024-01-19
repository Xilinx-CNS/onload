/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  Control Plane resolution protocol kernel code
**   \date  2005/07/18
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/



/*! The code in this file is relevant only to the kernel - it is not visible
 *  from the user-mode libraries.
 *
 *  This code is specific to the handling address resolution protocols in
 *  the control plane.
 */


/*****************************************************************************
 *                                                                           *
 *          Headers                                                          *
 *          =======							     *
 *                                                                           *
 *****************************************************************************/


#include "onload_internal.h"
#include "onload/cplane_ops.h"
#include "onload/debug.h"
#include <ci/net/arp.h>
#include <etherfabric/checksum.h>


#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif




/*****************************************************************************
 *                                                                           *
 *          Configuration                                                    *
 *          =============						     *
 *                                                                           *
 *****************************************************************************/



#define CODEID "cplane prot"



/*****************************************************************************
 *                                                                           *
 *          Debugging                                                        *
 *          =========							     *
 *                                                                           *
 *****************************************************************************/



#define DO(_x) _x
#define IGNORE(_x)


/* #define FORCEDEBUG */ /* include debugging even in NDEBUG builds */

#define DPRINTF ci_log


/*****************************************************************************
 *****************************************************************************
 *									     *
 *          PROT - Raw Socket Synchronization				     *
 *          =================================				     *
 *									     *
 *****************************************************************************
 *****************************************************************************/






/*! create the raw socket */
static int cicp_raw_sock_ctor(int family, struct socket **raw_sock)
{
  int rc = sock_create(family, SOCK_RAW, IPPROTO_RAW, raw_sock);
  if (CI_UNLIKELY(rc < 0)) {
    ci_log("%s: failed to create the raw socket, rc=%d", __FUNCTION__, rc);
    return rc;
  }
  
  if (CI_UNLIKELY((*raw_sock)->sk == 0)) {
    ci_log("ERROR:%s: cicp_raw_sock->sk is zero!", __FUNCTION__);
    sock_release(*raw_sock);
    return -EINVAL;
  }

  (*raw_sock)->sk->sk_allocation = GFP_ATOMIC;
  return 0;
}





/*! destroy the raw socket */
static void cicp_raw_sock_dtor(struct socket *raw_sock)
{
  sock_release(raw_sock);
}





static int
cicp_raw_sock_send(struct socket *raw_sock, int ifindex,
                   ci_addr_t saddr, ci_addr_t daddr,
                   const void* buf, unsigned int size)
{
  struct msghdr msg;
  struct kvec iov;
  struct sockaddr_storage daddr_ss;
#if CI_CFG_IPV6
  char cmsg_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#endif
  int rc;

  daddr_ss = ci_make_sockaddr_storage_from_addr(0, daddr);

  msg.msg_name = &daddr_ss;
  msg.msg_namelen = sizeof(daddr_ss);
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = MSG_DONTWAIT;

#if CI_CFG_IPV6
  /*
   * IPv6 wants to know the local IP to create a correct neighbour solicitation.
   * If not set, route lookup in sendmsg() would fail with ENETUNREACH error.
   */
  if( CI_IS_ADDR_IP6(saddr) ) {
    struct cmsghdr *cmsg;
    struct in6_pktinfo *pktinfo;
    struct sockaddr_storage saddr_ss;

    saddr_ss = ci_make_sockaddr_storage_from_addr(0, saddr);

    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(*pktinfo));

    pktinfo = (struct in6_pktinfo *) CMSG_DATA(cmsg);
    memset(pktinfo, 0, sizeof(*pktinfo));
    pktinfo->ipi6_addr = ((struct sockaddr_in6*)&saddr_ss)->sin6_addr;
    pktinfo->ipi6_ifindex = ifindex;
  }
#endif

  iov.iov_base = (void*) buf;
  iov.iov_len  = size;

  rc = kernel_sendmsg(raw_sock, &msg, &iov, 1, size);

  return rc;
}



static int
cicp_raw_sock_send_bindtodev(struct oo_cplane_handle* cp, int ifindex,
                             int af, ci_addr_t saddr, ci_addr_t daddr,
                             const void* buf, unsigned int size)
{
  struct cicppl_instance* cppl = &cp->cppl;
  struct net_device* dev = NULL;
  int rc;
  char* ifname;
  const struct cred *orig_creds;
  struct cred *my_creds = NULL; /* appease gcc from RHEL6 */
  struct socket* sock;

#if CI_CFG_IPV6
  if( af == AF_INET6 ) {
    sock = cppl->bindtodev_raw_sock_ip6;
  }
  else
#endif
  {
    sock = cppl->bindtodev_raw_sock;
  }

  if( ifindex != cppl->bindtodevice_ifindex ) {
    dev = dev_get_by_index(cppl->cp->cp_netns, ifindex);
    if( dev != NULL ) 
      ifname = dev->name;
    else {
      OO_DEBUG_ARP(ci_log("%s: bad net device index %d", __FUNCTION__,
                          ifindex));
      return -EINVAL;
    }

    orig_creds = oo_cplane_empower_cap_net_raw(cp->cp_netns, &my_creds);
#ifndef EFRM_HAS_SOCKPTR
    {
      mm_segment_t oldfs = get_fs();
      set_fs(KERNEL_DS);
      rc = sock_setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
                         ifname, strlen(ifname));
      set_fs(oldfs);
    }
#else
    rc = sock_setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
                         KERNEL_SOCKPTR(ifname), strlen(ifname));
#endif
    oo_cplane_drop_cap_net_raw(orig_creds, my_creds);

    if( dev != NULL )
      dev_put(dev);

    if( rc != 0 ) {
      OO_DEBUG_ARP(ci_log("%s: failed to BINDTODEVICE %d", __FUNCTION__, rc));
      return rc;
    }

    cppl->bindtodevice_ifindex = ifindex;
  }

  return cicp_raw_sock_send(sock, ifindex, saddr, daddr, buf, size);
}



/*****************************************************************************
 *                                                                           *
 *          Deferred packet transmission                                     *
 *          ============================                                     *
 *                                                                           *
 *****************************************************************************/




int cicp_raw_ip_send(struct oo_cplane_handle* cp, int af,
                     ci_ipx_hdr_t* ipx, int len, ci_ifid_t ifindex,
                     ci_addr_t next_hop)
{
  void* ipx_data = ci_ipx_data_ptr(af, ipx);
  ci_tcp_hdr* tcp;
  ci_udp_hdr* udp;
  int l4paylen;

  switch( ipx_hdr_protocol(af, ipx) ) {
  case IPPROTO_TCP:
    if( af == AF_INET )
      ci_assert_equal(ipx->ip4.ip_frag_off_be16, CI_IP4_FRAG_DONT);
    tcp = ipx_data;
    l4paylen = len - CI_IPX_IHL(af, ipx) - CI_TCP_HDR_LEN(tcp);
    tcp->tcp_check_be16 = ef_tcp_checksum_ipx_buf(af, ipx_hdr_ptr(af, ipx),
                                                  (struct tcphdr*)tcp,
                                                  CI_TCP_PAYLOAD(tcp),
                                                  l4paylen);
    break;
  case IPPROTO_UDP:
  {
    /* In case of fragmented UDP packet we have already calculated checksum */
    if( ci_ipx_is_frag(af, ipx) )
      break;
    udp = ipx_data;
    l4paylen = len - CI_IPX_IHL(af, ipx) - sizeof(ci_udp_hdr);
    udp->udp_check_be16 = ef_udp_checksum_ipx_buf(af, ipx_hdr_ptr(af, ipx),
                                                  (struct udphdr*)udp,
                                                  CI_UDP_PAYLOAD(udp),
                                                  l4paylen);
    break;
  }
  }

  ci_assert(!CI_IPX_ADDR_IS_ANY(next_hop));
  ci_assert_ge(ifindex, 1);

  return cicp_raw_sock_send_bindtodev(cp, ifindex, af, ipx_hdr_saddr(af, ipx),
                                      next_hop, ipx, len);
}



/*****************************************************************************
 *                                                                           *
 *          Packet Buffer Pool                                               *
 *          ==================	  				             *
 *                                                                           *
 *****************************************************************************/





#include <ci/tools/istack.h>


#define CICPPL_PKTBUF_SIZE                                      \
  (sizeof(struct cicp_bufpool_pkt) + CI_MAX_ETH_FRAME_LEN)


#define cicp_bufset_ptr(ref_bufset, id) \
        ((char *)(*(ref_bufset)) + (CICPPL_PKTBUF_SIZE * (id)))





/*****************************************************************************
 *                                                                           *
 *          O/S-specific Synchronization Overall Operation                   *
 *          ==============================================                   *
 *                                                                           *
 *****************************************************************************/






/*! Initialize any driver-global O/S specific protocol control plane state */
int /* rc */
cicpplos_ctor(struct cicppl_instance* cppl)
{  
  int rc;
    
  /* cicp_raw_sock_ctor() calls sock_create(), which uses
   * current->nsproxy->net_ns.  We expect that we are called in the right
   * namespace. */
  ci_assert_equal(current->nsproxy->net_ns, cppl->cp->cp_netns);

  /* construct raw socket */
  if (CI_UNLIKELY((rc =
      cicp_raw_sock_ctor(PF_INET, &cppl->bindtodev_raw_sock)) < 0)) {
    ci_log(CODEID": ERROR - couldn't construct raw socket module, rc=%d",
           -rc);
    return rc;
  } 
#if CI_CFG_IPV6
  if (CI_UNLIKELY((rc =
      cicp_raw_sock_ctor(PF_INET6, &cppl->bindtodev_raw_sock_ip6)) < 0)) {
    ci_log(CODEID": ERROR - couldn't construct IP6 raw socket module, rc=%d",
           -rc);
    cicp_raw_sock_dtor(cppl->bindtodev_raw_sock);
    return rc;
  }
#endif
  cppl->bindtodevice_ifindex = 0; /* invalid ifindex */

  return 0;
}


/*! Finalize any driver-global O/S specific protocol control plane state */
void
cicpplos_dtor(struct cicppl_instance *cppl)
{
  if( cppl->bindtodev_raw_sock != NULL )
    cicp_raw_sock_dtor(cppl->bindtodev_raw_sock);
#if CI_CFG_IPV6
  if( cppl->bindtodev_raw_sock_ip6 != NULL )
    cicp_raw_sock_dtor(cppl->bindtodev_raw_sock_ip6);
#endif
}


