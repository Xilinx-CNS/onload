/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_arp.h>
#include <libmnl/libmnl.h>

#include "cplane_unit.h"
#include <ci/efhw/common.h>
#include <cplane/ioctl.h>


static struct nlmsghdr*
build_nl_link_msg_base(char* buf, uint16_t nlmsg_type, int ifindex,
		       int peer_ifindex, const char* name, const char* mac)
{
  struct nlmsghdr* nlh;
  struct ifinfomsg* ifm;

  /* Build the generic header, indicating that this is a link message. */
  nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = nlmsg_type;
  nlh->nlmsg_pid = 0;
  nlh->nlmsg_seq = 0;

  ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(*ifm));
  ifm->ifi_family = AF_INET;
  ifm->ifi_type = ARPHRD_ETHER;
  ifm->ifi_change = 0;
  ifm->ifi_flags = IFF_UP;
  ifm->ifi_index = ifindex;

  mnl_attr_put_strz(nlh, IFLA_IFNAME, name);
  mnl_attr_put(nlh, IFLA_ADDRESS, 6, mac);
  mnl_attr_put_u32(nlh, IFLA_MTU, 1500);

  if( peer_ifindex != 0 ) {
    mnl_attr_put_u32(nlh, IFLA_LINK, peer_ifindex);
  }

  return nlh;
}


/* This function fabricates a netlink message simulating the message that the
 * kernel generates to describe the properties of a network interface, and
 * passes it to the control plane. */
void
cp_unit_nl_handle_link_msg(struct cp_session* s, uint16_t nlmsg_type,
                           int ifindex, cicp_hwport_mask_t hwports,
                           const char* name, const char* mac)
{
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr* nlh = build_nl_link_msg_base(buf, nlmsg_type, ifindex, 0,
						name, mac);

  /* Pass the message to the control plane. */
  cp_nl_net_handle_msg(s, nlh, nlh->nlmsg_len);

  /* Tell the control plane that this llap has hwport(s). */
  for( ; hwports; hwports &= (hwports - 1) ) {
    ci_hwport_id_t hwport = cp_hwport_mask_first(hwports);
    cp_populate_llap_hwports(s, ifindex, hwport, (ci_uint64) -1);
  }
}


static void nl_link_msg_add_kind(struct nlmsghdr* nlh, const char* kind)
{
  struct nlattr* nest = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
  mnl_attr_put(nlh, IFLA_INFO_KIND, strlen(kind), kind);
  mnl_attr_nest_end(nlh, nest);
}


/* Like cp_unit_nl_handle_link_msg(), but additionally marks the interface with
 * an IFLA_INFO_KIND attribute. */
static void
cp_unit_nl_handle_link_msg_with_kind(struct cp_session* s, uint16_t nlmsg_type,
		                     int ifindex, int peer_ifindex,
                                     const char* name, const char* mac,
                                     const char* kind)
{
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr* nlh = build_nl_link_msg_base(buf, nlmsg_type, ifindex,
						peer_ifindex, name, mac);
  nl_link_msg_add_kind(nlh, kind);

  /* Pass the message to the control plane. */
  cp_nl_net_handle_msg(s, nlh, nlh->nlmsg_len);
}


/* Like cp_unit_nl_handle_link_msg(), but additionally marks the interface as
 * being a macvlan on top of the specified base interface. */
void
cp_unit_nl_handle_macvlan_link_msg(struct cp_session* s, uint16_t nlmsg_type,
		                   int ifindex, const char* name,
				   const char* mac, int link_ifindex)
{
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr* nlh = build_nl_link_msg_base(buf, nlmsg_type, ifindex, 0,
						name, mac);
  nl_link_msg_add_kind(nlh, "macvlan");
  mnl_attr_put_u32(nlh, IFLA_LINK, link_ifindex);

  /* Pass the message to the control plane. */
  cp_nl_net_handle_msg(s, nlh, nlh->nlmsg_len);
}


/* Like cp_unit_nl_handle_link_msg(), but additionally marks the interface as
 * being a veth. */
void
cp_unit_nl_handle_veth_link_msg(struct cp_session* s, uint16_t nlmsg_type,
                                int ifindex, int peer_ifindex, const char* name,
                                const char* mac)
{
  return cp_unit_nl_handle_link_msg_with_kind(s, nlmsg_type, ifindex,
                                              peer_ifindex, name, mac, "veth");
}


/* Like cp_unit_nl_handle_link_msg(), but additionally marks the interface as
 * being a teaming master. */
void
cp_unit_nl_handle_team_link_msg(struct cp_session* s, uint16_t nlmsg_type,
		                int ifindex, const char* name, const char* mac)
{
  cp_unit_nl_handle_link_msg_with_kind(s, nlmsg_type, ifindex, 0, name, mac,
				       "team");
}


/* Like cp_unit_nl_handle_link_msg(), but additionally marks the interface as
 * being a teaming slave. */
void
cp_unit_nl_handle_teamslave_link_msg(struct cp_session* s, uint16_t nlmsg_type,
		                     int ifindex, const char* name,
				     const char* mac)
{
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr* nlh = build_nl_link_msg_base(buf, nlmsg_type, ifindex, 0,
						name, mac);

  mnl_attr_put(nlh, IFLA_INFO_SLAVE_KIND, 4, "team");

  /* Pass the message to the control plane. */
  cp_nl_net_handle_msg(s, nlh, nlh->nlmsg_len);
}


/* This function fabricates a netlink message simulating the message that the
 * kernel generates in response to the addition or resolution of a route, and
 * passes it to the control plane. */
void
cp_unit_nl_handle_route_msg(struct cp_session* s, in_addr_t dest,
			    int dest_prefix, in_addr_t src,
			    in_addr_t src_prefix, in_addr_t pref_src,
			    in_addr_t gateway, int ifindex, int iif_ifindex,
			    uint32_t nlmsg_pid, uint32_t nlmsg_seq)
{
  struct nlmsghdr* nlh;
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct rtmsg* rtm;

  CP_TEST(ifindex != 0);

  /* Build the generic header, indicating that this is a route message. */
  nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = RTM_NEWROUTE;
  nlh->nlmsg_pid = nlmsg_pid;
  nlh->nlmsg_seq = nlmsg_seq;

  /* Allocate and populate the rtmsg header. */
  rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
  rtm->rtm_family = AF_INET;
  rtm->rtm_dst_len = dest_prefix;
  rtm->rtm_src_len = 0;
  rtm->rtm_tos = 0;
  rtm->rtm_protocol = RTPROT_STATIC;
  rtm->rtm_table = RT_TABLE_MAIN;
  rtm->rtm_type = RTN_UNICAST;
  rtm->rtm_scope = gateway != 0 ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;

  /* Append rtmsg attributes. */
  if( dest != 0 )
    mnl_attr_put_u32(nlh, RTA_DST, dest);
  if( src != 0 )
    mnl_attr_put_u32(nlh, RTA_SRC, src);
  if( pref_src != 0 )
    mnl_attr_put_u32(nlh, RTA_PREFSRC, pref_src);
  if( gateway != 0 )
    mnl_attr_put_u32(nlh, RTA_GATEWAY, gateway);
  if( iif_ifindex != 0 )
    mnl_attr_put_u32(nlh, RTA_IIF, iif_ifindex);
  mnl_attr_put_u32(nlh, RTA_OIF, ifindex);

  /* Pass the message to the control plane. */
  cp_nl_net_handle_msg(s, nlh, nlh->nlmsg_len);
}


/* This function fabricates a netlink message simulating the message
 * that the kernel generates in response to the addition or removal of
 * a neighbour, and passes it to the control plane. */
void
cp_unit_nl_handle_neigh_msg(struct cp_session* s, int ifindex, int type,
                            int state, in_addr_t dest, const uint8_t* macaddr,
                            int reachable_ms, uint32_t nlmsg_pid,
                            uint32_t nlmsg_seq)
{
  struct nlmsghdr* nlh;
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct ndmsg* ndm;

  CP_TEST(ifindex != 0);

  /* Build the generic header, indicating that this is a route message. */
  nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = type;
  nlh->nlmsg_pid = nlmsg_pid;
  nlh->nlmsg_seq = nlmsg_seq;

  /* Allocate and populate the ndmsg header. */
  ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
  ndm->ndm_family = AF_INET;
  ndm->ndm_ifindex = ifindex;
  ndm->ndm_state = state;
  ndm->ndm_flags = 0; /* not presently used by cplane */
  ndm->ndm_type = 0; /* not presently used by cplane */

  /* Append ndmsg attributes. */
  if( dest != 0 )
    mnl_attr_put_u32(nlh, NDA_DST, dest);

  if( macaddr != 0 )
    mnl_attr_put(nlh, NDA_LLADDR, 6, macaddr);

  if( reachable_ms != 0 ) {
    struct nda_cacheinfo cacheinfo = {
      .ndm_confirmed = reachable_ms,
      /* other fields not presently used by cplane */
    };

    mnl_attr_put(nlh, NDA_CACHEINFO, sizeof(struct nda_cacheinfo), &cacheinfo);
  }

  /* Pass the message to the control plane. */
  cp_nl_net_handle_msg(s, nlh, nlh->nlmsg_len);
}


/* This function fabricates a netlink message simulating the message
 * that the kernel generates to describe the properties of an IP address
 * associated with an interface, and passes it to the control plane. */
void
cp_unit_nl_handle_addr_msg(struct cp_session* s, in_addr_t laddr, int ifindex,
                           int prefixlen, int scope)
{
  struct nlmsghdr* nlh;
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct ifaddrmsg *ifmsg;

  CP_TEST(ifindex != 0);

  /* Build the generic header, indicating that this is a route message. */
  nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = RTM_NEWADDR;

  /* Allocate and populate the ifmsg header. */
  ifmsg = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));
  ifmsg->ifa_family = AF_INET;
  ifmsg->ifa_index = ifindex;
  ifmsg->ifa_prefixlen = prefixlen;
  ifmsg->ifa_scope = scope;

  mnl_attr_put_u32(nlh, IFA_LOCAL, laddr);

  /* Pass the message to the control plane. */
  cp_nl_net_handle_msg(s, nlh, nlh->nlmsg_len);
}


int cp_unit_cplane_ioctl(int fd, long unsigned int op, ...)
{
  void* arg __attribute__((unused));
  va_list va;
  va_start(va, op);
  arg = (void*)va_arg(va, long);
  va_end(va);

  switch( op ) {
    case OO_IOC_CP_READY:
    case OO_IOC_CP_ARP_RESOLVE:
    case OO_IOC_CP_CHECK_VETH_ACCELERATION:
    case OO_IOC_CP_DUMP_HWPORTS:
    case OO_IOC_OOF_CP_IP_MOD:
      return 0;
  }
  ci_assert(! "No ioctl ops into onload expected");
  ci_unreachable();
}

extern int cplane_ioctl(int, long unsigned int, ...)
    __attribute__ ((alias ("cp_unit_cplane_ioctl")));


int oo_fd_open(int fd, long unsigned int op, ...)
{
  ci_assert(! "No calls to oo_fd_open ops expected");
  ci_unreachable();
}

