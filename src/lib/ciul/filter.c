/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
 *//*! \file
   ** <L5_PRIVATE L5_SOURCE>
   ** \author  
   **  \brief  
   **   \date  
   **    \cop  (c) Level 5 Networks Limited.
   ** </L5_PRIVATE>
   *//*
       \**************************************************************************/
  
/*! \cidoxg_lib_ef */
#include <etherfabric/vi.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"
#include <stdbool.h>
#include <netinet/ether.h>


enum ef_filter_type {
  EF_FILTER_MAC                 = 0x1,
  EF_FILTER_IP4                 = 0x2,
  EF_FILTER_ALL_UNICAST         = 0x4,
  EF_FILTER_ALL_MULTICAST       = 0x8,
  EF_FILTER_VLAN                = 0x10,
  EF_FILTER_MISMATCH_UNICAST    = 0x20,
  EF_FILTER_MISMATCH_MULTICAST  = 0x40,
  EF_FILTER_PORT_SNIFF          = 0x80,
  EF_FILTER_BLOCK_KERNEL        = 0x100,
  EF_FILTER_BLOCK_KERNEL_UNICAST  = 0x200,
  EF_FILTER_BLOCK_KERNEL_MULTICAST  = 0x400,
  EF_FILTER_TX_PORT_SNIFF       = 0x800,
  EF_FILTER_IP_PROTO            = 0x1000,
  EF_FILTER_ETHER_TYPE          = 0x2000,
  EF_FILTER_IP6                 = 0x4000,
};


/**********************************************************************
 * Initialise filter specs.
 */

void ef_filter_spec_init(ef_filter_spec *fs,
			 enum ef_filter_flags flags)
{
  fs->type = 0;
  fs->flags = flags;
}


int ef_filter_spec_set_ip4_local(ef_filter_spec *fs, int protocol,
				 unsigned host_be32, int port_be16)
{
  if (fs->type != 0 && fs->type != EF_FILTER_VLAN)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_IP4;
  fs->data[0] = protocol;
  fs->data[1] = host_be32;
  fs->data[2] = port_be16;
  fs->data[3] = 0;
  fs->data[4] = 0;
  return 0;
}


int ef_filter_spec_set_ip4_full(ef_filter_spec *fs, int protocol,
				unsigned host_be32, int port_be16,
				unsigned rhost_be32, int rport_be16)
{
  if (fs->type != 0 && fs->type != EF_FILTER_VLAN)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_IP4;
  fs->data[0] = protocol;
  fs->data[1] = host_be32;
  fs->data[2] = port_be16;
  fs->data[3] = rhost_be32;
  fs->data[4] = rport_be16;
  return 0;
}


int ef_filter_spec_set_ip6_local(ef_filter_spec *fs, int protocol,
				 const struct in6_addr *host, int port_be16)
{
  if (fs->type != 0 && fs->type != EF_FILTER_VLAN)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_IP6;
  fs->data[0] = protocol;
  memcpy(&fs->data[1], host, 16);
  /* data[5] is reserved for a VLAN ID */
  fs->data[6] = port_be16;
  memset(&fs->data[7], 0, 16);
  fs->data[11] = 0;
  return 0;
}


int ef_filter_spec_set_ip6_full(ef_filter_spec *fs, int protocol,
				const struct in6_addr *host, int port_be16,
				const struct in6_addr *rhost, int rport_be16)
{
  if (fs->type != 0 && fs->type != EF_FILTER_VLAN)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_IP6;
  fs->data[0] = protocol;
  memcpy(&fs->data[1], host, 16);
  /* data[5] is reserved for a VLAN ID */
  fs->data[6] = port_be16;
  memcpy(&fs->data[7], rhost, 16);
  fs->data[11] = rport_be16;
  return 0;
}


int ef_filter_spec_set_vlan(ef_filter_spec *fs, int vlan_id)
{
  if (fs->type != 0 && fs->type != EF_FILTER_IP4 &&
      fs->type != EF_FILTER_MISMATCH_MULTICAST &&
      fs->type != EF_FILTER_MISMATCH_UNICAST &&
      fs->type != EF_FILTER_IP_PROTO && fs->type != EF_FILTER_ETHER_TYPE &&
      fs->type != EF_FILTER_IP6)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_VLAN;
  fs->data[5] = vlan_id;
  return 0;
}


int ef_filter_spec_set_eth_local(ef_filter_spec *fs, int vlan_id,
				 const void *mac)
{
  if (fs->type != 0 && fs->type != EF_FILTER_IP_PROTO &&
      fs->type != EF_FILTER_ETHER_TYPE)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_MAC;
  fs->data[0] = vlan_id;
  memcpy(&fs->data[1], mac, 6);
  return 0;
}


int ef_filter_spec_set_unicast_all(ef_filter_spec *fs)
{
  if (fs->type != 0 )
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_ALL_UNICAST;
  return 0;
}


int ef_filter_spec_set_multicast_all(ef_filter_spec *fs)
{
  if (fs->type != 0 )
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_ALL_MULTICAST;
  return 0;
}


int ef_filter_spec_set_unicast_mismatch(ef_filter_spec *fs)
{
  if (fs->type != 0 && fs->type != EF_FILTER_VLAN)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_MISMATCH_UNICAST;
  return 0;
}


int ef_filter_spec_set_multicast_mismatch(ef_filter_spec *fs)
{
  if (fs->type != 0 && fs->type != EF_FILTER_VLAN)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_MISMATCH_MULTICAST;
  return 0;
}


int ef_filter_spec_set_port_sniff(ef_filter_spec *fs, int promiscuous)
{
  if (fs->type != 0)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_PORT_SNIFF;
  fs->data[0] = promiscuous;
  return 0;
}


int ef_filter_spec_set_tx_port_sniff(ef_filter_spec *fs)
{
  if (fs->type != 0)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_TX_PORT_SNIFF;
  return 0;
}


int ef_filter_spec_set_block_kernel(ef_filter_spec *fs)
{
  if (fs->type != 0)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_BLOCK_KERNEL;
  return 0;
}


int ef_filter_spec_set_block_kernel_multicast(ef_filter_spec *fs)
{
  if (fs->type != 0)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_BLOCK_KERNEL_MULTICAST;
  return 0;
}


int ef_filter_spec_set_block_kernel_unicast(ef_filter_spec *fs)
{
  if (fs->type != 0)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_BLOCK_KERNEL_UNICAST;
  return 0;
}

#define EF_FILTER_DATA_INDEX_IPPROTO_OR_ETHERTYPE  3

int ef_filter_spec_set_ip_proto(ef_filter_spec *fs, uint8_t ip_proto)
{
  if (fs->type != 0 && fs->type != EF_FILTER_VLAN && fs->type != EF_FILTER_MAC)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_IP_PROTO;
  fs->data[EF_FILTER_DATA_INDEX_IPPROTO_OR_ETHERTYPE] = ip_proto;
  return 0;
}


int ef_filter_spec_set_eth_type(ef_filter_spec *fs, uint16_t ether_type_be16)
{
  if (fs->type != 0 && fs->type != EF_FILTER_VLAN && fs->type != EF_FILTER_MAC)
    return -EPROTONOSUPPORT;
  fs->type |= EF_FILTER_ETHER_TYPE;
  fs->data[EF_FILTER_DATA_INDEX_IPPROTO_OR_ETHERTYPE] = ether_type_be16;
  return 0;
}


/**********************************************************************
 * Add and remove filters.
 */

static int ef_filter_add_special(ef_driver_handle dh, int resource_id,
                                 int type, bool promisc, uint16_t vlan_id,
                                 ef_filter_cookie *filter_cookie_out,
                                 int *rxq_out)
{
  ci_resource_op_t op;
  int rc;

  op.id = efch_make_resource_id(resource_id);
  switch (type) {
  case EF_FILTER_PORT_SNIFF:
    op.op = CI_RSOP_PT_SNIFF;
    op.u.pt_sniff.enable = 1;
    op.u.pt_sniff.promiscuous = promisc;
    break;
  case EF_FILTER_TX_PORT_SNIFF:
    op.op = CI_RSOP_TX_PT_SNIFF;
    op.u.tx_pt_sniff.enable = 1;
    break;
  case EF_FILTER_BLOCK_KERNEL:
    op.op = CI_RSOP_FILTER_ADD_BLOCK_KERNEL;
    break;
  case EF_FILTER_BLOCK_KERNEL_UNICAST:
    op.op = CI_RSOP_FILTER_ADD_BLOCK_KERNEL_UNICAST;
    break;
  case EF_FILTER_BLOCK_KERNEL_MULTICAST:
    op.op = CI_RSOP_FILTER_ADD_BLOCK_KERNEL_MULTICAST;
    break;
  case EF_FILTER_ALL_UNICAST:
    op.op = CI_RSOP_FILTER_ADD_ALL_UNICAST;
    break;
  case EF_FILTER_ALL_MULTICAST:
    op.op = CI_RSOP_FILTER_ADD_ALL_MULTICAST;
    break;
  case EF_FILTER_MISMATCH_UNICAST | EF_FILTER_VLAN:
    op.op = CI_RSOP_FILTER_ADD_MISMATCH_UNICAST_VLAN;
    op.u.filter_add.mac.vlan_id = vlan_id;
    break;
  case EF_FILTER_MISMATCH_UNICAST:
    op.op = CI_RSOP_FILTER_ADD_MISMATCH_UNICAST;
    break;
  case EF_FILTER_MISMATCH_MULTICAST | EF_FILTER_VLAN:
    op.op = CI_RSOP_FILTER_ADD_MISMATCH_MULTICAST_VLAN;
    op.u.filter_add.mac.vlan_id = vlan_id;
    break;
  case EF_FILTER_MISMATCH_MULTICAST:
    op.op = CI_RSOP_FILTER_ADD_MISMATCH_MULTICAST;
    break;
  default:
    return -EINVAL;
  }
  rc = ci_resource_op(dh, &op);
  *rxq_out = op.u.filter_add.u.out.rxq;
  if( rc == 0 && filter_cookie_out != NULL ) {
    /* SNIFF does not return an ID.  The
     * filter_id field is ignored when removing,
     * but let's set it to something that will not be
     * confused with a real ID
     */
    filter_cookie_out->filter_id = -1;
    filter_cookie_out->filter_type = type;
  }
  return rc;
}

static int ef_filter_add(ef_driver_handle dh, int resource_id,
			 const ef_filter_spec *fs, unsigned flags,
			 ef_filter_cookie *filter_cookie_out, int *rxq_out)
{
  ci_filter_add_t filter_add;
  int rc;

  memset(&filter_add, 0, sizeof(filter_add));
  filter_add.in.in_len = sizeof(filter_add.in);
  filter_add.in.out_size = sizeof(filter_add.out);

  filter_add.in.res_id = efch_make_resource_id(resource_id);
  filter_add.in.flags = flags;
  filter_add.in.flags |= fs->flags & EF_FILTER_FLAG_MCAST_LOOP_RECEIVE ?
                         CI_FILTER_FLAG_MCAST_LOOP : 0;

  /* Common spec-population for flags shared by multiple filter-types. */
  if (fs->type & EF_FILTER_MAC) {
    filter_add.in.fields |= CI_FILTER_FIELD_LOC_MAC;
    memcpy(filter_add.in.spec.l2.dhost, &fs->data[1], 6);
    if (fs->type & EF_FILTER_VLAN ||
        (int)fs->data[0] != EF_FILTER_VLAN_ID_ANY) {
      filter_add.in.fields |= CI_FILTER_FIELD_OUTER_VID;
      filter_add.in.spec.l2.vid = fs->data[0];
    }
  }
  else {
    if (fs->type & EF_FILTER_IP4) {
      filter_add.in.fields |= CI_FILTER_FIELD_LOC_HOST |
                              CI_FILTER_FIELD_LOC_PORT;
      filter_add.in.spec.l2.type = htons(ETH_P_IP);
      filter_add.in.spec.l3.protocol = fs->data[0];
      filter_add.in.spec.l3.u.ipv4.daddr = fs->data[1];
      filter_add.in.spec.l4.ports.dest = fs->data[2];
      if (fs->data[3]) {
        filter_add.in.fields |= CI_FILTER_FIELD_REM_HOST |
                                CI_FILTER_FIELD_REM_PORT;
        filter_add.in.spec.l3.u.ipv4.saddr = fs->data[3];
        filter_add.in.spec.l4.ports.source = fs->data[4];
      }
    }
    if (fs->type & EF_FILTER_IP6) {
      filter_add.in.fields |= CI_FILTER_FIELD_LOC_HOST |
                              CI_FILTER_FIELD_LOC_PORT;
      filter_add.in.spec.l2.type = htons(ETH_P_IPV6);
      filter_add.in.spec.l3.protocol = fs->data[0];
      memcpy(&filter_add.in.spec.l3.u.ipv6.daddr, &fs->data[1], 16);
      filter_add.in.spec.l4.ports.dest = fs->data[6];
      if (fs->data[11]) {
        filter_add.in.fields |= CI_FILTER_FIELD_REM_HOST |
                                CI_FILTER_FIELD_REM_PORT;
        memcpy(&filter_add.in.spec.l3.u.ipv6.saddr, &fs->data[7], 16);
        filter_add.in.spec.l4.ports.source = fs->data[11];
      }
    }
  }

  /* EF_FILTER_IP_PROTO and EF_FILTER_ETHER_TYPE are mutually exclusive with
   * EF_FILTER_IP4.  They may be combined with at most one of EF_FILTER_MAC or
   * EF_FILTER_VLAN, however. */
  if (fs->type & EF_FILTER_IP_PROTO) {
    filter_add.in.fields |= CI_FILTER_FIELD_ETHER_TYPE |
                            CI_FILTER_FIELD_IP_PROTO;
    filter_add.in.spec.l2.type = htons(ETH_P_IP);
    filter_add.in.spec.l3.protocol =
            fs->data[EF_FILTER_DATA_INDEX_IPPROTO_OR_ETHERTYPE];
  }
  if (fs->type & EF_FILTER_ETHER_TYPE) {
    filter_add.in.fields |= CI_FILTER_FIELD_ETHER_TYPE;
    filter_add.in.spec.l2.type =
            fs->data[EF_FILTER_DATA_INDEX_IPPROTO_OR_ETHERTYPE];
  }
  if (fs->type & EF_FILTER_VLAN && !(fs->type & EF_FILTER_MAC)) {
    filter_add.in.fields |= CI_FILTER_FIELD_OUTER_VID;
    filter_add.in.spec.l2.vid = fs->data[5];
  }

  switch (fs->type) {
  case EF_FILTER_IP4:
  case EF_FILTER_IP4 | EF_FILTER_VLAN:
  case EF_FILTER_IP6:
  case EF_FILTER_IP6 | EF_FILTER_VLAN:
  case EF_FILTER_MAC:
  case EF_FILTER_MAC | EF_FILTER_IP_PROTO:
  case EF_FILTER_MAC | EF_FILTER_ETHER_TYPE:
  case EF_FILTER_IP_PROTO | EF_FILTER_VLAN:
  case EF_FILTER_ETHER_TYPE | EF_FILTER_VLAN:
  case EF_FILTER_IP_PROTO:
  case EF_FILTER_ETHER_TYPE:
    break;
  default:
    return -EINVAL;
  }
  rc = ci_filter_add(dh, &filter_add);
  *rxq_out = filter_add.out.rxq;
  if( rc == 0 && filter_cookie_out != NULL ) {
    filter_cookie_out->filter_id = filter_add.out.filter_id;
    filter_cookie_out->filter_type = fs->type;
  }
  return rc;
}


static int ef_filter_del(ef_driver_handle dh, int resource_id,
			 ef_filter_cookie *filter_cookie)
{
  ci_resource_op_t op;

  if( filter_cookie->filter_type == EF_FILTER_PORT_SNIFF ) {
    op.op = CI_RSOP_PT_SNIFF;
    op.id = efch_make_resource_id(resource_id);
    op.u.pt_sniff.enable = 0;
  }
  else if( filter_cookie->filter_type == EF_FILTER_TX_PORT_SNIFF ) {
    op.op = CI_RSOP_TX_PT_SNIFF;
    op.id = efch_make_resource_id(resource_id);
    op.u.tx_pt_sniff.enable = 0;
  }
  else {
    op.op = CI_RSOP_FILTER_DEL;
    op.id = efch_make_resource_id(resource_id);
    op.u.filter_del.filter_id = filter_cookie->filter_id;
  }
  return ci_resource_op(dh, &op);
}


int ef_vi_filter_add(ef_vi *vi, ef_driver_handle dh, const ef_filter_spec *fs,
		     ef_filter_cookie *filter_cookie_out)
{
  if( ! vi->vi_clustered ) {
    int rc;
    int rxq;
    ef_filter_cookie cookie;
    unsigned flags = 0;

    if( vi->vi_flags & EF_VI_RX_EXCLUSIVE )
      flags |= CI_FILTER_FLAG_EXCLUSIVE_RXQ;

    switch( fs->type ) {
    case EF_FILTER_PORT_SNIFF:
    case EF_FILTER_TX_PORT_SNIFF:
    case EF_FILTER_BLOCK_KERNEL:
    case EF_FILTER_BLOCK_KERNEL_UNICAST:
    case EF_FILTER_BLOCK_KERNEL_MULTICAST:
    case EF_FILTER_ALL_UNICAST:
    case EF_FILTER_ALL_MULTICAST:
    case EF_FILTER_MISMATCH_UNICAST | EF_FILTER_VLAN:
    case EF_FILTER_MISMATCH_UNICAST:
    case EF_FILTER_MISMATCH_MULTICAST | EF_FILTER_VLAN:
    case EF_FILTER_MISMATCH_MULTICAST:
      rc = ef_filter_add_special(dh, vi->vi_resource_id, fs->type, fs->data[0],
                                 fs->data[5], &cookie, &rxq);
      break;
    default:
      rc = ef_filter_add(dh, vi->vi_resource_id, fs, flags, &cookie, &rxq);
      break;
    }
    if( rc < 0 )
      return rc;

    if( filter_cookie_out )
      *filter_cookie_out = cookie;
    if( vi->internal_ops.post_filter_add ) {
      rc = vi->internal_ops.post_filter_add(vi, fs, &cookie, rxq);
      if( rc < 0 )
        ef_filter_del(dh, vi->vi_resource_id, &cookie);
    }
    return rc;
  }
  ef_log("%s: WARNING: Ignored attempt to set a filter on a cluster",
         __FUNCTION__);
  return 0;
}


int ef_vi_filter_del(ef_vi *vi, ef_driver_handle dh,
		     ef_filter_cookie *filter_cookie)
{
  if( ! vi->vi_clustered )
    return ef_filter_del(dh, vi->vi_resource_id, filter_cookie);
  return 0;
}


int ef_vi_set_filter_add(ef_vi_set* vi_set, ef_driver_handle dh,
			 const ef_filter_spec* fs,
			 ef_filter_cookie *filter_cookie_out)
{
  int rxq;
  return ef_filter_add(dh, vi_set->vis_res_id, fs, CI_FILTER_FLAG_RSS,
                       filter_cookie_out, &rxq);
}


int ef_vi_set_filter_del(ef_vi_set* vi_set, ef_driver_handle dh,
			 ef_filter_cookie *filter_cookie)
{
  return ef_filter_del(dh, vi_set->vis_res_id, filter_cookie);
}
