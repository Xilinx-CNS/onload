/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include <bits/sockaddr.h>
#include <linux/rtnetlink.h>
#include <ci/compat.h>
#include <ci/net/ethernet.h>
#include <ci/tools.h>

#define CI_CFG_IPV6 1
#include <ci/net/ipvx.h>

#include <cplane/mib.h>
#include "../cplane/mibdump.h"


void cp_dump_hwport_table(struct cp_mibs* mib)
{
  ci_hwport_id_t hwport;

  for( hwport = 0; hwport < mib->dim->hwport_max; hwport++ ) {
    if( ! cicp_hwport_row_is_free(&mib->hwport[hwport]) ) {
      printf("hwport[%03d]: flags=%08x nic_flags=%016"CI_PRIx64"\n", hwport,
             mib->hwport[hwport].flags, mib->hwport[hwport].nic_flags);
    }
  }
}

static void dump_hwport_mask(cicp_hwport_mask_t hwports)
{
  for( ; hwports != 0; hwports &= (hwports-1) )
    printf(" %d", cp_hwport_mask_first(hwports));
}

void cp_dump_llap_table(struct cp_mibs* mib)
{
  cicp_rowid_t id;

  printf("LLAP table:\n\n");

  for( id = 0; id < mib->dim->llap_max; id++ ) {
    if( cicp_llap_row_is_free(&mib->llap[id]) )
      return;

    ci_uint8 flags = mib->llap[id].flags;
    printf("llap[%03d]: %8s (%d) %s mtu %d\n",
           id, mib->llap[id].name, mib->llap[id].ifindex,
           (flags & CP_LLAP_UP) ? "UP" : "DOWN",
           mib->llap[id].mtu);
    if( mib->llap[id].encap.type != CICP_LLAP_TYPE_NONE ) {
      printf("\t encap " CICP_ENCAP_NAME_FMT "\n",
             cicp_encap_name(mib->llap[id].encap.type));
    }

    if( mib->llap[id].tx_hwports != 0 ) {
      printf("\t TX hwports");
      dump_hwport_mask(mib->llap[id].tx_hwports);
      printf("\n");
    }
    else {
      printf("\t no TX hwports\n");
    }
    if( mib->llap[id].rx_hwports != 0 ) {
      printf("\t RX hwports");
      dump_hwport_mask(mib->llap[id].rx_hwports);
      printf("\n");
    }
    else {
      printf("\t no RX hwports\n");
    }

    if( mib->llap[id].iif_fwd_table_id != CP_FWD_TABLE_ID_INVALID ) {
      printf("\t fwd-table ID %u", mib->llap[id].iif_fwd_table_id);
      printf("\n");
    }

    if( mib->llap[id].encap.type &
        (CICP_LLAP_TYPE_VLAN | CICP_LLAP_TYPE_MACVLAN) ) {
      printf("\t ");
      if( mib->llap[id].encap.type & CICP_LLAP_TYPE_VLAN )
        printf("vlan id %d, ", mib->llap[id].encap.vlan_id);
      if( mib->llap[id].encap.type & CICP_LLAP_TYPE_MACVLAN )
        printf("macvlan, ");
      printf("base interface %s (%d)\n",
             cp_ifindex2name(mib, mib->llap[id].encap.link_ifindex),
             mib->llap[id].encap.link_ifindex);
    }

    if( mib->llap[id].encap.type & CICP_LLAP_TYPE_SLAVE ) {
      printf("\t slave in aggregation\n");
    }
    else if( mib->llap[id].encap.type & CICP_LLAP_TYPE_BOND ) {
      printf("\t bond %s%s%s%s\n",
             mib->llap[id].encap.type & CICP_LLAP_TYPE_USES_HASH ?
                                                        " hash" : "",
             mib->llap[id].encap.type & CICP_LLAP_TYPE_XMIT_HASH_LAYER34 ?
                                                             " layer34" : "",
             mib->llap[id].encap.type & CICP_LLAP_TYPE_XMIT_HASH_LAYER2 ?
                                                             " layer2" : "",
             mib->llap[id].encap.type & CICP_LLAP_TYPE_XMIT_HASH_LAYER23 ?
                                                             " layer23" : "");
    }
    if( mib->llap[id].tx_hwports != 0 ) {
      printf("\t mac %02x:%02x:%02x:%02x:%02x:%02x\n",
             mib->llap[id].mac[0], mib->llap[id].mac[1],
             mib->llap[id].mac[2], mib->llap[id].mac[3],
             mib->llap[id].mac[4], mib->llap[id].mac[5]);
    }
  }
}


static const char*
rt_scope_str(int scope)
{
  switch(scope) {
    case RT_SCOPE_UNIVERSE: return "univ";
    case RT_SCOPE_SITE:     return "site";
    case RT_SCOPE_LINK:     return "link";
    case RT_SCOPE_HOST:     return "host";
    case RT_SCOPE_NOWHERE:  return "nwhr";
    default:                return "<other>";
  }
}

void cp_dump_ipif_table(struct cp_mibs* mib)
{
  cicp_rowid_t id;

  printf("IPIF table:\n\n");

  for( id = 0; id < mib->dim->ipif_max; id++ ) {
    if( cicp_ipif_row_is_free(&mib->ipif[id]) )
      return;

    printf("ipif[%03d]: %8s (%d) "CI_IP_PRINTF_FORMAT"/%d"
           " bcast "CI_IP_PRINTF_FORMAT" scope %s\n", id,
           cp_ifindex2name(mib, mib->ipif[id].ifindex),
           mib->ipif[id].ifindex,
           CI_IP_PRINTF_ARGS(&mib->ipif[id].net_ip),
           mib->ipif[id].net_ipset,
           CI_IP_PRINTF_ARGS(&mib->ipif[id].bcast_ip),
           rt_scope_str(mib->ipif[id].scope));
  }
}

void cp_dump_ip6if_table(struct cp_mibs* mib)
{
  cicp_rowid_t id;

  printf("IP6IF table:\n");

  if( mib->dim->ip6if_max == 0 ) {
    printf("IPv6 support disabled\n");
    return;
  }

  printf("\n");

  for( id = 0; id < mib->dim->ip6if_max; id++ ) {
    if( cicp_ip6if_row_is_free(&mib->ip6if[id]) )
      return;

    printf("ip6if[%03d]: %8s (%d) %s/%d scope %s\n", id,
           cp_ifindex2name(mib, mib->ip6if[id].ifindex),
           mib->ip6if[id].ifindex,
           AF_IP(CI_ADDR_FROM_IP6(mib->ip6if[id].net_ip6)),
           mib->ip6if[id].net_ipset,
           rt_scope_str(mib->ip6if[id].scope));
  }
}

void cp_dump_services(struct cp_mibs* mib)
{
  cicp_mac_rowid_t id;

  printf("Services:\n\n");

  for( id = 0; id < mib->dim->svc_ep_max; ++id ) {
    struct cp_svc_ep_dllist* entry = &mib->svc_ep_table[id];

    if( entry->use == 0 )
      continue;

    printf("svc[%06d]: use=%u ", id, entry->use);

    if( entry->row_type == CP_SVC_EMPTY )
      printf("(empty)\n");
    else
      printf(IPX_PORT_FMT" %s\n",
             IPX_ARG(AF_IP(entry->ep.addr)),
             ntohs(entry->ep.port),
             entry->row_type == CP_SVC_SERVICE ? "service" :
             entry->row_type == CP_SVC_BACKEND ? "backend" : "?");
  }
}

