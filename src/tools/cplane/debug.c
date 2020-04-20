/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef NDEBUG

#include "private.h"

/* llap_only==true would also imply checking hwports as it is assumed
 * that a hwport change affects llap */
void cp_mibs_verify_identical(struct cp_session* s, bool llap_only)
{
  int i, j;
  ci_assert_equal(*s->mib[0].llap_version, *s->mib[1].llap_version);
  ci_assert_equal(strncmp(s->mib[0].sku->value, s->mib[1].sku->value,
                          sizeof(s->mib[0].sku->value)), 0);
  for( i = 0; i < s->mib[0].dim->hwport_max; i++ ) {
    struct cp_hwport_row* a = &s->mib[0].hwport[i];
    struct cp_hwport_row* b = &s->mib[1].hwport[i];
    ci_assert_equal(cicp_hwport_row_is_free(a),
                    cicp_hwport_row_is_free(b));
    if( cicp_hwport_row_is_free(a) )
      continue;
  }
  for( i = 0; i < s->mib[0].dim->llap_max; i++ ) {
    cicp_llap_row_t* a = &s->mib[0].llap[i];
    cicp_llap_row_t* b = &s->mib[1].llap[i];
    ci_assert_equal(cicp_llap_row_is_free(a),
                    cicp_llap_row_is_free(b));
    if( cicp_llap_row_is_free(a) )
      continue;
    ci_assert_equal(a->ifindex, b->ifindex);
    ci_assert_equal(a->flags, b->flags);
    ci_assert(strcmp(a->name, b->name) == 0);
    ci_assert(memcmp(a->mac, b->mac, sizeof(a->mac)) == 0);
    ci_assert_equal(a->tx_hwports, b->tx_hwports);
    ci_assert_equal(a->encap.type, b->encap.type);
    ci_assert_equal(a->encap.link_ifindex, b->encap.link_ifindex);
    ci_assert_impl(a->encap.type &CICP_LLAP_TYPE_VLAN,
                   a->encap.vlan_id == b->encap.vlan_id);
    ci_assert_equal(a->iif_fwd_table_id, b->iif_fwd_table_id);
  }
  if( llap_only )
    return;
  for( i = 0; i < s->mib[0].dim->ipif_max; i++ ) {
    cicp_ipif_row_t* a = &s->mib[0].ipif[i];
    cicp_ipif_row_t* b = &s->mib[1].ipif[i];
    ci_assert_equal(cicp_ipif_row_is_free(a),
                    cicp_ipif_row_is_free(b));
    if( cicp_ipif_row_is_free(a) )
      continue;
    ci_assert_equal(a->ifindex, b->ifindex);
    ci_assert_equal(a->net_ip, b->net_ip);
    ci_assert_equal(a->net_ipset, b->net_ipset);
    ci_assert_equal(a->bcast_ip, b->bcast_ip);
    ci_assert_equal(a->scope, b->scope);
  }
  for( i = 0; i < s->mib[0].dim->ip6if_max; i++ ) {
    cicp_ip6if_row_t* a = &s->mib[0].ip6if[i];
    cicp_ip6if_row_t* b = &s->mib[1].ip6if[i];
    ci_assert_equal(cicp_ip6if_row_is_free(a),
                    cicp_ip6if_row_is_free(b));
    if( cicp_ip6if_row_is_free(a) )
      continue;
    ci_assert_equal(a->ifindex, b->ifindex);
    ci_assert(!memcmp(a->net_ip6, b->net_ip6, sizeof(a->net_ip6)));
    ci_assert_equal(a->net_ipset, b->net_ipset);
    ci_assert_equal(a->scope, b->scope);
  }
  for( i = 0; i < s->mib[0].dim->svc_arrays_max; i++ ) {
    struct cp_svc_ep_array* a = &s->mib[0].svc_arrays[i];
    struct cp_svc_ep_array* b = &s->mib[1].svc_arrays[i];
    for( j = 0; j < CP_SVC_BACKENDS_PER_ARRAY; j++ ) {
      ci_assert( CI_IPX_ADDR_EQ(a->eps[j].addr, b->eps[j].addr) );
      ci_assert_equal(a->eps[j].port, b->eps[j].port);
    }
  }
  for( i = 0; i < s->mib[0].dim->svc_ep_max; i++ ) {
    struct cp_svc_ep_dllist* a = &s->mib[0].svc_ep_table[i];
    struct cp_svc_ep_dllist* b = &s->mib[1].svc_ep_table[i];

    ci_assert( CI_IPX_ADDR_EQ(a->ep.addr, b->ep.addr) );
    ci_assert_equal(a->ep.port, b->ep.port);
    ci_assert_equal(a->use, b->use);
    ci_assert_equal(a->row_type, b->row_type);

    switch( a->row_type ) {
    case CP_SVC_SERVICE:
      ci_assert_equal(a->u.service.head_array_id, b->u.service.head_array_id);
      ci_assert_equal(a->u.service.tail_array_id, b->u.service.tail_array_id);
      ci_assert_equal(a->u.service.n_backends, b->u.service.n_backends);
      break;
    case CP_SVC_BACKEND:
      ci_assert_equal(a->u.backend.svc_id, b->u.backend.svc_id);
      ci_assert_equal(a->u.backend.element_id, b->u.backend.element_id);
      break;
    case CP_SVC_EMPTY:
      break;
    }
  }
}

void cp_fwd_verify_identical(struct cp_fwd_row* s)
{
  if( ~s->flags & CICP_FWD_FLAG_DATA_VALID )
    return;
  ci_assert_nflags(s->flags, CICP_FWD_FLAG_CHANGES_STARTED);
  ci_assert_flags(s->flags, CICP_FWD_FLAG_OCCUPIED);
  /* memcmp exploits the fact that the data in fwd table is 0 padded */
  ci_assert(memcmp(&s->data[0], &s->data[1], sizeof(s->data[0])) == 0);
}

#endif
