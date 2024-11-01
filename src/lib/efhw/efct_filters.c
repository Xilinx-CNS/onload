/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#include <ci/driver/kernel_compat.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/ci_aux.h>
#include <ci/driver/ci_efct.h>
#include <ci/efhw/common.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/efct.h>
#include <ci/efhw/efct_filters.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/checks.h>
#include <ci/driver/ci_efct.h>
#include <ci/tools/bitfield.h>
#include <ci/net/ipv6.h>
#include <ci/net/ipv4.h>
#include <net/sock.h>
#include <ci/tools/sysdep.h>
#include <ci/tools/bitfield.h>
#include <uapi/linux/ethtool.h>
#include "ethtool_flow.h"
#include <linux/hashtable.h>
#include <etherfabric/internal/internal.h>
#include "efct.h"
#include "efct_superbuf.h"

#if CI_HAVE_EFCT_COMMON


/* NUM_FILTER_CLASSES: Number of different filter types (and hence hash
 * tables) that we have */
#define ACTION_COUNT_FILTER_CLASSES(F) +1
#define NUM_FILTER_CLASSES (FOR_EACH_FILTER_CLASS(ACTION_COUNT_FILTER_CLASSES))

#define ACTION_DEFINE_FILTER_CLASS_ENUM(F) FILTER_CLASS_##F,
enum filter_class_id {
  /* FILTER_CLASS_full_match [=0], FILTER_CLASS_semi_wild [=1], ... */
  FOR_EACH_FILTER_CLASS(ACTION_DEFINE_FILTER_CLASS_ENUM)
};

static u32 filter_hash_table_seed;
static bool filter_hash_table_seed_inited = false;


int efct_filter_state_init(struct efct_filter_state *state, int num_filter,
                           int rx_queues)
{
  mutex_init(&state->driver_filters_mtx);

  state->hw_filters_n = num_filter;
  state->hw_filters = vzalloc(sizeof(*state->hw_filters) * state->hw_filters_n);
  if( ! state->hw_filters )
    return -ENOMEM;

  state->exclusive_rxq_mapping = kzalloc(sizeof(*state->exclusive_rxq_mapping)
                                         * rx_queues, GFP_KERNEL);
  if( ! state->exclusive_rxq_mapping )
    return -ENOMEM;

  if( ! filter_hash_table_seed_inited ) {
    filter_hash_table_seed_inited = true;
    filter_hash_table_seed = get_random_u32();
  }

#define ACTION_INIT_HASH_TABLE(F) \
        hash_init(state->filters.F);
  FOR_EACH_FILTER_CLASS(ACTION_INIT_HASH_TABLE)

  return 0;
}


void efct_filter_state_free(struct efct_filter_state *state)
{
  if( state->hw_filters )
    vfree(state->hw_filters);
  if( state->exclusive_rxq_mapping )
    kfree(state->exclusive_rxq_mapping);
}


static uint32_t zero_remote_port(uint32_t l4_4_bytes)
{
  return htonl(ntohl(l4_4_bytes) & 0xffff);
}

int sanitise_ethtool_flow(struct ethtool_rx_flow_spec *dst)
{
  /* Blat out the remote fields: we can soft-filter them even though the
   * hardware can't */
  switch (dst->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) {
  case UDP_V4_FLOW:
  case TCP_V4_FLOW:
    EFHW_ASSERT(&dst->h_u.udp_ip4_spec == &dst->h_u.tcp_ip4_spec);
    if( dst->m_u.udp_ip4_spec.tos )
      return -EPROTONOSUPPORT;
    dst->h_u.udp_ip4_spec.ip4src = 0;
    dst->h_u.udp_ip4_spec.psrc = 0;
    dst->m_u.udp_ip4_spec.ip4src = 0;
    dst->m_u.udp_ip4_spec.psrc = 0;
    break;
  case IPV4_USER_FLOW:
    if( dst->m_u.usr_ip4_spec.tos || dst->m_u.usr_ip4_spec.ip_ver )
      return -EPROTONOSUPPORT;
    dst->h_u.usr_ip4_spec.ip4src = 0;
    dst->m_u.usr_ip4_spec.ip4src = 0;
    dst->h_u.usr_ip4_spec.l4_4_bytes =
                          zero_remote_port(dst->h_u.usr_ip4_spec.l4_4_bytes);
    dst->m_u.usr_ip4_spec.l4_4_bytes =
                          zero_remote_port(dst->m_u.usr_ip4_spec.l4_4_bytes);
    break;
  case UDP_V6_FLOW:
  case TCP_V6_FLOW:
    EFHW_ASSERT(&dst->h_u.udp_ip6_spec == &dst->h_u.tcp_ip6_spec);
    memset(dst->h_u.udp_ip6_spec.ip6src, 0,
           sizeof(dst->h_u.udp_ip6_spec.ip6src));
    dst->h_u.udp_ip6_spec.psrc = 0;
    memset(dst->m_u.udp_ip6_spec.ip6src, 0,
           sizeof(dst->m_u.udp_ip6_spec.ip6src));
    dst->m_u.udp_ip6_spec.psrc = 0;
    break;
  case IPV6_USER_FLOW:
    memset(dst->h_u.usr_ip6_spec.ip6src, 0,
           sizeof(dst->h_u.usr_ip6_spec.ip6src));
    memset(dst->m_u.usr_ip6_spec.ip6src, 0,
           sizeof(dst->m_u.usr_ip6_spec.ip6src));
    dst->h_u.usr_ip6_spec.l4_4_bytes =
                          zero_remote_port(dst->h_u.usr_ip6_spec.l4_4_bytes);
    dst->m_u.usr_ip6_spec.l4_4_bytes =
                          zero_remote_port(dst->m_u.usr_ip6_spec.l4_4_bytes);
    break;
  case ETHER_FLOW:
    dst->h_u.ether_spec.h_proto = 0;
    dst->m_u.ether_spec.h_proto = 0;
    break;
  default:
    return -EPROTONOSUPPORT;
  }

  /* We don't support MAC in combination with IP filters */
  if (dst->flow_type & FLOW_MAC_EXT)
    return -EPROTONOSUPPORT;

  if (dst->flow_type & FLOW_EXT) {
    if (dst->m_ext.vlan_etype || dst->m_ext.vlan_tci != htons(0xfff) ||
        dst->m_ext.data[0] || dst->m_ext.data[1])
      return -EPROTONOSUPPORT;
    /* VLAN tags are only supported with flow_type ETHER_FLOW */
    if ((dst->flow_type & ~(FLOW_EXT | FLOW_MAC_EXT)) != ETHER_FLOW)
      dst->flow_type &= ~FLOW_EXT;
  }

  return 0;
}

static bool
hw_filters_are_equal(const struct efct_filter_node *node,
                     const struct efct_hw_filter *hw_filter,
                     int clas)
{
  switch (clas) {
  /* FIXME EF10CT this is different for X4LL */
  case FILTER_CLASS_semi_wild:
  case FILTER_CLASS_full_match:
    if (hw_filter->proto == node->proto &&
        hw_filter->ip == node->u.ip4.lip &&
        hw_filter->port == node->lport)
      return true;
    break;
  case FILTER_CLASS_ipproto:
    if (hw_filter->ethertype == node->ethertype &&
        hw_filter->proto == node->proto)
      return true;
    break;
  case FILTER_CLASS_mac:
  case FILTER_CLASS_mac_vlan:
  /* The vlan id is checked for every filter, including MAC filters without a
   * specified vlan, as otherwise we could get false positives between vlans.
   */
    if (!memcmp(&hw_filter->loc_mac, &node->loc_mac,
        sizeof(node->loc_mac)) && hw_filter->outer_vlan == node->vlan)
      return true;
    break;
  default:
    /* This should only be called for filter types that correspond to a real
     * HW filter. */
    EFHW_ASSERT(0);
    break;
  }

  return false;
}


/* Computes the hash over the efct_filter_node. The actual number of relevant
 * bytes depends on the type of match we're going to be doing */
static u32
hash_filter_node(const struct efct_filter_node* node, size_t node_len)
{
  return jhash2(&node->key_start,
                (node_len - offsetof(struct efct_filter_node, key_start))
                / sizeof(u32), filter_hash_table_seed);
}

static bool find_one_filter(struct hlist_head* table, size_t hash_bits,
                            const struct efct_filter_node* node,
                            size_t node_len)
{
  struct efct_filter_node* existing;
  size_t key_len = node_len - offsetof(struct efct_filter_node, key_start);
  u32 hash = hash_filter_node(node, node_len);

  hlist_for_each_entry_rcu(existing, &table[hash_min(hash, hash_bits)], node)
    if( ! memcmp(&existing->key_start, &node->key_start, key_len))
      return true;
  return false;
}

/* True iff 'node' is in 'table', i.e. if a packet matches one of our stored
 * filters for one specific class of filter.
 *
 * vlan_required parameter is used for filters that match on a single vlan id.
 */
static bool
filter_matches(struct hlist_head* table, size_t hash_bits,
               struct efct_filter_node* node, size_t node_len,
               bool vlan_required)
{
  bool found;

  rcu_read_lock();
  found = find_one_filter(table, hash_bits, node, node_len);
  if( ! found && ! vlan_required ) {
    int32_t vlan = node->vlan;
    node->vlan = -1;
    found = find_one_filter(table, hash_bits, node, node_len);
    node->vlan = vlan;
  }
  rcu_read_unlock();
  return found;
}

/* We need to generate a filter_id int that we can find again at removal time.
 * To do this we split it up into bits:
 *   0..1: filter type, i.e. the index in to the FOR_EACH_FILTER_CLASS
 *         metaarray
 *   2..15: bucket number (number of bits allocated here depends on the hash
 *          table size)
 *   16..30: random uniquifier
 */

static const int FILTER_CLASS_BITS = roundup_pow_of_two(NUM_FILTER_CLASSES);

static int
get_filter_class(int filter_id)
{
  int clas = filter_id & (FILTER_CLASS_BITS - 1);
  EFHW_ASSERT(clas < NUM_FILTER_CLASSES);
  return clas;
}

static int
do_filter_insert(int clas, struct hlist_head* table, size_t *table_n,
                 size_t hash_bits, size_t max_n, struct efct_filter_node* node,
                 struct efct_filter_state *state, size_t node_len,
                 bool allow_dups, struct efct_filter_node** used_node)
{
  size_t key_len = node_len - offsetof(struct efct_filter_node, key_start);
  struct efct_filter_node* node_ptr;
  u32 hash = hash_filter_node(node, node_len);
  int bkt = hash_min(hash, hash_bits);
  int i;
  bool is_duplicate = false;

  if( *table_n >= max_n )
    return -ENOSPC;

  /* We don't have a good way of generating the topmost few bits of the
   * filter_id, so use a random number and repeat until there's no collision */
  for( i = 10; i; --i ) {
    struct efct_filter_node* old;
    bool id_dup = false;
    node->filter_id = clas | (bkt << FILTER_CLASS_BITS) |
                      (get_random_u32() << (FILTER_CLASS_BITS + hash_bits));
    node->filter_id &= 0x7fffffff;
    hlist_for_each_entry_rcu(old, &table[bkt], node) {
      if( old->filter_id == node->filter_id ) {
        id_dup = true;
        break;
      }
      if( ! memcmp(&old->key_start, &node->key_start, key_len)) {
        if( ! allow_dups )
          return -EEXIST;
        ++old->refcount;
        node->filter_id = old->filter_id;
        *used_node = old;
        is_duplicate = true;
        break;
      }
    }
    if( ! id_dup )
      break;
  }
  if( ! i )
    return -ENOSPC;

  if ( !is_duplicate ) {
    node_ptr = kmalloc(node_len, GFP_KERNEL);
    if( ! node_ptr )
      return -ENOMEM;
    memcpy(node_ptr, node, node_len);
    hlist_add_head_rcu(&node_ptr->node, &table[bkt]);
    ++*table_n;
    *used_node = node_ptr;
  }

  if ( node->hw_filter >= 0 )
    ++state->hw_filters[node->hw_filter].refcount;
  return 0;
}

static struct efct_filter_node*
lookup_filter_by_id(struct efct_filter_state *state, int filter_id,
                    size_t **class_n)
{
  int clasi = 0;
  int clas = get_filter_class(filter_id);

#define ACTION_LOOKUP_BY_FILTER_ID(F) \
    if( clasi++ == clas ) { \
      int bkt = (filter_id >> FILTER_CLASS_BITS) & \
                (HASH_SIZE(state->filters.F) - 1); \
      struct efct_filter_node* node; \
      hlist_for_each_entry_rcu(node, &state->filters.F[bkt], node) { \
        if( node->filter_id == filter_id ) { \
          EFHW_ASSERT(state->filters.F##_n > 0); \
          if( class_n ) \
            *class_n = &state->filters.F##_n; \
          return node; \
        } \
      } \
    }
  FOR_EACH_FILTER_CLASS(ACTION_LOOKUP_BY_FILTER_ID)
  return NULL;
}

static void do_filter_del(struct efct_filter_state *state, int filter_id,
                         int* hw_filter)
{
  size_t *class_n;
  struct efct_filter_node *node = lookup_filter_by_id(state, filter_id, &class_n);

  *hw_filter = -1;
  if( node ) {
    *hw_filter = node->hw_filter;
    if( node->hw_filter >= 0 ) {
      --state->hw_filters[node->hw_filter].refcount;
    }
    if( --node->refcount == 0 ) {
      hash_del_rcu(&node->node);
      --*class_n;
      kfree_rcu(node, free_list);
    }
  }
}

int
efct_filter_insert(struct efct_filter_state *state, struct efx_filter_spec *spec,
                    struct ethtool_rx_flow_spec *hw_filter,
                   int *rxq, unsigned pd_excl_token, unsigned flags,
                   drv_filter_insert insert_op, void *insert_data)
{
  int rc;
  struct efct_filter_insert_in op_in;
  struct efct_filter_insert_out op_out;
  struct efct_filter_node node;
  struct efct_filter_node* sw_filter_node;
  size_t node_len;
  int clas;
  bool insert_hw_filter = false;
  unsigned no_vlan_flags = spec->match_flags & ~EFX_FILTER_MATCH_OUTER_VID;
  unsigned q_excl_token = 0;

  if( *rxq >= 0 )
    hw_filter->ring_cookie = *rxq;

  /* Step 1 of 2: Convert ethtool_rx_flow_spec to efct_filter_node */
  memset(&node, 0, sizeof(node));
  node.hw_filter = -1;
  node.vlan = -1;
  node.refcount = 1;

  if( no_vlan_flags == EFX_FILTER_MATCH_ETHER_TYPE ) {
    clas = FILTER_CLASS_ethertype;
    node_len = offsetof(struct efct_filter_node, proto);
    node.ethertype = spec->ether_type;
  }
  else if( no_vlan_flags == (EFX_FILTER_MATCH_ETHER_TYPE |
                             EFX_FILTER_MATCH_IP_PROTO) ) {
    if (spec->match_flags & EFX_FILTER_MATCH_OUTER_VID) {
      clas = FILTER_CLASS_ipproto_vlan;
      node.vlan = spec->outer_vid;
    }
    else {
      clas = FILTER_CLASS_ipproto;
      node.vlan = -1;
    }
    node_len = offsetof(struct efct_filter_node, rport);
    node.ethertype = spec->ether_type;
    node.proto = spec->ip_proto;
  }
  else if( no_vlan_flags == (EFX_FILTER_MATCH_ETHER_TYPE |
                             EFX_FILTER_MATCH_IP_PROTO |
                             EFX_FILTER_MATCH_LOC_HOST |
                             EFX_FILTER_MATCH_LOC_PORT) ) {
    clas = FILTER_CLASS_semi_wild;
    node.ethertype = spec->ether_type;
    node.proto = spec->ip_proto;
    node.lport = spec->loc_port;
    if( node.ethertype == htons(ETH_P_IP) ) {
      node_len = offsetof(struct efct_filter_node, u.ip4.rip);
      node.u.ip4.lip = spec->loc_host[0];
    }
    else {
      node_len = offsetof(struct efct_filter_node, u.ip6.rip);
      memcpy(&node.u.ip6.lip, spec->loc_host, sizeof(node.u.ip6.lip));
    }
  }
  else if( no_vlan_flags == (EFX_FILTER_MATCH_ETHER_TYPE |
                             EFX_FILTER_MATCH_IP_PROTO |
                             EFX_FILTER_MATCH_LOC_HOST |
                             EFX_FILTER_MATCH_LOC_PORT |
                             EFX_FILTER_MATCH_REM_HOST |
                             EFX_FILTER_MATCH_REM_PORT) ) {
    clas = FILTER_CLASS_full_match;
    node.ethertype = spec->ether_type;
    node.proto = spec->ip_proto;
    node.lport = spec->loc_port;
    node.rport = spec->rem_port;
    if( node.ethertype == htons(ETH_P_IP) ) {
      node_len = offsetof(struct efct_filter_node, u.ip4.rip) +
                 sizeof(node.u.ip4.rip);
      node.u.ip4.lip = spec->loc_host[0];
      node.u.ip4.rip = spec->rem_host[0];
    }
    else {
      node_len = sizeof(struct efct_filter_node);
      memcpy(&node.u.ip6.lip, spec->loc_host, sizeof(node.u.ip6.lip));
      memcpy(&node.u.ip6.rip, spec->rem_host, sizeof(node.u.ip6.rip));
    }
  }
  else if( no_vlan_flags == EFX_FILTER_MATCH_LOC_MAC_IG ) {
    /* Insert a filter by setting the ethertype to magic value 0xFFFF, which is a     *
     * reserved value. We then set the proto to allow differentiating between ucast   *
     * and mcast. This allows us to also utilise the existing vlan combined filtering *
     * from ethertype filters, thus supporting multicast-mis + vid filters.           */
    clas = FILTER_CLASS_ethertype;
    node_len = offsetof(struct efct_filter_node, rport);
    node.ethertype = EFCT_ETHERTYPE_IG_FILTER;
    node.proto = (spec->loc_mac[0] ? EFCT_PROTO_MCAST_IG_FILTER : EFCT_PROTO_UCAST_IG_FILTER);
  }
  else if( no_vlan_flags == EFX_FILTER_MATCH_LOC_MAC ) {
    if (spec->match_flags & EFX_FILTER_MATCH_OUTER_VID) {
      clas = FILTER_CLASS_mac_vlan;
      node.vlan = spec->outer_vid;
    } else {
      clas = FILTER_CLASS_mac;
      node.vlan = -1;
    }
    node_len = offsetof(struct efct_filter_node, loc_mac) +
               sizeof(node.loc_mac);
    memcpy(&node.loc_mac, spec->loc_mac, sizeof(node.loc_mac));
  }
  else {
    return -EPROTONOSUPPORT;
  }

  if( spec->match_flags & EFX_FILTER_MATCH_OUTER_VID )
    node.vlan = spec->outer_vid;

  /* Step 2 of 2: Insert efct_filter_node in to the correct hash table */
  mutex_lock(&state->driver_filters_mtx);

  if ( *rxq > 0 ) {
    q_excl_token = state->exclusive_rxq_mapping[*rxq];

    /* If the q excl tokens are 0, we are in a fresh state and can claim it.
    *  If both the pd and q are EFHW_PD_NON_EXC_TOKEN, we are in a non-exclusive queue.
    *  If the q one is set, but the pd one does not match, than the pd is overstepping on another rxq.
    *  The q state is owned and managed by the driver and persists external to the application. */
    if ( ( q_excl_token > 0 ) && ( q_excl_token != pd_excl_token ) ) {
      mutex_unlock(&state->driver_filters_mtx);
      return -EPERM;
    }
  }

  if( flags & EFHW_FILTER_F_USE_HW ) {
    int i;
    int avail = -1;
    for( i = 0; i < state->hw_filters_n; ++i ) {
      if( ! state->hw_filters[i].refcount )
        avail = i;
      else {
        if( hw_filters_are_equal(&node, &state->hw_filters[i], clas) ) {

          if( ! (flags & (EFHW_FILTER_F_ANY_RXQ | EFHW_FILTER_F_PREF_RXQ) ) &&
              *rxq >= 0 && *rxq != state->hw_filters[i].rxq ) {
            mutex_unlock(&state->driver_filters_mtx);
            return -EEXIST;
          }

          if ( state->hw_filters[i].rxq > 0 &&
               pd_excl_token !=
               state->exclusive_rxq_mapping[state->hw_filters[i].rxq] ) {
            /* Trying to attach onto an rxq owned by someone else. */
            mutex_unlock(&state->driver_filters_mtx);
            return -EPERM;
          }

          node.hw_filter = i;
          break;
        }
      }
    }
    if( node.hw_filter < 0 ) {
      /* If we have no free hw filters, that's fine: we'll just use rxq0 */
      if( avail >= 0 ) {
        node.hw_filter = avail;
        state->hw_filters[avail].proto = node.proto;
        state->hw_filters[avail].ip = node.u.ip4.lip;
        state->hw_filters[avail].port = node.lport;
        memcpy(&state->hw_filters[avail].loc_mac, &node.loc_mac,
                sizeof(node.loc_mac));
        state->hw_filters[avail].outer_vlan = node.vlan;
        insert_hw_filter = true;
      }
    }
  }

  /* If we aren't going to have a hw filter and we're not allowed to fall back
   * to SW filtering, then bail out now. */
  if( node.hw_filter < 0 && !(flags & EFHW_FILTER_F_USE_SW) ) {
    mutex_unlock(&state->driver_filters_mtx);
    return -ENOSPC;
  }

  /* If we aren't going to have a hw filter, then we definitely don't have an
   * exclusive queue available. */
  if( node.hw_filter < 0 && (flags & EFHW_FILTER_F_EXCL_RXQ) ) {
    mutex_unlock(&state->driver_filters_mtx);
    return -EPERM;
  }

#define ACTION_DO_FILTER_INSERT(F) \
    if( clas == FILTER_CLASS_##F ) { \
      rc = do_filter_insert(clas, state->filters.F, &state->filters.F##_n, \
                            HASH_BITS(state->filters.F), MAX_ALLOWED_##F, \
                            &node, state, node_len, \
                            clas != FILTER_CLASS_full_match, &sw_filter_node); \
    }
  FOR_EACH_FILTER_CLASS(ACTION_DO_FILTER_INSERT)

  if( rc < 0 ) {
    mutex_unlock(&state->driver_filters_mtx);
    return rc;
  }

  if( insert_hw_filter ) {
    op_in = (struct efct_filter_insert_in) {
      .drv_opaque = insert_data,
      .filter = hw_filter,
    };

    rc = insert_op(&op_in, &op_out);

    if( rc == -ENOSPC && sw_filter_node->refcount == 1 ) {
      /* We discovered we had fewer hardware filters than we thought - undo a bit
       * and use rxq0 / sw filtering only */
      rc = flags & EFHW_FILTER_F_EXCL_RXQ ? -EPERM : 0;
      --state->hw_filters[node.hw_filter].refcount;
      sw_filter_node->hw_filter = -1;
      node.hw_filter = -1;
    }
  }

  if( rc < 0 ) {
    int unused;
    do_filter_del(state, node.filter_id, &unused);
  }
  else {
    if( node.hw_filter >= 0 ) {
      if( insert_hw_filter ) {
        state->hw_filters[node.hw_filter].rxq = op_out.rxq;
        state->hw_filters[node.hw_filter].drv_id = op_out.drv_id;
        state->hw_filters[node.hw_filter].hw_id = op_out.filter_handle;
      }
      *rxq = state->hw_filters[node.hw_filter].rxq;
      if ( *rxq > 0 )
        state->exclusive_rxq_mapping[*rxq] = pd_excl_token;
    }
    else {
      *rxq = 0;
    }
  }
  mutex_unlock(&state->driver_filters_mtx);

  return rc < 0 ? rc : node.filter_id;
}

static void
remove_exclusive_rxq_ownership(struct efct_filter_state *state, int hw_filter)
{
  int i;
  bool delete_owner = true;
  int rxq = state->hw_filters[hw_filter].rxq;

  if( state->exclusive_rxq_mapping[rxq] ) {
    /* We should never have claimed rxq 0 as exclusive as this is always shared
     * with the net driver. */
    EFHW_ASSERT(rxq > 0);

    /* Only bother worrying about exclusive mapping iff the filter has an exclusive entry */
    for( i = 0; i < state->hw_filters_n; ++i ) {
      if ( state->hw_filters[i].refcount ) {
        /* Iff any of the currently active filters (ie refcount > 0) share the same rxq
          * as the one we are attempting to delete, we cannot clear the rxq ownership.*/
        if( state->hw_filters[i].rxq == rxq ) {
          delete_owner = false;
          break;
        }
      }
    }
  }
  
  if ( delete_owner )
    state->exclusive_rxq_mapping[rxq] = 0;
}


bool
efct_filter_remove(struct efct_filter_state *state, int filter_id,
                   uint64_t *drv_id_out)
{
  int hw_filter;
  bool remove_drv = false;

  mutex_lock(&state->driver_filters_mtx);

  do_filter_del(state, filter_id, &hw_filter);

  if( hw_filter >= 0 ) {
    if( state->hw_filters[hw_filter].refcount == 0 ) {
        /* The above check implies the current filter is unused. */
        *drv_id_out = state->hw_filters[hw_filter].drv_id;
        remove_exclusive_rxq_ownership(state, hw_filter);
        remove_drv = true;
    }
  }


  mutex_unlock(&state->driver_filters_mtx);
  return remove_drv;
}

static bool
ethertype_is_vlan(uint16_t ethertype_be)
{
  /* This list from SF-120734, i.e. what EF100 recognises */
  return ethertype_be == htons(0x9100) ||
         ethertype_be == htons(0x9200) ||
         ethertype_be == htons(0x9300) ||
         ethertype_be == htons(0x88a8) ||
         ethertype_be == htons(0x8100);
}

static bool is_ipv6_extension_hdr(uint8_t type)
{
  /* Capture only the hop-by-hop, routing and destination options, because
   * everything else somewhat implies a lack of (or unreadable) L4 */
  return type == 0 || type == 43 || type == 60;
}

bool efct_packet_matches_filter(struct efct_filter_state *state,
                                struct net_device *net_dev, int rxq,
                                const unsigned char* pkt, size_t pkt_len)
{
  struct efct_filter_node node;
  size_t l3_off;
  size_t l4_off = SIZE_MAX;
  size_t full_match_node_len = 0;
  size_t semi_wild_node_len = 0;
  struct netdev_hw_addr *hw_addr;
  bool is_mcast = false;
  bool is_outer_vlan;
  int32_t vlan;
  size_t mac_node_len = offsetof(struct efct_filter_node, loc_mac) +
                        sizeof(node.loc_mac);

  /* Should be checked by caller */
  EFHW_ASSERT(pkt_len >= ETH_HLEN);

  memset(&node, 0, sizeof(node));

  /* -------- layer 2 -------- */
  l3_off = ETH_HLEN;
  memcpy(&node.ethertype, pkt + l3_off - 2, 2);
  if( (is_outer_vlan = ethertype_is_vlan(node.ethertype)) ) {
    uint16_t vid;
    l3_off += 4;
    if( pkt_len >= l3_off ) {
      memcpy(&vid, pkt + l3_off - 4, 2);
      memcpy(&node.ethertype, pkt + l3_off - 2, 2);
      node.vlan = vid;

      /* Like U26z, we support only two VLAN nestings. The inner is only used
       * for skipping-over */
      if( ethertype_is_vlan(node.ethertype) ) {
        l3_off += 4;
        if( pkt_len >= l3_off )
          memcpy(&node.ethertype, pkt + l3_off - 2, 2);
      }
    }
  }
  memcpy(&node.loc_mac, pkt + 0, ETH_ALEN);
  /* Check for MAC+VLAN filter match */
  if( is_outer_vlan ) {
    if( filter_matches(state->filters.mac_vlan,
                      HASH_BITS(state->filters.mac_vlan),
                      &node, mac_node_len, true) )
      return true;
  }
  /* Check for MAC filter match */
  vlan = node.vlan;
  node.vlan = -1;
  if( filter_matches(state->filters.mac,
                      HASH_BITS(state->filters.mac),
                      &node, mac_node_len, true) )
    return true;
  node.vlan = vlan;

  /* Only filters inserted into the mac and mac_vlan tables include a MAC, so
   * unset this field now that we've failed to match those filter types. */
  memset(&node.loc_mac, 0, sizeof(node.loc_mac));

  /* If there's no VLAN tag then we leave node.vlan=0, making us match EF10
   * and EF100 firmware behaviour by having a filter with vid==0 match packets
   * with no VLAN tag in addition to packets with the (technically-illegal)
   * tag of 0 */

  /* -------- layer 3 -------- */
  if( node.ethertype == htons(ETH_P_IP) ) {
    if( pkt_len >= l3_off + 20 &&
        (pkt[l3_off] >> 4) == 4 &&
        (pkt[l3_off] & 0x0f) >= 5 ) {
      l4_off = l3_off + (pkt[l3_off] & 15) * 4;
      node.proto = pkt[l3_off + 9];
      memcpy(&node.u.ip4.rip, pkt + l3_off + 12, 4);
      memcpy(&node.u.ip4.lip, pkt + l3_off + 16, 4);
      is_mcast = CI_IP_IS_MULTICAST(node.u.ip4.lip);
      semi_wild_node_len = offsetof(struct efct_filter_node, u.ip4.rip);
      full_match_node_len = offsetof(struct efct_filter_node, u.ip4.rip) +
                            sizeof(node.u.ip4.rip);

      if( node.proto == IPPROTO_UDP &&
          (pkt[l3_off + 6] & 0x3f) | pkt[l3_off + 7] )
        return false;  /* fragment */
    }
  }
  else if( node.ethertype == htons(ETH_P_IPV6) ) {
    if( pkt_len >= l3_off + 40 &&
        (pkt[l3_off] >> 4) == 6 ) {
      int i;
      l4_off = l3_off + 40;
      node.proto = pkt[l3_off + 6];
      memcpy(node.u.ip6.rip, pkt + l3_off + 8, 16);
      memcpy(node.u.ip6.lip, pkt + l3_off + 24, 16);
      is_mcast = CI_IP6_IS_MULTICAST(node.u.ip6.lip);
      for( i = 0; i < 8 /* arbitrary cap */; ++i) {
        if( ! is_ipv6_extension_hdr(node.proto) || pkt_len < l4_off + 8 )
          break;
        node.proto = pkt[l4_off];
        l4_off += 8 * (1 + pkt[l4_off + 1]);
      }
      semi_wild_node_len = offsetof(struct efct_filter_node, u.ip6.rip);
      full_match_node_len = sizeof(struct efct_filter_node);
    }
  }

  /* -------- layer 4 -------- */
  if( (node.proto == IPPROTO_UDP || node.proto == IPPROTO_TCP) &&
      pkt_len >= l4_off + 8 ) {
    memcpy(&node.rport, pkt + l4_off, 2);
    memcpy(&node.lport, pkt + l4_off + 2, 2);

    if( filter_matches(state->filters.full_match,
                       HASH_BITS(state->filters.full_match),
                       &node, full_match_node_len, false) )
      return true;
    node.rport = 0;

    if( filter_matches(state->filters.semi_wild,
                          HASH_BITS(state->filters.semi_wild),
                          &node, semi_wild_node_len, false) )
      return true;
  }

  /* First check with the vlan included in the vlan filters */
  if( is_outer_vlan &&
      filter_matches(state->filters.ipproto_vlan,
                     HASH_BITS(state->filters.ipproto_vlan), &node,
                     offsetof(struct efct_filter_node, rport), true) )
    return true;
  vlan = node.vlan;
  node.vlan = -1;
  /* Then check ignoring the vlan in the non-vlan filters */
  if( filter_matches(state->filters.ipproto,
                     HASH_BITS(state->filters.ipproto),
                     &node, offsetof(struct efct_filter_node, rport), false) )
    return true;
  node.vlan = vlan;

  if( filter_matches(state->filters.ethertype,
                        HASH_BITS(state->filters.ethertype),
                        &node, offsetof(struct efct_filter_node, proto),
                        false) )
    return true;

  if( !is_mcast ) {
    if( state->block_kernel & EFCT_NIC_BLOCK_KERNEL_UNICAST ) {
      netdev_for_each_uc_addr(hw_addr, net_dev) {
        if( ether_addr_equal(pkt, hw_addr->addr) )
          return false;
      }
    }

    node.ethertype = EFCT_ETHERTYPE_IG_FILTER;
    node.proto = EFCT_PROTO_UCAST_IG_FILTER;
    if( filter_matches(state->filters.ethertype,
                          HASH_BITS(state->filters.ethertype),
                          &node, offsetof(struct efct_filter_node, rport),
                          false) )
      return true;
  }
  else {
    if( state->block_kernel & EFCT_NIC_BLOCK_KERNEL_MULTICAST ) {
      /* Iterate through our subscribed multicast MAC addresses, and check if they   *
      * are equal to the dest MAC of the incoming packet. If any of them match,     *
      * this this is _not_ a multicast mismatch, and we can return false here -  we *
      * don't need to deal with multicast mismatch filtering.                       */
      netdev_for_each_mc_addr(hw_addr, net_dev) {
        if( ether_addr_equal(pkt, hw_addr->addr) )
          return false;
      }
    }

    node.ethertype = EFCT_ETHERTYPE_IG_FILTER;
    node.proto = EFCT_PROTO_MCAST_IG_FILTER;
    if( filter_matches(state->filters.ethertype,
                          HASH_BITS(state->filters.ethertype),
                          &node, offsetof(struct efct_filter_node, rport),
                          false) )
      return true;
  }

  return false;
}

int
efct_filter_query(struct efct_filter_state *state, int filter_id,
                  struct efhw_filter_info *info)
{
  int rc;
  struct efct_filter_node *node;
  int exclusivity_id = 0;

  mutex_lock(&state->driver_filters_mtx);
  node = lookup_filter_by_id(state, filter_id, NULL);
  if( ! node ) {
    rc = -ENOENT;
  }
  else if( node->hw_filter >= 0 ) {
    info->hw_id = state->hw_filters[node->hw_filter].hw_id;
    info->rxq = state->hw_filters[node->hw_filter].rxq;
    exclusivity_id = state->exclusive_rxq_mapping[info->rxq];
    if ( exclusivity_id != 0 && exclusivity_id != EFHW_PD_NON_EXC_TOKEN )
      info->flags |= EFHW_FILTER_F_IS_EXCL;
    rc = 0;
  }
  else {
    info->hw_id = -1;
    /* No hardware filter was used, i.e. the traffic all goes to the default
     * queue 0 and the filter exists only in software to tell the kernel
     * networking stack to ignore these packets. */
    info->rxq = 0;
    info->flags = 0;
    rc = 0;
  }
  mutex_unlock(&state->driver_filters_mtx);
  return rc;
}

int
efct_multicast_block(struct efct_filter_state *state, bool block)
{
  /* Keep track of whether this has been set to allow us to tell if our *
   * MAC I/G filter is multicast-mis or multicast-all.                  */
  state->block_kernel = (block ?
                        state->block_kernel | EFCT_NIC_BLOCK_KERNEL_MULTICAST :
                        state->block_kernel & ~EFCT_NIC_BLOCK_KERNEL_MULTICAST);
  return 0;
}

int
efct_unicast_block(struct efct_filter_state *state, bool block)
{
  state->block_kernel = (block ?
                        state->block_kernel | EFCT_NIC_BLOCK_KERNEL_UNICAST :
                        state->block_kernel & ~EFCT_NIC_BLOCK_KERNEL_UNICAST);
  return 0;
}

#endif
