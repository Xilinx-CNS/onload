/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <etherfabric/capabilities.h>
#include <ci/efch/op_types.h>
#include <ci/efhw/efhw_types.h>
#include <ci/efrm/resource.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/efrm_client.h>

#include "efch.h"
#include "linux_char_internal.h"
#include "char_internal.h"

static void get_from_queue_sizes(struct efhw_nic* nic, int q_type,
                                 struct efch_capabilities_out* out)
{
  out->support_rc = 0;
  out->val = nic->q_sizes[q_type];
}


static void get_from_nic_flags(struct efhw_nic* nic, uint64_t flags,
                               struct efch_capabilities_out* out)
{
  if( (nic->flags & flags) == flags ) {
    out->support_rc = 0;
    out->val = 1;
  }
  else {
    out->support_rc = -EOPNOTSUPP;
    out->val = 0;
  }
}

int efch_capabilities_op(struct efch_capabilities_in* in,
                         struct efch_capabilities_out* out)
{
  int rc;
  struct efrm_client* client = NULL;
  struct efhw_nic* nic;
  struct efrm_resource* pd = NULL;

  if( in->ifindex >= 0 ) {
    /* Query by ifindex. */
    if ((rc = efrm_client_get(in->ifindex, NULL, NULL, &client)) < 0) {
      EFCH_ERR("%s: ERROR: ifindex=%d rc=%d", __FUNCTION__,
               in->ifindex, rc);
      goto out;
    }

    nic = efrm_client_get_nic(client);
  }
  else {
    /* Query by PD. */
    if( (rc = efch_lookup_rs(in->pd_fd, in->pd_id, EFRM_RESOURCE_PD,
                             &pd)) < 0 ) {
      EFCH_ERR("%s: ERROR: PD lookup failed: pd_id=%u rc=%d", __FUNCTION__,
               in->pd_id.index, rc);
      goto out;
    }

    nic = efrm_client_get_nic(pd->rs_client);
  }


  switch( in->cap ) {

  case EF_VI_CAP_PIO:
    get_from_nic_flags(nic, NIC_FLAG_PIO, out);
    break;
  case EF_VI_CAP_PIO_BUFFER_SIZE:
    if( nic->flags & NIC_FLAG_PIO ) {
      out->support_rc = 0;
      out->val = nic->pio_size;
    }
    else {
      out->support_rc = -EOPNOTSUPP;
      out->val = 0;
    }
    break;
  case EF_VI_CAP_PIO_BUFFER_COUNT:
    if( nic->flags & NIC_FLAG_PIO ) {
      out->support_rc = 0;
      out->val = nic->pio_num;
    }
    else {
      out->support_rc = -EOPNOTSUPP;
      out->val = 0;
    }
    break;
 
  case EF_VI_CAP_HW_MULTICAST_LOOPBACK:
    get_from_nic_flags(nic, NIC_FLAG_MCAST_LOOP_HW, out);
    break;
  case EF_VI_CAP_HW_MULTICAST_REPLICATION:
    get_from_nic_flags(nic, NIC_FLAG_HW_MULTICAST_REPLICATION, out);
    break;
 
  case EF_VI_CAP_HW_RX_TIMESTAMPING:
    get_from_nic_flags(nic, NIC_FLAG_HW_RX_TIMESTAMPING, out);
    break;
  case EF_VI_CAP_HW_TX_TIMESTAMPING:
    out->support_rc = -ENOSYS;
    out->val = 0;
    break;

  case EF_VI_CAP_PACKED_STREAM:
    get_from_nic_flags(nic, NIC_FLAG_PACKED_STREAM, out);
    break;

  case EF_VI_CAP_RX_FORCE_EVENT_MERGING:
    get_from_nic_flags(nic, NIC_FLAG_RX_FORCE_EVENT_MERGING, out);
    break;

  case EF_VI_CAP_PACKED_STREAM_BUFFER_SIZES:
    /* ef_vi only presents a subset of the supported buffer sizes, based on
     * whether NIC_FLAG_VAR_PACKED_STREAM is set.
     */
    if( nic->flags & NIC_FLAG_VAR_PACKED_STREAM ) {
      out->support_rc = 0;
      out->val = 1024 | 64;
      break;
    }
    else if( nic->flags & NIC_FLAG_PACKED_STREAM ) {
      out->support_rc = 0;
      out->val = 1024;
      break;
    }
    else {
      out->support_rc = -EOPNOTSUPP;
      out->val = 0;
      break;
    }
 
  case EF_VI_CAP_VPORTS:
    get_from_nic_flags(nic, NIC_FLAG_VPORTS, out);
    break;
 
  case EF_VI_CAP_PHYS_MODE:
    get_from_nic_flags(nic, NIC_FLAG_PHYS_MODE, out);
    break;
  case EF_VI_CAP_BUFFER_MODE:
    get_from_nic_flags(nic, NIC_FLAG_BUFFER_MODE, out);
    break;

  case EF_VI_CAP_MULTICAST_FILTER_CHAINING:
    get_from_nic_flags(nic, NIC_FLAG_MULTICAST_FILTER_CHAINING, out);
    break;

  case EF_VI_CAP_MAC_SPOOFING:
    get_from_nic_flags(nic, NIC_FLAG_MAC_SPOOFING, out);
    break;

  /* We are slightly making some assumptions here, as we don't install filters
   * directly, but rely on the net driver.  These check that the combos of
   * match criteria that we expect to be necessary for the filters that we
   * use are present.
   */
  case EF_VI_CAP_RX_FILTER_TYPE_UDP_LOCAL:
  case EF_VI_CAP_RX_FILTER_TYPE_TCP_LOCAL:
    get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_TYPE_IP_LOCAL, out);
    break;
  case EF_VI_CAP_RX_FILTER_TYPE_UDP_FULL:
  case EF_VI_CAP_RX_FILTER_TYPE_TCP_FULL:
    get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_TYPE_IP_FULL, out);
    break;
  case EF_VI_CAP_RX_FILTER_TYPE_IP_VLAN:
    get_from_nic_flags(nic, NIC_FLAG_VLAN_FILTERS, out);
    break;

  /* Hardware support for IPv6 doesn't imply software support - however this
   * API postdates addition of IPv6 support to ef_vi, so we can assume that
   * if the NIC supports it, it's available.
   */
  case EF_VI_CAP_RX_FILTER_TYPE_UDP6_LOCAL:
  case EF_VI_CAP_RX_FILTER_TYPE_TCP6_LOCAL:
    get_from_nic_flags(nic,NIC_FLAG_RX_FILTER_TYPE_IP_LOCAL |
                      NIC_FLAG_RX_FILTER_TYPE_IP6, out);
    break;
  case EF_VI_CAP_RX_FILTER_TYPE_UDP6_FULL:
  case EF_VI_CAP_RX_FILTER_TYPE_TCP6_FULL:
    get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_TYPE_IP_FULL |
                      NIC_FLAG_RX_FILTER_TYPE_IP6, out);
    break;
  case EF_VI_CAP_RX_FILTER_TYPE_IP6_VLAN:
    get_from_nic_flags(nic, NIC_FLAG_VLAN_FILTERS | NIC_FLAG_RX_FILTER_TYPE_IP6,
                      out);
    break;

  case EF_VI_CAP_RX_FILTER_TYPE_ETH_LOCAL:
    get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_TYPE_ETH_LOCAL, out);
    break;

  case EF_VI_CAP_RX_FILTER_TYPE_ETH_LOCAL_VLAN:
    get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_TYPE_ETH_LOCAL_VLAN, out);
    break;

  /* We can support "all" filters either by using an all filter, if the fw
   * supports it, or using a mismatch filter, together with kernel block in
   * the net driver, so check for either of the NIC capabilties.
   */
  case EF_VI_CAP_RX_FILTER_TYPE_UCAST_ALL:
    get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_TYPE_UCAST_ALL, out);
    if( out->support_rc != 0 )
      get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_TYPE_UCAST_MISMATCH, out);
    break;
  case EF_VI_CAP_RX_FILTER_TYPE_MCAST_ALL:
    get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_TYPE_MCAST_ALL, out);
    if( out->support_rc != 0 )
      get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_TYPE_MCAST_MISMATCH, out);
    break;
  case EF_VI_CAP_RX_FILTER_TYPE_UCAST_MISMATCH:
    get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_TYPE_UCAST_MISMATCH, out);
    break;
  case EF_VI_CAP_RX_FILTER_TYPE_MCAST_MISMATCH:
    get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_TYPE_MCAST_MISMATCH, out);
    break;

  case EF_VI_CAP_RX_FILTER_TYPE_SNIFF:
    out->support_rc = -ENOSYS;
    out->val = 0;
    break;
  case EF_VI_CAP_TX_FILTER_TYPE_SNIFF:
    out->support_rc = -ENOSYS;
    out->val = 0;
    break;

  case EF_VI_CAP_RX_FILTER_IP4_PROTO:
    get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_IP4_PROTO, out);
    break;

  case EF_VI_CAP_RX_FILTER_ETHERTYPE:
    get_from_nic_flags(nic, NIC_FLAG_RX_FILTER_ETHERTYPE, out);
    break;

  case EF_VI_CAP_RXQ_SIZES:
    get_from_queue_sizes(nic, EFHW_RXQ, out);
    break;

  case EF_VI_CAP_TXQ_SIZES:
    get_from_queue_sizes(nic, EFHW_TXQ, out);
    break;

  case EF_VI_CAP_EVQ_SIZES:
    get_from_queue_sizes(nic, EFHW_EVQ, out);
    break;

  case EF_VI_CAP_ZERO_RX_PREFIX:
    get_from_nic_flags(nic, NIC_FLAG_ZERO_RX_PREFIX, out);
    break;

  /* This checks availability of an ef_vi API flag.  This is policed based
   * on NIC arch, so we use the same test here.
   */
  case EF_VI_CAP_TX_PUSH_ALWAYS:
    out->support_rc = -EOPNOTSUPP;
    out->val = 0;
    break;

  case EF_VI_CAP_NIC_PACE:
    get_from_nic_flags(nic, NIC_FLAG_NIC_PACE, out);
    break;

  case EF_VI_CAP_RX_MERGE:
    get_from_nic_flags(nic, NIC_FLAG_RX_MERGE, out);
    break;

  case EF_VI_CAP_TX_ALTERNATIVES:
    get_from_nic_flags(nic, NIC_FLAG_TX_ALTERNATIVES, out);
    break;

  case EF_VI_CAP_TX_ALTERNATIVES_VFIFOS:
    get_from_nic_flags(nic, NIC_FLAG_TX_ALTERNATIVES, out);
    if( out->support_rc == 0 )
      out->val = nic->tx_alts_vfifos;
    break;

  case EF_VI_CAP_TX_ALTERNATIVES_CP_BUFFERS:
    get_from_nic_flags(nic, NIC_FLAG_TX_ALTERNATIVES, out);
    if( out->support_rc == 0 )
      out->val = nic->tx_alts_cp_bufs;
    break;

  case EF_VI_CAP_TX_ALTERNATIVES_CP_BUFFER_SIZE:
    get_from_nic_flags(nic, NIC_FLAG_TX_ALTERNATIVES, out);
    if( out->support_rc == 0 )
      out->val = nic->tx_alts_cp_buf_size;
    break;

  case EF_VI_CAP_RX_FW_VARIANT:
    out->support_rc = 0;
    out->val = nic->rx_variant;
    break;

  case EF_VI_CAP_TX_FW_VARIANT:
    out->support_rc = 0;
    out->val = nic->tx_variant;
    break;

  case EF_VI_CAP_CTPIO:
    get_from_nic_flags(nic, NIC_FLAG_TX_CTPIO, out);
    break;

  default:
    out->support_rc = -ENOSYS;
    out->val = 0;
  }

  if( client != NULL )
    efrm_client_put(client);
  if( pd != NULL )
    efrm_resource_release(pd);

 out:
   return rc;
}
