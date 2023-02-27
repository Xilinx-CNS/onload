/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#include <ci/driver/kernel_compat.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/ci_aux.h>
#include <ci/driver/ci_efct.h>
#include <ci/efhw/common.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/efct.h>
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
#include "efct.h"
#include "efct_superbuf.h"

#if CI_HAVE_EFCT_AUX


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


static void efct_check_for_flushes(struct work_struct *work);

int
efct_nic_rxq_bind(struct efhw_nic *nic, int qid, bool timestamp_req,
                  size_t n_hugepages, struct file* memfd, off_t* memfd_off,
                  struct efab_efct_rxq_uk_shm_q *shm,
                  unsigned wakeup_instance, struct efhw_efct_rxq *rxq)
{
  struct device *dev;
  struct efct_client_device* edev;
  struct efct_client* cli;
  int rc;

  struct efct_client_rxq_params qparams = {
    .qid = qid,
    .timestamp_req = timestamp_req,
    .n_hugepages = n_hugepages,
  };

  if( n_hugepages > CI_EFCT_MAX_HUGEPAGES ) {
    /* We'd fail later on in bind_rxq(), but only after we'd done a load of
     * shuffling-about and memory allocation. So let's have this early sanity
     * check as well */
    return -EINVAL;
  }
  efct_provide_bind_memfd(memfd, *memfd_off);
  EFCT_PRE(dev, edev, cli, nic, rc);

  rc = __efct_nic_rxq_bind(edev, cli, &qparams, nic->arch_extra, n_hugepages, shm, wakeup_instance, rxq);
  EFCT_POST(dev, edev, cli, nic, rc);
  efct_unprovide_bind_memfd(memfd_off);
  return rc;
}


void
efct_nic_rxq_free(struct efhw_nic *nic, struct efhw_efct_rxq *rxq,
                  efhw_efct_rxq_free_func_t *freer)
{
  struct device *dev;
  struct efct_client_device* edev;
  struct efct_client* cli;
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc)
  __efct_nic_rxq_free(edev, cli, rxq, freer);
  EFCT_POST(dev, edev, cli, nic, rc);
}


int
efct_get_hugepages(struct efhw_nic *nic, int hwqid,
                   struct efct_client_hugepage *pages, size_t n_pages)
{
  struct device *dev;
  struct efct_client_device* edev;
  struct efct_client* cli;
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc)
  rc = edev->ops->get_hugepages(cli, hwqid, pages, n_pages);
  EFCT_POST(dev, edev, cli, nic, rc);
  return rc;
}


static size_t
efct_max_shared_rxqs(struct efhw_nic *nic)
{
  struct efhw_nic_efct* efct = nic->arch_extra;
  return efct->rxq_n;
}

/*----------------------------------------------------------------------------
 *
 * Initialisation and configuration discovery
 *
 *---------------------------------------------------------------------------*/
static int
efct_nic_license_check(struct efhw_nic *nic, const uint32_t feature,
                       int* licensed)
{
  return 0;
}


static int
efct_nic_v3_license_check(struct efhw_nic *nic, const uint64_t app_id,
                          int* licensed)
{
  return 0;
}


static int
efct_nic_license_challenge(struct efhw_nic *nic,
                           const uint32_t feature,
                           const uint8_t* challenge,
                           uint32_t* expiry,
                           uint8_t* signature)
{
  return 0;
}


static int
efct_nic_v3_license_challenge(struct efhw_nic *nic,
                              const uint64_t app_id,
                              const uint8_t* challenge,
                              uint32_t* expiry,
                              uint32_t* days,
                              uint8_t* signature,
                              uint8_t* base_mac,
                              uint8_t* vadaptor_mac)
{
  return 0;
}


static void
efct_nic_tweak_hardware(struct efhw_nic *nic)
{
  nic->flags |= NIC_FLAG_PHYS_CONTIG_EVQ;
  nic->flags |= NIC_FLAG_EVQ_IRQ;
}


static int
efct_nic_init_hardware(struct efhw_nic *nic,
                       struct efhw_ev_handler *ev_handlers,
                       const uint8_t *mac_addr)
{
  memcpy(nic->mac_addr, mac_addr, ETH_ALEN);
  nic->ev_handlers = ev_handlers;
  nic->flags |= NIC_FLAG_TX_CTPIO | NIC_FLAG_CTPIO_ONLY
             | NIC_FLAG_HW_RX_TIMESTAMPING | NIC_FLAG_HW_TX_TIMESTAMPING
             | NIC_FLAG_RX_SHARED
             | NIC_FLAG_RX_FILTER_TYPE_IP_LOCAL
             | NIC_FLAG_RX_FILTER_TYPE_IP_FULL
             | NIC_FLAG_VLAN_FILTERS
             | NIC_FLAG_RX_FILTER_ETHERTYPE
             | NIC_FLAG_HW_MULTICAST_REPLICATION
             ;
  efct_nic_tweak_hardware(nic);
  return 0;
}


void efct_nic_filter_init(struct efhw_nic_efct *efct)
{
  if( ! filter_hash_table_seed_inited ) {
    filter_hash_table_seed_inited = true;
    filter_hash_table_seed = get_random_int();
  }

#define ACTION_INIT_HASH_TABLE(F) \
        hash_init(efct->filters.F);
  FOR_EACH_FILTER_CLASS(ACTION_INIT_HASH_TABLE)
}


static void
efct_nic_release_hardware(struct efhw_nic* nic)
{
#ifndef NDEBUG
  struct efhw_nic_efct* efct = nic->arch_extra;

#define ACTION_ASSERT_HASH_TABLE_EMPTY(F) \
    EFHW_ASSERT(efct->filters.F##_n == 0);
  FOR_EACH_FILTER_CLASS(ACTION_ASSERT_HASH_TABLE_EMPTY)
#endif
}

/*--------------------------------------------------------------------
 *
 * Event Management - and SW event posting
 *
 *--------------------------------------------------------------------*/

/* This function will enable the given event queue with the requested
 * properties.
 */
static int
efct_nic_event_queue_enable(struct efhw_nic *nic, uint32_t client_id,
                            struct efhw_evq_params *efhw_params)
{
  struct device *dev;
  struct efct_client_device* edev;
  struct efct_client* cli;
  struct efct_client_evq_params qparams = {
    .qid = efhw_params->evq,
    .entries = efhw_params->evq_size,
    /* We don't provide a pci_dev to enable queue memory to be mapped for us,
     * so we're given plain physical addresses.
     */
    .q_page = pfn_to_page(efhw_params->dma_addrs[0] >> PAGE_SHIFT),
    .page_offset = 0,
    .q_size = efhw_params->evq_size * sizeof(efhw_event_t),
    .subscribe_time_sync = efhw_params->flags & EFHW_VI_TX_TIMESTAMPS,
    .unsol_credit = efhw_params->flags & EFHW_VI_TX_TIMESTAMPS ? CI_CFG_TIME_SYNC_EVENT_EVQ_CAPACITY  - 1 : 0,
  };
  struct efhw_nic_efct *efct = nic->arch_extra;
  struct efhw_nic_efct_evq *efct_evq;
  int rc;
#ifndef NDEBUG
  int i;
#endif

  /* This is a dummy EVQ, so nothing to do. */
  if( efhw_params->evq >= efct->evq_n )
    return 0;

  efct_evq = &efct->evq[efhw_params->evq];

  /* We only look at the first page because this memory should be physically
   * contiguous, but the API provides us with an address per 4K (NIC page)
   * chunk, so sanity check that there are enough pages for the size of queue
   * we're asking for.
   */
  EFHW_ASSERT(efhw_params->n_pages * EFHW_NIC_PAGES_IN_OS_PAGE * CI_PAGE_SIZE
	      >= qparams.q_size);
#ifndef NDEBUG
  /* We should have been provided with physical addresses of physically
   * contiguous memory, so sanity check the addresses look right.
   */
  for( i = 1; i < efhw_params->n_pages; i++ ) {
    EFHW_ASSERT(efhw_params->dma_addrs[i] - efhw_params->dma_addrs[i-1] ==
		EFHW_NIC_PAGE_SIZE);
  }
#endif

  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = edev->ops->init_evq(cli, &qparams);
  EFCT_POST(dev, edev, cli, nic, rc);

  if( rc == 0 ) {
    efct_evq->nic = nic;
    efct_evq->base = phys_to_virt(efhw_params->dma_addrs[0]);
    efct_evq->capacity = efhw_params->evq_size;
    atomic_set(&efct_evq->queues_flushing, 0);
    INIT_DELAYED_WORK(&efct_evq->check_flushes, efct_check_for_flushes);
  }

  return rc;
}

static void
efct_nic_event_queue_disable(struct efhw_nic *nic, uint32_t client_id,
                             uint evq, int time_sync_events_enabled)
{
  struct device *dev;
  struct efct_client_device* edev;
  struct efct_client* cli;
  struct efhw_nic_efct *efct = nic->arch_extra;
  struct efhw_nic_efct_evq *efct_evq;
  int rc = 0;

  /* This is a dummy EVQ, so nothing to do. */
  if( evq >= efct->evq_n )
    return;

  efct_evq = &efct->evq[evq];

  /* In the normal case we'll be disabling the queue because all outstanding
   * flushes have completed. However, in the case of a flush timeout there may
   * still be a work item scheduled. We want to avoid it rescheduling if so.
   */
  atomic_set(&efct_evq->queues_flushing, -1);
  cancel_delayed_work_sync(&efct_evq->check_flushes);

  EFCT_PRE(dev, edev, cli, nic, rc);
  edev->ops->free_evq(cli, evq);
  EFCT_POST(dev, edev, cli, nic, rc);
}

static void
efct_nic_wakeup_request(struct efhw_nic *nic, volatile void __iomem* io_page,
                        int vi_id, int rptr)
{
	ci_dword_t dwrptr;

	__DWCHCK(ERF_HZ_READ_IDX);
	__RANGECHCK(rptr, ERF_HZ_READ_IDX_WIDTH);
	__RANGECHCK(vi_id, ERF_HZ_EVQ_ID_WIDTH);

	CI_POPULATE_DWORD_2(dwrptr,
			    ERF_HZ_EVQ_ID, vi_id,
			    ERF_HZ_READ_IDX, rptr);
	writel(dwrptr.u32[0], nic->int_prime_reg);
	mmiowb();
}

static void efct_nic_sw_event(struct efhw_nic *nic, int data, int evq)
{
}

static bool efct_accept_vi_constraints(struct efhw_nic *nic, int low,
                                       unsigned order, void* arg)
{
  struct efhw_vi_constraints *vc = arg;
  struct efhw_nic_efct *efct = nic->arch_extra;

  /* If this VI will want a TXQ it needs a HW EVQ. These all fall within
   * the range [0,efct->evq_n). We use the space above that to provide
   * dummy EVQS. */
  if( vc->want_txq ) {
    if( low < efct->evq_n )
      return efct->evq[low].txq != EFCT_EVQ_NO_TXQ;
    else
      return false;
  }
  else {
    return low >= efct->evq_n;
  }
}

/*--------------------------------------------------------------------
 *
 * EF10 specific event callbacks
 *
 *--------------------------------------------------------------------*/

static int
efct_handle_event(struct efhw_nic *nic, efhw_event_t *ev, int budget)
{
  return -EOPNOTSUPP;
}


/*----------------------------------------------------------------------------
 *
 * TX Alternatives
 *
 *---------------------------------------------------------------------------*/


static int
efct_tx_alt_alloc(struct efhw_nic *nic, int tx_q_id, int num_alt,
                  int num_32b_words, unsigned *cp_id_out, unsigned *alt_ids_out)
{
  return -EOPNOTSUPP;
}


static int
efct_tx_alt_free(struct efhw_nic *nic, int num_alt, unsigned cp_id,
                 const unsigned *alt_ids)
{
  return -EOPNOTSUPP;
}


/*----------------------------------------------------------------------------
 *
 * DMAQ low-level register interface
 *
 *---------------------------------------------------------------------------*/


static int
efct_dmaq_tx_q_init(struct efhw_nic *nic, uint32_t client_id,
                    struct efhw_dmaq_params *txq_params)
{
  struct device *dev;
  struct efct_client_device* edev;
  struct efct_client* cli;
  struct efhw_nic_efct *efct = nic->arch_extra;
  struct efhw_nic_efct_evq *efct_evq = &efct->evq[txq_params->evq];
  struct efct_client_txq_params params = {
    .evq = txq_params->evq,
    .qid = efct_evq->txq,
    .label = txq_params->tag,
  };
  int rc;

  EFHW_ASSERT(txq_params->evq < efct->evq_n);
  EFHW_ASSERT(params.qid != EFCT_EVQ_NO_TXQ);

  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = edev->ops->init_txq(cli, &params);
  EFCT_POST(dev, edev, cli, nic, rc);

  if( rc >= 0 ) {
    txq_params->tx.qid_out = rc;
    rc = 0;
  }

  return 0;
}


static int
efct_dmaq_rx_q_init(struct efhw_nic *nic, uint32_t client_id,
                    struct efhw_dmaq_params *params)
{
  /* efct doesn't do rxqs like this, so nothing to do here */
  return 0;
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - mid level API
 *
 *--------------------------------------------------------------------*/


static void efct_check_for_flushes(struct work_struct *work)
{
  struct efhw_nic_efct_evq *evq =  container_of(work, struct efhw_nic_efct_evq,
                                                check_flushes.work);
  ci_qword_t *event = evq->base;
  bool found_flush = false;
  int txq;
  int i;

  /* In the case of a flush timeout this may have been rescheduled following
   * evq disable. In which case bail out now.
   */
  if( atomic_read(&evq->queues_flushing) < 0 )
    return;

  for(i = 0; i < evq->capacity; i++) {
    if(CI_QWORD_FIELD(*event, EFCT_EVENT_TYPE) == EFCT_EVENT_TYPE_CONTROL &&
       CI_QWORD_FIELD(*event, EFCT_CTRL_SUBTYPE) == EFCT_CTRL_EV_FLUSH &&
       CI_QWORD_FIELD(*event, EFCT_FLUSH_TYPE) == EFCT_FLUSH_TYPE_TX) {
      found_flush = true;
      txq = CI_QWORD_FIELD(*event, EFCT_FLUSH_QUEUE_ID);
      efhw_handle_txdmaq_flushed(evq->nic, txq);
      break;
    }
    event++;
  }

  if( !found_flush || !atomic_dec_and_test(&evq->queues_flushing) ) {
    EFHW_ERR("%s: WARNING: No TX flush found, scheduling delayed work",
             __FUNCTION__);
    schedule_delayed_work(&evq->check_flushes, 100);
  }
}


static int efct_flush_tx_dma_channel(struct efhw_nic *nic,
                                     uint32_t client_id, uint dmaq, uint evq)
{
  struct device *dev;
  struct efct_client_device* edev;
  struct efct_client* cli;
  struct efhw_nic_efct *efct = nic->arch_extra;
  struct efhw_nic_efct_evq *efct_evq = &efct->evq[evq];
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc);
  edev->ops->free_txq(cli, dmaq);
  EFCT_POST(dev, edev, cli, nic, rc);

  atomic_inc(&efct_evq->queues_flushing);
  schedule_delayed_work(&efct_evq->check_flushes, 0);

  return 0;
}


static int efct_flush_rx_dma_channel(struct efhw_nic *nic,
                                     uint32_t client_id, uint dmaq)
{
  /* rxqs are a software-only concept, no flush required */
  return -EALREADY;
}


static int efct_translate_dma_addrs(struct efhw_nic* nic,
                                    const dma_addr_t *src, dma_addr_t *dst,
                                    int n)
{
  /* All efct NICs have 1:1 mappings */
  memmove(dst, src, n * sizeof(src[0]));
  return 0;
}

/*--------------------------------------------------------------------
 *
 * Buffer table - API
 *
 *--------------------------------------------------------------------*/

static const int __efct_nic_buffer_table_get_orders[] = {};


static int
efct_nic_buffer_table_alloc(struct efhw_nic *nic, int owner, int order,
                            struct efhw_buffer_table_block **block_out,
                            int reset_pending)
{
  return -EOPNOTSUPP;
}


static int
efct_nic_buffer_table_realloc(struct efhw_nic *nic, int owner, int order,
                              struct efhw_buffer_table_block *block)
{
  return -EOPNOTSUPP;
}


static void
efct_nic_buffer_table_free(struct efhw_nic *nic,
                           struct efhw_buffer_table_block *block,
                           int reset_pending)
{
}


static int
efct_nic_buffer_table_set(struct efhw_nic *nic,
                          struct efhw_buffer_table_block *block,
                          int first_entry, int n_entries,
                          dma_addr_t *dma_addrs)
{
  return -EOPNOTSUPP;
}


static void
efct_nic_buffer_table_clear(struct efhw_nic *nic,
                            struct efhw_buffer_table_block *block,
                            int first_entry, int n_entries)
{
}


/*--------------------------------------------------------------------
 *
 * Port Sniff
 *
 *--------------------------------------------------------------------*/

static int
efct_nic_set_tx_port_sniff(struct efhw_nic *nic, int instance, int enable,
                           int rss_context)
{
  return -EOPNOTSUPP;
}


static int
efct_nic_set_port_sniff(struct efhw_nic *nic, int instance, int enable,
                        int promiscuous, int rss_context)
{
  return -EOPNOTSUPP;
}

/*--------------------------------------------------------------------
 *
 * Error Stats
 *
 *--------------------------------------------------------------------*/

static int
efct_get_rx_error_stats(struct efhw_nic *nic, int instance,
                        void *data, int data_len, int do_reset)
{
  return -EOPNOTSUPP;
}

/*--------------------------------------------------------------------
 *
 * Dynamic client IDs
 *
 *--------------------------------------------------------------------*/

static int
efct_client_alloc(struct efhw_nic *nic, uint32_t parent, uint32_t *id)
{
  /* The specific return value of ENOSYS is recognised by clients to mean that
   * we don't provide or require client ids.
   */
  return -ENOSYS;
}


static int
efct_client_free(struct efhw_nic *nic, uint32_t id)
{
  return -EOPNOTSUPP;
}


static int
efct_vi_set_user(struct efhw_nic *nic, uint32_t vi_instance, uint32_t user)
{
  return -EOPNOTSUPP;
}

/*--------------------------------------------------------------------
 *
 * Filtering
 *
 *--------------------------------------------------------------------*/
static int
efct_rss_alloc(struct efhw_nic *nic, const u32 *indir, const u8 *key,
               u32 nic_rss_flags, int num_qs, u32 *rss_context_out)
{
  return -EOPNOTSUPP;
}

static int
efct_rss_update(struct efhw_nic *nic, const u32 *indir, const u8 *key,
                u32 nic_rss_flags, u32 rss_context)
{
  return -EOPNOTSUPP;
}

static int
efct_rss_free(struct efhw_nic *nic, u32 rss_context)
{
  return -EOPNOTSUPP;
}

static int
efct_rss_flags(struct efhw_nic *nic, u32 *flags_out)
{
  return -EOPNOTSUPP;
}

static uint32_t zero_remote_port(uint32_t l4_4_bytes)
{
  return htonl(ntohl(l4_4_bytes) & 0xffff);
}

static int filter_spec_to_ethtool_spec(const struct efx_filter_spec *src,
                                       struct ethtool_rx_flow_spec *dst)
{
  int rc = efx_spec_to_ethtool_flow(src, dst);
  if( rc < 0 )
    return rc;

  /* Blat out the remote fields: we can soft-filter them even though the
   * hardware can't */
  switch (dst->flow_type & ~FLOW_EXT) {
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
    break;
  default:
    return -EPROTONOSUPPORT;
  }

  if (dst->flow_type & FLOW_EXT) {
    if (dst->m_ext.vlan_etype || dst->m_ext.vlan_tci != 0xffff ||
        dst->m_ext.data[0] || dst->m_ext.data[1])
      return -EPROTONOSUPPORT;
    dst->flow_type &= ~FLOW_EXT;
  }

  return 0;
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
 * filters for one specific class of filter. */
static bool
filter_matches(struct hlist_head* table, size_t hash_bits,
               struct efct_filter_node* node, size_t node_len)
{
  bool found;

  rcu_read_lock();
  found = find_one_filter(table, hash_bits, node, node_len);
  if( ! found ) {
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
                 struct efhw_nic_efct *efct, size_t node_len, bool allow_dups)
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
                      (get_random_int() << (FILTER_CLASS_BITS + hash_bits));
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
  }

  if ( node->hw_filter >= 0 )
    ++efct->hw_filters[node->hw_filter].refcount;
  return 0;
}

static void do_filter_del(struct efhw_nic_efct *efct, int filter_id,
                         int* hw_filter)
{
  int clasi = 0;
  int clas = get_filter_class(filter_id);

  *hw_filter = -1;
#define ACTION_DEL_BY_FILTER_ID(F) \
    if( clasi++ == clas ) { \
      int bkt = (filter_id >> FILTER_CLASS_BITS) & \
                (HASH_SIZE(efct->filters.F) - 1); \
      struct efct_filter_node* node; \
      hlist_for_each_entry_rcu(node, &efct->filters.F[bkt], node) { \
        if( node->filter_id == filter_id ) { \
          EFHW_ASSERT(efct->filters.F##_n > 0); \
          *hw_filter = node->hw_filter; \
          if ( node->hw_filter >= 0 ) {\
            --efct->hw_filters[node->hw_filter].refcount; \
          } \
          if ( --node->refcount == 0 ) { \
            hash_del_rcu(&node->node); \
            --efct->filters.F##_n; \
            kfree_rcu(node, free_list); \
          } \
          return; \
        } \
      } \
    }
  FOR_EACH_FILTER_CLASS(ACTION_DEL_BY_FILTER_ID)
}

static int
efct_filter_insert(struct efhw_nic *nic, struct efx_filter_spec *spec,
                   int *rxq, const struct cpumask *mask, unsigned flags)
{
  int rc;
  struct ethtool_rx_flow_spec hw_filter;
  struct efct_client_filter_params params;
  struct efhw_nic_efct *efct = nic->arch_extra;
  struct device *dev;
  struct efct_client_device* edev;
  struct efct_client* cli;
  struct efct_filter_node node;
  size_t node_len;
  int clas;
  bool insert_hw_filter = false;
  unsigned no_vlan_flags = spec->match_flags & ~EFX_FILTER_MATCH_OUTER_VID;

  if( flags & EFHW_FILTER_F_REPLACE )
    return -EOPNOTSUPP;
  rc = filter_spec_to_ethtool_spec(spec, &hw_filter);
  if( rc < 0 )
    return rc;
  params = (struct efct_client_filter_params){
    .spec = &hw_filter,
    .mask = mask ? mask : cpu_all_mask,
  };
  if( *rxq >= 0 )
    hw_filter.ring_cookie = *rxq;
  if( flags & EFHW_FILTER_F_ANY_RXQ )
    params.flags |= EFCT_CLIENT_FILTER_F_ANYQUEUE_LOOSE;
  if( flags & EFHW_FILTER_F_PREF_RXQ )
    params.flags |= EFCT_CLIENT_FILTER_F_PREF_QUEUE;
  if( flags & EFHW_FILTER_F_EXCL_RXQ )
    params.flags |= EFCT_CLIENT_FILTER_F_EXCLUSIVE_QUEUE;


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
  else {
    return -EPROTONOSUPPORT;
  }

  if( spec->match_flags & EFX_FILTER_MATCH_OUTER_VID )
    node.vlan = spec->outer_vid;

  /* Step 2 of 2: Insert efct_filter_node in to the correct hash table */
  mutex_lock(&efct->driver_filters_mtx);

  if( spec->match_flags & EFX_FILTER_MATCH_LOC_HOST &&
      node.ethertype == htons(ETH_P_IP) ) {
    int i;
    int avail = -1;
    for( i = 0; i < efct->hw_filters_n; ++i ) {
      if( ! efct->hw_filters[i].refcount )
        avail = i;
      else {
        if( efct->hw_filters[i].proto == node.proto &&
            efct->hw_filters[i].ip == node.u.ip4.lip &&
            efct->hw_filters[i].port == node.lport ) {
          if( ! (flags & (EFHW_FILTER_F_ANY_RXQ | EFHW_FILTER_F_PREF_RXQ) ) &&
              *rxq >= 0 && *rxq != efct->hw_filters[i].rxq ) {
            mutex_unlock(&efct->driver_filters_mtx);
            return -EEXIST;
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
        efct->hw_filters[avail].proto = node.proto;
        efct->hw_filters[avail].ip = node.u.ip4.lip;
        efct->hw_filters[avail].port = node.lport;
        insert_hw_filter = true;
      }
    }
  }

#define ACTION_DO_FILTER_INSERT(F) \
    if( clas == FILTER_CLASS_##F ) { \
      rc = do_filter_insert(clas, efct->filters.F, &efct->filters.F##_n, \
                            HASH_BITS(efct->filters.F), MAX_ALLOWED_##F, \
                            &node, efct, node_len, clas != FILTER_CLASS_full_match); \
    }
  FOR_EACH_FILTER_CLASS(ACTION_DO_FILTER_INSERT)

  if( rc < 0 ) {
    mutex_unlock(&efct->driver_filters_mtx);
    return rc;
  }

  if( insert_hw_filter ) {
    EFCT_PRE(dev, edev, cli, nic, rc);
    rc = edev->ops->filter_insert(cli, &params);
    EFCT_POST(dev, edev, cli, nic, rc);
  }

  if( rc < 0 ) {
    int unused;
    do_filter_del(efct, node.filter_id, &unused);
  }
  else {
    if( node.hw_filter >= 0 ) {
      if( insert_hw_filter ) {
        efct->hw_filters[node.hw_filter].rxq = params.rxq_out;
        efct->hw_filters[node.hw_filter].drv_id = params.filter_id_out;
      }
      *rxq = efct->hw_filters[node.hw_filter].rxq;
    }
    else {
      *rxq = 0;
    }
  }
  mutex_unlock(&efct->driver_filters_mtx);

  return rc < 0 ? rc : node.filter_id;
}

static void
efct_filter_remove(struct efhw_nic *nic, int filter_id)
{
  struct efhw_nic_efct *efct = nic->arch_extra;
  struct device *dev;
  struct efct_client_device* edev;
  struct efct_client* cli;
  int rc;
  int hw_filter;
  int drv_id = -1;

  mutex_lock(&efct->driver_filters_mtx);
  do_filter_del(efct, filter_id, &hw_filter);
  if( hw_filter >= 0 ) {
    if( efct->hw_filters[hw_filter].refcount == 0 )
      drv_id = efct->hw_filters[hw_filter].drv_id;
  }

  mutex_unlock(&efct->driver_filters_mtx);

  if( drv_id >= 0 ) {
    EFCT_PRE(dev, edev, cli, nic, rc);
    rc = edev->ops->filter_remove(cli, drv_id);
    EFCT_POST(dev, edev, cli, nic, rc);
  }
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

bool efct_packet_handled(void *driver_data, int rxq, bool flow_lookup,
                         const void* meta, const void* payload)
{
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) driver_data;
  struct efct_filter_node node;
  const unsigned char* pkt = payload;
  size_t l3_off;
  size_t l4_off = SIZE_MAX;
  size_t full_match_node_len = 0;
  size_t semi_wild_node_len = 0;
  const ci_oword_t* header = meta;
  size_t pkt_len = CI_OWORD_FIELD(*header, EFCT_RX_HEADER_PACKET_LENGTH);
  struct netdev_hw_addr *hw_addr;
  bool is_mcast = false;

  if( pkt_len < ETH_HLEN )
    return false;

  /* This is asserting the next_frame_loc for the wrong packet: we should be
   * looking at the preceeding metadata. Still, having it will probably
   * detect hardware that doesn't use a fixed value fairly rapidly. */
  EFHW_ASSERT(CI_OWORD_FIELD(*header, EFCT_RX_HEADER_NEXT_FRAME_LOC) == 1);
  pkt += EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
  memset(&node, 0, sizeof(node));

  /* -------- layer 2 -------- */
  l3_off = ETH_HLEN;
  memcpy(&node.ethertype, pkt + l3_off - 2, 2);
  if( ethertype_is_vlan(node.ethertype) ) {
    uint16_t tpid;
    l3_off += 4;
    if( pkt_len >= l3_off ) {
      memcpy(&tpid, pkt + l3_off - 4, 2);
      memcpy(&node.ethertype, pkt + l3_off - 2, 2);
      node.vlan = tpid;

      /* Like U26z, we support only two VLAN nestings. The inner is only used
       * for skipping-over */
      if( ethertype_is_vlan(node.ethertype) ) {
        l3_off += 4;
        if( pkt_len >= l3_off )
          memcpy(&node.ethertype, pkt + l3_off - 2, 2);
      }
    }
  }
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

    if( filter_matches(efct->filters.full_match,
                       HASH_BITS(efct->filters.full_match),
                       &node, full_match_node_len) )
      return true;
    node.rport = 0;

    if( filter_matches(efct->filters.semi_wild,
                          HASH_BITS(efct->filters.semi_wild),
                          &node, semi_wild_node_len) )
      return true;
  }

  if( filter_matches(efct->filters.ethertype,
                        HASH_BITS(efct->filters.ethertype),
                        &node, offsetof(struct efct_filter_node, proto)) )
    return true;

  if( !is_mcast ) {
    if( efct->block_kernel & EFCT_NIC_BLOCK_KERNEL_UNICAST ) {
      netdev_for_each_uc_addr(hw_addr, efct->nic->net_dev) {
        if( ether_addr_equal(pkt, hw_addr->addr) )
          return false;
      }
    }

    node.ethertype = EFCT_ETHERTYPE_IG_FILTER;
    node.proto = EFCT_PROTO_UCAST_IG_FILTER;
    if( filter_matches(efct->filters.ethertype,
                          HASH_BITS(efct->filters.ethertype),
                          &node, offsetof(struct efct_filter_node, rport)) )
      return true;
  }
  else {
    if( efct->block_kernel & EFCT_NIC_BLOCK_KERNEL_MULTICAST ) {
      /* Iterate through our subscribed multicast MAC addresses, and check if they   *
      * are equal to the dest MAC of the incoming packet. If any of them match,     *
      * this this is _not_ a multicast mismatch, and we can return false here -  we *
      * don't need to deal with multicast mismatch filtering.                       */
      netdev_for_each_mc_addr(hw_addr, efct->nic->net_dev) {
        if( ether_addr_equal(pkt, hw_addr->addr) )
          return false;
      }
    }

    node.ethertype = EFCT_ETHERTYPE_IG_FILTER;
    node.proto = EFCT_PROTO_MCAST_IG_FILTER;
    if( filter_matches(efct->filters.ethertype,
                          HASH_BITS(efct->filters.ethertype),
                          &node, offsetof(struct efct_filter_node, rport)) )
      return true;
  }

  return false;
}

static int
efct_filter_redirect(struct efhw_nic *nic, int filter_id,
                     struct efx_filter_spec *spec)
{
  return -EOPNOTSUPP;
}

static int
efct_multicast_block(struct efhw_nic *nic, bool block)
{
  /* Keep track of whether this has been set to allow us to tell if our *
   * MAC I/G filter is multicast-mis or multicast-all.                  */
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) nic->arch_extra;
  efct->block_kernel = (block ?
                        efct->block_kernel | EFCT_NIC_BLOCK_KERNEL_MULTICAST :
                        efct->block_kernel & ~EFCT_NIC_BLOCK_KERNEL_MULTICAST);
  return 0;
}

static int
efct_unicast_block(struct efhw_nic *nic, bool block)
{
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) nic->arch_extra;
  efct->block_kernel = (block ?
                        efct->block_kernel | EFCT_NIC_BLOCK_KERNEL_UNICAST :
                        efct->block_kernel & ~EFCT_NIC_BLOCK_KERNEL_UNICAST);
  return 0;
}

/*--------------------------------------------------------------------
 *
 * vports
 *
 *--------------------------------------------------------------------*/
static int
efct_vport_alloc(struct efhw_nic *nic, u16 vlan_id, u16 *vport_handle_out)
{
  return -EOPNOTSUPP;
}

static int
efct_vport_free(struct efhw_nic *nic, u16 vport_handle)
{
  return -EOPNOTSUPP;
}

/*--------------------------------------------------------------------
 *
 * AF_XDP
 *
 *--------------------------------------------------------------------*/
static int
efct_dmaq_kick(struct efhw_nic* nic, int instance)
{
  return 0;
}

static void*
efct_af_xdp_mem(struct efhw_nic* nic, int instance)
{
  return NULL;
}

static int
efct_af_xdp_init(struct efhw_nic* nic, int instance, int chunk_size,
                 int headroom, struct efhw_page_map* pages_out)
{
  return 0;
}

/*--------------------------------------------------------------------
 *
 * Device
 *
 *--------------------------------------------------------------------*/
static struct pci_dev*
efct_get_pci_dev(struct efhw_nic *nic)
{
  return NULL;
}

static int
efct_vi_io_region(struct efhw_nic *nic, int instance, size_t* size_out,
                  resource_size_t* addr_out)
{
  struct device *dev;
  struct efct_client_device* edev;
  struct efct_client* cli;
  union efct_client_param_value val;
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc)
  rc = edev->ops->get_param(cli, EFCT_CLIENT_EVQ_WINDOW, &val);
  EFCT_POST(dev, edev, cli, nic, rc);

  *size_out = val.evq_window.stride;
  *addr_out = val.evq_window.base;
  *addr_out += (instance - nic->vi_min) * val.evq_window.stride;

  return rc;
}

static int
efct_inject_reset_ev(struct efhw_nic* nic, void* base, unsigned capacity,
                      const volatile uint32_t* evq_ptr)
{
	return -EOPNOTSUPP;
}

/*--------------------------------------------------------------------
 *
 * CTPIO
 *
 *--------------------------------------------------------------------*/
static int
efct_ctpio_addr(struct efhw_nic* nic, int instance, resource_size_t* addr)
{
  struct device *dev;
  struct efct_client_device* edev;
  struct efct_client* cli;
  size_t region_size;
  int rc;

  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = edev->ops->ctpio_addr(cli, instance, addr, &region_size);
  EFCT_POST(dev, edev, cli, nic, rc);

  /* Currently we assume throughout onload that we have a 4k region */
  if( (rc == 0) && (region_size != 0x1000) )
    return -EOPNOTSUPP;

  return rc;
}

/*--------------------------------------------------------------------
 *
 * Abstraction Layer Hooks
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops efct_char_functional_units = {
  efct_nic_init_hardware,
  efct_nic_tweak_hardware,
  efct_nic_release_hardware,
  efct_nic_event_queue_enable,
  efct_nic_event_queue_disable,
  efct_nic_wakeup_request,
  efct_nic_sw_event,
  efct_handle_event,
  efct_accept_vi_constraints,
  efct_dmaq_tx_q_init,
  efct_dmaq_rx_q_init,
  efct_flush_tx_dma_channel,
  efct_flush_rx_dma_channel,
  efct_translate_dma_addrs,
  __efct_nic_buffer_table_get_orders,
  0,
  efct_nic_buffer_table_alloc,
  efct_nic_buffer_table_realloc,
  efct_nic_buffer_table_free,
  efct_nic_buffer_table_set,
  efct_nic_buffer_table_clear,
  efct_nic_set_port_sniff,
  efct_nic_set_tx_port_sniff,
  efct_nic_license_challenge,
  efct_nic_license_check,
  efct_nic_v3_license_challenge,
  efct_nic_v3_license_check,
  efct_get_rx_error_stats,
  efct_tx_alt_alloc,
  efct_tx_alt_free,
  efct_client_alloc,
  efct_client_free,
  efct_vi_set_user,
  efct_rss_alloc,
  efct_rss_update,
  efct_rss_free,
  efct_rss_flags,
  efct_filter_insert,
  efct_filter_remove,
  efct_filter_redirect,
  efct_multicast_block,
  efct_unicast_block,
  efct_vport_alloc,
  efct_vport_free,
  efct_dmaq_kick,
  efct_af_xdp_mem,
  efct_af_xdp_init,
  efct_get_pci_dev,
  efct_vi_io_region,
  efct_inject_reset_ev,
  efct_ctpio_addr,
  efct_max_shared_rxqs,
};

#endif
