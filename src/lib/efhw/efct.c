/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#include <ci/driver/kernel_compat.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/ci_aux.h>
#include <ci/driver/ci_efct.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/efct.h>
#include <ci/driver/ci_efct.h>
#include <ci/tools/sysdep.h>
#include "efct.h"

#if CI_HAVE_EFCT_AUX

int
efct_nic_rxq_bind(struct efhw_nic *nic, int qid, const struct cpumask *mask,
                  bool timestamp_req, size_t n_hugepages,
                  struct efhw_efct_rxq *rxq)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  struct xlnx_efct_rxq_params qparams = {
    .qid = qid,
/* EFCT TODO: temporary hack to keep things building across both sides of an
 * API change. Ultimately all masks are moving to filter add */
#ifndef XLNX_EFCT_FILTER_F_ANYQUEUE_STRICT
    .mask = mask,
#endif
    .timestamp_req = timestamp_req,
    .n_hugepages = n_hugepages,
  };
  int rc;

  if( n_hugepages > CI_EFCT_MAX_HUGEPAGES ) {
    /* We'd fail later on in bind_rxq(), but only after we'd done a load of
     * shuffling-about and memory allocation. So let's have this early sanity
     * check as well */
    return -EINVAL;
  }

  rxq->n_hugepages = n_hugepages;
  rxq->max_allowed_superbufs = n_hugepages * CI_EFCT_SUPERBUFS_PER_PAGE;
  rxq->shm = vmalloc_user(sizeof(*rxq->shm));
  if( ! rxq->shm )
    return -ENOMEM;

  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = edev->ops->bind_rxq(cli, &qparams);
  if( rc == 0 ) {
    struct efhw_nic_efct *efct = nic->arch_extra;
    struct efhw_nic_efct_rxq *q = &efct->rxq[rc];

    rxq->qid = rc;
    efct_app_list_push(&q->new_apps, rxq);
    edev->ops->rollover_rxq(cli, rxq->qid);
  }
  EFCT_POST(dev, edev, cli, nic, rc);

  return rc;
}


void
efct_nic_rxq_free(struct efhw_nic *nic, struct efhw_efct_rxq *rxq,
                  efhw_efct_rxq_free_func_t *freer)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc)
  rxq->destroy = true;
  rxq->freer = freer;
  edev->ops->free_rxq(cli, rxq->qid, rxq->n_hugepages);
  EFCT_POST(dev, edev, cli, nic, rc);
}


int
efct_get_hugepages(struct efhw_nic *nic, struct efhw_efct_rxq *rxq,
                   struct xlnx_efct_hugepage *pages, size_t n_pages)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc)
  rc = edev->ops->get_hugepages(cli, rxq->qid, pages, n_pages);
  EFCT_POST(dev, edev, cli, nic, rc);
  return rc;
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
  nic->flags |= NIC_FLAG_TX_CTPIO | NIC_FLAG_CTPIO_ONLY
             | NIC_FLAG_HW_RX_TIMESTAMPING | NIC_FLAG_HW_TX_TIMESTAMPING;
  return 0;
}


static void
efct_nic_release_hardware(struct efhw_nic* nic)
{
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
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  struct xlnx_efct_evq_params qparams = {
    .qid = efhw_params->evq,
    .entries = efhw_params->evq_size,
    /* We don't provide a pci_dev to enable queue memory to be mapped for us,
     * so we're given plain physical addresses.
     */
    .q_page = pfn_to_page(efhw_params->dma_addrs[0] >> PAGE_SHIFT),
    .page_offset = 0,
    .q_size = efhw_params->evq_size * sizeof(efhw_event_t),
  };
  int rc;
#ifndef NDEBUG
  int i;
#endif

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

  return rc;
}

static void
efct_nic_event_queue_disable(struct efhw_nic *nic, uint32_t client_id,
                             uint evq, int time_sync_events_enabled)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc);
  edev->ops->free_evq(cli, evq);
  EFCT_POST(dev, edev, cli, nic, rc);
}

static void
efct_nic_wakeup_request(struct efhw_nic *nic, volatile void __iomem* io_page,
                        int vi_id, int rptr)
{
}

static void efct_nic_sw_event(struct efhw_nic *nic, int data, int evq)
{
}

/*--------------------------------------------------------------------
 *
 * EF10 specific event callbacks
 *
 *--------------------------------------------------------------------*/

static int
efct_handle_event(struct efhw_nic *nic, struct efhw_ev_handler *h,
                  efhw_event_t *ev, int budget)
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
efct_dmaq_tx_q_init(struct efhw_nic *nic, uint32_t client_id, uint instance,
                    uint *qid_out, uint evq_id, uint own_id, uint tag,
                    uint dmaq_size, dma_addr_t *dma_addrs, int n_dma_addrs,
                    uint vport_id, uint stack_id, uint flags)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  struct xlnx_efct_txq_params params = { .evq = evq_id };
  int rc;

  EFCT_PRE(dev, edev, cli, nic, rc);
  rc = edev->ops->alloc_txq(cli, &params);
  EFCT_POST(dev, edev, cli, nic, rc);

  if( rc >= 0 ) {
    *qid_out = rc;
    rc = 0;
  }

  return 0;
}


static int
efct_dmaq_rx_q_init(struct efhw_nic *nic, uint32_t client_id, uint dmaq,
                    uint evq_id, uint own_id, uint tag, uint dmaq_size,
                    dma_addr_t *dma_addrs, int n_dma_addrs,
                    uint vport_id, uint stack_id, uint ps_buf_size, uint flags)
{
  /* efct doesn't do rxqs like this, so nothing to do here */
  return 0;
}


static void efct_dmaq_tx_q_disable(struct efhw_nic *nic, uint dmaq)
{
}

static void efct_dmaq_rx_q_disable(struct efhw_nic *nic, uint dmaq)
{
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - mid level API
 *
 *--------------------------------------------------------------------*/


static int efct_flush_tx_dma_channel(struct efhw_nic *nic,
                                     uint32_t client_id, uint dmaq)
{
  struct device *dev;
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
  int rc = 0;

  EFCT_PRE(dev, edev, cli, nic, rc);
  edev->ops->free_txq(cli, dmaq);
  EFCT_POST(dev, edev, cli, nic, rc);

  return 0;
}


static int efct_flush_rx_dma_channel(struct efhw_nic *nic,
                                     uint32_t client_id, uint dmaq)
{
  return 0;
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

static int
efct_filter_insert(struct efhw_nic *nic, struct efx_filter_spec *spec,
                   bool replace)
{
  /* TODO EFCT */
  return 0;
}

static void
efct_filter_remove(struct efhw_nic *nic, int filter_id)
{
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
  return -EOPNOTSUPP;
}

static int
efct_unicast_block(struct efhw_nic *nic, bool block)
{
  return -EOPNOTSUPP;
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

static u32
efct_vi_io_size(struct efhw_nic *nic)
{
  /* We have no need to map the IO area on efct NICs as all control through
   * the NIC's register interface is handled through the net driver. Although
   * we manage our own TX, there is no separate TX doorbell as TX is triggered
   * directly through writes to the CTPIO region. */
  return 0;
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
  struct xlnx_efct_device* edev;
  struct xlnx_efct_client* cli;
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
  efct_dmaq_tx_q_init,
  efct_dmaq_rx_q_init,
  efct_dmaq_tx_q_disable,
  efct_dmaq_rx_q_disable,
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
  efct_vi_io_size,
  efct_inject_reset_ev,
  efct_ctpio_addr,
};

#endif
