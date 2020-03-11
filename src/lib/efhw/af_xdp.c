/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#include <ci/driver/efab/hardware.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/af_xdp.h>


/*----------------------------------------------------------------------------
 *
 * Initialisation and configuration discovery
 *
 *---------------------------------------------------------------------------*/

static int
af_xdp_nic_license_check(struct efhw_nic *nic, const uint32_t feature,
		       int* licensed)
{
	return 0;
}


static int
af_xdp_nic_v3_license_check(struct efhw_nic *nic, const uint64_t app_id,
		       int* licensed)
{
	return 0;
}


static int
af_xdp_nic_license_challenge(struct efhw_nic *nic,
			   const uint32_t feature,
			   const uint8_t* challenge,
			   uint32_t* expiry,
			   uint8_t* signature)
{
	return 0;
}


static int
af_xdp_nic_v3_license_challenge(struct efhw_nic *nic,
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
af_xdp_nic_tweak_hardware(struct efhw_nic *nic)
{
	nic->pio_num = 0;
	nic->pio_size = 0;
	nic->tx_alts_vfifos = 0;
	nic->tx_alts_cp_bufs = 0;
	nic->tx_alts_cp_buf_size = 0;
        nic->rx_variant = 0;
        nic->tx_variant = 0;
        nic->rx_prefix_len = 0;
}


static int
af_xdp_nic_init_hardware(struct efhw_nic *nic,
		       struct efhw_ev_handler *ev_handlers,
		       const uint8_t *mac_addr)
{
	EFHW_TRACE("%s:", __FUNCTION__);

	memcpy(nic->mac_addr, mac_addr, ETH_ALEN);

	af_xdp_nic_tweak_hardware(nic);

	return 0;
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
af_xdp_nic_event_queue_enable(struct efhw_nic *nic, uint evq, uint evq_size,
			    dma_addr_t *dma_addrs,
			    uint n_pages, int interrupting, int enable_dos_p,
			    int wakeup_evq, int flags, int* flags_out)
{
	return 0;
}

static void
af_xdp_nic_event_queue_disable(struct efhw_nic *nic, uint evq,
			     int time_sync_events_enabled)
{
}

static void
af_xdp_nic_wakeup_request(struct efhw_nic *nic, volatile void __iomem* io_page,
			int vi_id, int rptr)
{
}

static void af_xdp_nic_sw_event(struct efhw_nic *nic, int data, int evq)
{
	EFHW_ASSERT(0);
}

/*--------------------------------------------------------------------
 *
 * EF10 specific event callbacks
 *
 *--------------------------------------------------------------------*/

static int
af_xdp_handle_event(struct efhw_nic *nic, struct efhw_ev_handler *h,
		  efhw_event_t *ev, int budget)
{
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}


/*----------------------------------------------------------------------------
 *
 * TX Alternatives
 *
 *---------------------------------------------------------------------------*/


static int
af_xdp_tx_alt_alloc(struct efhw_nic *nic, int tx_q_id, int num_alt,
		  int num_32b_words, unsigned *cp_id_out, unsigned *alt_ids_out)
{
	return -EOPNOTSUPP;
}


static int
af_xdp_tx_alt_free(struct efhw_nic *nic, int num_alt, unsigned cp_id,
		 const unsigned *alt_ids)
{
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}


/*----------------------------------------------------------------------------
 *
 * DMAQ low-level register interface
 *
 *---------------------------------------------------------------------------*/


static int
af_xdp_dmaq_tx_q_init(struct efhw_nic *nic, uint dmaq, uint evq_id, uint own_id,
		    uint tag, uint dmaq_size,
		    dma_addr_t *dma_addrs, int n_dma_addrs,
		    uint vport_id, uint stack_id, uint flags)
{
	return 0;
}


static int
af_xdp_dmaq_rx_q_init(struct efhw_nic *nic, uint dmaq, uint evq_id, uint own_id,
		    uint tag, uint dmaq_size,
		    dma_addr_t *dma_addrs, int n_dma_addrs,
		    uint vport_id, uint stack_id, uint ps_buf_size, uint flags)
{
	return 0;
}


static void af_xdp_dmaq_tx_q_disable(struct efhw_nic *nic, uint dmaq)
{
}

static void af_xdp_dmaq_rx_q_disable(struct efhw_nic *nic, uint dmaq)
{
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - mid level API
 *
 *--------------------------------------------------------------------*/


static int af_xdp_flush_tx_dma_channel(struct efhw_nic *nic, uint dmaq)
{
	return -EOPNOTSUPP;
}


static int af_xdp_flush_rx_dma_channel(struct efhw_nic *nic, uint dmaq)
{
	return -EOPNOTSUPP;
}


/*--------------------------------------------------------------------
 *
 * Buffer table - API
 *
 *--------------------------------------------------------------------*/

static const int __af_xdp_nic_buffer_table_get_orders[] = {0,4,8,10};


static int
af_xdp_nic_buffer_table_alloc(struct efhw_nic *nic, int owner, int order,
			    struct efhw_buffer_table_block **block_out,
			    int reset_pending)
{
	return -EOPNOTSUPP;
}


static int
af_xdp_nic_buffer_table_realloc(struct efhw_nic *nic, int owner, int order,
			      struct efhw_buffer_table_block *block)
{
	return -EOPNOTSUPP;
}


static void
af_xdp_nic_buffer_table_free(struct efhw_nic *nic,
			   struct efhw_buffer_table_block *block,
			   int reset_pending)
{
	EFHW_ASSERT(0);
}


static int
af_xdp_nic_buffer_table_set(struct efhw_nic *nic,
			  struct efhw_buffer_table_block *block,
			  int first_entry, int n_entries,
			  dma_addr_t *dma_addrs)
{
	return -EOPNOTSUPP;
}


static void
af_xdp_nic_buffer_table_clear(struct efhw_nic *nic,
			    struct efhw_buffer_table_block *block,
			    int first_entry, int n_entries)
{
	EFHW_ASSERT(0);
}


/*--------------------------------------------------------------------
 *
 * Port Sniff
 *
 *--------------------------------------------------------------------*/

static int
af_xdp_nic_set_tx_port_sniff(struct efhw_nic *nic, int instance, int enable,
			   int rss_context)
{
	return -EOPNOTSUPP;
}


static int
af_xdp_nic_set_port_sniff(struct efhw_nic *nic, int instance, int enable,
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
af_xdp_get_rx_error_stats(struct efhw_nic *nic, int instance,
			void *data, int data_len, int do_reset)
{
	return -EOPNOTSUPP;
}


/*--------------------------------------------------------------------
 *
 * Abstraction Layer Hooks
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops af_xdp_char_functional_units = {
	af_xdp_nic_init_hardware,
	af_xdp_nic_tweak_hardware,
	af_xdp_nic_event_queue_enable,
	af_xdp_nic_event_queue_disable,
	af_xdp_nic_wakeup_request,
	af_xdp_nic_sw_event,
	af_xdp_handle_event,
	af_xdp_dmaq_tx_q_init,
	af_xdp_dmaq_rx_q_init,
	af_xdp_dmaq_tx_q_disable,
	af_xdp_dmaq_rx_q_disable,
	af_xdp_flush_tx_dma_channel,
	af_xdp_flush_rx_dma_channel,
	__af_xdp_nic_buffer_table_get_orders,
	sizeof(__af_xdp_nic_buffer_table_get_orders) /
		sizeof(__af_xdp_nic_buffer_table_get_orders[0]),
	af_xdp_nic_buffer_table_alloc,
	af_xdp_nic_buffer_table_realloc,
	af_xdp_nic_buffer_table_free,
	af_xdp_nic_buffer_table_set,
	af_xdp_nic_buffer_table_clear,
	af_xdp_nic_set_port_sniff,
	af_xdp_nic_set_tx_port_sniff,
	af_xdp_nic_license_challenge,
	af_xdp_nic_license_check,
	af_xdp_nic_v3_license_challenge,
	af_xdp_nic_v3_license_check,
	af_xdp_get_rx_error_stats,
	af_xdp_tx_alt_alloc,
	af_xdp_tx_alt_free,
};
