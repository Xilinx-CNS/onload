/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#include <ci/driver/efab/hardware.h>
#include <ci/efhw/debug.h>
#include <ci/efhw/iopage.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/checks.h>
#include <ci/efhw/efhw_buftable.h>

#include <ci/driver/driverlink_api.h>
#include <ci/driver/resource/driverlink.h>

#include <ci/efhw/mc_driver_pcol.h>
#include <ci/efhw/mcdi_pcol_plugins.h>
#include <ci/efhw/ef10.h>
#include <ci/efhw/ef100.h>
#include "ef10_mcdi.h"
#include "ef10_ef100.h"

/*----------------------------------------------------------------------------
 *
 * Initialisation and configuration discovery
 *
 *---------------------------------------------------------------------------*/

static int _ef100_nic_check_capabilities(struct efhw_nic *nic,
					uint64_t* capability_flags,
					const char* caller)
{
	size_t out_size = 0;
	unsigned flags;
	int rc;

	EFHW_MCDI_DECLARE_BUF(ver_out, MC_CMD_GET_VERSION_OUT_LEN);
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_GET_CAPABILITIES_V2_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_CAPABILITIES_V3_OUT_LEN);
	EFHW_MCDI_INITIALISE_BUF(ver_out);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_GET_CAPABILITIES,
				 sizeof(in), sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_GET_CAPABILITIES, rc, out_size, 0);
	if (rc != 0)
		return rc;
	flags = EFHW_MCDI_DWORD(out, GET_CAPABILITIES_V3_OUT_FLAGS1);
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_TX_MCAST_UDP_LOOPBACK_LBN))
		*capability_flags |= NIC_FLAG_MCAST_LOOP_HW;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_RX_RSS_LIMITED_LBN))
		*capability_flags |= NIC_FLAG_RX_RSS_LIMITED;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_ADDITIONAL_RSS_MODES_LBN))
		*capability_flags |= NIC_FLAG_ADDITIONAL_RSS_MODES;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_RX_TIMESTAMP_LBN))
		*capability_flags |= NIC_FLAG_HW_RX_TIMESTAMPING;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_TX_TIMESTAMP_LBN))
		*capability_flags |= NIC_FLAG_HW_TX_TIMESTAMPING;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_MCAST_FILTER_CHAINING_LBN))
		*capability_flags |= NIC_FLAG_MULTICAST_FILTER_CHAINING;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_RX_BATCHING_LBN))
		*capability_flags |= NIC_FLAG_RX_MERGE;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_RX_FORCE_EVENT_MERGING_LBN)) {
		*capability_flags |= NIC_FLAG_RX_FORCE_EVENT_MERGING;
	}

	/* If MAC filters are policed then check we've got the right privileges
	 * before saying we can do MAC spoofing.
	 */
	if (flags & (1u <<
		MC_CMD_GET_CAPABILITIES_V3_OUT_TX_MAC_SECURITY_FILTERING_LBN)) {
		if( ef10_ef100_nic_mac_spoofing_privilege(nic) == 1 )
			*capability_flags |= NIC_FLAG_MAC_SPOOFING;
	}
	else {
		*capability_flags |= NIC_FLAG_MAC_SPOOFING;
	}

	flags = EFHW_MCDI_DWORD(out, GET_CAPABILITIES_V3_OUT_FLAGS2);
	if (flags & (1u <<
		MC_CMD_GET_CAPABILITIES_V3_OUT_TX_VFIFO_ULL_MODE_LBN))
		*capability_flags |= NIC_FLAG_TX_ALTERNATIVES;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_INIT_EVQ_V2_LBN))
		*capability_flags |= NIC_FLAG_EVQ_V2;
	if (flags & (1u << MC_CMD_GET_CAPABILITIES_V2_OUT_CTPIO_LBN))
		*capability_flags |= NIC_FLAG_TX_CTPIO;

	nic->pio_num = 0;
	nic->pio_size = 0;

	nic->tx_alts_vfifos = 0;
	nic->tx_alts_cp_bufs = 0;
	nic->tx_alts_cp_buf_size = 0;

	nic->rx_variant = 0;
	nic->tx_variant = 0;

	return rc;
}

static void
ef100_nic_tweak_hardware(struct efhw_nic *nic)
{
	/* No need to set RX_USR_BUF_SIZE for ef100, it's set
	 * per-descriptor by net driver
	 */

	/* Some capabilities are always present on ef100 */
	nic->flags |= NIC_FLAG_PHYS_MODE;
	nic->flags |= NIC_FLAG_PHYS_CONTIG_EVQ | NIC_FLAG_PHYS_CONTIG_TXQ |
		      NIC_FLAG_PHYS_CONTIG_RXQ;
	nic->flags |= NIC_FLAG_EVQ_IRQ;
	nic->flags |= NIC_FLAG_SHARED_PD;

	/* Determine what the filtering capabilies are */
	ef10_ef100_nic_check_supported_filters(nic);

	/* Determine capabilities reported by firmware */
	_ef100_nic_check_capabilities(nic, &nic->flags, __FUNCTION__);

	nic->rx_prefix_len = 22;
}


static void
ef100_nic_sw_ctor(struct efhw_nic *nic,
		  const struct vi_resource_dimensions *res)
{
	/* FIXME: wrong numbers for queues sizes */
	nic->q_sizes[EFHW_EVQ] = 16 | 256 | 512 | 1024 | 2048 | 4096 |
		8192 | 16384;
	nic->q_sizes[EFHW_TXQ] = 16 | 256 | 512 | 1024 | 2048 | 4096 |
		8192 | 16384;
	nic->q_sizes[EFHW_RXQ] = 16 | 256 | 512 | 1024 | 2048 | 4096 |
		8192 | 16384 ;

	nic->ctr_ap_bar = EF100_P_CTR_AP_BAR;

	if (res->mem_bar != VI_RES_MEM_BAR_UNDEFINED)
		nic->ctr_ap_bar = res->mem_bar;
	nic->ctr_ap_addr = pci_resource_start(to_pci_dev(nic->dev),
					      nic->ctr_ap_bar);

	/* FIXME: wrong numbers for queues numbers*/
	nic->num_evqs   = 1024;
	nic->num_dmaqs  = 1024;
	nic->num_timers = 1024;

	nic->vi_base = res->vi_base;
	nic->vi_shift = res->vi_shift;
	nic->vi_stride = res->vi_stride;
}


static int
ef100_nic_init_hardware(struct efhw_nic *nic,
		       struct efhw_ev_handler *ev_handlers,
		       const uint8_t *mac_addr)
{
	int rc;
	EFHW_TRACE("%s:", __FUNCTION__);

	nic->ev_handlers = ev_handlers;
	memcpy(nic->mac_addr, mac_addr, ETH_ALEN);

	ef100_nic_tweak_hardware(nic);

	EFHW_TRACE("%s: WARNING: there are no HW timestamp corrections on EF100",
		   __FUNCTION__);
	/* Without HW timestamp corrections the user is unlikely
	 * to be doing such accurate timestamping, but try to
	 * do something sensible... these values are correct
	 * for Huntington.
	 */
	nic->rx_ts_correction = -12;
	nic->tx_ts_correction = 178;
	EFHW_TRACE("%s: WARNING: there are no PTP attributes on EF100",
		    __FUNCTION__);
	nic->ts_format = TS_FORMAT_SECONDS_27FRACTION;

	/* No buffer_table_ctor() on EF100 */
	/* No non_irq_evq on EF100 */

	nic->rss_indir_size = EF10_EF100_RSS_INDIRECTION_TABLE_LEN;
	nic->rss_key_size = EF10_EF100_RSS_KEY_LEN;

	rc = ef10_ef100_init_vi_allocator(nic);
	if( rc < 0 ) {
		return rc;
	}
	return 0;
}


/* This function will enable the given event queue with the requested
 * properties.
 */
static int
ef100_nic_event_queue_enable(struct efhw_nic *nic,
			     struct efhw_evq_params *params)
{
	int rc;
	int flags = params->flags;
	int enable_time_sync_events = (flags & (EFHW_VI_RX_TIMESTAMPS |
						EFHW_VI_TX_TIMESTAMPS)) != 0;
	int enable_cut_through = (flags & EFHW_VI_NO_EV_CUT_THROUGH) == 0;
	int enable_rx_merging = ((flags & EFHW_VI_RX_PACKED_STREAM) != 0) ||
                                ((flags & EFHW_VI_ENABLE_RX_MERGE) != 0);
	int enable_timer = (flags & EFHW_VI_ENABLE_EV_TIMER);

	if( enable_time_sync_events ) {
		EFHW_ERR("%s: timestamping isn't supported on EF100",
			   __FUNCTION__);
		return -EOPNOTSUPP;
	}

	rc = ef10_ef100_mcdi_cmd_event_queue_enable(nic, params,
						    enable_cut_through,
						    enable_rx_merging,
						    enable_timer);

	EFHW_TRACE("%s: enable evq %u size %u rc %d", __FUNCTION__,
		   params->evq, params->evq_size, rc);

	return rc;
}


static void
ef100_nic_event_queue_disable(struct efhw_nic *nic, uint evq,
			     int time_sync_events_enabled)
{
	if( time_sync_events_enabled )
		EFHW_TRACE("%s: timestamping isn't supported on EF100",
			   __FUNCTION__);
	ef10_ef100_mcdi_cmd_event_queue_disable(nic, evq);
}


static int
ef100_dmaq_tx_q_init(struct efhw_nic *nic,
                     struct efhw_dmaq_params *params)
{
	int rc;
	int flag_timestamp = (params->flags & EFHW_VI_TX_TIMESTAMPS) != 0;
	int flag_tcp_udp_only = (params->flags & EFHW_VI_TX_TCPUDP_ONLY) != 0;
	int flag_tcp_csum_dis =
		(params->flags & EFHW_VI_TX_TCPUDP_CSUM_DIS) != 0;
	int flag_ip_csum_dis = (params->flags & EFHW_VI_TX_IP_CSUM_DIS) != 0;
	int flag_buff_mode = (params->flags & EFHW_VI_TX_PHYS_ADDR_EN) == 0;
	int flag_ctpio = (params->flags & EFHW_VI_TX_CTPIO) != 0;
	int flag_ctpio_uthresh =
		(params->flags & EFHW_VI_TX_CTPIO_NO_POISON) == 0;
	int flag_pacer_bypass;

	if (nic->flags & NIC_FLAG_MCAST_LOOP_HW) {
		EFHW_ERR("%s: HW multicast loopback isn't supported on EF100",
			   __FUNCTION__);
	}

	/* No option for pacer bypass yet, but we want it on as it cuts latency.
	 * This might not work in some cases due to permissions (e.g. VF),
	 * if so we retry without it. */
	for (flag_pacer_bypass = 1; 1; flag_pacer_bypass = 0) {
		rc = ef10_ef100_mcdi_cmd_init_txq
			(nic, params->dma_addrs,
			 params->n_dma_addrs, params->vport_id,
			 params->stack_id, REAL_OWNER_ID(params->owner),
			 flag_timestamp, QUEUE_CRC_MODE_NONE,
			 flag_tcp_udp_only, flag_tcp_csum_dis,
			 flag_ip_csum_dis, flag_buff_mode, flag_pacer_bypass,
			 flag_ctpio, flag_ctpio_uthresh,
			 params->dmaq, params->tag,
			 params->evq, params->dmaq_size);
		if ((rc != -EPERM) || (!flag_pacer_bypass))
			break;
	}

	if ((rc == 0) && !flag_pacer_bypass) {
		EFHW_WARN("%s: WARNING: failed to enable pacer bypass, "
			 "continuing without it", __FUNCTION__);
	}

	if (rc == -EOPNOTSUPP)
		rc = -ENOKEY;

	if (rc == 0)
		params->qid_out = params->dmaq;

	return rc;
}


static int
ef100_dmaq_rx_q_init(struct efhw_nic *nic,
		     struct efhw_dmaq_params *params)
{
	int rc;
	int flag_rx_prefix = (params->flags & EFHW_VI_RX_PREFIX) != 0;
	int flag_timestamp = (params->flags & EFHW_VI_RX_TIMESTAMPS) != 0;
	int flag_hdr_split = (params->flags & EFHW_VI_RX_HDR_SPLIT) != 0;
	int flag_buff_mode = (params->flags & EFHW_VI_RX_PHYS_ADDR_EN) == 0;
	int flag_packed_stream =
		(params->flags & EFHW_VI_RX_PACKED_STREAM) != 0;
	int flag_force_rx_merge =
		((params->flags & EFHW_VI_NO_RX_CUT_THROUGH) != 0) &&
		(nic->flags & NIC_FLAG_RX_FORCE_EVENT_MERGING);
	if (flag_packed_stream)
		return -EOPNOTSUPP;

	rc = ef10_ef100_mcdi_cmd_init_rxq
		(nic, params->dma_addrs, params->n_dma_addrs,
		 params->vport_id, params->stack_id,
		 REAL_OWNER_ID(params->owner), QUEUE_CRC_MODE_NONE,
		 flag_timestamp, flag_hdr_split, flag_buff_mode,
		 flag_rx_prefix, flag_packed_stream, params->dmaq, params->tag,
		 params->evq, params->dmaq_size, params->rx.ps_buf_size,
		 flag_force_rx_merge, EF100_RX_USR_BUF_SIZE);

	if (rc == 0)
		params->qid_out = params->dmaq;

	return nic->rx_prefix_len;
}

/*--------------------------------------------------------------------
 *
 * DMA Queues - MCDI cmds
 *
 *--------------------------------------------------------------------*/

static void
ef100_nic_wakeup_request(struct efhw_nic *nic, volatile void __iomem* io_page,
			 int vi_id, int rptr)
{
	ci_dword_t dwrptr;

	__DWCHCK(ERF_GZ_IDX);
	__RANGECHCK(rptr, ERF_GZ_IDX_WIDTH);
	__RANGECHCK(vi_id, ERF_GZ_EVQ_ID_WIDTH);

	CI_POPULATE_DWORD_2(dwrptr,
			    ERF_GZ_EVQ_ID, vi_id,
			    ERF_GZ_IDX, rptr);
	writel(dwrptr.u32[0], nic->int_prime_reg);
	mmiowb();
}

/*--------------------------------------------------------------------
 *
 * EF100 specific event callbacks
 *
 *--------------------------------------------------------------------*/

static int
ef100_handle_event(struct efhw_nic *nic, efhw_event_t *ev, int budget)
{
	unsigned evq;

	if (EF100_EVENT_CODE(ev) == EF100_EVENT_CODE_SW) {
		int code = EF100_EVENT_SW_SUBCODE(ev);
		switch (code) {
		case MCDI_EVENT_CODE_TX_FLUSH:
			evq = EF100_EVENT_TX_FLUSH_Q_ID(ev);
			EFHW_TRACE("%s: tx flush done %d", __FUNCTION__, evq);
			return efhw_handle_txdmaq_flushed(nic, evq);
		case MCDI_EVENT_CODE_RX_FLUSH:
			evq = EF100_EVENT_RX_FLUSH_Q_ID(ev);
			EFHW_TRACE("%s: rx flush done %d", __FUNCTION__, evq);
			return efhw_handle_rxdmaq_flushed(nic, evq, false);
		case MCDI_EVENT_CODE_TX_ERR:
			EFHW_NOTICE("%s: unexpected MCDI TX error event "
				    "(event code %d)",__FUNCTION__, code);
			return -EINVAL;
		case MCDI_EVENT_CODE_RX_ERR:
			EFHW_NOTICE("%s: unexpected MCDI RX error event "
				    "(event code %d)",__FUNCTION__, code);
			return -EINVAL;
		case MCDI_EVENT_CODE_AOE:
			/* This event doesn't signify an error case,
			 * so just return 0 to avoid logging
			 */
			return -EINVAL;
		default:
			EFHW_NOTICE("%s: unexpected MCDI event code %d",
				    __FUNCTION__, code);
			return -EINVAL;
		}
	}

	EFHW_TRACE("%s: unknown event type=%x", __FUNCTION__,
		   (unsigned)EF100_EVENT_CODE(ev));

	return -EINVAL;
}


static void ef100_nic_sw_event(struct efhw_nic *nic, int data, int evq)
{
	uint64_t ev_data = data;

	ev_data &= ~EF100_EVENT_CODE_MASK;
	ev_data |= EF100_EVENT_CODE_SW;

	/* No MCDI event code is set for a sw event so it is implicitly 0 */

	ef10_ef100_mcdi_cmd_driver_event(nic, ev_data, evq);
	EFHW_TRACE("%s: evq[%d]->%x", __FUNCTION__, evq, data);
}


/*--------------------------------------------------------------------
 *
 * Buffer table - API
 *
 *--------------------------------------------------------------------*/

static const int ef100_nic_buffer_table_orders[] = {9};

/*--------------------------------------------------------------------
 *
 * EF100 special functions
 *
 *--------------------------------------------------------------------*/


static int ef100_translate_dma_addrs(struct efhw_nic* nic,
				     const dma_addr_t *src,
				     dma_addr_t *dst, int n)
{
	struct efx_dl_device *efx_dev;
	int rc;

	efx_dev = efhw_nic_acquire_dl_device(nic);
	if (!efx_dev)
		return -ENETDOWN;
	rc = efx_dl_dma_xlate(efx_dev, src, dst, n);
	if (rc < 0) {
		EFHW_ERR("%s: ERROR: DMA address translation failed (%d)",
		         __FUNCTION__, rc);
	}
	else if (rc < n) {
		EFHW_ERR("%s: ERROR: DMA address translation failed on "
		         "%d/%d (%llx)", __FUNCTION__, rc, n, src[rc]);
		rc = -EIO;
	}
	else {
		rc = 0;
	}
	efhw_nic_release_dl_device(nic, efx_dev);
	return rc;
}


int ef100_nic_ext_alloc(struct efhw_nic* nic,
                        const unsigned char* service_guid,
                        uint32_t* out_mc_handle)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PLUGIN_ALLOC_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_PLUGIN_ALLOC_OUT_LEN);

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	memcpy(EFHW_MCDI_PTR(in, PLUGIN_ALLOC_IN_UUID),
	       service_guid, 16);
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PLUGIN_ALLOC,
				 sizeof(in), sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_PLUGIN_ALLOC, rc, out_size, 0);
	*out_mc_handle = EFHW_MCDI_DWORD(out, PLUGIN_ALLOC_OUT_HANDLE);
	return rc;
}


int ef100_nic_ext_free(struct efhw_nic* nic, uint32_t mc_handle)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PLUGIN_FREE_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_PLUGIN_FREE_OUT_LEN);

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, PLUGIN_FREE_IN_HANDLE, mc_handle);
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PLUGIN_FREE,
	                         sizeof(in), sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_PLUGIN_FREE, rc, out_size, 0);
	return rc;
}


int ef100_nic_ext_get_meta_global(struct efhw_nic* nic, uint32_t mc_handle,
                                  uint8_t* uuid, uint16_t* minor_ver,
                                  uint16_t* patch_ver, uint32_t* nmsgs,
                                  uint32_t* nrsrc_classes,
                                  uint16_t* mapped_csr_offset,
                                  uint16_t* mapped_csr_size,
                                  uint8_t* mapped_csr_flags)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PLUGIN_GET_META_GLOBAL_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_LEN);

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, PLUGIN_GET_META_GLOBAL_IN_HANDLE, mc_handle);
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PLUGIN_GET_META_GLOBAL,
	                         sizeof(in), sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_PLUGIN_GET_META_GLOBAL, rc, out_size, 0);
	memcpy(uuid, EFHW_MCDI_PTR(out, PLUGIN_GET_META_GLOBAL_OUT_UUID), 16);
	*minor_ver = EFHW_MCDI_WORD(out, PLUGIN_GET_META_GLOBAL_OUT_MINOR_VER);
	*patch_ver = EFHW_MCDI_WORD(out, PLUGIN_GET_META_GLOBAL_OUT_PATCH_VER);
	*nmsgs = EFHW_MCDI_DWORD(out, PLUGIN_GET_META_GLOBAL_OUT_NUM_MSGS);
	*nrsrc_classes = EFHW_MCDI_DWORD(out, PLUGIN_GET_META_GLOBAL_OUT_NUM_RCS);
	*mapped_csr_offset =
	        EFHW_MCDI_WORD(out, PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_OFFSET);
	*mapped_csr_size =
	        EFHW_MCDI_WORD(out, PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_SIZE);
	*mapped_csr_flags =
	        EFHW_MCDI_WORD(out, PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_FLAGS);
	return rc;
}


int ef100_nic_ext_get_meta_rc(struct efhw_nic* nic, uint32_t mc_handle,
                              uint32_t clas,
                              uint32_t* max, uint32_t* kern_extra)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PLUGIN_GET_META_RC_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_PLUGIN_GET_META_RC_OUT_LEN);

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, PLUGIN_GET_META_RC_IN_HANDLE, mc_handle);
	EFHW_MCDI_SET_DWORD(in, PLUGIN_GET_META_RC_IN_CLASS, clas);
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PLUGIN_GET_META_RC,
	                         sizeof(in), sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_PLUGIN_GET_META_RC, rc, out_size, 0);
	*max = EFHW_MCDI_DWORD(out, PLUGIN_GET_META_RC_OUT_MAX_ALLOWED);
	*kern_extra = EFHW_MCDI_DWORD(out, PLUGIN_GET_META_RC_OUT_KERN_EXTRA);
	return rc;
}


int ef100_nic_ext_get_meta_msg(struct efhw_nic* nic, uint32_t mc_handle,
                               uint32_t msg_id, uint32_t* index, char* name,
                               size_t name_len, uint32_t* ef_vi_param_size,
                               uint32_t* mcdi_param_size, uint32_t* ninsns)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PLUGIN_GET_META_MSG_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_PLUGIN_GET_META_MSG_OUT_LEN);

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, PLUGIN_GET_META_MSG_IN_HANDLE, mc_handle);
	EFHW_MCDI_SET_DWORD(in, PLUGIN_GET_META_MSG_IN_ID, msg_id);
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PLUGIN_GET_META_MSG,
	                         sizeof(in), sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_PLUGIN_GET_META_MSG, rc, out_size, 0);
	*index = EFHW_MCDI_DWORD(out, PLUGIN_GET_META_MSG_OUT_INDEX);
	memset(name, 0, name_len);
	memcpy(name, EFHW_MCDI_PTR(out, PLUGIN_GET_META_MSG_OUT_NAME),
	       CI_MIN(name_len, (size_t)MC_CMD_PLUGIN_GET_META_MSG_OUT_NAME_LEN));
	*ef_vi_param_size = EFHW_MCDI_DWORD(out,
	                                 PLUGIN_GET_META_MSG_OUT_USER_PARAM_SIZE);
	*mcdi_param_size = EFHW_MCDI_DWORD(out,
	                                 PLUGIN_GET_META_MSG_OUT_MCDI_PARAM_SIZE);
	*ninsns = EFHW_MCDI_DWORD(out, PLUGIN_GET_META_MSG_OUT_PROG_NUM_INSNS);
	return rc;
}


int ef100_nic_ext_get_meta_msg_prog(struct efhw_nic* nic, uint32_t mc_handle,
                                    uint32_t msg_id,
                                    void* prog, size_t prog_bytes)
{
	int rc;
	size_t out_size;
	uint32_t offset = 0;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PLUGIN_GET_META_MSG_PROG_IN_LEN);

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	EFHW_MCDI_INITIALISE_BUF(in);

	EFHW_MCDI_SET_DWORD(in, PLUGIN_GET_META_MSG_PROG_IN_HANDLE, mc_handle);
	EFHW_MCDI_SET_DWORD(in, PLUGIN_GET_META_MSG_PROG_IN_ID, msg_id);
	do {
		EFHW_MCDI_SET_DWORD(in, PLUGIN_GET_META_MSG_PROG_IN_OFFSET, offset);
		rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PLUGIN_GET_META_MSG_PROG,
								 sizeof(in), prog_bytes - offset, &out_size,
								 in, (char*)prog + offset);
		ef10_ef100_mcdi_check_response(__func__,
		                               "MC_CMD_PLUGIN_GET_META_MSG_PROG",
		                               rc, 0, out_size, 0);
		if (rc < 0)
			break;
		if (out_size == 0)
			return -ENODATA;
		offset += out_size;
	} while (offset < prog_bytes);
	return rc;
}


int ef100_nic_ext_msg(struct efhw_nic* nic, uint32_t mc_handle,
                      uint32_t msg_id, void* payload, size_t len)
{
	ci_dword_t* bufs;
	void* out;
	size_t in_len = len + MC_CMD_PLUGIN_REQ_IN_DATA_OFST;
	size_t out_size;
	int rc;

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	if (len >= MC_CMD_PLUGIN_REQ_IN_DATA_MAXNUM_MCDI2)
		return -E2BIG;
	/* space for two, because we're putting the output in the same alloc: */
	bufs = kzalloc(CI_ROUND_UP(in_len, 8) + CI_ROUND_UP(len, 8), GFP_KERNEL);
	if (!bufs)
		return -ENOMEM;
	out = (char*)bufs + CI_ROUND_UP(in_len, 8);

	EFHW_MCDI_SET_DWORD(bufs, PLUGIN_REQ_IN_HANDLE, mc_handle);
	EFHW_MCDI_SET_DWORD(bufs, PLUGIN_REQ_IN_ID, msg_id);
	memcpy(EFHW_MCDI_PTR(bufs, PLUGIN_REQ_IN_DATA), payload, len);
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PLUGIN_REQ, CI_ROUND_UP(in_len, 4),
	                         CI_ROUND_UP(len, 8), &out_size, bufs, out);
	ef10_ef100_mcdi_check_response(__func__, "MC_CMD_PLUGIN_REQ", rc,
	                               len, out_size, 0);

	if (rc >= 0)
		memcpy(payload, out, len);
	kfree(bufs);
	return rc;
}


int ef100_nic_ext_destroy_rsrc(struct efhw_nic* nic, uint32_t mc_handle,
                               uint32_t clas, uint32_t id)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PLUGIN_DESTROY_RSRC_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_PLUGIN_DESTROY_RSRC_OUT_LEN);

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, PLUGIN_DESTROY_RSRC_IN_HANDLE, mc_handle);
	EFHW_MCDI_SET_DWORD(in, PLUGIN_DESTROY_RSRC_IN_CLASS, clas);
	EFHW_MCDI_SET_DWORD(in, PLUGIN_DESTROY_RSRC_IN_ID, id);
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PLUGIN_DESTROY_RSRC,
	                         sizeof(in), sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_PLUGIN_DESTROY_RSRC, rc, out_size, 0);
	return rc;
}

/*--------------------------------------------------------------------
 *
 * Device
 *
 *--------------------------------------------------------------------*/
int ef100_vi_io_region(struct efhw_nic* nic, int instance, size_t* size_out,
		       resource_size_t* addr_out)
{
	unsigned vi_stride = nic->vi_stride;

	*size_out = CI_PAGE_SIZE;

	/* We say that we only needed one page for the IO mapping so check
	 * that the registers we're interested in fall within a page. */
	EFHW_ASSERT(ef100_tx_dma_page_offset(vi_stride, instance) <
		    CI_PAGE_SIZE);
	EFHW_ASSERT(ef100_rx_dma_page_offset(vi_stride, instance) <
		    CI_PAGE_SIZE);
	EFHW_ASSERT(ef100_tx_dma_page_base(vi_stride, instance) ==
		    ef100_rx_dma_page_base(vi_stride, instance));

	*addr_out = nic->ctr_ap_addr +
		    ef100_tx_dma_page_base(vi_stride, instance);

	return 0;
}

static int
ef100_inject_reset_ev(struct efhw_nic* nic, void* base, unsigned capacity,
                      const volatile uint32_t* evq_ptr)
{
	ci_qword_t* evq = base;
	ci_qword_t* endev;
	uint32_t mask = capacity - 1;
	ci_qword_t reset_ev;
	uint32_t ptrend;
	uint32_t i;
	int phase;

	EFHW_ASSERT((capacity & (capacity - 1)) == 0);

	ptrend = READ_ONCE(*evq_ptr);
	for (i = 0; i < capacity; ++i) {
		int ix = ptrend / sizeof(evq[0]);
		phase = (ix & (mask + 1)) != 0;
		endev = &evq[ix & mask];
		if (CI_QWORD_FIELD(*endev, ESF_GZ_EV_RXPKTS_PHASE) != phase)
			break;
		ptrend += sizeof(evq[0]);
	}
	if (i == capacity)
		return -EOVERFLOW;

	CI_POPULATE_QWORD_3(reset_ev,
	                    ESF_GZ_EV_RXPKTS_PHASE, phase,
	                    ESF_GZ_E_TYPE, ESE_GZ_EF100_EV_MCDI,
	                    MCDI_EVENT_CODE, MCDI_EVENT_CODE_MC_REBOOT);
	WRITE_ONCE(endev->u64[0], reset_ev.u64[0]);
	return 0;
}


/*--------------------------------------------------------------------
 *
 * Abstraction Layer Hooks
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops ef100_char_functional_units = {
	.sw_ctor = ef100_nic_sw_ctor,
	.init_hardware = ef100_nic_init_hardware,
	.post_reset = ef100_nic_tweak_hardware,
	.release_hardware = ef10_ef100_nic_release_hardware,
	.event_queue_enable = ef100_nic_event_queue_enable,
	.event_queue_disable = ef100_nic_event_queue_disable,
	.wakeup_request = ef100_nic_wakeup_request,
	.sw_event = ef100_nic_sw_event,
	.handle_event = ef100_handle_event,
	.vi_alloc = ef10_ef100_vi_alloc,
	.vi_free = ef10_ef100_vi_free,
	.dmaq_tx_q_init = ef100_dmaq_tx_q_init,
	.dmaq_rx_q_init = ef100_dmaq_rx_q_init,
	.flush_tx_dma_channel = ef10_ef100_flush_tx_dma_channel,
	.flush_rx_dma_channel = ef10_ef100_flush_rx_dma_channel,
	.translate_dma_addrs = ef100_translate_dma_addrs,
	.buffer_table_orders = ef100_nic_buffer_table_orders,
	.buffer_table_orders_num = CI_ARRAY_SIZE(ef100_nic_buffer_table_orders),
	.buffer_table_alloc = ef10_ef100_nic_buffer_table_alloc,
	.buffer_table_realloc = ef10_ef100_nic_buffer_table_realloc,
	.buffer_table_free = ef10_ef100_nic_buffer_table_free,
	.buffer_table_set = ef10_ef100_nic_buffer_table_set,
	.buffer_table_clear = ef10_ef100_nic_buffer_table_clear,
	.rss_alloc = ef10_ef100_rss_alloc,
	.rss_free = ef10_ef100_rss_free,
	.filter_insert = ef10_ef100_filter_insert,
	.filter_remove = ef10_ef100_filter_remove,
	.filter_redirect = ef10_ef100_filter_redirect,
	.filter_query = ef10_ef100_filter_query,
	.multicast_block = ef10_ef100_multicast_block,
	.unicast_block = ef10_ef100_unicast_block,
	.vport_alloc = ef10_ef100_vport_alloc,
	.vport_free = ef10_ef100_vport_free,
	.get_pci_dev = ef10_ef100_get_pci_dev,
	.vi_io_region = ef100_vi_io_region,
	.inject_reset_ev = ef100_inject_reset_ev,
};
