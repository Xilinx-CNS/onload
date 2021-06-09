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

#include <ci/efhw/ef10.h>
#include <ci/efhw/ef100.h>
#include <ci/efhw/mc_driver_pcol.h>
#include <ci/efhw/mcdi_pcol_plugins.h>
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

	/* The ONLOAD_UNSUPPORTED flag is managed by the resource manager, so
	 * we don't reset the value here.
	 */
	nic->flags &= ~NIC_FLAG_ONLOAD_UNSUPPORTED;

	/* Some capabilities are always present on ef100 */
	nic->flags |= NIC_FLAG_PHYS_MODE;

	/* Determine what the filtering capabilies are */
	ef10_ef100_nic_check_supported_filters(nic);

	/* Determine capabilities reported by firmware */
	_ef100_nic_check_capabilities(nic, &nic->flags, __FUNCTION__);

	nic->rx_prefix_len = 22;
}

static int
ef100_nic_init_hardware(struct efhw_nic *nic,
		       struct efhw_ev_handler *ev_handlers,
		       const uint8_t *mac_addr)
{
	EFHW_TRACE("%s:", __FUNCTION__);

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

	return 0;
}


static void
ef100_nic_release_hardware(struct efhw_nic *nic)
{
	EFHW_TRACE("%s:", __FUNCTION__);
}


/* This function will enable the given event queue with the requested
 * properties.
 */
static int
ef100_nic_event_queue_enable(struct efhw_nic *nic, uint32_t client_id,
			    uint evq, uint evq_size,
			    dma_addr_t *dma_addrs,
			    uint n_pages, int interrupting, int enable_dos_p,
			    int wakeup_evq, int flags, int* flags_out)
{
	int rc;
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

	rc = ef10_ef100_mcdi_cmd_event_queue_enable(nic, client_id, evq, evq_size,
						    dma_addrs, n_pages, interrupting,
						    enable_dos_p, enable_cut_through,
						    enable_rx_merging,
						    wakeup_evq, enable_timer);

	EFHW_TRACE("%s: enable evq %u size %u rc %d", __FUNCTION__, evq,
		   evq_size, rc);

	return rc;
}


static void
ef100_nic_event_queue_disable(struct efhw_nic *nic, uint32_t client_id,
			     uint evq, int time_sync_events_enabled)
{
	if( time_sync_events_enabled )
		EFHW_TRACE("%s: timestamping isn't supported on EF100",
			   __FUNCTION__);
	ef10_ef100_mcdi_cmd_event_queue_disable(nic, client_id, evq);
}


static int
ef100_dmaq_tx_q_init(struct efhw_nic *nic, uint32_t client_id, uint dmaq,
		    uint evq_id, uint own_id, uint tag, uint dmaq_size,
		    dma_addr_t *dma_addrs, int n_dma_addrs,
		    uint vport_id, uint stack_id, uint flags)
{
	int rc;
	int flag_timestamp = (flags & EFHW_VI_TX_TIMESTAMPS) != 0;
	int flag_tcp_udp_only = (flags & EFHW_VI_TX_TCPUDP_ONLY) != 0;
	int flag_tcp_csum_dis = (flags & EFHW_VI_TX_TCPUDP_CSUM_DIS) != 0;
	int flag_ip_csum_dis = (flags & EFHW_VI_TX_IP_CSUM_DIS) != 0;
	int flag_buff_mode = (flags & EFHW_VI_TX_PHYS_ADDR_EN) == 0;
	int flag_ctpio = (flags & EFHW_VI_TX_CTPIO) != 0;
	int flag_ctpio_uthresh = (flags & EFHW_VI_TX_CTPIO_NO_POISON) == 0;
	int flag_m2m_d2c = (flags & EFHW_VI_TX_M2M_D2C) != 0;
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
			(nic, client_id, dma_addrs, n_dma_addrs, vport_id, stack_id,
			 REAL_OWNER_ID(own_id), flag_timestamp,
			 QUEUE_CRC_MODE_NONE, flag_tcp_udp_only,
			 flag_tcp_csum_dis, flag_ip_csum_dis,
			 flag_buff_mode, flag_pacer_bypass, flag_ctpio,
			 flag_ctpio_uthresh, flag_m2m_d2c, dmaq, tag, evq_id, dmaq_size);
		if ((rc != -EPERM) || (!flag_pacer_bypass))
			break;
	}

	if ((rc == 0) && !flag_pacer_bypass) {
		EFHW_WARN("%s: WARNING: failed to enable pacer bypass, "
			 "continuing without it", __FUNCTION__);
	}

	if (rc == -EOPNOTSUPP)
		rc = -ENOKEY;

	return rc;
}


static int
ef100_dmaq_rx_q_init(struct efhw_nic *nic, uint32_t client_id, uint dmaq,
		    uint evq_id, uint own_id, uint tag, uint dmaq_size,
		    dma_addr_t *dma_addrs, int n_dma_addrs,
		    uint vport_id, uint stack_id, uint ps_buf_size, uint flags)
{
	int rc;
	int flag_rx_prefix = (flags & EFHW_VI_RX_PREFIX) != 0;
	int flag_timestamp = (flags & EFHW_VI_RX_TIMESTAMPS) != 0;
	int flag_hdr_split = (flags & EFHW_VI_RX_HDR_SPLIT) != 0;
	int flag_buff_mode = (flags & EFHW_VI_RX_PHYS_ADDR_EN) == 0;
	int flag_packed_stream = (flags & EFHW_VI_RX_PACKED_STREAM) != 0;
	int flag_force_rx_merge = ((flags & EFHW_VI_NO_RX_CUT_THROUGH) != 0) &&
				(nic->flags & NIC_FLAG_RX_FORCE_EVENT_MERGING);
	if (flag_packed_stream)
		return -EOPNOTSUPP;

	rc = ef10_ef100_mcdi_cmd_init_rxq
		(nic, client_id, dma_addrs, n_dma_addrs, vport_id, stack_id,
		 REAL_OWNER_ID(own_id), QUEUE_CRC_MODE_NONE, flag_timestamp,
		 flag_hdr_split, flag_buff_mode, flag_rx_prefix,
		 flag_packed_stream, dmaq, tag, evq_id, dmaq_size, ps_buf_size,
		 flag_force_rx_merge, EF100_RX_USR_BUF_SIZE);

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
ef100_handle_event(struct efhw_nic *nic, struct efhw_ev_handler *h,
		   efhw_event_t *ev, int budget)
{
	unsigned evq;

	if (EF100_EVENT_CODE(ev) == EF100_EVENT_CODE_SW) {
		int code = EF100_EVENT_SW_SUBCODE(ev);
		switch (code) {
		case MCDI_EVENT_CODE_TX_FLUSH:
			evq = EF100_EVENT_TX_FLUSH_Q_ID(ev);
			EFHW_TRACE("%s: tx flush done %d", __FUNCTION__, evq);
			return efhw_handle_txdmaq_flushed(nic, h, evq);
		case MCDI_EVENT_CODE_RX_FLUSH:
			evq = EF100_EVENT_RX_FLUSH_Q_ID(ev);
			EFHW_TRACE("%s: rx flush done %d", __FUNCTION__, evq);
			return efhw_handle_rxdmaq_flushed(nic, h, evq, false);
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

static const int __ef100_nic_buffer_table_get_orders[] = {9};

/*--------------------------------------------------------------------
 *
 * EF100 unsupported functions
 *
 *--------------------------------------------------------------------*/

static int
ef100_nic_set_port_sniff(struct efhw_nic *nic, int instance, int enable,
			int promiscuous, int rss_context)
{
	EFHW_TRACE("%s: Port sniffering is not supported for EF100", __FUNCTION__);
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}

static int
ef100_nic_set_tx_port_sniff(struct efhw_nic *nic, int instance, int enable,
			   int rss_context)
{
	EFHW_TRACE("%s: Port sniffering is not supported for EF100", __FUNCTION__);
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}

static int
ef100_nic_license_challenge(struct efhw_nic *nic, 
			   const uint32_t feature, 
			   const uint8_t* challenge, 
			   uint32_t* expiry,
			   uint8_t* signature) {
	EFHW_TRACE("%s: NIC license check is not supported for EF100", __FUNCTION__);
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}

static int
ef100_nic_license_check(struct efhw_nic *nic, const uint32_t feature,
		       int* licensed) {
	EFHW_TRACE("%s: NIC license check is not supported for EF100", __FUNCTION__);
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}

static int
ef100_nic_v3_license_challenge(struct efhw_nic *nic,
			   const uint64_t app_id,
			   const uint8_t* challenge,
			   uint32_t* expiry,
			   uint32_t* days,
			   uint8_t* signature,
                           uint8_t* base_mac,
                           uint8_t* vadaptor_mac) {
	EFHW_TRACE("%s: NIC license check is not supported for EF100", __FUNCTION__);
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}

static int
ef100_nic_v3_license_check(struct efhw_nic *nic, const uint64_t app_id,
		       int* licensed) {
	EFHW_TRACE("%s: NIC license check is not supported for EF100", __FUNCTION__);
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}

static int
ef100_get_rx_error_stats(struct efhw_nic *nic, int instance,
			void *data, int data_len, int do_reset)
{
	EFHW_TRACE("%s: RX error stats are not supported for EF100", __FUNCTION__);
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}

/* TX Alternatives are not supported for EF100 */
static int
ef100_tx_alt_alloc(struct efhw_nic *nic, int tx_q_id, int num_alt,
		  int num_32b_words, unsigned *cp_id_out, unsigned *alt_ids_out)
{
	EFHW_TRACE("%s: TX Alternatives are not supported for EF100", __FUNCTION__);
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}

static int
ef100_tx_alt_free(struct efhw_nic *nic, int num_alt, unsigned cp_id,
		 const unsigned *alt_ids)
{
	EFHW_TRACE("%s: TX Alternatives are not supported for EF100", __FUNCTION__);
	EFHW_ASSERT(0);
	return -EOPNOTSUPP;
}

int ef100_nic_ext_alloc(struct efhw_nic* nic, uint32_t client_id,
                        const unsigned char* service_guid,
                        bool flag_info_only,
                        uint32_t* out_mc_handle)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_PROXYABLE_BUF(in, MC_CMD_PLUGIN_ALLOC_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_PLUGIN_ALLOC_OUT_LEN);

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	memcpy(EFHW_MCDI_PTR(in, PLUGIN_ALLOC_IN_UUID),
	       service_guid, 16);
	EFHW_MCDI_POPULATE_DWORD_1(in, PLUGIN_ALLOC_IN_FLAGS,
	                           PLUGIN_ALLOC_IN_FLAG_INFO_ONLY, flag_info_only);
	rc = ef10_ef100_mcdi_rpc_client(nic, client_id, MC_CMD_PLUGIN_ALLOC,
				 MC_CMD_PLUGIN_ALLOC_IN_LEN, sizeof(out),
				 &out_size, in, out);
	MCDI_CHECK(MC_CMD_PLUGIN_ALLOC, rc, out_size, 0);
	*out_mc_handle = EFHW_MCDI_DWORD(out, PLUGIN_ALLOC_OUT_HANDLE);
	return rc;
}


int ef100_nic_ext_free(struct efhw_nic* nic, uint32_t client_id,
                       uint32_t mc_handle)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_PROXYABLE_BUF(in, MC_CMD_PLUGIN_FREE_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_PLUGIN_FREE_OUT_LEN);

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, PLUGIN_FREE_IN_HANDLE, mc_handle);
	rc = ef10_ef100_mcdi_rpc_client(nic, client_id, MC_CMD_PLUGIN_FREE,
	                                MC_CMD_PLUGIN_FREE_IN_LEN, sizeof(out),
					&out_size, in, out);
	MCDI_CHECK(MC_CMD_PLUGIN_FREE, rc, out_size, 0);
	return rc;
}


int ef100_nic_ext_get_meta_global(struct efhw_nic* nic, uint32_t client_id,
                                  uint32_t mc_handle,
                                  uint8_t* uuid, uint16_t* minor_ver,
                                  uint16_t* patch_ver, uint32_t* nmsgs,
                                  uint16_t* mapped_csr_offset,
                                  uint16_t* mapped_csr_size,
                                  uint8_t* mapped_csr_flags,
                                  uint8_t* admin_group)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_PROXYABLE_BUF(in, MC_CMD_PLUGIN_GET_META_GLOBAL_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_LEN);

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, PLUGIN_GET_META_GLOBAL_IN_HANDLE, mc_handle);
	rc = ef10_ef100_mcdi_rpc_client(nic, client_id,
	                                MC_CMD_PLUGIN_GET_META_GLOBAL,
	                                MC_CMD_PLUGIN_GET_META_GLOBAL_IN_LEN,
	                                sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_PLUGIN_GET_META_GLOBAL, rc, out_size, 0);
	memcpy(uuid, EFHW_MCDI_PTR(out, PLUGIN_GET_META_GLOBAL_OUT_UUID), 16);
	*minor_ver = EFHW_MCDI_WORD(out, PLUGIN_GET_META_GLOBAL_OUT_MINOR_VER);
	*patch_ver = EFHW_MCDI_WORD(out, PLUGIN_GET_META_GLOBAL_OUT_PATCH_VER);
	*nmsgs = EFHW_MCDI_DWORD(out, PLUGIN_GET_META_GLOBAL_OUT_NUM_MSGS);
	*mapped_csr_offset =
	        EFHW_MCDI_WORD(out, PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_OFFSET);
	*mapped_csr_size =
	        EFHW_MCDI_WORD(out, PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_SIZE);
	*mapped_csr_flags =
	        EFHW_MCDI_BYTE(out, PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_FLAGS);
	*admin_group =
	        EFHW_MCDI_BYTE(out, PLUGIN_GET_META_GLOBAL_OUT_ADMIN_GROUP);
	return rc;
}


int ef100_nic_ext_get_meta_msg(struct efhw_nic* nic, uint32_t client_id,
                               uint32_t mc_handle,
                               uint32_t msg_id, uint32_t* index, char* name,
                               size_t name_len, uint32_t* mcdi_param_size)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_PROXYABLE_BUF(in, MC_CMD_PLUGIN_GET_META_MSG_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_PLUGIN_GET_META_MSG_OUT_LEN);

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, PLUGIN_GET_META_MSG_IN_HANDLE, mc_handle);
	EFHW_MCDI_SET_DWORD(in, PLUGIN_GET_META_MSG_IN_ID, msg_id);
	rc = ef10_ef100_mcdi_rpc_client(nic, client_id, MC_CMD_PLUGIN_GET_META_MSG,
	                                MC_CMD_PLUGIN_GET_META_MSG_IN_LEN,
	                                sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_PLUGIN_GET_META_MSG, rc, out_size, 0);
	*index = EFHW_MCDI_DWORD(out, PLUGIN_GET_META_MSG_OUT_INDEX);
	memset(name, 0, name_len);
	memcpy(name, EFHW_MCDI_PTR(out, PLUGIN_GET_META_MSG_OUT_NAME),
	       CI_MIN(name_len, (size_t)MC_CMD_PLUGIN_GET_META_MSG_OUT_NAME_LEN));
	*mcdi_param_size = EFHW_MCDI_DWORD(out,
	                                   PLUGIN_GET_META_MSG_OUT_DATA_SIZE);
	return rc;
}


int ef100_nic_ext_msg(struct efhw_nic* nic, uint32_t client_id,
                      uint32_t mc_handle,
                      uint32_t msg_id, void* payload, size_t len)
{
	ci_dword_t* bufs;
	void* out;
	size_t in_len = len + MC_CMD_PLUGIN_REQ_IN_DATA_OFST;
	size_t in_space = CI_ROUND_UP(in_len + EFHW_PROXY_EXTRA_BYTES, 8);
	size_t out_size;
	int rc;

	EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF100);
	if (len >= MC_CMD_PLUGIN_REQ_IN_DATA_MAXNUM_MCDI2)
		return -E2BIG;
	/* space for two, because we're putting the output in the same alloc: */
	bufs = kzalloc(in_space + CI_ROUND_UP(len, 8), GFP_KERNEL);
	if (!bufs)
		return -ENOMEM;
	out = (char*)bufs + in_space;

	EFHW_MCDI_SET_DWORD(bufs, PLUGIN_REQ_IN_HANDLE, mc_handle);
	EFHW_MCDI_SET_DWORD(bufs, PLUGIN_REQ_IN_ID, msg_id);
	memcpy(EFHW_MCDI_PTR(bufs, PLUGIN_REQ_IN_DATA), payload, len);
	rc = ef10_ef100_mcdi_rpc_client(nic, client_id, MC_CMD_PLUGIN_REQ,
	                                CI_ROUND_UP(in_len, 4),
									CI_ROUND_UP(len, 8), &out_size, bufs, out);
	ef10_ef100_mcdi_check_response(__func__, "MC_CMD_PLUGIN_REQ", rc,
	                               len, out_size, 0);

	if (rc >= 0)
		memcpy(payload, out, len);
	kfree(bufs);
	return rc;
}


/*--------------------------------------------------------------------
 *
 * Dynamic client IDs
 *
 *--------------------------------------------------------------------*/

static int
ef100_client_alloc(struct efhw_nic *nic, uint32_t parent, uint32_t *id)
{
	int rc;
	struct efx_dl_device *efx_dev;
	EFX_DL_PRE(efx_dev, nic, rc)
		rc = efx_dl_client_alloc(efx_dev, parent, id);
	EFX_DL_POST(efx_dev, nic, rc)
	return rc;
}


static int
ef100_client_free(struct efhw_nic *nic, uint32_t id)
{
	int rc;
	struct efx_dl_device *efx_dev;
	EFX_DL_PRE(efx_dev, nic, rc)
		rc = efx_dl_client_free(efx_dev, id);
	EFX_DL_POST(efx_dev, nic, rc)
	return rc;
}


static int
ef100_vi_set_user(struct efhw_nic *nic, uint32_t vi_instance, uint32_t user)
{
	int rc;
	struct efx_dl_device *efx_dev;
	EFX_DL_PRE(efx_dev, nic, rc)
		rc = efx_dl_vi_set_user(efx_dev, vi_instance, user);
	EFX_DL_POST(efx_dev, nic, rc)
	return rc;
}


/*--------------------------------------------------------------------
 *
 * AF_XDP
 *
 *--------------------------------------------------------------------*/

static int ef100_dmaq_kick(struct efhw_nic *nic, int instance)
{
  return 0;
}

static void* ef100_af_xdp_mem(struct efhw_nic* nic, int instance)
{
  return NULL;
}

static int ef100_af_xdp_init(struct efhw_nic* nic, int instance,
                             int chunk_size, int headroom,
                             struct efhw_page_map* pages_out)
{
  return 0;
}


/*--------------------------------------------------------------------
 *
 * CTPIO
 *
 *--------------------------------------------------------------------*/
static int ef100_ctpio_addr(struct efhw_nic* nic, int instance,
			    resource_size_t* addr)
{
	return -ENOSYS;
}


/*--------------------------------------------------------------------
 *
 * Abstraction Layer Hooks
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops ef100_char_functional_units = {
	ef100_nic_init_hardware,
	ef100_nic_tweak_hardware,
	ef100_nic_release_hardware,
	ef100_nic_event_queue_enable,
	ef100_nic_event_queue_disable,
	ef100_nic_wakeup_request,
	ef100_nic_sw_event,
	ef100_handle_event,
	ef100_dmaq_tx_q_init,
	ef100_dmaq_rx_q_init,
	ef10_ef100_dmaq_tx_q_disable,
	ef10_ef100_dmaq_rx_q_disable,
	ef10_ef100_flush_tx_dma_channel,
	ef10_ef100_flush_rx_dma_channel,
	ef10_ef100_translate_dma_addrs,
	__ef100_nic_buffer_table_get_orders,
	sizeof(__ef100_nic_buffer_table_get_orders) /
		sizeof(__ef100_nic_buffer_table_get_orders[0]),
	ef10_ef100_nic_buffer_table_alloc,
	ef10_ef100_nic_buffer_table_realloc,
	ef10_ef100_nic_buffer_table_free,
	ef10_ef100_nic_buffer_table_set,
	ef10_ef100_nic_buffer_table_clear,
	ef100_nic_set_port_sniff,
	ef100_nic_set_tx_port_sniff,
	ef100_nic_license_challenge,
	ef100_nic_license_check,
	ef100_nic_v3_license_challenge,
	ef100_nic_v3_license_check,
	ef100_get_rx_error_stats,
	ef100_tx_alt_alloc,
	ef100_tx_alt_free,
	ef100_client_alloc,
	ef100_client_free,
	ef100_vi_set_user,
	ef10_ef100_rss_alloc,
	ef10_ef100_rss_update,
	ef10_ef100_rss_free,
	ef10_ef100_rss_flags,
	ef10_ef100_filter_insert,
	ef10_ef100_filter_remove,
	ef10_ef100_filter_redirect,
	ef10_ef100_multicast_block,
	ef10_ef100_unicast_block,
	ef10_ef100_vport_alloc,
	ef10_ef100_vport_free,
	ef100_dmaq_kick,
	ef100_af_xdp_mem,
	ef100_af_xdp_init,
	ef10_ef100_get_pci_dev,
	ef10_ef100_vi_io_size,
	ef100_ctpio_addr,
};
