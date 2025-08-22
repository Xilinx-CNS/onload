/***************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2012-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "net_driver.h"
#include "ef10_regs.h"
#include "io.h"
#include "mcdi.h"
#include "mcdi_pcol.h"
#include "mcdi_port.h"
#include "mcdi_port_common.h"
#include "nic.h"
#include "mcdi_filters.h"
#include "mcdi_functions.h"
#include "efx_common.h"
#include "efx_channels.h"
#include "rx_common.h"
#include "tx_common.h"
#include "workarounds.h"
#include "selftest.h"
#include "sriov.h"
#include "ef10_sriov.h"
#include <linux/in.h>
#include <linux/jhash.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
#include <net/udp_tunnel.h>
#endif
#ifdef EFX_NOT_UPSTREAM
#include "efx_ioctl.h"
#endif
#include <linux/module.h>
#include "debugfs.h"

static unsigned int tx_push_max_fill = 0xffffffff;
module_param(tx_push_max_fill, uint, 0444);
MODULE_PARM_DESC(tx_push_max_fill,
		 "[SFC9100-family] Only use Tx push when the queue is below "
		 "this fill level; 0=>never push 1=>push when empty; "
		 "default always to push");

static bool tx_coalesce_doorbell = false;
module_param(tx_coalesce_doorbell, bool, 0444);
MODULE_PARM_DESC(tx_coalesce_doorbell,
		 "[SFC9100-family] Coalesce notification to NIC of pending TX"
		 "data when set this option sets tx_push_max_fill=0:"
		 ":default=N");

static bool multicast_chaining = true;
module_param(multicast_chaining, bool, 0444);
MODULE_PARM_DESC(multicast_chaining,
		 "[SFC9100-family] Enabled multicast filter chaining in "
		 "firmware; default=Y");

#ifdef EFX_NOT_UPSTREAM
static bool monitor_hw_available = false;
module_param(monitor_hw_available, bool, 0644);
MODULE_PARM_DESC(monitor_hw_available,
		 "[SFC9100-family] Check hardware availability during periodic "
		 "monitor; default=N");
#endif

#ifdef EFX_NOT_UPSTREAM
static bool tx_non_csum_queue = false;
module_param(tx_non_csum_queue, bool, 0644);
MODULE_PARM_DESC(tx_non_csum_queue,
		 "[SFC9100-family] Allocate dedicated TX queues for traffic "
		 "not requiring checksum offload; default=N");
#endif

#ifdef EFX_NOT_UPSTREAM
/* A fixed key for RSS that has been tested and found to provide good
 * spreading behaviour.  It also has the desirable property of being
 * symmetric.
 */
static const u8 efx_rss_fixed_key[40] = {
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
	0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
};

static bool efx_rss_use_fixed_key = true;
module_param_named(rss_use_fixed_key, efx_rss_use_fixed_key, bool, 0444);
MODULE_PARM_DESC(rss_use_fixed_key, "Use a fixed RSS hash key, "
		"tested for reliable spreading across channels");
#endif

/* Hardware control for EF10 architecture including 'Huntington'. */

#define EFX_EF10_DRVGEN_EV		7
enum {
	EFX_EF10_TEST = 1,
	EFX_EF10_REFILL,
#ifdef EFX_NOT_UPSTREAM
	EFX_EF10_RERING_RX_DOORBELL,
#endif
};
#define EFX_EF10_DRVGEN_MAGIC(_code, _data)	((_code) | ((_data) << 8))
#define EFX_EF10_DRVGEN_CODE(_magic)	((_magic) & 0xff)
#define EFX_EF10_DRVGEN_DATA(_magic)	((_magic) >> 8)

#ifdef EFX_NOT_UPSTREAM
#define EF10_ONLOAD_PF_VIS 240
#define EF10_ONLOAD_VF_VIS 0
#endif

static bool efx_ef10_hw_unavailable(struct efx_nic *efx);
static void _efx_ef10_rx_write(struct efx_rx_queue *rx_queue);

#ifdef CONFIG_SFC_SRIOV
static void efx_ef10_vf_update_stats_work(struct work_struct *data);
#endif
#ifdef EFX_NOT_UPSTREAM
static struct efx_tx_queue *
efx_ef10_select_tx_queue_non_csum(struct efx_channel *channel,
				  struct sk_buff *skb);
#endif
static struct efx_tx_queue *
efx_ef10_select_tx_queue(struct efx_channel *channel, struct sk_buff *skb);
#ifdef EFX_USE_OVERLAY_TX_CSUM
#ifdef EFX_NOT_UPSTREAM
static struct efx_tx_queue *
efx_ef10_select_tx_queue_non_csum_overlay(struct efx_channel *channel,
					  struct sk_buff *skb);
#endif
static struct efx_tx_queue *
efx_ef10_select_tx_queue_overlay(struct efx_channel *channel,
				 struct sk_buff *skb);
#endif /* EFX_USE_OVERLAY_TX_CSUM */

static u8 *efx_ef10_mcdi_buf(struct efx_nic *efx, u8 bufid,
			     dma_addr_t *dma_addr)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	if (dma_addr)
		*dma_addr = nic_data->mcdi_buf.dma_addr +
			    bufid * ALIGN(MCDI_BUF_LEN, 256);
	return nic_data->mcdi_buf.addr + bufid * ALIGN(MCDI_BUF_LEN, 256);
}

static int efx_ef10_get_warm_boot_count(struct efx_nic *efx)
{
	efx_dword_t reg;

	efx_readd(efx, &reg, ER_DZ_BIU_MC_SFT_STATUS);

	if (EFX_DWORD_FIELD(reg, EFX_DWORD_0) == 0xffffffff) {
		netif_err(efx, hw, efx->net_dev, "Hardware unavailable\n");
		efx->state = STATE_DISABLED;
		return -ENETDOWN;
	} else {
		return EFX_DWORD_FIELD(reg, EFX_WORD_1) == 0xb007 ?
			EFX_DWORD_FIELD(reg, EFX_WORD_0) : -EIO;
	}
}

/* On all EF10s up to and including SFC9220 (Medford1), all PFs use BAR 0 for
 * I/O space and BAR 2(&3) for memory.  On SFC9250 (Medford2), there is no I/O
 * bar; PFs use BAR 0/1 for memory.
 */
static unsigned int efx_ef10_pf_mem_bar(struct efx_nic *efx)
{
	switch (efx->pci_dev->device) {
	case 0x0b03: /* SFC9250 PF */
		return 0;
	default:
		return 2;
	}
}

#if defined(CONFIG_SFC_SRIOV)
/* All VFs use BAR 0/1 for memory */
static unsigned int efx_ef10_vf_mem_bar(struct efx_nic *efx)
{
	return 0;
}
#endif

static unsigned int efx_ef10_initial_mem_map_size(struct efx_nic *efx)
{
	/* For the initial memory mapping, map only one (minimum-size) VI's-
	 * worth. This is enough to get the VI-independent registers.
	 */
#ifdef EFX_NOT_UPSTREAM
	/* ...but is not so much as to interfere with pre-existing mappings of
	 * portions of the BAR held by Onload.
	 */
#endif
	return EFX_DEFAULT_VI_STRIDE;
}

static unsigned int efx_ef10_bar_size(struct efx_nic *efx)
{
	int bar;

	bar = efx->type->mem_bar(efx);
	return resource_size(&efx->pci_dev->resource[bar]);
}

static bool efx_ef10_is_vf(struct efx_nic *efx)
{
	return efx->type->is_vf;
}

static int efx_ef10_init_datapath_caps(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_CAPABILITIES_V4_OUT_LEN);
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	size_t outlen;
	int rc;

	BUILD_BUG_ON(MC_CMD_GET_CAPABILITIES_IN_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_CAPABILITIES, NULL, 0,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < MC_CMD_GET_CAPABILITIES_OUT_LEN) {
		pci_err(efx->pci_dev,
			"unable to read datapath firmware capabilities\n");
		return -EIO;
	}

	nic_data->datapath_caps =
		MCDI_DWORD(outbuf, GET_CAPABILITIES_OUT_FLAGS1);

	if (outlen >= MC_CMD_GET_CAPABILITIES_V2_OUT_LEN) {
		nic_data->datapath_caps2 = MCDI_DWORD(outbuf,
				GET_CAPABILITIES_V2_OUT_FLAGS2);
		nic_data->piobuf_size = MCDI_WORD(outbuf,
				GET_CAPABILITIES_V2_OUT_SIZE_PIO_BUFF);
#ifdef EFX_NOT_UPSTREAM
		/* Does the largest sw-possible PIO packet fit inside a hw
		 * PIO buffer?
		 */
		EFX_WARN_ON_PARANOID(nic_data->piobuf_size < ER_DZ_TX_PIOBUF_SIZE);
#endif
	} else {
		nic_data->datapath_caps2 = 0;
		nic_data->piobuf_size = ER_DZ_TX_PIOBUF_SIZE;
	}

	if (!efx_ef10_has_cap(nic_data->datapath_caps, RX_PREFIX_LEN_14)) {
		pci_err(efx->pci_dev,
			"current firmware does not support an RX prefix\n");
		return -ENODEV;
	}

	if (outlen >= MC_CMD_GET_CAPABILITIES_V3_OUT_LEN) {
		u8 vi_window_mode = MCDI_BYTE(outbuf,
				GET_CAPABILITIES_V3_OUT_VI_WINDOW_MODE);

		rc = efx_mcdi_window_mode_to_stride(efx, vi_window_mode);
		if (rc)
			return rc;
	} else {
		/* keep default VI stride */
		pci_dbg(efx->pci_dev,
			"firmware did not report VI window mode, assuming vi_stride = %u\n",
			efx->vi_stride);
	}

	if (outlen >= MC_CMD_GET_CAPABILITIES_V4_OUT_LEN) {
		efx->num_mac_stats = MCDI_WORD(outbuf,
				GET_CAPABILITIES_V4_OUT_MAC_STATS_NUM_STATS);
		pci_dbg(efx->pci_dev,
			"firmware reports num_mac_stats = %u\n",
			efx->num_mac_stats);
	} else {
		/* leave num_mac_stats as the default value, MC_CMD_MAC_NSTATS */
		pci_dbg(efx->pci_dev,
			"firmware did not report num_mac_stats, assuming %u\n",
			efx->num_mac_stats);
	}

	return 0;
}

static void efx_ef10_read_licensed_features(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_LICENSING_V3_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_LICENSING_V3_OUT_LEN);
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	size_t outlen;
	int rc, try;

	MCDI_SET_DWORD(inbuf, LICENSING_V3_IN_OP,
		       MC_CMD_LICENSING_V3_IN_OP_REPORT_LICENSE);
	for (try=0; try < 15; try++) {
		rc = efx_mcdi_rpc_quiet(efx, MC_CMD_LICENSING_V3, inbuf,
					sizeof(inbuf), outbuf, sizeof(outbuf),
					&outlen);
		if (rc != -EAGAIN)
			break;
		/* It takes a long time to verify the license on an 8xxx
		 * series.
		 */
		msleep(200);
	}
	if (!rc && (outlen >= MC_CMD_LICENSING_V3_OUT_LEN)) {
		nic_data->licensed_features = MCDI_QWORD(outbuf,
					 LICENSING_V3_OUT_LICENSED_FEATURES);
		return;
	}
	if (rc != -MC_CMD_ERR_ENOSYS)
		efx_mcdi_display_error(efx, MC_CMD_LICENSING_V3,
				       MC_CMD_LICENSING_V3_IN_LEN, outbuf,
				       outlen, rc);


	/* LICENSING_V3 will fail on older firmwares, so fall back to
	 * LICENSED_APP_STATE.
	 */
	BUILD_BUG_ON(MC_CMD_GET_LICENSED_APP_STATE_IN_LEN >
		     MC_CMD_LICENSING_V3_IN_LEN);
	BUILD_BUG_ON(MC_CMD_GET_LICENSED_APP_STATE_OUT_LEN >
		     MC_CMD_LICENSING_V3_OUT_LEN);

	MCDI_SET_DWORD(inbuf, GET_LICENSED_APP_STATE_IN_APP_ID,
		       LICENSED_APP_ID_PTP);
	rc = efx_mcdi_rpc(efx, MC_CMD_GET_LICENSED_APP_STATE, inbuf,
			  MC_CMD_GET_LICENSED_APP_STATE_IN_LEN,
			  outbuf, MC_CMD_GET_LICENSED_APP_STATE_OUT_LEN,
			  &outlen);
	if (rc || (outlen < MC_CMD_GET_LICENSED_APP_STATE_OUT_LEN))
	    return;

	if (MCDI_QWORD(outbuf, GET_LICENSED_APP_STATE_OUT_STATE) ==
	    MC_CMD_GET_LICENSED_APP_STATE_OUT_LICENSED)
		nic_data->licensed_features |=
			(1 << LICENSED_V3_FEATURES_TX_TIMESTAMPS_LBN);
}

static int efx_ef10_get_sysclk_freq(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_CLOCK_OUT_LEN);
	int rc;

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_CLOCK, NULL, 0,
			  outbuf, sizeof(outbuf), NULL);
	if (rc)
		return rc;
	rc = MCDI_DWORD(outbuf, GET_CLOCK_OUT_SYS_FREQ);
	return rc > 0 ? rc : -ERANGE;
}

static int efx_ef10_get_timer_workarounds(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	unsigned int implemented;
	unsigned int enabled;
	int rc;

	nic_data->workaround_35388 = false;
	nic_data->workaround_61265 = false;

	rc = efx_mcdi_get_workarounds(efx, &implemented, &enabled);

	if (rc == -ENOSYS) {
		/* Firmware without GET_WORKAROUNDS - not a problem. */
		rc = 0;
	} else if (rc == 0) {
		/* Bug61265 workaround is always enabled if implemented. */
		if (enabled & MC_CMD_GET_WORKAROUNDS_OUT_BUG61265)
			nic_data->workaround_61265 = true;

		if (enabled & MC_CMD_GET_WORKAROUNDS_OUT_BUG35388) {
			nic_data->workaround_35388 = true;
		} else if (implemented & MC_CMD_GET_WORKAROUNDS_OUT_BUG35388) {
			/* Workaround is implemented but not enabled.
			 * Try to enable it.
			 */
			rc = efx_mcdi_set_workaround(efx,
						     MC_CMD_WORKAROUND_BUG35388,
						     true, NULL);
			if (rc == 0)
				nic_data->workaround_35388 = true;
			/* If we failed to set the workaround just carry on. */
			rc = 0;
		}
	}

	pci_dbg(efx->pci_dev,
		"workaround for bug 35388 is %sabled\n",
		nic_data->workaround_35388 ? "en" : "dis");
	pci_dbg(efx->pci_dev,
		"workaround for bug 61265 is %sabled\n",
		nic_data->workaround_61265 ? "en" : "dis");

	return rc;
}

static void efx_ef10_process_timer_config(struct efx_nic *efx,
					  const efx_dword_t *data)
{
	unsigned int max_count;

	if (EFX_EF10_WORKAROUND_61265(efx)) {
		efx->timer_quantum_ns = MCDI_DWORD(data,
			GET_EVQ_TMR_PROPERTIES_OUT_MCDI_TMR_STEP_NS);
		efx->timer_max_ns = MCDI_DWORD(data,
			GET_EVQ_TMR_PROPERTIES_OUT_MCDI_TMR_MAX_NS);
	} else if (EFX_EF10_WORKAROUND_35388(efx)) {
		efx->timer_quantum_ns = MCDI_DWORD(data,
			GET_EVQ_TMR_PROPERTIES_OUT_BUG35388_TMR_NS_PER_COUNT);
		max_count = MCDI_DWORD(data,
			GET_EVQ_TMR_PROPERTIES_OUT_BUG35388_TMR_MAX_COUNT);
		efx->timer_max_ns = max_count * efx->timer_quantum_ns;
	} else {
		efx->timer_quantum_ns = MCDI_DWORD(data,
			GET_EVQ_TMR_PROPERTIES_OUT_TMR_REG_NS_PER_COUNT);
		max_count = MCDI_DWORD(data,
			GET_EVQ_TMR_PROPERTIES_OUT_TMR_REG_MAX_COUNT);
		efx->timer_max_ns = max_count * efx->timer_quantum_ns;
	}

	pci_dbg(efx->pci_dev,
		"got timer properties from MC: quantum %u ns; max %u ns\n",
		efx->timer_quantum_ns, efx->timer_max_ns);
}

static int efx_ef10_get_timer_config(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_EVQ_TMR_PROPERTIES_OUT_LEN);
	int rc;

	rc = efx_ef10_get_timer_workarounds(efx);
	if (rc)
		return rc;

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_GET_EVQ_TMR_PROPERTIES, NULL, 0,
				outbuf, sizeof(outbuf), NULL);

	if (rc == 0) {
		efx_ef10_process_timer_config(efx, outbuf);
	} else if (rc == -ENOSYS || rc == -EPERM) {
		/* Not available - fall back to Huntington defaults. */
		unsigned int quantum;

		rc = efx_ef10_get_sysclk_freq(efx);
		if (rc < 0)
			return rc;

		quantum = 1536000 / rc; /* 1536 cycles */
		efx->timer_quantum_ns = quantum;
		efx->timer_max_ns = efx->type->timer_period_max * quantum;
		rc = 0;
	} else {
		efx_mcdi_display_error(efx, MC_CMD_GET_EVQ_TMR_PROPERTIES,
				       MC_CMD_GET_EVQ_TMR_PROPERTIES_OUT_LEN,
				       NULL, 0, rc);
	}

	return rc;
}

static int efx_ef10_get_mac_address_pf(struct efx_nic *efx, u8 *mac_address)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_MAC_ADDRESSES_OUT_LEN);
	size_t outlen;
	int rc;

	BUILD_BUG_ON(MC_CMD_GET_MAC_ADDRESSES_IN_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_MAC_ADDRESSES, NULL, 0,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < MC_CMD_GET_MAC_ADDRESSES_OUT_LEN)
		return -EIO;

	ether_addr_copy(mac_address,
			MCDI_PTR(outbuf, GET_MAC_ADDRESSES_OUT_MAC_ADDR_BASE));
#ifdef EFX_NOT_UPSTREAM
	if (mac_address[0] & 2)
		netif_warn(efx, probe, efx->net_dev,
			   "static config does not include a global MAC address pool; using local address\n");
#endif
	return 0;
}

#if defined(CONFIG_SFC_SRIOV)
static int efx_ef10_get_mac_address_vf(struct efx_nic *efx, u8 *mac_address)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_VPORT_GET_MAC_ADDRESSES_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_VPORT_GET_MAC_ADDRESSES_OUT_LENMAX);
	size_t outlen;
	int num_addrs, rc;

	MCDI_SET_DWORD(inbuf, VPORT_GET_MAC_ADDRESSES_IN_VPORT_ID,
		       EVB_PORT_ID_ASSIGNED);
	rc = efx_mcdi_rpc(efx, MC_CMD_VPORT_GET_MAC_ADDRESSES, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), &outlen);

	if (rc)
		return rc;
	if (outlen < MC_CMD_VPORT_GET_MAC_ADDRESSES_OUT_LENMIN)
		return -EIO;

	num_addrs = MCDI_DWORD(outbuf,
			       VPORT_GET_MAC_ADDRESSES_OUT_MACADDR_COUNT);

	WARN_ON(num_addrs != 1);

	ether_addr_copy(mac_address,
			MCDI_PTR(outbuf, VPORT_GET_MAC_ADDRESSES_OUT_MACADDR));

	return 0;
}
#endif

#ifdef CONFIG_SFC_SRIOV
static int efx_vf_parent(struct efx_nic *efx, struct efx_nic **efx_pf)
{
	struct pci_dev *pci_dev_pf = pci_physfn(efx->pci_dev);
	int rc = 0;

	/* By default succeed without a parent PF */
	*efx_pf = NULL;

	/* Suceed if this is a PF already, or if there is noparent PF.
	 * Fail if the parent is not an sfc device.
	 */
	if (!pci_dev_pf || (efx->pci_dev == pci_dev_pf))
		rc = 0;
	else if (!pci_dev_pf->dev.driver ||
		 (pci_dev_pf->dev.driver->owner != THIS_MODULE))
		rc = -EBUSY;
	else
		*efx_pf = pci_get_drvdata(pci_dev_pf);

	return rc;
}
#endif

int efx_ef10_vswitch_alloc(struct efx_nic *efx, unsigned int port_id,
			   unsigned int vswitch_type)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_VSWITCH_ALLOC_IN_LEN);
	int rc;

	MCDI_SET_DWORD(inbuf, VSWITCH_ALLOC_IN_UPSTREAM_PORT_ID, port_id);
	MCDI_SET_DWORD(inbuf, VSWITCH_ALLOC_IN_TYPE, vswitch_type);
	MCDI_SET_DWORD(inbuf, VSWITCH_ALLOC_IN_NUM_VLAN_TAGS, 2);
	MCDI_POPULATE_DWORD_1(inbuf, VSWITCH_ALLOC_IN_FLAGS,
			      VSWITCH_ALLOC_IN_FLAG_AUTO_PORT, 0);

	/* Quietly try to allocate 2 VLAN tags */
	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_VSWITCH_ALLOC, inbuf, sizeof(inbuf),
				NULL, 0, NULL);

	/* If 2 VLAN tags is too many, revert to trying with 1 VLAN tags */
	if (rc == -EPROTO) {
		MCDI_SET_DWORD(inbuf, VSWITCH_ALLOC_IN_NUM_VLAN_TAGS, 1);
		rc = efx_mcdi_rpc(efx, MC_CMD_VSWITCH_ALLOC, inbuf,
				  sizeof(inbuf), NULL, 0, NULL);
	} else if (rc) {
		efx_mcdi_display_error(efx, MC_CMD_VSWITCH_ALLOC,
				       MC_CMD_VSWITCH_ALLOC_IN_LEN, NULL, 0,
				       rc);
	}
	return rc;
}

int efx_ef10_vswitch_free(struct efx_nic *efx, unsigned int port_id)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_VSWITCH_FREE_IN_LEN);

	MCDI_SET_DWORD(inbuf, VSWITCH_FREE_IN_UPSTREAM_PORT_ID, port_id);

	return efx_mcdi_rpc(efx, MC_CMD_VSWITCH_FREE, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

int efx_ef10_vport_alloc(struct efx_nic *efx, u16 vlan, bool vlan_restrict,
			 unsigned int *port_id_out)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_VPORT_ALLOC_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_VPORT_ALLOC_OUT_LEN);
	size_t outlen;
	int rc;

	EFX_WARN_ON_PARANOID(!port_id_out);

	/* we only ever want a single level of vports, so parent is ASSIGNED */
	MCDI_SET_DWORD(inbuf, VPORT_ALLOC_IN_UPSTREAM_PORT_ID,
		       EVB_PORT_ID_ASSIGNED);
	/* we also only ever want NORMAL type, the others are obsolete */
	MCDI_SET_DWORD(inbuf, VPORT_ALLOC_IN_TYPE,
		       MC_CMD_VPORT_ALLOC_IN_VPORT_TYPE_NORMAL);
	MCDI_SET_DWORD(inbuf, VPORT_ALLOC_IN_NUM_VLAN_TAGS,
		       (vlan != EFX_FILTER_VID_UNSPEC));
	MCDI_POPULATE_DWORD_2(inbuf, VPORT_ALLOC_IN_FLAGS,
			      VPORT_ALLOC_IN_FLAG_AUTO_PORT, 0,
			      VPORT_ALLOC_IN_FLAG_VLAN_RESTRICT, vlan_restrict);
	if (vlan != EFX_FILTER_VID_UNSPEC)
		MCDI_POPULATE_DWORD_1(inbuf, VPORT_ALLOC_IN_VLAN_TAGS,
				      VPORT_ALLOC_IN_VLAN_TAG_0, vlan);

	rc = efx_mcdi_rpc(efx, MC_CMD_VPORT_ALLOC, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < MC_CMD_VPORT_ALLOC_OUT_LEN)
		return -EIO;

	*port_id_out = MCDI_DWORD(outbuf, VPORT_ALLOC_OUT_VPORT_ID);
	return 0;
}

int efx_ef10_vport_free(struct efx_nic *efx, unsigned int port_id)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_VPORT_FREE_IN_LEN);

	MCDI_SET_DWORD(inbuf, VPORT_FREE_IN_VPORT_ID, port_id);

	return efx_mcdi_rpc(efx, MC_CMD_VPORT_FREE, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

int efx_ef10_vadaptor_query(struct efx_nic *efx, unsigned int port_id,
			    u32 *port_flags, u32 *vadaptor_flags,
			    unsigned int *vlan_tags)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_VADAPTOR_QUERY_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_VADAPTOR_QUERY_OUT_LEN);
	size_t outlen;
	int rc;

	if (efx_ef10_has_cap(nic_data->datapath_caps, VADAPTOR_QUERY)) {
		MCDI_SET_DWORD(inbuf, VADAPTOR_QUERY_IN_UPSTREAM_PORT_ID,
			       port_id);

		rc = efx_mcdi_rpc(efx, MC_CMD_VADAPTOR_QUERY,
				  inbuf, sizeof(inbuf),
				  outbuf, sizeof(outbuf), &outlen);
		if (rc)
			return rc;

		if (outlen < sizeof(outbuf)) {
			rc = -EIO;
			return rc;
		}
	}

	if (port_flags)
		*port_flags = MCDI_DWORD(outbuf, VADAPTOR_QUERY_OUT_PORT_FLAGS);
	if (vadaptor_flags)
		*vadaptor_flags =
			MCDI_DWORD(outbuf, VADAPTOR_QUERY_OUT_VADAPTOR_FLAGS);
	if (vlan_tags)
		*vlan_tags =
			MCDI_DWORD(outbuf,
				   VADAPTOR_QUERY_OUT_NUM_AVAILABLE_VLAN_TAGS);

	return 0;
}

int efx_ef10_vadaptor_alloc(struct efx_nic *efx, unsigned int port_id)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_VADAPTOR_ALLOC_IN_LEN);

	MCDI_SET_DWORD(inbuf, VADAPTOR_ALLOC_IN_UPSTREAM_PORT_ID, port_id);
	MCDI_POPULATE_DWORD_1(inbuf, VADAPTOR_ALLOC_IN_FLAGS,
		VADAPTOR_ALLOC_IN_FLAG_PERMIT_SET_MAC_WHEN_FILTERS_INSTALLED,
		1);
	return efx_mcdi_rpc(efx, MC_CMD_VADAPTOR_ALLOC, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

int efx_ef10_vadaptor_free(struct efx_nic *efx, unsigned int port_id)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_VADAPTOR_FREE_IN_LEN);

	MCDI_SET_DWORD(inbuf, VADAPTOR_FREE_IN_UPSTREAM_PORT_ID, port_id);
	return efx_mcdi_rpc(efx, MC_CMD_VADAPTOR_FREE, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

int efx_ef10_evb_port_assign(struct efx_nic *efx, unsigned int port_id,
			     unsigned int vf_fn)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_EVB_PORT_ASSIGN_IN_LEN);
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	MCDI_SET_DWORD(inbuf, EVB_PORT_ASSIGN_IN_PORT_ID, port_id);
	MCDI_POPULATE_DWORD_2(inbuf, EVB_PORT_ASSIGN_IN_FUNCTION,
			      EVB_PORT_ASSIGN_IN_PF, nic_data->pf_index,
			      EVB_PORT_ASSIGN_IN_VF, vf_fn);

	return efx_mcdi_rpc(efx, MC_CMD_EVB_PORT_ASSIGN, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

int efx_ef10_vport_add_mac(struct efx_nic *efx, unsigned int port_id, const u8 *mac)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_VPORT_ADD_MAC_ADDRESS_IN_LEN);

	MCDI_SET_DWORD(inbuf, VPORT_ADD_MAC_ADDRESS_IN_VPORT_ID, port_id);
	ether_addr_copy(MCDI_PTR(inbuf, VPORT_ADD_MAC_ADDRESS_IN_MACADDR), mac);

	return efx_mcdi_rpc(efx, MC_CMD_VPORT_ADD_MAC_ADDRESS, inbuf,
			    sizeof(inbuf), NULL, 0, NULL);
}

int efx_ef10_vport_del_mac(struct efx_nic *efx, unsigned int port_id, const u8 *mac)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_VPORT_DEL_MAC_ADDRESS_IN_LEN);

	MCDI_SET_DWORD(inbuf, VPORT_DEL_MAC_ADDRESS_IN_VPORT_ID, port_id);
	ether_addr_copy(MCDI_PTR(inbuf, VPORT_DEL_MAC_ADDRESS_IN_MACADDR), mac);

	return efx_mcdi_rpc(efx, MC_CMD_VPORT_DEL_MAC_ADDRESS, inbuf,
			    sizeof(inbuf), NULL, 0, NULL);
}

#ifdef EFX_USE_PIO

static void efx_ef10_free_piobufs(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_FREE_PIOBUF_IN_LEN);
	unsigned int i;
	int rc;

	BUILD_BUG_ON(MC_CMD_FREE_PIOBUF_OUT_LEN != 0);

	for (i = 0; i < nic_data->n_piobufs; i++) {
		MCDI_SET_DWORD(inbuf, FREE_PIOBUF_IN_PIOBUF_HANDLE,
			       nic_data->piobuf_handle[i]);
		rc = efx_mcdi_rpc(efx, MC_CMD_FREE_PIOBUF, inbuf, sizeof(inbuf),
				  NULL, 0, NULL);
		if (unlikely(rc && rc != -ENETDOWN &&
			     !efx_ef10_hw_unavailable(efx)))
			netif_warn(efx, probe, efx->net_dev,
				   "Failed to free PIO buffers: %d\n", rc);
	}

	nic_data->n_piobufs = 0;
}

static int efx_ef10_alloc_piobufs(struct efx_nic *efx, unsigned int n)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	MCDI_DECLARE_BUF(outbuf, MC_CMD_ALLOC_PIOBUF_OUT_LEN);
	unsigned int i;
	size_t outlen;
	int rc = 0;

	BUILD_BUG_ON(MC_CMD_ALLOC_PIOBUF_IN_LEN != 0);

	for (i = 0; i < n; i++) {
		rc = efx_mcdi_rpc_quiet(efx, MC_CMD_ALLOC_PIOBUF, NULL, 0,
					outbuf, sizeof(outbuf), &outlen);
		if (rc == -EPERM) {
			netif_info(efx, probe, efx->net_dev, "no PIO support\n");
			break;
		} else if (rc) {
			/* Don't display the MC error if we didn't have space
			 * for a VF.
			 */
			if (!(efx_ef10_is_vf(efx) && rc == -ENOSPC))
				efx_mcdi_display_error(efx, MC_CMD_ALLOC_PIOBUF,
						       0, outbuf, outlen, rc);
			break;
		}
		if (outlen < MC_CMD_ALLOC_PIOBUF_OUT_LEN) {
			rc = -EIO;
			break;
		}
		nic_data->piobuf_handle[i] =
			MCDI_DWORD(outbuf, ALLOC_PIOBUF_OUT_PIOBUF_HANDLE);
		netif_dbg(efx, probe, efx->net_dev,
			  "allocated PIO buffer %u handle %x\n", i,
			  nic_data->piobuf_handle[i]);
	}

	nic_data->n_piobufs = i;
	if (rc)
		efx_ef10_free_piobufs(efx);
	return rc;
}

static int efx_ef10_link_piobufs(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_LINK_PIOBUF_IN_LEN);
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;
	unsigned int offset, index;
	int rc;

	BUILD_BUG_ON(MC_CMD_LINK_PIOBUF_OUT_LEN != 0);
	BUILD_BUG_ON(MC_CMD_UNLINK_PIOBUF_OUT_LEN != 0);

	/* Link a buffer to each VI in the write-combining mapping */
	for (index = 0; index < nic_data->n_piobufs; ++index) {
		MCDI_SET_DWORD(inbuf, LINK_PIOBUF_IN_PIOBUF_HANDLE,
			       nic_data->piobuf_handle[index]);
		MCDI_SET_DWORD(inbuf, LINK_PIOBUF_IN_TXQ_INSTANCE,
			       nic_data->pio_write_vi_base + index);
		rc = efx_mcdi_rpc(efx, MC_CMD_LINK_PIOBUF,
				  inbuf, MC_CMD_LINK_PIOBUF_IN_LEN,
				  NULL, 0, NULL);
		if (rc) {
			netif_err(efx, drv, efx->net_dev,
				  "failed to link VI %u to PIO buffer %u (%d)\n",
				  nic_data->pio_write_vi_base + index, index,
				  rc);
			goto fail;
		}
		netif_dbg(efx, probe, efx->net_dev,
			  "linked VI %u to PIO buffer %u\n",
			  nic_data->pio_write_vi_base + index, index);
	}

	/* Link a buffer to each TX queue */
	efx_for_each_channel(channel, efx) {
		if (!efx_channel_has_tx_queues(channel))
			continue;

		efx_for_each_channel_tx_queue(tx_queue, channel) {
			/* We assign the PIO buffers to queues in
			 * reverse order to allow for the following
			 * special case.
			 */
			offset = ((efx->tx_channel_offset +
				   efx_tx_channels(efx) -
				   tx_queue->channel->channel - 1) *
				  efx_piobuf_size);
			index = offset / nic_data->piobuf_size;
			offset = offset % nic_data->piobuf_size;

			/* When the host page size is 4K, the first
			 * host page in the WC mapping may be within
			 * the same VI page as the last TX queue.  We
			 * can only link one buffer to each VI.
			 */
			if (tx_queue->queue == nic_data->pio_write_vi_base) {
				BUG_ON(index != 0);
				rc = 0;
			} else {
				MCDI_SET_DWORD(inbuf,
					       LINK_PIOBUF_IN_PIOBUF_HANDLE,
					       nic_data->piobuf_handle[index]);
				MCDI_SET_DWORD(inbuf,
					       LINK_PIOBUF_IN_TXQ_INSTANCE,
					       tx_queue->queue);
				rc = efx_mcdi_rpc(efx, MC_CMD_LINK_PIOBUF,
						  inbuf, MC_CMD_LINK_PIOBUF_IN_LEN,
						  NULL, 0, NULL);
			}

			if (rc) {
				/* This is non-fatal; the TX path just
				 * won't use PIO for this queue
				 */
				netif_err(efx, drv, efx->net_dev,
					  "failed to link VI %u to PIO buffer %u (%d)\n",
					  tx_queue->queue, index, rc);
				tx_queue->piobuf = NULL;

				if (rc == -ENETDOWN)
					goto fail;
			} else {
				tx_queue->piobuf =
					nic_data->pio_write_base +
					index * efx->vi_stride + offset;
				tx_queue->piobuf_offset = offset;
				netif_dbg(efx, probe, efx->net_dev,
					  "linked VI %u to PIO buffer %u offset %x addr %p\n",
					  tx_queue->queue, index,
					  tx_queue->piobuf_offset,
					  tx_queue->piobuf);
			}
		}
	}

	return 0;

fail:
	/* inbuf was defined for MC_CMD_LINK_PIOBUF.  We can use the same
	 * buffer for MC_CMD_UNLINK_PIOBUF because it's shorter.
	 */
	BUILD_BUG_ON(MC_CMD_LINK_PIOBUF_IN_LEN < MC_CMD_UNLINK_PIOBUF_IN_LEN);
	while (index--) {
		MCDI_SET_DWORD(inbuf, UNLINK_PIOBUF_IN_TXQ_INSTANCE,
			       nic_data->pio_write_vi_base + index);
		efx_mcdi_rpc(efx, MC_CMD_UNLINK_PIOBUF,
			     inbuf, MC_CMD_UNLINK_PIOBUF_IN_LEN,
			     NULL, 0, NULL);
	}
	return rc;
}

static void efx_ef10_forget_old_piobufs(struct efx_nic *efx)
{
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;

	/* All our existing PIO buffers went away */
	efx_for_each_channel(channel, efx)
		efx_for_each_channel_tx_queue(tx_queue, channel)
			tx_queue->piobuf = NULL;
}

#else /* !EFX_USE_PIO */

static int efx_ef10_alloc_piobufs(struct efx_nic *efx, unsigned int n)
{
	return n == 0 ? 0 : -ENOBUFS;
}

static int efx_ef10_link_piobufs(struct efx_nic *efx)
{
	return 0;
}

static void efx_ef10_free_piobufs(struct efx_nic *efx)
{
}

static void efx_ef10_forget_old_piobufs(struct efx_nic *efx)
{
}

#endif /* EFX_USE_PIO */

static int efx_ef10_alloc_vis(struct efx_nic *efx,
			      unsigned int min_vis, unsigned int max_vis)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	return efx_mcdi_alloc_vis(efx, min_vis, max_vis,
#if defined(EFX_NOT_UPSTREAM) && IS_MODULE(CONFIG_SFC_DRIVERLINK)
				  &efx->ef10_resources.vi_base,
				  &efx->ef10_resources.vi_shift,
#else
				  NULL, NULL,
#endif
				  &nic_data->n_allocated_vis);
}

static void efx_ef10_free_resources(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	efx_mcdi_free_vis(efx);

	if (nic_data->wc_membase) {
		iounmap(nic_data->wc_membase);
		nic_data->wc_membase = NULL;
	}

	if (!nic_data->must_restore_piobufs)
		efx_ef10_free_piobufs(efx);
}

static int efx_ef10_dimension_resources(struct efx_nic *efx)
{
#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	struct efx_dl_ef10_resources *res = &efx->ef10_resources;
#endif
#endif
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	unsigned int uc_mem_map_size, wc_mem_map_size;
	unsigned int channel_vis, pio_write_vi_base, max_vis;
	unsigned int tx_channels, tx_vis, rx_vis, pio_vis;
	unsigned int rx_vis_per_queue;
	void __iomem *membase;
	unsigned int min_vis;
	int rc;

	rx_vis_per_queue = efx_tx_vi_spreading(efx) ? 2 : 1;

	/* A VI (virtual interface) consists of three queues: rx, tx and
	 * event. It's possible for any event queue to service any rx or tx
	 * queue, and multiple queues can be serviced by a single event queue.
	 */
	min_vis = max3(efx->tx_queues_per_channel,
		       separate_tx_channels ? 2u : 1u, /* Event queues */
		       rx_vis_per_queue);

	rx_vis = efx_rx_channels(efx) * rx_vis_per_queue;
	tx_channels = efx_tx_channels(efx);
	if (efx->max_tx_channels && efx->max_tx_channels < tx_channels) {
		netif_dbg(efx, drv, efx->net_dev,
			  "Reducing TX channels from %u to %u\n",
			  tx_channels, efx->max_tx_channels);
		tx_channels = efx->max_tx_channels;
	}
	tx_vis = tx_channels * efx->tx_queues_per_channel;

	tx_vis += efx_xdp_channels(efx) * efx->xdp_tx_per_channel;

	channel_vis = max(rx_vis, tx_vis);
	if (efx->max_vis && efx->max_vis < channel_vis) {
		netif_dbg(efx, drv, efx->net_dev,
			  "Reducing channel VIs from %u to %u\n",
			  channel_vis, efx->max_vis);
		channel_vis = efx->max_vis;
	}

#ifdef EFX_USE_PIO
	/* Try to allocate PIO buffers if wanted and if the full
	 * number of PIO buffers would be sufficient to allocate one
	 * copy-buffer per TX channel.  Failure is non-fatal, as there
	 * are only a small number of PIO buffers shared between all
	 * functions of the controller.
	 */
	if (efx_piobuf_size != 0 &&
	    nic_data->piobuf_size / efx_piobuf_size * EF10_TX_PIOBUF_COUNT >=
	    efx_tx_channels(efx)) {
		unsigned int n_piobufs =
			DIV_ROUND_UP(efx_tx_channels(efx),
				     nic_data->piobuf_size / efx_piobuf_size);

		rc = efx_ef10_alloc_piobufs(efx, n_piobufs);
		if (rc == -ENOSPC)
			netif_dbg(efx, probe, efx->net_dev,
				  "out of PIO buffers; cannot allocate more\n");
		else if (rc == -EPERM)
			netif_dbg(efx, probe, efx->net_dev,
				  "not permitted to allocate PIO buffers\n");
		else if (rc)
			netif_err(efx, probe, efx->net_dev,
				  "failed to allocate PIO buffers (%d)\n", rc);
		else
			netif_dbg(efx, probe, efx->net_dev,
				  "allocated %u PIO buffers\n", n_piobufs);
	}
#else
	nic_data->n_piobufs = 0;
#endif

	/* PIO buffers should be mapped with write-combining enabled,
	 * and we want to make single UC and WC mappings rather than
	 * several of each (in fact that's the only option if host
	 * page size is >4K).  So we may allocate some extra VIs just
	 * for writing PIO buffers through.
	 *
	 * The UC mapping contains (channel_vis - 1) complete VIs and the
	 * first 4K of the next VI.  Then the WC mapping begins with
	 * the remainder of this last VI.
	 */
	uc_mem_map_size = PAGE_ALIGN((channel_vis - 1) * efx->vi_stride +
				     ER_DZ_TX_PIOBUF);
	if (nic_data->n_piobufs) {
		/* pio_write_vi_base rounds down to give the number of complete
		 * VIs inside the UC mapping.
		 */
		pio_write_vi_base = uc_mem_map_size / efx->vi_stride;
		wc_mem_map_size = (PAGE_ALIGN((pio_write_vi_base +
					       nic_data->n_piobufs) *
					      efx->vi_stride) -
				   uc_mem_map_size);
		pio_vis = pio_write_vi_base + nic_data->n_piobufs;
	} else {
		pio_write_vi_base = 0;
		wc_mem_map_size = 0;
		pio_vis = 0;
	}
	max_vis = max(pio_vis, channel_vis);

#ifdef EFX_NOT_UPSTREAM
	max_vis += efx_target_num_vis >= 0 ?
			efx_target_num_vis :
			efx_ef10_is_vf(efx) ? EF10_ONLOAD_VF_VIS
					    : EF10_ONLOAD_PF_VIS;
	if (efx->max_vis && efx->max_vis < max_vis) {
		netif_dbg(efx, drv, efx->net_dev,
			  "reducing max VIs requested from %u to %u\n",
			  max_vis, efx->max_vis);
		max_vis = efx->max_vis;
	}
#endif

	max_vis = max(min_vis, max_vis);
	/* In case the last attached driver failed to free VIs, do it now */
	rc = efx_mcdi_free_vis(efx);
	if (rc != 0)
		return rc;

	rc = efx_ef10_alloc_vis(efx, min_vis, max_vis);
	if (rc != 0) {
		netif_err(efx, drv, efx->net_dev,
			  "Could not allocate %u VIs.\n", min_vis);
		return rc;
	}

	if (nic_data->n_allocated_vis < channel_vis) {
		netif_info(efx, drv, efx->net_dev,
			   "Could not allocate enough VIs to satisfy RSS "
			   "requirements. Performance may be impaired.\n");
		/* We didn't get the VIs to populate our channels. We could keep
		 * what we got but then we'd have more interrupts than we need.
		 * Instead calculate new max_channels and restart */
		efx->max_vis = efx->max_channels = nic_data->n_allocated_vis;
		efx->max_tx_channels =
			nic_data->n_allocated_vis / efx->tx_queues_per_channel;

		efx_mcdi_free_vis(efx);
		return -EAGAIN;
	}

	/* If we didn't get enough VIs to map all the PIO buffers, free the
	 * PIO buffers
	 */
	if (nic_data->n_piobufs &&
	    nic_data->n_allocated_vis <
	    pio_write_vi_base + nic_data->n_piobufs) {
		netif_dbg(efx, probe, efx->net_dev,
			  "%u VIs are not sufficient to map %u PIO buffers\n",
			  nic_data->n_allocated_vis, nic_data->n_piobufs);
		efx_ef10_free_piobufs(efx);
		pio_write_vi_base = 0;
		wc_mem_map_size = 0;
	}

	/* Extend the original UC mapping of the memory BAR */
#if defined(EFX_USE_KCOMPAT)
	membase = efx_ioremap(efx->membase_phys, uc_mem_map_size);
#else
	membase = ioremap(efx->membase_phys, uc_mem_map_size);
#endif
	if (!membase) {
		netif_err(efx, probe, efx->net_dev,
			  "could not extend memory BAR to %x\n",
			  uc_mem_map_size);
		return -ENOMEM;
	}
	iounmap(efx->membase);
	efx->membase = membase;

	/* Set up the WC mapping if needed */
	if (wc_mem_map_size) {
		nic_data->wc_membase = ioremap_wc(efx->membase_phys +
						  uc_mem_map_size,
						  wc_mem_map_size);
		if (!nic_data->wc_membase) {
			netif_err(efx, probe, efx->net_dev,
				  "could not allocate WC mapping of size %x\n",
				  wc_mem_map_size);
			return -ENOMEM;
		}
		nic_data->pio_write_vi_base = pio_write_vi_base;
		nic_data->pio_write_base =
			nic_data->wc_membase +
			(pio_write_vi_base * efx->vi_stride + ER_DZ_TX_PIOBUF -
			 uc_mem_map_size);

		rc = efx_ef10_link_piobufs(efx);
		if (rc)
			efx_ef10_free_piobufs(efx);
		if (rc == -ENETDOWN)
			return rc;
	}

	netif_dbg(efx, probe, efx->net_dev,
		  "memory BAR at %llx (virtual %p+%x UC, %p+%x WC)\n",
		  (unsigned long long)efx->membase_phys, efx->membase,
		  uc_mem_map_size, nic_data->wc_membase, wc_mem_map_size);

#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	res->vi_min = DIV_ROUND_UP(uc_mem_map_size + wc_mem_map_size,
				   efx->vi_stride);
	res->vi_lim = nic_data->n_allocated_vis;
	res->timer_quantum_ns = efx->timer_quantum_ns;
	res->rss_channel_count = efx->rss_spread;
	res->rx_channel_count = efx_rx_channels(efx);
	res->flags |= EFX_DL_EF10_USE_MSI;
	res->vi_stride = efx->vi_stride;
	res->mem_bar = efx->type->mem_bar(efx);

	efx->dl_nic.dl_info = &res->hdr;
#endif
#endif
	return 0;
}

#ifdef EFX_NOT_UPSTREAM
static struct efx_tx_queue *
efx_ef10_select_tx_queue_non_csum(struct efx_channel *channel,
				  struct sk_buff *skb)
{
	return &channel->tx_queues[skb->ip_summed ? EFX_TXQ_TYPE_CSUM_OFFLOAD :
						    EFX_TXQ_TYPE_NO_OFFLOAD];
}
#endif

static void efx_ef10_set_tx_queue_csum(struct efx_tx_queue *tx_queue,
				       unsigned int txq_type)
{
	if (tx_queue->csum_offload != txq_type) {
		bool outer_csum = txq_type & EFX_TXQ_TYPE_CSUM_OFFLOAD;
		bool inner_csum = txq_type & EFX_TXQ_TYPE_INNER_CSUM_OFFLOAD;
		bool tso_v2 = ((tx_queue->tso_version == 2) &&
			       !tx_queue->timestamping);
		struct efx_tx_buffer *buffer =
			efx_tx_queue_get_insert_buffer(tx_queue);

		buffer->flags = EFX_TX_BUF_OPTION;
		buffer->len = buffer->unmap_len = 0;
		EFX_POPULATE_QWORD_7(buffer->option,
				     ESF_DZ_TX_DESC_IS_OPT, true,
				     ESF_DZ_TX_OPTION_TYPE,
				     ESE_DZ_TX_OPTION_DESC_CRC_CSUM,
				     ESF_DZ_TX_OPTION_UDP_TCP_CSUM,
					outer_csum,
				     ESF_DZ_TX_OPTION_IP_CSUM,
					outer_csum && !tso_v2,
				     ESF_DZ_TX_OPTION_INNER_UDP_TCP_CSUM,
					inner_csum,
				     ESF_DZ_TX_OPTION_INNER_IP_CSUM,
					inner_csum && !tso_v2,
				     ESF_DZ_TX_TIMESTAMP,
					tx_queue->timestamping);

		++tx_queue->insert_count;
		tx_queue->csum_offload = txq_type;
	}
}

static struct efx_tx_queue *
efx_ef10_select_tx_queue(struct efx_channel *channel,
			 struct sk_buff *skb)
{
	unsigned int txq_type = skb->ip_summed == CHECKSUM_PARTIAL ?
				EFX_TXQ_TYPE_CSUM_OFFLOAD :
				EFX_TXQ_TYPE_NO_OFFLOAD;
	struct efx_tx_queue *tx_queue = &channel->tx_queues[0];

	efx_ef10_set_tx_queue_csum(tx_queue, txq_type);

	return tx_queue;
}

#ifdef EFX_USE_OVERLAY_TX_CSUM
static unsigned int efx_ef10_select_tx_queue_type(struct sk_buff *skb)
{
	unsigned int txq_type = EFX_TXQ_TYPE_NO_OFFLOAD;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return txq_type;

	if (skb->encapsulation &&
	    skb_checksum_start_offset(skb) ==
	      skb_inner_transport_offset(skb)) {
		/* we only advertise features for IPv4 and IPv6 checksums on
		 * encapsulated packets, so if the checksum is for the inner
		 * packet, it must be one of them; no further checking required.
		 */
		txq_type = EFX_TXQ_TYPE_INNER_CSUM_OFFLOAD;

#if !defined (EFX_USE_KCOMPAT) || defined (EFX_HAVE_GSO_UDP_TUNNEL_CSUM)
		/* Do we also need to offload the outer header checksum? */
		if (skb_shinfo(skb)->gso_segs > 1 &&
#if !defined (EFX_USE_KCOMPAT) || defined (EFX_HAVE_GSO_PARTIAL)
		    !(skb_shinfo(skb)->gso_type & SKB_GSO_PARTIAL) &&
#endif
		    (skb_shinfo(skb)->gso_type & SKB_GSO_UDP_TUNNEL_CSUM))
			txq_type |= EFX_TXQ_TYPE_CSUM_OFFLOAD;
#endif
		return txq_type;
	}

	/* similarly, we only advertise features for IPv4 and IPv6 checksums,
	 * so it must be one of them. No need for further checks.
	 */
	return EFX_TXQ_TYPE_CSUM_OFFLOAD;
}

#ifdef EFX_NOT_UPSTREAM
static struct efx_tx_queue *
efx_ef10_select_tx_queue_non_csum_overlay(struct efx_channel *channel,
					  struct sk_buff *skb)
{
	unsigned int txq_type = efx_ef10_select_tx_queue_type(skb);

	EFX_WARN_ON_PARANOID(txq_type > channel->tx_queue_count);

	return &channel->tx_queues[txq_type];
}
#endif

static struct efx_tx_queue *
efx_ef10_select_tx_queue_overlay(struct efx_channel *channel,
				 struct sk_buff *skb)
{
	unsigned int txq_type = efx_ef10_select_tx_queue_type(skb);
	/* map no offload and overlay offload to second queue, which
	 * will be reconfigured with option descriptors if needed.
	 */
	static const unsigned int txq_map[] = {
		[EFX_TXQ_TYPE_CSUM_OFFLOAD] = EFX_TXQ_TYPE_CSUM_OFFLOAD,
		[EFX_TXQ_TYPE_NO_OFFLOAD] = EFX_TXQ_TYPE_NO_OFFLOAD,
		[EFX_TXQ_TYPE_INNER_CSUM_OFFLOAD] = EFX_TXQ_TYPE_NO_OFFLOAD,
		[EFX_TXQ_TYPE_BOTH_CSUM_OFFLOAD] = EFX_TXQ_TYPE_NO_OFFLOAD,
	};
	struct efx_tx_queue *tx_queue = &channel->tx_queues[txq_map[txq_type]];

	efx_ef10_set_tx_queue_csum(tx_queue, txq_type);

	return tx_queue;
}
#endif

static void efx_ef10_fini_nic(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	kfree(nic_data->mc_stats);
	nic_data->mc_stats = NULL;

	if (!efx_ptp_uses_separate_channel(efx) &&
	    !efx_ptp_use_mac_tx_timestamps(efx))
		efx_ptp_remove(efx);
}

static int efx_ef10_init_nic(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	u32 old_datapath_caps = nic_data->datapath_caps;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_FEATURES_CHECK)
#ifdef EFX_USE_OVERLAY_TX_CSUM
	netdev_features_t hw_enc_features;
#endif
#endif
	int rc;

	if (nic_data->must_check_datapath_caps) {
		rc = efx_ef10_init_datapath_caps(efx);
		if (rc)
			return rc;
		nic_data->must_check_datapath_caps = false;
	}

	if (nic_data->datapath_caps != old_datapath_caps)
		efx_mcdi_filter_probe_supported_filters(efx);

	if (nic_data->must_realloc_vis) {
		/* We cannot let the number of VIs change now */
		rc = efx_ef10_alloc_vis(efx, nic_data->n_allocated_vis,
					nic_data->n_allocated_vis);
		if (rc)
			return rc;
		nic_data->must_realloc_vis = false;
	}

	nic_data->mc_stats = kmalloc_array(efx->num_mac_stats, sizeof(__le64),
					   GFP_KERNEL);
	if (!nic_data->mc_stats)
		return -ENOMEM;

	if (nic_data->must_reprobe_sensors) {
		efx_mcdi_mon_remove(efx);
		efx_mcdi_mon_probe(efx);
		nic_data->must_reprobe_sensors = false;
	}

	/* Don't fail init if RSS setup doesn't work, except that EAGAIN needs
	 * passing up.
	 */
	rc = efx->type->rx_push_rss_config(efx, false,
					   efx->rss_context.rx_indir_table, NULL);
	if (rc == -EAGAIN)
		return rc;

	if (nic_data->must_restore_piobufs && nic_data->n_piobufs) {
		rc = efx_ef10_alloc_piobufs(efx, nic_data->n_piobufs);
		if (rc == 0) {
			rc = efx_ef10_link_piobufs(efx);
			if (rc)
				efx_ef10_free_piobufs(efx);
		}

		/* Log an error on failure, but this is non-fatal.
		 * Permission errors are less important - we've presumably
		 * had the PIO buffer licence removed.
		 */
		if (rc == -EPERM)
			netif_dbg(efx, drv, efx->net_dev,
				  "not permitted to restore PIO buffers\n");
		else if (rc)
			netif_err(efx, drv, efx->net_dev,
				  "failed to restore PIO buffers (%d)\n", rc);
		nic_data->must_restore_piobufs = false;
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_FEATURES_CHECK)
#ifdef EFX_USE_OVERLAY_TX_CSUM
	hw_enc_features = 0;

	/* add encapsulated checksum offload features */
	if (efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE) &&
	    !efx_ef10_is_vf(efx))
		hw_enc_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;

	/* add encapsulated TSO features */
	if (efx_ef10_has_cap(nic_data->datapath_caps2, TX_TSO_V2_ENCAP)) {
		netdev_features_t encap_tso_features;

		encap_tso_features = NETIF_F_GSO_UDP_TUNNEL | NETIF_F_GSO_GRE |
			NETIF_F_GSO_UDP_TUNNEL_CSUM | NETIF_F_GSO_GRE_CSUM;

		hw_enc_features |= encap_tso_features | NETIF_F_TSO;
		efx->net_dev->features |= encap_tso_features;
	}

	efx->net_dev->hw_enc_features = hw_enc_features;
#endif
#endif

	if (!efx_ptp_uses_separate_channel(efx) &&
	    !efx_ptp_use_mac_tx_timestamps(efx))
		efx_ptp_probe(efx, NULL);

	return 0;
}

static void efx_ef10_reset_mc_allocations(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
#ifdef CONFIG_SFC_SRIOV
	unsigned int i;
#endif

	efx_mcdi_filter_table_reset_mc_allocations(efx);
	efx->rss_context.context_id = EFX_MCDI_RSS_CONTEXT_INVALID;
	efx_ef10_forget_old_piobufs(efx);


	/* Driver-created vswitches and vports must be re-created */
	nic_data->must_probe_vswitching = true;
	efx->vport.vport_id = EVB_PORT_ID_ASSIGNED;
#ifdef CONFIG_SFC_SRIOV
	if (nic_data->vf)
		for (i = 0; i < nic_data->vf_count; i++)
			nic_data->vf[i].vport_id = 0;
#endif

	/* All our allocations have been reset */
	if (!efx_net_allocated(efx->state))
		return;

	nic_data->must_realloc_vis = true;
	nic_data->must_restore_piobufs = true;
	efx->stats_initialised = false;
}

static enum reset_type efx_ef10_map_reset_reason(enum reset_type reason)
{
	if (reason == RESET_TYPE_MC_FAILURE)
		return RESET_TYPE_DATAPATH;
	else if (reason < RESET_TYPE_MAX_METHOD ||
		 reason == RESET_TYPE_MCDI_TIMEOUT)
		return reason;
	else
		return RESET_TYPE_ALL;
}

static int efx_ef10_map_reset_flags(u32 *flags)
{
	enum {
		EF10_RESET_PORT = ((ETH_RESET_MAC | ETH_RESET_PHY) <<
				   ETH_RESET_SHARED_SHIFT),
		EF10_RESET_MC = ((ETH_RESET_DMA | ETH_RESET_FILTER |
				  ETH_RESET_OFFLOAD | ETH_RESET_MAC |
				  ETH_RESET_PHY | ETH_RESET_MGMT) <<
				 ETH_RESET_SHARED_SHIFT)
	};

	/* We assume for now that our PCI function is permitted to
	 * reset everything.
	 */

	if ((*flags & EF10_RESET_MC) == EF10_RESET_MC) {
		*flags &= ~EF10_RESET_MC;
		*flags &= ~ETH_RESET_MAC;
		return RESET_TYPE_WORLD;
	}

	if ((*flags & EF10_RESET_PORT) == EF10_RESET_PORT) {
		*flags &= ~EF10_RESET_PORT;
		*flags &= ~ETH_RESET_MAC;
		return RESET_TYPE_ALL;
	}

	/* no invisible reset implemented */

	return -EINVAL;
}

static int efx_ef10_reset(struct efx_nic *efx, enum reset_type reset_type)
{
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
#endif
	int rc;

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
	/* Make sure any UDP tunnel work has finished, else it could cause more
	 * MC reboots during reset_up
	 */
	flush_work(&nic_data->udp_tunnel_work);
#endif

	rc = efx_mcdi_reset(efx, reset_type);

	efx->last_reset = jiffies;

	/* Unprivileged functions return -EPERM, but need to return success
	 * here so that the datapath is brought back up.
	 */
	if (reset_type == RESET_TYPE_WORLD && rc == -EPERM)
		rc = 0;

	/* If it was a port reset, trigger reallocation of MC resources.
	 * Note that on an MC reset nothing needs to be done now because we'll
	 * detect the MC reset later and handle it then.
	 * For an FLR, we never get an MC reset event, but the MC has reset all
	 * resources assigned to us, so we have to trigger reallocation now.
	 */
	if ((reset_type == RESET_TYPE_ALL ||
	     reset_type == RESET_TYPE_RECOVER_OR_ALL ||
	     reset_type == RESET_TYPE_MCDI_TIMEOUT) && !rc)
		efx_ef10_reset_mc_allocations(efx);
	return rc;
}

static bool efx_ef10_hw_unavailable(struct efx_nic *efx)
{
	if (efx->state == STATE_DISABLED || efx_recovering(efx->state))
		return true;

	/* we just haven't initialised I/O yet. */
	if (!efx->membase)
		return false;

	if (_efx_readd(efx, ER_DZ_BIU_MC_SFT_STATUS) ==
	    cpu_to_le32(0xffffffff)) {
		netif_err(efx, hw, efx->net_dev, "Hardware unavailable\n");
		efx->state = STATE_DISABLED;
		return true;
	}

	return false;
}

#ifdef EFX_NOT_UPSTREAM
static int efx_ef10_rx_defer_ring_rx_doorbell(struct efx_rx_queue *rx_queue)
{
	struct efx_channel *channel = efx_rx_queue_channel(rx_queue);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_DRIVER_EVENT_IN_LEN);
	efx_qword_t event;
	size_t outlen;
	u32 magic;

	magic = EFX_EF10_DRVGEN_MAGIC(EFX_EF10_RERING_RX_DOORBELL,
				      efx_rx_queue_index(rx_queue));
	EFX_POPULATE_QWORD_2(event,
			     ESF_DZ_EV_CODE, EFX_EF10_DRVGEN_EV,
			     ESF_DZ_EV_DATA, magic);

	MCDI_SET_DWORD(inbuf, DRIVER_EVENT_IN_EVQ, channel->channel);

	/* MCDI_SET_QWORD is not appropriate here since EFX_POPULATE_* has
	 * already swapped the data to little-endian order.
	 */
	memcpy(MCDI_PTR(inbuf, DRIVER_EVENT_IN_DATA), &event.u64[0],
	       sizeof(efx_qword_t));

	return efx_mcdi_rpc_quiet(channel->efx, MC_CMD_DRIVER_EVENT,
				  inbuf, sizeof(inbuf), NULL, 0, &outlen);
}
#endif

static void efx_ef10_monitor(struct efx_nic *efx)
{
#if defined(EFX_NOT_UPSTREAM)
	if (monitor_hw_available && efx_ef10_hw_unavailable(efx)) {
		if (efx->link_state.up) {
			efx->link_state.up = false;
			efx_link_status_changed(efx);
		}
	}
#endif
#if defined(CONFIG_EEH)
	{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_EEH_DEV_CHECK_FAILURE)
	struct eeh_dev *eehdev = pci_dev_to_eeh_dev(efx->pci_dev);

	eeh_dev_check_failure(eehdev);
#else
	struct pci_dev *pcidev = efx->pci_dev;
	struct device_node *dn = pci_device_to_OF_node(pcidev);

	eeh_dn_check_failure(dn, pcidev);
#endif
	}
#endif

#ifdef EFX_NOT_UPSTREAM
	if (EFX_WORKAROUND_59975(efx)) {
		/* re-ring the RX doorbell. Should be harmless */
		struct efx_channel *channel;
		int rc = 0;
		efx_for_each_channel(channel, efx) {
			struct efx_rx_queue *rxq;
			efx_for_each_channel_rx_queue(rxq, channel) {
				if (rxq->removed_count != 0)
					continue;
				rc = efx_ef10_rx_defer_ring_rx_doorbell(rxq);
				if (rc != 0)
					break;
			}
			if (rc != 0)
				break;
		}
	}
#endif
}

#define EF10_DMA_STAT(ext_name, mcdi_name)			\
	[EF10_STAT_ ## ext_name] =				\
	{ #ext_name, 64, 8 * MC_CMD_MAC_ ## mcdi_name }
#define EF10_DMA_INVIS_STAT(int_name, mcdi_name)		\
	[EF10_STAT_ ## int_name] =				\
	{ NULL, 64, 8 * MC_CMD_MAC_ ## mcdi_name }
#define EF10_OTHER_STAT(ext_name)				\
	[EF10_STAT_ ## ext_name] = { #ext_name, 0, 0 }

static const struct efx_hw_stat_desc efx_ef10_stat_desc[EF10_STAT_COUNT] = {
	EF10_DMA_STAT(port_tx_bytes, TX_BYTES),
	EF10_DMA_STAT(port_tx_packets, TX_PKTS),
	EF10_DMA_STAT(port_tx_pause, TX_PAUSE_PKTS),
	EF10_DMA_STAT(port_tx_control, TX_CONTROL_PKTS),
	EF10_DMA_STAT(port_tx_unicast, TX_UNICAST_PKTS),
	EF10_DMA_STAT(port_tx_multicast, TX_MULTICAST_PKTS),
	EF10_DMA_STAT(port_tx_broadcast, TX_BROADCAST_PKTS),
	EF10_DMA_STAT(port_tx_lt64, TX_LT64_PKTS),
	EF10_DMA_STAT(port_tx_64, TX_64_PKTS),
	EF10_DMA_STAT(port_tx_65_to_127, TX_65_TO_127_PKTS),
	EF10_DMA_STAT(port_tx_128_to_255, TX_128_TO_255_PKTS),
	EF10_DMA_STAT(port_tx_256_to_511, TX_256_TO_511_PKTS),
	EF10_DMA_STAT(port_tx_512_to_1023, TX_512_TO_1023_PKTS),
	EF10_DMA_STAT(port_tx_1024_to_15xx, TX_1024_TO_15XX_PKTS),
	EF10_DMA_STAT(port_tx_15xx_to_jumbo, TX_15XX_TO_JUMBO_PKTS),
	EF10_DMA_STAT(port_rx_bytes, RX_BYTES),
	EF10_DMA_INVIS_STAT(port_rx_bytes_minus_good_bytes, RX_BAD_BYTES),
	EF10_OTHER_STAT(port_rx_good_bytes),
	EF10_OTHER_STAT(port_rx_bad_bytes),
	EF10_DMA_STAT(port_rx_packets, RX_PKTS),
	EF10_DMA_STAT(port_rx_good, RX_GOOD_PKTS),
	EF10_DMA_STAT(port_rx_bad, RX_BAD_FCS_PKTS),
	EF10_DMA_STAT(port_rx_pause, RX_PAUSE_PKTS),
	EF10_DMA_STAT(port_rx_control, RX_CONTROL_PKTS),
	EF10_DMA_STAT(port_rx_unicast, RX_UNICAST_PKTS),
	EF10_DMA_STAT(port_rx_multicast, RX_MULTICAST_PKTS),
	EF10_DMA_STAT(port_rx_broadcast, RX_BROADCAST_PKTS),
	EF10_DMA_STAT(port_rx_lt64, RX_UNDERSIZE_PKTS),
	EF10_DMA_STAT(port_rx_64, RX_64_PKTS),
	EF10_DMA_STAT(port_rx_65_to_127, RX_65_TO_127_PKTS),
	EF10_DMA_STAT(port_rx_128_to_255, RX_128_TO_255_PKTS),
	EF10_DMA_STAT(port_rx_256_to_511, RX_256_TO_511_PKTS),
	EF10_DMA_STAT(port_rx_512_to_1023, RX_512_TO_1023_PKTS),
	EF10_DMA_STAT(port_rx_1024_to_15xx, RX_1024_TO_15XX_PKTS),
	EF10_DMA_STAT(port_rx_15xx_to_jumbo, RX_15XX_TO_JUMBO_PKTS),
	EF10_DMA_STAT(port_rx_gtjumbo, RX_GTJUMBO_PKTS),
	EF10_DMA_STAT(port_rx_bad_gtjumbo, RX_JABBER_PKTS),
	EF10_DMA_STAT(port_rx_overflow, RX_OVERFLOW_PKTS),
	EF10_DMA_STAT(port_rx_align_error, RX_ALIGN_ERROR_PKTS),
	EF10_DMA_STAT(port_rx_length_error, RX_LENGTH_ERROR_PKTS),
	EF10_DMA_STAT(port_rx_nodesc_drops, RX_NODESC_DROPS),
	EFX_GENERIC_SW_STAT(rx_nodesc_trunc),
	EFX_GENERIC_SW_STAT(rx_noskb_drops),
	EF10_DMA_STAT(port_rx_pm_trunc_bb_overflow, PM_TRUNC_BB_OVERFLOW),
	EF10_DMA_STAT(port_rx_pm_discard_bb_overflow, PM_DISCARD_BB_OVERFLOW),
	EF10_DMA_STAT(port_rx_pm_trunc_vfifo_full, PM_TRUNC_VFIFO_FULL),
	EF10_DMA_STAT(port_rx_pm_discard_vfifo_full, PM_DISCARD_VFIFO_FULL),
	EF10_DMA_STAT(port_rx_pm_trunc_qbb, PM_TRUNC_QBB),
	EF10_DMA_STAT(port_rx_pm_discard_qbb, PM_DISCARD_QBB),
	EF10_DMA_STAT(port_rx_pm_discard_mapping, PM_DISCARD_MAPPING),
	EF10_DMA_STAT(port_rx_dp_q_disabled_packets, RXDP_Q_DISABLED_PKTS),
	EF10_DMA_STAT(port_rx_dp_di_dropped_packets, RXDP_DI_DROPPED_PKTS),
	EF10_DMA_STAT(port_rx_dp_streaming_packets, RXDP_STREAMING_PKTS),
	EF10_DMA_STAT(port_rx_dp_hlb_fetch, RXDP_HLB_FETCH_CONDITIONS),
	EF10_DMA_STAT(port_rx_dp_hlb_wait, RXDP_HLB_WAIT_CONDITIONS),
	EF10_DMA_STAT(rx_unicast, VADAPTER_RX_UNICAST_PACKETS),
	EF10_DMA_STAT(rx_unicast_bytes, VADAPTER_RX_UNICAST_BYTES),
	EF10_DMA_STAT(rx_multicast, VADAPTER_RX_MULTICAST_PACKETS),
	EF10_DMA_STAT(rx_multicast_bytes, VADAPTER_RX_MULTICAST_BYTES),
	EF10_DMA_STAT(rx_broadcast, VADAPTER_RX_BROADCAST_PACKETS),
	EF10_DMA_STAT(rx_broadcast_bytes, VADAPTER_RX_BROADCAST_BYTES),
	EF10_DMA_STAT(rx_bad, VADAPTER_RX_BAD_PACKETS),
	EF10_DMA_STAT(rx_bad_bytes, VADAPTER_RX_BAD_BYTES),
	EF10_DMA_STAT(rx_overflow, VADAPTER_RX_OVERFLOW),
	EF10_DMA_STAT(tx_unicast, VADAPTER_TX_UNICAST_PACKETS),
	EF10_DMA_STAT(tx_unicast_bytes, VADAPTER_TX_UNICAST_BYTES),
	EF10_DMA_STAT(tx_multicast, VADAPTER_TX_MULTICAST_PACKETS),
	EF10_DMA_STAT(tx_multicast_bytes, VADAPTER_TX_MULTICAST_BYTES),
	EF10_DMA_STAT(tx_broadcast, VADAPTER_TX_BROADCAST_PACKETS),
	EF10_DMA_STAT(tx_broadcast_bytes, VADAPTER_TX_BROADCAST_BYTES),
	EF10_DMA_STAT(tx_bad, VADAPTER_TX_BAD_PACKETS),
	EF10_DMA_STAT(tx_bad_bytes, VADAPTER_TX_BAD_BYTES),
	EF10_DMA_STAT(tx_overflow, VADAPTER_TX_OVERFLOW),
	EF10_DMA_STAT(fec_uncorrected_errors, FEC_UNCORRECTED_ERRORS),
	EF10_DMA_STAT(fec_corrected_errors, FEC_CORRECTED_ERRORS),
	EF10_DMA_STAT(fec_corrected_symbols_lane0, FEC_CORRECTED_SYMBOLS_LANE0),
	EF10_DMA_STAT(fec_corrected_symbols_lane1, FEC_CORRECTED_SYMBOLS_LANE1),
	EF10_DMA_STAT(fec_corrected_symbols_lane2, FEC_CORRECTED_SYMBOLS_LANE2),
	EF10_DMA_STAT(fec_corrected_symbols_lane3, FEC_CORRECTED_SYMBOLS_LANE3),
	EF10_DMA_STAT(ctpio_vi_busy_fallback, CTPIO_VI_BUSY_FALLBACK),
	EF10_DMA_STAT(ctpio_long_write_success, CTPIO_LONG_WRITE_SUCCESS),
	EF10_DMA_STAT(ctpio_missing_dbell_fail, CTPIO_MISSING_DBELL_FAIL),
	EF10_DMA_STAT(ctpio_overflow_fail, CTPIO_OVERFLOW_FAIL),
	EF10_DMA_STAT(ctpio_underflow_fail, CTPIO_UNDERFLOW_FAIL),
	EF10_DMA_STAT(ctpio_timeout_fail, CTPIO_TIMEOUT_FAIL),
	EF10_DMA_STAT(ctpio_noncontig_wr_fail, CTPIO_NONCONTIG_WR_FAIL),
	EF10_DMA_STAT(ctpio_frm_clobber_fail, CTPIO_FRM_CLOBBER_FAIL),
	EF10_DMA_STAT(ctpio_invalid_wr_fail, CTPIO_INVALID_WR_FAIL),
	EF10_DMA_STAT(ctpio_vi_clobber_fallback, CTPIO_VI_CLOBBER_FALLBACK),
	EF10_DMA_STAT(ctpio_unqualified_fallback, CTPIO_UNQUALIFIED_FALLBACK),
	EF10_DMA_STAT(ctpio_runt_fallback, CTPIO_RUNT_FALLBACK),
	EF10_DMA_STAT(ctpio_success, CTPIO_SUCCESS),
	EF10_DMA_STAT(ctpio_fallback, CTPIO_FALLBACK),
	EF10_DMA_STAT(ctpio_poison, CTPIO_POISON),
	EF10_DMA_STAT(ctpio_erase, CTPIO_ERASE),
};

static void efx_ef10_common_stat_mask(unsigned long *mask)
{
	__set_bit(EF10_STAT_port_tx_bytes, mask);
	__set_bit(EF10_STAT_port_tx_packets, mask);
	__set_bit(EF10_STAT_port_tx_pause, mask);
	__set_bit(EF10_STAT_port_tx_unicast, mask);
	__set_bit(EF10_STAT_port_tx_multicast, mask);
	__set_bit(EF10_STAT_port_tx_broadcast, mask);
	__set_bit(EF10_STAT_port_rx_bytes, mask);
	__set_bit(EF10_STAT_port_rx_bytes_minus_good_bytes, mask);
	__set_bit(EF10_STAT_port_rx_good_bytes, mask);
	__set_bit(EF10_STAT_port_rx_bad_bytes, mask);
	__set_bit(EF10_STAT_port_rx_packets, mask);
	__set_bit(EF10_STAT_port_rx_good, mask);
	__set_bit(EF10_STAT_port_rx_bad, mask);
	__set_bit(EF10_STAT_port_rx_pause, mask);
	__set_bit(EF10_STAT_port_rx_control, mask);
	__set_bit(EF10_STAT_port_rx_unicast, mask);
	__set_bit(EF10_STAT_port_rx_multicast, mask);
	__set_bit(EF10_STAT_port_rx_broadcast, mask);
	__set_bit(EF10_STAT_port_rx_lt64, mask);
	__set_bit(EF10_STAT_port_rx_64, mask);
	__set_bit(EF10_STAT_port_rx_65_to_127, mask);
	__set_bit(EF10_STAT_port_rx_128_to_255, mask);
	__set_bit(EF10_STAT_port_rx_256_to_511, mask);
	__set_bit(EF10_STAT_port_rx_512_to_1023, mask);
	__set_bit(EF10_STAT_port_rx_1024_to_15xx, mask);
	__set_bit(EF10_STAT_port_rx_15xx_to_jumbo, mask);
	__set_bit(EF10_STAT_port_rx_gtjumbo, mask);
	__set_bit(EF10_STAT_port_rx_bad_gtjumbo, mask);
	__set_bit(EF10_STAT_port_rx_overflow, mask);
	__set_bit(EF10_STAT_port_rx_nodesc_drops, mask);
	__set_bit(GENERIC_STAT_rx_nodesc_trunc, mask);
	__set_bit(GENERIC_STAT_rx_noskb_drops, mask);
}

/* On 7000 series NICs, these statistics are only provided by the 10G MAC.
 * For a 10G/40G switchable port we do not expose these because they might
 * not include all the packets they should.
 * On 8000 series NICs these statistics are always provided.
 */
static void efx_ef10_10g_only_stat_mask(unsigned long *mask)
{
	__set_bit(EF10_STAT_port_tx_control, mask);
	__set_bit(EF10_STAT_port_tx_lt64, mask);
	__set_bit(EF10_STAT_port_tx_64, mask);
	__set_bit(EF10_STAT_port_tx_65_to_127, mask);
	__set_bit(EF10_STAT_port_tx_128_to_255, mask);
	__set_bit(EF10_STAT_port_tx_256_to_511, mask);
	__set_bit(EF10_STAT_port_tx_512_to_1023, mask);
	__set_bit(EF10_STAT_port_tx_1024_to_15xx, mask);
	__set_bit(EF10_STAT_port_tx_15xx_to_jumbo, mask);
}

/* These statistics are only provided by the 40G MAC.  For a 10G/40G
 * switchable port we do expose these because the errors will otherwise
 * be silent.
 */
static void efx_ef10_40g_extra_stat_mask(unsigned long *mask)
{
	__set_bit(EF10_STAT_port_rx_align_error, mask);
	__set_bit(EF10_STAT_port_rx_length_error, mask);
}

/* These statistics are only provided if the firmware supports the
 * capability PM_AND_RXDP_COUNTERS.
 */
static void efx_ef10_pm_and_rxdp_stat_mask(unsigned long *mask)
{
	__set_bit(EF10_STAT_port_rx_pm_trunc_bb_overflow, mask);
	__set_bit(EF10_STAT_port_rx_pm_discard_bb_overflow, mask);
	__set_bit(EF10_STAT_port_rx_pm_trunc_vfifo_full, mask);
	__set_bit(EF10_STAT_port_rx_pm_discard_vfifo_full, mask);
	__set_bit(EF10_STAT_port_rx_pm_trunc_qbb, mask);
	__set_bit(EF10_STAT_port_rx_pm_discard_qbb, mask);
	__set_bit(EF10_STAT_port_rx_pm_discard_mapping, mask);
	__set_bit(EF10_STAT_port_rx_dp_q_disabled_packets, mask);
	__set_bit(EF10_STAT_port_rx_dp_di_dropped_packets, mask);
	__set_bit(EF10_STAT_port_rx_dp_streaming_packets, mask);
	__set_bit(EF10_STAT_port_rx_dp_hlb_fetch, mask);
	__set_bit(EF10_STAT_port_rx_dp_hlb_wait, mask);
}

/* These statistics are only provided if the NIC supports MC_CMD_MAC_STATS_V2,
 * indicated by returning a value >= MC_CMD_MAC_NSTATS_V2 in
 * MC_CMD_GET_CAPABILITIES_V4_OUT_MAC_STATS_NUM_STATS.
 */
static void efx_ef10_fec_stat_mask(unsigned long *mask)
{
	__set_bit(EF10_STAT_fec_uncorrected_errors, mask);
	__set_bit(EF10_STAT_fec_corrected_errors, mask);
	__set_bit(EF10_STAT_fec_corrected_symbols_lane0, mask);
	__set_bit(EF10_STAT_fec_corrected_symbols_lane1, mask);
	__set_bit(EF10_STAT_fec_corrected_symbols_lane2, mask);
	__set_bit(EF10_STAT_fec_corrected_symbols_lane3, mask);
}

/* These statistics are only provided if the NIC supports MC_CMD_MAC_STATS_V3,
 * indicated by returning a value >= MC_CMD_MAC_NSTATS_V3 in
 * MC_CMD_GET_CAPABILITIES_V4_OUT_MAC_STATS_NUM_STATS.
 * These bits are in the second u64 of the raw mask.
 */
static void efx_ef10_ctpio_stat_mask(unsigned long *mask)
{
	__set_bit(EF10_STAT_ctpio_vi_busy_fallback, mask);
	__set_bit(EF10_STAT_ctpio_long_write_success, mask);
	__set_bit(EF10_STAT_ctpio_missing_dbell_fail, mask);
	__set_bit(EF10_STAT_ctpio_overflow_fail, mask);
	__set_bit(EF10_STAT_ctpio_underflow_fail, mask);
	__set_bit(EF10_STAT_ctpio_timeout_fail, mask);
	__set_bit(EF10_STAT_ctpio_noncontig_wr_fail, mask);
	__set_bit(EF10_STAT_ctpio_frm_clobber_fail, mask);
	__set_bit(EF10_STAT_ctpio_invalid_wr_fail, mask);
	__set_bit(EF10_STAT_ctpio_vi_clobber_fallback, mask);
	__set_bit(EF10_STAT_ctpio_unqualified_fallback, mask);
	__set_bit(EF10_STAT_ctpio_runt_fallback, mask);
	__set_bit(EF10_STAT_ctpio_success, mask);
	__set_bit(EF10_STAT_ctpio_fallback, mask);
	__set_bit(EF10_STAT_ctpio_poison, mask);
	__set_bit(EF10_STAT_ctpio_erase, mask);
}

static void efx_ef10_get_stat_mask(struct efx_nic *efx, unsigned long *mask)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	u32 port_caps = efx_mcdi_phy_get_caps(efx);
	unsigned int i;

	efx_ef10_common_stat_mask(mask);
	if (efx->mcdi->fn_flags & (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_LINKCTRL)) {
		if (port_caps & (1 << MC_CMD_PHY_CAP_40000FDX_LBN)) {
			efx_ef10_40g_extra_stat_mask(mask);
			/* 8000 series have everything even at 40G */
			if (efx_ef10_has_cap(nic_data->datapath_caps2,
					     MAC_STATS_40G_TX_SIZE_BINS))
				efx_ef10_10g_only_stat_mask(mask);
		} else {
			efx_ef10_10g_only_stat_mask(mask);
		}

		if (efx_ef10_has_cap(nic_data->datapath_caps, PM_AND_RXDP_COUNTERS))
			efx_ef10_pm_and_rxdp_stat_mask(mask);
	}

	/* Only show vadaptor stats when EVB capability is present */
	if (efx_ef10_has_cap(nic_data->datapath_caps, EVB))
		for (i = EF10_STAT_port_COUNT; i < EF10_STAT_V1_COUNT; i++)
			__set_bit(i, mask);

	/* Only show FEC stats when NIC supports MC_CMD_MAC_STATS_V2 */
	if (efx->num_mac_stats >= MC_CMD_MAC_NSTATS_V2)
		efx_ef10_fec_stat_mask(mask);

	/* CTPIO stats appear in V3. Only show them on devices that actually
	 * support CTPIO. Although this driver doesn't use CTPIO others might,
	 * and we may be reporting the stats for the underlying port.
	 */
	if ((efx->num_mac_stats >= MC_CMD_MAC_NSTATS_V3) &&
	    efx_ef10_has_cap(nic_data->datapath_caps2, CTPIO))
		efx_ef10_ctpio_stat_mask(mask);
}

static size_t efx_ef10_describe_stats(struct efx_nic *efx, u8 *names)
{
	DECLARE_BITMAP(mask, EF10_STAT_COUNT) = {};

	efx_ef10_get_stat_mask(efx, mask);
	return efx_nic_describe_stats(efx_ef10_stat_desc, EF10_STAT_COUNT,
				      mask, names);
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_FECSTATS)
static void efx_ef10_get_fec_stats(struct efx_nic *efx,
				   struct ethtool_fec_stats *fec_stats)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	DECLARE_BITMAP(mask, EF10_STAT_COUNT) = {};
	u64 *stats = nic_data->stats;

	efx_ef10_get_stat_mask(efx, mask);
	if (test_bit(EF10_STAT_fec_corrected_errors, mask))
		fec_stats->corrected_blocks.total =
			stats[EF10_STAT_fec_corrected_errors];
	if (test_bit(EF10_STAT_fec_uncorrected_errors, mask))
		fec_stats->uncorrectable_blocks.total =
			stats[EF10_STAT_fec_uncorrected_errors];
}
#endif

static bool efx_use_vadaptor_stats(struct efx_nic *efx)
{
#ifdef CONFIG_SFC_SRIOV
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
#endif

	if (!(efx->mcdi->fn_flags &
	     (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_LINKCTRL)))
		return true;
#ifdef CONFIG_SFC_SRIOV
	if (efx->type->is_vf || nic_data->vf_count)
		return true;
#endif

	return false;
}

static size_t efx_ef10_update_stats_common(struct efx_nic *efx, u64 *full_stats,
					   struct rtnl_link_stats64 *core_stats)
{
	DECLARE_BITMAP(mask, EF10_STAT_COUNT) = {};
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	u64 *stats = nic_data->stats;
	size_t stats_count = 0, index;

	efx_ef10_get_stat_mask(efx, mask);

	if (full_stats) {
		for_each_set_bit(index, mask, EF10_STAT_COUNT) {
			if (efx_ef10_stat_desc[index].name) {
				*full_stats++ = stats[index];
				++stats_count;
			}
		}
	}

	if (!core_stats)
		return stats_count;

	if (efx_use_vadaptor_stats(efx)) {
		core_stats->rx_packets = stats[EF10_STAT_rx_unicast] +
					 stats[EF10_STAT_rx_multicast] +
					 stats[EF10_STAT_rx_broadcast];
		core_stats->tx_packets = stats[EF10_STAT_tx_unicast] +
					 stats[EF10_STAT_tx_multicast] +
					 stats[EF10_STAT_tx_broadcast];
		core_stats->rx_bytes = stats[EF10_STAT_rx_unicast_bytes] +
				       stats[EF10_STAT_rx_multicast_bytes] +
				       stats[EF10_STAT_rx_broadcast_bytes];
		core_stats->tx_bytes = stats[EF10_STAT_tx_unicast_bytes] +
				       stats[EF10_STAT_tx_multicast_bytes] +
				       stats[EF10_STAT_tx_broadcast_bytes];
		core_stats->rx_dropped = stats[GENERIC_STAT_rx_nodesc_trunc] +
					 stats[GENERIC_STAT_rx_noskb_drops];
		core_stats->multicast = stats[EF10_STAT_rx_multicast];
		core_stats->rx_crc_errors = stats[EF10_STAT_rx_bad];
		core_stats->rx_fifo_errors = stats[EF10_STAT_rx_overflow];
		core_stats->rx_errors = core_stats->rx_crc_errors;
		core_stats->tx_errors = stats[EF10_STAT_tx_bad];
	} else {
		/* Use port stats. */
		core_stats->rx_packets = stats[EF10_STAT_port_rx_packets];
		core_stats->tx_packets = stats[EF10_STAT_port_tx_packets];
		core_stats->rx_bytes = stats[EF10_STAT_port_rx_bytes];
		core_stats->tx_bytes = stats[EF10_STAT_port_tx_bytes];
		core_stats->rx_dropped = stats[EF10_STAT_port_rx_nodesc_drops] +
					 stats[GENERIC_STAT_rx_nodesc_trunc] +
					 stats[GENERIC_STAT_rx_noskb_drops];
		core_stats->multicast = stats[EF10_STAT_port_rx_multicast];
		core_stats->rx_length_errors =
				stats[EF10_STAT_port_rx_gtjumbo] +
				stats[EF10_STAT_port_rx_length_error];
		core_stats->rx_crc_errors = stats[EF10_STAT_port_rx_bad];
		core_stats->rx_frame_errors =
				stats[EF10_STAT_port_rx_align_error];
		core_stats->rx_fifo_errors = stats[EF10_STAT_port_rx_overflow];
		core_stats->rx_errors = (core_stats->rx_length_errors +
					 core_stats->rx_crc_errors +
					 core_stats->rx_frame_errors);
	}
	return stats_count;
}

static size_t efx_ef10_update_stats_pf(struct efx_nic *efx, u64 *full_stats,
				       struct rtnl_link_stats64 *core_stats)
	__acquires(efx->stats_lock)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	DECLARE_BITMAP(mask, EF10_STAT_COUNT) = {};
	u64 *stats = nic_data->stats;

	spin_lock_bh(&efx->stats_lock);

	efx_ef10_get_stat_mask(efx, mask);

	efx_nic_copy_stats(efx, nic_data->mc_stats);
	efx_nic_update_stats(efx_ef10_stat_desc, EF10_STAT_COUNT,
			     mask, stats, efx->mc_initial_stats, nic_data->mc_stats);

	/* Update derived statistics */
	efx_nic_fix_nodesc_drop_stat(efx,
				     &stats[EF10_STAT_port_rx_nodesc_drops]);
	/* MC Firmware reads RX_BYTES and RX_GOOD_BYTES from the MAC.
	 * It then calculates RX_BAD_BYTES and DMAs it to us with RX_BYTES.
	 * We report these as port_rx_ stats. We are not given RX_GOOD_BYTES.
	 * Here we calculate port_rx_good_bytes.
	 */
	stats[EF10_STAT_port_rx_good_bytes] =
		stats[EF10_STAT_port_rx_bytes] -
		stats[EF10_STAT_port_rx_bytes_minus_good_bytes];

	/* The asynchronous reads used to calculate RX_BAD_BYTES in
	 * MC Firmware are done such that we should not see an increase in
	 * RX_BAD_BYTES when a good packet has arrived. Unfortunately this
	 * does mean that the stat can decrease at times. Here we do not
	 * update the stat unless it has increased or has gone to zero
	 * (In the case of the NIC rebooting).
	 * Please see Bug 33781 for a discussion of why things work this way.
	 */
	efx_update_diff_stat(&stats[EF10_STAT_port_rx_bad_bytes],
			     stats[EF10_STAT_port_rx_bytes_minus_good_bytes]);
	efx_update_sw_stats(efx, stats);

	return efx_ef10_update_stats_common(efx, full_stats, core_stats);
}

static void efx_ef10_pull_stats_pf(struct efx_nic *efx)
{
	efx_mcdi_mac_pull_stats(efx);
	if (!efx->stats_initialised) {
		efx_reset_sw_stats(efx);
		efx_ptp_reset_stats(efx);
		efx_nic_reset_stats(efx);
		efx->stats_initialised = true;
	}
}

#ifdef CONFIG_SFC_SRIOV
static size_t efx_ef10_update_stats_vf(struct efx_nic *efx, u64 *full_stats,
				       struct rtnl_link_stats64 *core_stats)
	__acquires(efx->stats_lock)
{
	/* MCDI is required to update statistics, but it can't be used
	 * here since read dev_base_lock rwlock may be held outside and
	 * EVQ/CPU0 may wait for the write lock with bottom-halves
	 * disabled (i.e. NAPI cannot run to process MCDI completion).
	 */

	/* Serialize access to nic_data->stats */
	spin_lock_bh(&efx->stats_lock);
	/* The lock should be held on return */
	return efx_ef10_update_stats_common(efx, full_stats, core_stats);
}

static void efx_ef10_vf_schedule_stats_work(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	schedule_delayed_work(&nic_data->vf_stats_work,
			      msecs_to_jiffies(efx->stats_period_ms));
}

static void efx_ef10_start_stats_vf(struct efx_nic *efx)
{
	efx_ef10_vf_schedule_stats_work(efx);
}

static void efx_ef10_stop_stats_vf(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	cancel_delayed_work_sync(&nic_data->vf_stats_work);
}

static void efx_ef10_pull_stats_vf(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	MCDI_DECLARE_BUF(inbuf, MC_CMD_MAC_STATS_IN_LEN);
	DECLARE_BITMAP(mask, EF10_STAT_COUNT) = {};
	__le64 generation_start, generation_end;
	u32 dma_len = efx->num_mac_stats * sizeof(u64);
	struct efx_buffer stats_buf;
	__le64 *dma_stats;
	u64 *stats = nic_data->stats;
	int rc;

	efx_ef10_get_stat_mask(efx, mask);

	if (efx_nic_alloc_buffer(efx, &stats_buf, dma_len, GFP_KERNEL))
		return;

	dma_stats = stats_buf.addr;
	dma_stats[efx->num_mac_stats - 1] = EFX_MC_STATS_GENERATION_INVALID;

	MCDI_SET_QWORD(inbuf, MAC_STATS_IN_DMA_ADDR, stats_buf.dma_addr);
	MCDI_POPULATE_DWORD_1(inbuf, MAC_STATS_IN_CMD,
			      MAC_STATS_IN_DMA, 1);
	MCDI_SET_DWORD(inbuf, MAC_STATS_IN_DMA_LEN, dma_len);
	MCDI_SET_DWORD(inbuf, MAC_STATS_IN_PORT_ID, EVB_PORT_ID_ASSIGNED);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_MAC_STATS, inbuf, sizeof(inbuf),
				NULL, 0, NULL);

	if (rc) {
		/* Expect ENOENT if DMA queues have not been set up */
		if (rc != -ENOENT || atomic_read(&efx->active_queues))
			efx_mcdi_display_error(efx, MC_CMD_MAC_STATS,
					       sizeof(inbuf), NULL, 0, rc);
		goto out;
	}

	generation_end = dma_stats[efx->num_mac_stats - 1];
	if (generation_end == EFX_MC_STATS_GENERATION_INVALID) {
		WARN_ON_ONCE(1);
		goto out;
	}

	if (!efx->stats_initialised) {
		efx_ptp_reset_stats(efx);
		efx_reset_sw_stats(efx);
		memcpy(efx->mc_initial_stats, dma_stats,
		       efx->num_mac_stats * sizeof(u64));
		efx->stats_initialised = true;
	}

	/* Acquire lock back since stats should be updated under lock */
	spin_lock_bh(&efx->stats_lock);

	efx_nic_update_stats(efx_ef10_stat_desc, EF10_STAT_COUNT, mask,
			     stats, efx->mc_initial_stats, dma_stats);
	rmb();
	generation_start = dma_stats[MC_CMD_MAC_GENERATION_START];
	if (generation_end != generation_start)
		goto out_unlock;

	efx_update_sw_stats(efx, stats);

out_unlock:
	spin_unlock_bh(&efx->stats_lock);
out:
	efx_nic_free_buffer(efx, &stats_buf);
}

static void efx_ef10_vf_update_stats_work(struct work_struct *data)
{
	struct efx_ef10_nic_data *nic_data =
		container_of(data, struct efx_ef10_nic_data, vf_stats_work.work);

	efx_ef10_pull_stats_vf(nic_data->efx);
	efx_ef10_vf_schedule_stats_work(nic_data->efx);
}
#endif

static void efx_ef10_push_irq_moderation(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	unsigned int mode, usecs;
	efx_dword_t timer_cmd;

	if (channel->irq_moderation_us) {
		mode = 3;
		usecs = channel->irq_moderation_us;
	} else {
		mode = 0;
		usecs = 0;
	}

	if (EFX_EF10_WORKAROUND_61265(efx)) {
		MCDI_DECLARE_BUF(inbuf, MC_CMD_SET_EVQ_TMR_IN_LEN);
		unsigned int ns = usecs * 1000;

		MCDI_SET_DWORD(inbuf, SET_EVQ_TMR_IN_INSTANCE,
			       channel->channel);
		MCDI_SET_DWORD(inbuf, SET_EVQ_TMR_IN_TMR_LOAD_REQ_NS, ns);
		MCDI_SET_DWORD(inbuf, SET_EVQ_TMR_IN_TMR_RELOAD_REQ_NS, ns);
		MCDI_SET_DWORD(inbuf, SET_EVQ_TMR_IN_TMR_MODE, mode);

		efx_mcdi_rpc_async(efx, MC_CMD_SET_EVQ_TMR,
				   inbuf, sizeof(inbuf), NULL, 0);
	} else if (EFX_EF10_WORKAROUND_35388(efx)) {
		unsigned int ticks = efx_usecs_to_ticks(efx, usecs);

		EFX_POPULATE_DWORD_3(timer_cmd, ERF_DD_EVQ_IND_TIMER_FLAGS,
				     EFE_DD_EVQ_IND_TIMER_FLAGS,
				     ERF_DD_EVQ_IND_TIMER_MODE, mode,
				     ERF_DD_EVQ_IND_TIMER_VAL, ticks);
		efx_writed_page(efx, &timer_cmd, ER_DD_EVQ_INDIRECT,
				channel->channel);
	} else {
		unsigned int ticks = efx_usecs_to_ticks(efx, usecs);

		EFX_POPULATE_DWORD_3(timer_cmd, ERF_DZ_TC_TIMER_MODE, mode,
				     ERF_DZ_TC_TIMER_VAL, ticks,
				     ERF_FZ_TC_TMR_REL_VAL, ticks);
		efx_writed_page(efx, &timer_cmd, ER_DZ_EVQ_TMR,
				channel->channel);
	}
}

#ifdef CONFIG_SFC_SRIOV
static void efx_ef10_get_wol_vf(struct efx_nic *efx, struct ethtool_wolinfo *wol) {}

static int efx_ef10_set_wol_vf(struct efx_nic *efx, u32 type)
{
	return -EOPNOTSUPP;
}
#endif

static void efx_ef10_get_wol(struct efx_nic *efx, struct ethtool_wolinfo *wol)
{
	wol->supported = 0;
	wol->wolopts = 0;
	memset(&wol->sopass, 0, sizeof(wol->sopass));
}

static int efx_ef10_set_wol(struct efx_nic *efx, u32 type)
{
	if (type != 0)
		return -EINVAL;
	return 0;
}

static void efx_ef10_mcdi_request(struct efx_nic *efx, u8 bufid,
				  const efx_dword_t *hdr, size_t hdr_len,
				  const efx_dword_t *sdu, size_t sdu_len)
{
	dma_addr_t dma_addr;
	u8 *pdu = efx_ef10_mcdi_buf(efx, bufid, &dma_addr);

	memcpy(pdu, hdr, hdr_len);
	memcpy(pdu + hdr_len, sdu, sdu_len);
	wmb();

	/* The hardware provides 'low' and 'high' (doorbell) registers
	 * for passing the 64-bit address of an MCDI request to
	 * firmware.  However the dwords are swapped by firmware.  The
	 * least significant bits of the doorbell are then 0 for all
	 * MCDI requests due to alignment.
	 */
	_efx_writed(efx, cpu_to_le32((u64)dma_addr >> 32), ER_DZ_MC_DB_LWRD);
	_efx_writed(efx, cpu_to_le32((u32)dma_addr), ER_DZ_MC_DB_HWRD);
}

static bool efx_ef10_mcdi_poll_response(struct efx_nic *efx, u8 bufid)
{
	const efx_dword_t hdr =
		*(const efx_dword_t *)(efx_ef10_mcdi_buf(efx, bufid, NULL));

	rmb();
	return EFX_DWORD_FIELD(hdr, MCDI_HEADER_RESPONSE);
}

static void
efx_ef10_mcdi_read_response(struct efx_nic *efx, u8 bufid,
			    efx_dword_t *outbuf, size_t offset, size_t outlen)
{
	const u8 *pdu = efx_ef10_mcdi_buf(efx, bufid, NULL);

	memcpy(outbuf, pdu + offset, outlen);
}

static void efx_ef10_mcdi_reboot_detected(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	efx->current_reset = jiffies;

	/* All our allocations have been reset */
	efx_ef10_reset_mc_allocations(efx);

	/* The datapath firmware might have been changed */
	nic_data->must_check_datapath_caps = true;

	/* MAC statistics have been cleared on the NIC; clear the local
	 * statistic that we update with efx_update_diff_stat().
	 */
	nic_data->stats[EF10_STAT_port_rx_bad_bytes] = 0;

	/* The set of available sensors might have changed */
	nic_data->must_reprobe_sensors = true;
}

static int efx_ef10_mcdi_poll_reboot(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	int rc;

	rc = efx_ef10_get_warm_boot_count(efx);
	if (rc < 0) {
		/* The firmware is presumably in the process of
		 * rebooting.  However, we are supposed to report each
		 * reboot just once, so we must only do that once we
		 * can read and store the updated warm boot count.
		 */
		return 0;
	}

	if (rc == nic_data->warm_boot_count)
		return 0;

	nic_data->warm_boot_count = rc;

	return -EIO;
}

/* Record the warm boot count at the start of BIST.
 * If efx_ef10_mcdi_poll_reboot sees a reboot after the function enters BIST
 * mode but before the scheduled MC_BIST reset actually begins, then the warm
 * boot count increase will be recorded before the reset. This means that
 * efx_wait_for_bist_end will timeout waiting for an increase in the warm boot
 * count which has already happened. By comparing with the warm boot count at
 * the start of BIST mode we remove this race condition.
 */
static void efx_ef10_mcdi_record_bist_event(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	nic_data->bist_warm_boot_count = nic_data->warm_boot_count;
}

/* Poll for a warm boot count increase as compared with the count when the
 * function entered BIST mode.
 */
static int efx_ef10_mcdi_poll_bist_end(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	int rc;

	rc = efx_ef10_get_warm_boot_count(efx);
	if (rc < 0) {
		/* The firmware is presumably in the process of
		 * rebooting.  However, we are supposed to report each
		 * reboot just once, so we must only do that once we
		 * can read and store the updated warm boot count.
		 */
		return 0;
	}

	if (rc == nic_data->bist_warm_boot_count)
		return 0;

	return -EIO;
}

/* Get an MCDI buffer
 *
 * The caller is responsible for preventing racing by holding the
 * MCDI iface_lock.
 */
static bool efx_ef10_mcdi_get_buf(struct efx_nic *efx, u8 *bufid)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	*bufid = ffz(nic_data->mcdi_buf_use);
	if (*bufid < EF10_NUM_MCDI_BUFFERS) {
		set_bit(*bufid, &nic_data->mcdi_buf_use);
		return true;
	}

	return false;
}

/* Return an MCDI buffer */
static void efx_ef10_mcdi_put_buf(struct efx_nic *efx, u8 bufid)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	EFX_WARN_ON_PARANOID(bufid >= EF10_NUM_MCDI_BUFFERS);
	EFX_WARN_ON_PARANOID(!test_bit(bufid, &nic_data->mcdi_buf_use));

	clear_bit(bufid, &nic_data->mcdi_buf_use);
}

/* Handle an MSI interrupt
 *
 * Handle an MSI hardware interrupt.  This routine schedules event
 * queue processing.  No interrupt acknowledgement cycle is necessary.
 * Also, we never need to check that the interrupt is for us, since
 * MSI interrupts cannot be shared.
 */
static irqreturn_t efx_ef10_msi_interrupt(int irq, void *dev_id)
{
	struct efx_msi_context *context = dev_id;
	struct efx_nic *efx = context->efx;
	struct efx_channel *channel;

	netif_vdbg(efx, intr, efx->net_dev,
		   "IRQ %d on CPU %d\n", irq, raw_smp_processor_id());

	if (likely(READ_ONCE(efx->irq_soft_enabled))) {
		/* Note test interrupts */
		if (context->index == efx->irq_level)
			efx->last_irq_cpu = raw_smp_processor_id();

		/* Schedule processing of the channel */
		channel = efx_get_channel(efx, context->index);
		efx_schedule_channel_irq(channel);
	}

	return IRQ_HANDLED;
}

static int efx_ef10_irq_test_generate(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_TRIGGER_INTERRUPT_IN_LEN);

	if (efx_mcdi_set_workaround(efx, MC_CMD_WORKAROUND_BUG41750, true,
				    NULL) == 0)
		return -EOPNOTSUPP;

	BUILD_BUG_ON(MC_CMD_TRIGGER_INTERRUPT_OUT_LEN != 0);

	MCDI_SET_DWORD(inbuf, TRIGGER_INTERRUPT_IN_INTR_LEVEL, efx->irq_level);
	return efx_mcdi_rpc_quiet(efx, MC_CMD_TRIGGER_INTERRUPT,
				  inbuf, sizeof(inbuf), NULL, 0, NULL);
}

static int efx_ef10_tx_probe(struct efx_tx_queue *tx_queue)
{
	return efx_nic_alloc_buffer(tx_queue->efx, &tx_queue->txd,
				    (tx_queue->ptr_mask + 1) *
				    sizeof(efx_qword_t),
				    GFP_KERNEL);
}

/* This writes to the TX_DESC_WPTR and also pushes data.  If multiple
 * descriptors are queued, subsequent descriptors will then be DMA-fetched.
 */
static inline void efx_ef10_push_tx_desc(struct efx_tx_queue *tx_queue,
					 const efx_qword_t *txd)
{
	unsigned int write_ptr;
	efx_oword_t reg;

	write_ptr = tx_queue->write_count & tx_queue->ptr_mask;
	EFX_POPULATE_OWORD_1(reg, ERF_DZ_TX_DESC_WPTR, write_ptr);
	reg.qword[0] = *txd;
	efx_writeo_page(tx_queue->efx, &reg,
			ER_DZ_TX_DESC_UPD, tx_queue->queue);
	tx_queue->notify_count = tx_queue->write_count;
}

/* Add Firmware-Assisted TSO v2 option descriptors to a queue.
 */
static int efx_ef10_tx_tso_desc(struct efx_tx_queue *tx_queue,
				struct sk_buff *skb,
				bool *data_mapped)
{
	struct efx_tx_buffer *buffer;
	u16 inner_ipv4_id = 0;
	u16 outer_ipv4_id = 0;
	struct tcphdr *tcp;
	struct iphdr *ip;
	u16 ip_tot_len;
	u32 seqnum;
	u32 mss;

	EFX_WARN_ON_ONCE_PARANOID(tx_queue->tso_version != 2);

	mss = skb_shinfo(skb)->gso_size;

	if (unlikely(mss < 4)) {
		WARN_ONCE(1, "MSS of %u is too small for TSO v2\n", mss);
		return -EINVAL;
	}

	if (skb->encapsulation) {
		if (!tx_queue->tso_encap)
			return -EINVAL;
		ip = ip_hdr(skb);
		if (ip->version == 4)
			outer_ipv4_id = ntohs(ip->id);

		ip = inner_ip_hdr(skb);
		tcp = inner_tcp_hdr(skb);
	} else {
		ip = ip_hdr(skb);
		tcp = tcp_hdr(skb);
	}

	/* 8000-series EF10 hardware requires that IP Total Length be
	 * greater than or equal to the value it will have in each segment
	 * (which is at most mss + 208 + TCP header length), but also less
	 * than (0x10000 - inner_network_header).  Otherwise the TCP
	 * checksum calculation will be broken for encapsulated packets.
	 * We fill in ip->tot_len with 0xff30, which should satisfy the
	 * first requirement unless the MSS is ridiculously large (which
	 * should be impossible as the driver max MTU is 9216); it is
	 * guaranteed to satisfy the second as we only attempt TSO if
	 * inner_network_header <= 208.
	 */
	ip_tot_len = 0x10000 - EFX_TSO2_MAX_HDRLEN;
	EFX_WARN_ON_ONCE_PARANOID(mss + EFX_TSO2_MAX_HDRLEN +
				  (tcp->doff << 2u) > ip_tot_len);

	if (ip->version == 4) {
		ip->tot_len = htons(ip_tot_len);
		ip->check = 0;
		inner_ipv4_id = ntohs(ip->id);
	} else {
		((struct ipv6hdr *)ip)->payload_len = htons(ip_tot_len);
	}

	seqnum = ntohl(tcp->seq);

	buffer = efx_tx_queue_get_insert_buffer(tx_queue);

	buffer->flags = EFX_TX_BUF_OPTION;
	buffer->len = 0;
	buffer->unmap_len = 0;
	EFX_POPULATE_QWORD_5(buffer->option,
			ESF_DZ_TX_DESC_IS_OPT, 1,
			ESF_DZ_TX_OPTION_TYPE, ESE_DZ_TX_OPTION_DESC_TSO,
			ESF_DZ_TX_TSO_OPTION_TYPE,
			ESE_DZ_TX_TSO_OPTION_DESC_FATSO2A,
			ESF_DZ_TX_TSO_IP_ID, inner_ipv4_id,
			ESF_DZ_TX_TSO_TCP_SEQNO, seqnum
			);
	++tx_queue->insert_count;

	buffer = efx_tx_queue_get_insert_buffer(tx_queue);

	buffer->flags = EFX_TX_BUF_OPTION;
	buffer->len = 0;
	buffer->unmap_len = 0;
	EFX_POPULATE_QWORD_5(buffer->option,
			ESF_DZ_TX_DESC_IS_OPT, 1,
			ESF_DZ_TX_OPTION_TYPE, ESE_DZ_TX_OPTION_DESC_TSO,
			ESF_DZ_TX_TSO_OPTION_TYPE,
			ESE_DZ_TX_TSO_OPTION_DESC_FATSO2B,
			ESF_DZ_TX_TSO_OUTER_IPID, outer_ipv4_id,
			ESF_DZ_TX_TSO_TCP_MSS, mss
			);
	++tx_queue->insert_count;

	return 0;
}

static int efx_ef10_tx_init(struct efx_tx_queue *tx_queue)
{
	struct efx_channel *channel = tx_queue->channel;
	struct efx_nic *efx = tx_queue->efx;
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	efx_qword_t *txd;
	bool tso_v2 = false;
	int rc;
	bool outer_csum_offload =
		tx_queue->csum_offload & EFX_TXQ_TYPE_CSUM_OFFLOAD;
	bool inner_csum_offload =
		tx_queue->csum_offload & EFX_TXQ_TYPE_INNER_CSUM_OFFLOAD;

	EFX_WARN_ON_PARANOID(inner_csum_offload &&
		!efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE));

	/* Only allow TX timestamping if we have the license for it. */
	if (!(nic_data->licensed_features &
	      (1 << LICENSED_V3_FEATURES_TX_TIMESTAMPS_LBN))) {
		tx_queue->timestamping = false;
#ifdef CONFIG_SFC_PTP
		/* Disable sync events on this channel. */
		if (efx->type->ptp_set_ts_sync_events)
			efx->type->ptp_set_ts_sync_events(efx, false, false);
#endif
	}

#ifdef EFX_NOT_UPSTREAM
	/* TSOv2 is a limited resource that can only be configured on a limited
	 * number of queues.  On a queue with no checksum offloads, TSO cannot
	 * possibly be a thing, so we don't enable it there.  However, normally
	 * we use the same queue for NO_OFFLOAD and for INNER_CSUM_OFFLOAD, and
	 * it's initialised as a NO_OFFLOAD.  So it's only when
	 * tx_non_csum_queue is set (meaning we have separate NO_OFFLOAD and
	 * INNER_CSUM_OFFLOAD queues) that the NO_OFFLOAD queue doesn't want a
	 * TSOv2 context.
	 */

	if (!(tx_non_csum_queue &&
	      tx_queue->csum_offload == EFX_TXQ_TYPE_NO_OFFLOAD))
#endif
	/* TSOv2 cannot be used with Hardware timestamping, and is never needed
	 * for XDP tx. */
	if (!tx_queue->timestamping && !tx_queue->xdp_tx &&
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
	    !efx_is_xsk_tx_queue(tx_queue) &&
#endif
#endif
	    efx_ef10_has_cap(nic_data->datapath_caps2, TX_TSO_V2)) {
		tso_v2 = true;
		tx_queue->tso_wanted_version = 2;
	}

	rc = efx_mcdi_tx_init(tx_queue, &tso_v2);
	if (rc)
		goto fail;

	channel->tx_coalesce_doorbell = tx_coalesce_doorbell;

	/* A previous user of this TX queue might have set us up the
	 * bomb by writing a descriptor to the TX push collector but
	 * not the doorbell.  (Each collector belongs to a port, not a
	 * queue or function, so cannot easily be reset.)  We must
	 * attempt to push a no-op descriptor in its place.
	 */
	tx_queue->buffer[0].flags = EFX_TX_BUF_OPTION;
	tx_queue->insert_count = 1;
	txd = efx_tx_desc(tx_queue, 0);
	EFX_POPULATE_QWORD_7(*txd,
			     ESF_DZ_TX_DESC_IS_OPT, true,
			     ESF_DZ_TX_OPTION_TYPE,
			     ESE_DZ_TX_OPTION_DESC_CRC_CSUM,
			     ESF_DZ_TX_OPTION_UDP_TCP_CSUM,
				outer_csum_offload,
			     ESF_DZ_TX_OPTION_IP_CSUM,
				outer_csum_offload && !tso_v2,
			     ESF_DZ_TX_OPTION_INNER_UDP_TCP_CSUM,
				inner_csum_offload,
			     ESF_DZ_TX_OPTION_INNER_IP_CSUM,
				inner_csum_offload && !tso_v2,
			     ESF_DZ_TX_TIMESTAMP,
				tx_queue->timestamping);
	tx_queue->write_count = 1;

	if (tso_v2) {
		netif_dbg(efx, hw, efx->net_dev, "Using TSOv2 for channel %u\n",
			  channel->channel);
		tx_queue->handle_tso = efx_ef10_tx_tso_desc;
		tx_queue->tso_version = 2;

		if (efx_ef10_has_cap(nic_data->datapath_caps2, TX_TSO_V2_ENCAP))
			tx_queue->tso_encap = true;
	} else if (efx_ef10_has_cap(nic_data->datapath_caps, TX_TSO)) {
		tx_queue->tso_version = 1;
	}

	wmb();
	efx_ef10_push_tx_desc(tx_queue, txd);

	return 0;

fail:
	if (rc != -ENETDOWN && rc != -EAGAIN)
		netdev_WARN(efx->net_dev, "failed to initialise TXQ %d\n",
			    tx_queue->queue);

	return rc;
}

static void efx_ef10_notify_tx_desc(struct efx_tx_queue *tx_queue)
{
	unsigned int write_ptr;
	efx_dword_t reg;

	write_ptr = tx_queue->write_count & tx_queue->ptr_mask;
	EFX_POPULATE_DWORD_1(reg, ERF_DZ_TX_DESC_WPTR_DWORD, write_ptr);
	efx_writed_page(tx_queue->efx, &reg,
			ER_DZ_TX_DESC_UPD_DWORD, tx_queue->queue);
	tx_queue->notify_count = tx_queue->write_count;
	tx_queue->notify_jiffies = jiffies;
}

#define EFX_EF10_MAX_TX_DESCRIPTOR_LEN 0x3fff

static unsigned int efx_ef10_tx_limit_len(struct efx_tx_queue *tx_queue,
					  dma_addr_t dma_addr, unsigned int len)
{
	if (len > EFX_EF10_MAX_TX_DESCRIPTOR_LEN) {
		/* If we need to break across multiple descriptors we should
		 * stop at a page boundary. This assumes the length limit is
		 * greater than the page size.
		 */
		dma_addr_t end = dma_addr + EFX_EF10_MAX_TX_DESCRIPTOR_LEN;

		BUILD_BUG_ON(EFX_EF10_MAX_TX_DESCRIPTOR_LEN < EFX_PAGE_SIZE);
		len = (end & (~(EFX_PAGE_SIZE - 1))) - dma_addr;
	}

	return len;
}

static void efx_ef10_tx_write(struct efx_tx_queue *tx_queue)
{
	unsigned int old_write_count = tx_queue->write_count;
	unsigned int new_write_count = old_write_count;
	struct efx_tx_buffer *buffer;
	bool prohibit_push = false;
	unsigned int write_ptr;
	efx_qword_t *txd;

	tx_queue->xmit_pending = false;
	if (unlikely(tx_queue->write_count == tx_queue->insert_count))
		return;

	/* Some firmware versions don't like TSO descriptors in a tx push. */
	write_ptr = new_write_count & tx_queue->ptr_mask;
	buffer = &tx_queue->buffer[write_ptr];
	if (buffer->flags & EFX_TX_BUF_OPTION &&
	    EFX_QWORD_FIELD(buffer->option, ESF_DZ_TX_OPTION_TYPE) ==
	    ESE_DZ_TX_OPTION_DESC_TSO)
		prohibit_push = true;
	/* We've already got the write_ptr and buffer, so jump ahead. */
	goto got_buffer;

	do {
		write_ptr = new_write_count & tx_queue->ptr_mask;
		buffer = &tx_queue->buffer[write_ptr];
got_buffer:
		txd = efx_tx_desc(tx_queue, write_ptr);
		++new_write_count;

		/* Create TX descriptor ring entry */
		if (buffer->flags & EFX_TX_BUF_OPTION) {
			*txd = buffer->option;
			if (EFX_QWORD_FIELD(*txd, ESF_DZ_TX_OPTION_TYPE) == 1) {
				/* PIO descriptor */
				tx_queue->packet_write_count = new_write_count;
			}
		} else {
			tx_queue->packet_write_count = new_write_count;
			BUILD_BUG_ON(EFX_TX_BUF_CONT != 1);
			EFX_POPULATE_QWORD_3(
				*txd,
				ESF_DZ_TX_KER_CONT,
				buffer->flags & EFX_TX_BUF_CONT,
				ESF_DZ_TX_KER_BYTE_CNT, buffer->len,
				ESF_DZ_TX_KER_BUF_ADDR, buffer->dma_addr);
		}
	} while (new_write_count != tx_queue->insert_count);

	wmb(); /* Ensure descriptors are written before they are fetched */

	tx_queue->write_count = new_write_count;

	/* Only the first descriptor can be pushed, so don't need to consider
	 * whether multiple descriptors are queued.
	 */
	if (!prohibit_push &&
	    likely(old_write_count - tx_queue->read_count < tx_push_max_fill)) {
		txd = efx_tx_desc(tx_queue,
				  old_write_count & tx_queue->ptr_mask);
		efx_ef10_push_tx_desc(tx_queue, txd);
		++tx_queue->pushes;
	} else {
		/* The write_count above must be updated before reading
		 * channel->holdoff_doorbell to avoid a race with the
		 * completion path, so ensure these operations are not
		 * re-ordered.  This also flushes the update of write_count
		 * back into the cache.
		 */
		smp_mb();

		/* If the completion path is running and module option
		 * to enable coalescing is set we let the completion path
		 * handle the doorbell ping.
		 */
		if (!tx_queue->channel->holdoff_doorbell) {
			/* Completion handler not running so send out */
			efx_ef10_notify_tx_desc(tx_queue);
			++tx_queue->doorbell_notify_tx;
		}
	}
}

/* Maximum number of descriptors required for a single SKB */
static unsigned int efx_ef10_tx_max_skb_descs(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	unsigned int max_descs;

	/* In all cases we assume that we don't need to fragment a descriptor
	 * due to a DMA boundary for a single output packet.
	 */
	BUILD_BUG_ON(EFX_MAX_MTU > EFX_EF10_MAX_TX_DESCRIPTOR_LEN);

	if (efx_ef10_has_cap(nic_data->datapath_caps, TX_TSO)) {
		/* We need a header, option and payload descriptor for each
		 * output segment we might produce.
		 */
		max_descs = EFX_TSO_MAX_SEGS * 3 + MAX_SKB_FRAGS;
	} else if (efx_ef10_has_cap(nic_data->datapath_caps2, TX_TSO_V2)) {
		/* TSOv2 is limited to a certain number of queues, so we
		 * have to allow for a possible fallback to GSO. We make
		 * the assumption that GSO will segment things sensibly,
		 * so we allow for each possible output segment:
		 *  - 1 DMA descriptor for the header
		 *  - 1 DMA descriptor for the payload
		 *  - additional DMA descriptors to allow for a fragment
		 *    boundary in the middle of an output segment
		 *
		 * This is similar to the TSOv1 case above, but without
		 * the additional option descriptor.
		 */
		max_descs = EFX_TSO_MAX_SEGS * 2 + MAX_SKB_FRAGS;
	} else {
		/* We don't need to consider boundaries here - our maximum
		 * packet size is less than EFX_EF10_MAX_TX_DESCRIPTOR_LEN,
		 * as checked above.
		 */
		max_descs = MAX_SKB_FRAGS;
	}

	return max_descs;
}

#ifdef CONFIG_DEBUG_FS
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
static int efx_debugfs_udp_tunnels(struct seq_file *file, void *data)
{
	struct efx_nic *efx = data;
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	struct efx_udp_tunnel *tnl;
	char typebuf[8];
	unsigned int i;

	spin_lock_bh(&nic_data->udp_tunnels_lock);

	for (i = 0; i < ARRAY_SIZE(nic_data->udp_tunnels); ++i) {
		tnl = nic_data->udp_tunnels + i;
		efx_get_udp_tunnel_type_name(tnl->type, typebuf,
					     sizeof(typebuf));
		if (tnl->count)
			seq_printf(file, "%d (%s) (%u %c%c)\n",
				   ntohs(tnl->port), typebuf, tnl->count,
				   tnl->adding ? 'A' : '-',
				   tnl->removing ? 'R' : '-');
	}
	spin_unlock_bh(&nic_data->udp_tunnels_lock);
	return 0;
}
#endif

static int efx_debugfs_read_netdev_uc_addr(struct seq_file *file, void *data)
{
	struct net_device *net_dev = data;
	struct netdev_hw_addr *uc;
	unsigned int i = 0;

	netdev_for_each_uc_addr(uc, net_dev) {
		seq_printf(file, "%d - %pM\n", i, uc->addr);
		i++;
	}
	return 0;
}

static int efx_debugfs_read_netdev_mc_addr(struct seq_file *file, void *data)
{
	struct net_device *net_dev = data;
	struct netdev_hw_addr *mc;
	unsigned int i = 0;

	netdev_for_each_mc_addr(mc, net_dev) {
		seq_printf(file, "%d - %pM\n", i, mc->addr);
		i++;
	}
	return 0;
}

static int efx_debugfs_read_netdev_uc_count(struct seq_file *file, void *data)
{
	struct net_device *net_dev = data;

	seq_printf(file, "%d\n", netdev_uc_count(net_dev));
	return 0;
}

static int efx_debugfs_read_netdev_mc_count(struct seq_file *file, void *data)
{
	struct net_device *net_dev = data;

	seq_printf(file, "%d\n", netdev_mc_count(net_dev));
	return 0;
}

static int efx_debugfs_read_netdev_flags(struct seq_file *file, void *data)
{
	struct net_device *net_dev = data;

	seq_printf(file, "%#x promisc=%d\n", net_dev->flags,
		   net_dev->flags & IFF_PROMISC);
	return 0;
}

static int efx_debugfs_read_netdev_dev_addr(struct seq_file *file, void *data)
{
	struct net_device *net_dev = data;

	seq_printf(file, "%pM\n", net_dev->dev_addr);
	return 0;
}

static const struct efx_debugfs_parameter efx_debugfs[] = {
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
	_EFX_RAW_PARAMETER(udp_tunnels, efx_debugfs_udp_tunnels),
#endif
	{NULL},
};

static const struct efx_debugfs_parameter netdev_debugfs[] = {
	_EFX_RAW_PARAMETER(netdev_uc_addr, efx_debugfs_read_netdev_uc_addr),
	_EFX_RAW_PARAMETER(netdev_mc_addr, efx_debugfs_read_netdev_mc_addr),
	_EFX_RAW_PARAMETER(netdev_uc_count, efx_debugfs_read_netdev_uc_count),
	_EFX_RAW_PARAMETER(netdev_mc_count, efx_debugfs_read_netdev_mc_count),
	_EFX_RAW_PARAMETER(netdev_flags, efx_debugfs_read_netdev_flags),
	_EFX_RAW_PARAMETER(netdev_dev_addr, efx_debugfs_read_netdev_dev_addr),
	{NULL},
};
#else /* CONFIG_DEBUG_FS */
static const struct efx_debugfs_parameter efx_debugfs[] = {
	{NULL}
};

static const struct efx_debugfs_parameter netdev_debugfs[] = {
	{NULL}
};
#endif /* CONFIG_DEBUG_FS */

static int efx_ef10_probe_multicast_chaining(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	unsigned int enabled, implemented;
	bool want_workaround_26807;
	int rc;

	rc = efx_mcdi_get_workarounds(efx, &implemented, &enabled);
	if (rc == -ENOSYS) {
		/* GET_WORKAROUNDS was implemented before this workaround,
		 * thus it must be unavailable in this firmware.
		 */
		nic_data->workaround_26807 = false;
		return 0;
	}
	if (rc)
		return rc;
	want_workaround_26807 = multicast_chaining && \
		(implemented & MC_CMD_GET_WORKAROUNDS_OUT_BUG26807);
	nic_data->workaround_26807 =
		!!(enabled & MC_CMD_GET_WORKAROUNDS_OUT_BUG26807);

	if (want_workaround_26807 && !nic_data->workaround_26807) {
		unsigned int flags;

		rc = efx_mcdi_set_workaround(efx,
					     MC_CMD_WORKAROUND_BUG26807,
					     true, &flags);
		if (!rc) {
			if (flags &
			    1 << MC_CMD_WORKAROUND_EXT_OUT_FLR_DONE_LBN) {
				netif_info(efx, drv, efx->net_dev,
					   "other functions on NIC have been reset\n");

				/* With MCFW v4.6.x and earlier, the
				 * boot count will have incremented,
				 * so re-read the warm_boot_count
				 * value now to ensure this function
				 * doesn't think it has changed next
				 * time it checks.
				 */
				rc = efx_ef10_get_warm_boot_count(efx);
				if (rc >= 0) {
					nic_data->warm_boot_count = rc;
					rc = 0;
				}
			}
			nic_data->workaround_26807 = true;
		} else if (rc == -EPERM) {
			rc = 0;
		}
	}
	return rc;
}

static int efx_ef10_filter_table_probe(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	bool additional_rss = efx_ef10_has_cap(nic_data->datapath_caps,
					       ADDITIONAL_RSS_MODES);

	return efx_mcdi_filter_table_probe(efx, additional_rss);
}

static int efx_ef10_filter_table_init(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	bool encap = efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE);
	int rc = efx_ef10_probe_multicast_chaining(efx);

	if (rc)
		return rc;

	rc = efx_mcdi_filter_table_init(efx, nic_data->workaround_26807,
					encap);
	if (rc)
		return rc;

	efx_extend_debugfs_port(efx, efx, 0, efx_debugfs);
	efx_extend_debugfs_port(efx, efx->net_dev, 0, netdev_debugfs);
	return 0;
}

static int efx_ef10_filter_table_up(struct efx_nic *efx)
{
	int rc;

	down_write(&efx->filter_sem);
	rc = efx_mcdi_filter_table_up(efx);
	up_write(&efx->filter_sem);
	return rc;
}

static void efx_ef10_filter_table_down(struct efx_nic *efx)

{
	down_write(&efx->filter_sem);
	efx_mcdi_filter_table_down(efx);
	up_write(&efx->filter_sem);
}

static void efx_ef10_filter_table_fini(struct efx_nic *efx)
{
	efx_trim_debugfs_port(efx, efx_debugfs);
	efx_trim_debugfs_port(efx, netdev_debugfs);
	efx_mcdi_filter_table_fini(efx);
}

static int efx_ef10_pf_rx_push_rss_config(struct efx_nic *efx, bool user,
					  const u32 *rx_indir_table,
					  const u8 *key)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	if (efx_ef10_has_cap(nic_data->datapath_caps, RX_RSS_LIMITED))
		return -EOPNOTSUPP;
	return efx_mcdi_rx_push_rss_config(efx, user, rx_indir_table, key);
}

#ifdef CONFIG_SFC_SRIOV
static int efx_ef10_vf_rx_push_rss_config(struct efx_nic *efx, bool user,
					  const u32 *rx_indir_table,
					  const u8 *key)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	if (efx_ef10_has_cap(nic_data->datapath_caps, RX_RSS_LIMITED))
		return -EOPNOTSUPP;

	/* on EF10 we're limited on RSS contexts, so do not push an exclusive
	 * context, only accept a shared.
	 */
	if (user)
		return -EOPNOTSUPP;
	if (efx->rss_context.context_id != EFX_MCDI_RSS_CONTEXT_INVALID)
		return 0;

	return efx_mcdi_rx_push_shared_rss_config(efx, NULL);
}
#endif

static int efx_ef10_rx_init(struct efx_rx_queue *rx_queue)
{
	bool want_outer_classes = false;

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	struct efx_nic *efx = rx_queue->efx;
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	/* Outer classes (ETH_TAG_CLASS to be more precise) are required
	 * for Rx VLAN stripping offload.
	 */
	want_outer_classes = efx_ef10_has_cap(nic_data->datapath_caps,
				VXLAN_NVGRE) ||
			     efx_ef10_has_cap(nic_data->datapath_caps2,
				L3XUDP_SUPPORT);
#endif

	return efx_mcdi_rx_init(rx_queue, want_outer_classes);
}

/* This creates an entry in the RX descriptor queue */
static inline void
efx_ef10_build_rx_desc(struct efx_rx_queue *rx_queue, unsigned int index)
{
	struct efx_rx_buffer *rx_buf;
	efx_qword_t *rxd;

	rxd = efx_rx_desc(rx_queue, index);
	rx_buf = efx_rx_buffer(rx_queue, index);
	EFX_POPULATE_QWORD_2(*rxd,
			     ESF_DZ_RX_KER_BYTE_CNT, rx_buf->len,
			     ESF_DZ_RX_KER_BUF_ADDR, rx_buf->dma_addr);
}

static void _efx_ef10_rx_write(struct efx_rx_queue *rx_queue)
{
	struct efx_nic *efx = rx_queue->efx;
	unsigned int write_count;
	efx_dword_t reg;

	/* Firmware requires that RX_DESC_WPTR be a multiple of 8 */
	write_count = rx_queue->added_count & ~7;
	while (rx_queue->notified_count != write_count) {
		efx_ef10_build_rx_desc(
			rx_queue,
			rx_queue->notified_count & rx_queue->ptr_mask);
		++rx_queue->notified_count;
	}

	wmb();
	EFX_POPULATE_DWORD_1(reg, ERF_DZ_RX_DESC_WPTR,
			     write_count & rx_queue->ptr_mask);
	efx_writed_page(efx, &reg, ER_DZ_RX_DESC_UPD,
			efx_rx_queue_instance(rx_queue));
}

static void efx_ef10_rx_write(struct efx_rx_queue *rx_queue)
{
	unsigned int write_count;

	/* Firmware requires that RX_DESC_WPTR be a multiple of 8 */
	write_count = rx_queue->added_count & ~7;
	if (rx_queue->notified_count == write_count)
		return;

	_efx_ef10_rx_write(rx_queue);
}

static int efx_ef10_rx_defer_refill(struct efx_rx_queue *rx_queue)
{
	struct efx_channel *channel = efx_rx_queue_channel(rx_queue);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_DRIVER_EVENT_IN_LEN);
	efx_qword_t event;
	size_t outlen;
	u32 magic;

	magic = EFX_EF10_DRVGEN_MAGIC(EFX_EF10_REFILL,
				      efx_rx_queue_index(rx_queue));
	EFX_POPULATE_QWORD_2(event,
			     ESF_DZ_EV_CODE, EFX_EF10_DRVGEN_EV,
			     ESF_DZ_EV_DATA, magic);

	MCDI_SET_DWORD(inbuf, DRIVER_EVENT_IN_EVQ, channel->channel);

	/* MCDI_SET_QWORD is not appropriate here since EFX_POPULATE_* has
	 * already swapped the data to little-endian order.
	 */
	memcpy(MCDI_PTR(inbuf, DRIVER_EVENT_IN_DATA), &event.u64[0],
	       sizeof(efx_qword_t));

	return efx_mcdi_rpc(channel->efx, MC_CMD_DRIVER_EVENT,
			    inbuf, sizeof(inbuf), NULL, 0, &outlen);
}

static int efx_ef10_ev_init(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	bool use_v2 = efx_ef10_has_cap(nic_data->datapath_caps2, INIT_EVQ_V2);
	bool cut_thru = !efx_ef10_has_cap(nic_data->datapath_caps, RX_BATCHING);

	return efx_mcdi_ev_init(channel, cut_thru, use_v2);
}

static void efx_ef10_handle_rx_wrong_queue(struct efx_rx_queue *rx_queue,
					   unsigned int rx_queue_label)
{
	struct efx_nic *efx = rx_queue->efx;

	netif_info(efx, hw, efx->net_dev,
		   "rx event arrived on queue %d labeled as queue %u\n",
		   efx_rx_queue_index(rx_queue), rx_queue_label);

	efx_schedule_reset(efx, RESET_TYPE_DISABLE);
}

static void
efx_ef10_handle_rx_bad_lbits(struct efx_rx_queue *rx_queue,
			     unsigned int actual, unsigned int expected)
{
	unsigned int dropped = (actual - expected) & rx_queue->ptr_mask;
	struct efx_nic *efx = rx_queue->efx;

	netif_info(efx, hw, efx->net_dev,
		   "dropped %d events (index=%d expected=%d)\n",
		   dropped, actual, expected);

	atomic_inc(&efx->errors.missing_event);
	efx_schedule_reset(efx, RESET_TYPE_DATAPATH);
}

/* partially received RX was aborted. clean up. */
static void efx_ef10_handle_rx_abort(struct efx_rx_queue *rx_queue)
{
	unsigned int rx_desc_ptr;

	netif_dbg(rx_queue->efx, hw, rx_queue->efx->net_dev,
		  "scattered RX aborted (dropping %u buffers)\n",
		  rx_queue->scatter_n);

	rx_desc_ptr = rx_queue->removed_count & rx_queue->ptr_mask;

	if (rx_queue->scatter_n)
		efx_rx_packet(rx_queue, rx_desc_ptr, rx_queue->scatter_n,
			      0, EFX_RX_PKT_DISCARD);

	rx_queue->removed_count += rx_queue->scatter_n;
	rx_queue->scatter_n = 0;
	rx_queue->scatter_len = 0;
	++rx_queue->n_rx_nodesc_trunc;
}

static u16
efx_ef10_handle_rx_event_errors(struct efx_rx_queue *rx_queue,
				unsigned int n_packets,
				unsigned int rx_encap_hdr,
				unsigned int rx_l3_class,
				unsigned int rx_l4_class,
				const efx_qword_t *event)
{
	struct efx_nic *efx = rx_queue->efx;
	bool handled = false;

	if (EFX_QWORD_FIELD(*event, ESF_DZ_RX_ECRC_ERR)) {
		if (!(efx->net_dev->features & NETIF_F_RXALL)) {
			if (!efx->loopback_selftest)
				rx_queue->n_rx_eth_crc_err += n_packets;
			return EFX_RX_PKT_DISCARD;
		}
		handled = true;
	}
	if (EFX_QWORD_FIELD(*event, ESF_DZ_RX_IPCKSUM_ERR)) {
		if (unlikely(rx_encap_hdr != ESE_EZ_ENCAP_HDR_VXLAN &&
			     rx_l3_class != ESE_DZ_L3_CLASS_IP4 &&
			     rx_l3_class != ESE_DZ_L3_CLASS_IP4_FRAG &&
			     rx_l3_class != ESE_DZ_L3_CLASS_IP6 &&
			     rx_l3_class != ESE_DZ_L3_CLASS_IP6_FRAG))
			netdev_WARN(efx->net_dev,
				    "invalid class for RX_IPCKSUM_ERR: event="
				    EFX_QWORD_FMT "\n",
				    EFX_QWORD_VAL(*event));
		if (!efx->loopback_selftest)
			*(rx_encap_hdr ?
				&rx_queue->n_rx_outer_ip_hdr_chksum_err :
				&rx_queue->n_rx_ip_hdr_chksum_err) += n_packets;
		return 0;
	}
	if (EFX_QWORD_FIELD(*event, ESF_DZ_RX_TCPUDP_CKSUM_ERR)) {
		if (unlikely(rx_encap_hdr != ESE_EZ_ENCAP_HDR_VXLAN &&
			     ((rx_l3_class != ESE_DZ_L3_CLASS_IP4 &&
			       rx_l3_class != ESE_DZ_L3_CLASS_IP6) ||
			      (rx_l4_class != ESE_FZ_L4_CLASS_TCP &&
			       rx_l4_class != ESE_FZ_L4_CLASS_UDP))))
			netdev_WARN(efx->net_dev,
				    "invalid class for RX_TCPUDP_CKSUM_ERR: event="
				    EFX_QWORD_FMT "\n",
				    EFX_QWORD_VAL(*event));
		if (!efx->loopback_selftest)
			*(rx_encap_hdr ?
				&rx_queue->n_rx_outer_tcp_udp_chksum_err :
				&rx_queue->n_rx_tcp_udp_chksum_err) += n_packets;
		return 0;
	}
	if (EFX_QWORD_FIELD(*event, ESF_EZ_RX_IP_INNER_CHKSUM_ERR)) {
		if (unlikely(!rx_encap_hdr))
			netdev_WARN(efx->net_dev,
				    "invalid encapsulation type for RX_IP_INNER_CHKSUM_ERR: event="
				    EFX_QWORD_FMT "\n",
				    EFX_QWORD_VAL(*event));
		else if (unlikely(rx_l3_class != ESE_DZ_L3_CLASS_IP4 &&
				  rx_l3_class != ESE_DZ_L3_CLASS_IP4_FRAG &&
				  rx_l3_class != ESE_DZ_L3_CLASS_IP6 &&
				  rx_l3_class != ESE_DZ_L3_CLASS_IP6_FRAG))
			netdev_WARN(efx->net_dev,
				    "invalid class for RX_IP_INNER_CHKSUM_ERR: event="
				    EFX_QWORD_FMT "\n",
				    EFX_QWORD_VAL(*event));
		if (!efx->loopback_selftest)
			rx_queue->n_rx_inner_ip_hdr_chksum_err += n_packets;
		return 0;
	}
	if (EFX_QWORD_FIELD(*event, ESF_EZ_RX_TCP_UDP_INNER_CHKSUM_ERR)) {
		if (unlikely(!rx_encap_hdr))
			netdev_WARN(efx->net_dev,
				    "invalid encapsulation type for RX_TCP_UDP_INNER_CHKSUM_ERR: event="
				    EFX_QWORD_FMT "\n",
				    EFX_QWORD_VAL(*event));
		else if (unlikely((rx_l3_class != ESE_DZ_L3_CLASS_IP4 &&
				   rx_l3_class != ESE_DZ_L3_CLASS_IP6) ||
				  (rx_l4_class != ESE_FZ_L4_CLASS_TCP &&
				   rx_l4_class != ESE_FZ_L4_CLASS_UDP)))
			netdev_WARN(efx->net_dev,
				    "invalid class for RX_TCP_UDP_INNER_CHKSUM_ERR: event="
				    EFX_QWORD_FMT "\n",
				    EFX_QWORD_VAL(*event));
		if (!efx->loopback_selftest)
			rx_queue->n_rx_inner_tcp_udp_chksum_err += n_packets;
		return 0;
	}

	WARN_ON(!handled); /* No error bits were recognised */
	return 0;
}

static int efx_ef10_handle_rx_event(struct efx_channel *channel,
				    const efx_qword_t *event)
{
	unsigned int rx_bytes, next_ptr_lbits, rx_queue_label, rx_l4_class;
	unsigned int rx_l3_class, rx_encap_hdr;
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	unsigned int rx_eth_tag_class;
#endif
	unsigned int n_descs, n_packets, i;
	struct efx_nic *efx = channel->efx;
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	struct efx_rx_queue *rx_queue;
	efx_qword_t errors;
	bool rx_cont;
	u16 flags = 0;

	if (unlikely(READ_ONCE(efx->reset_pending)))
		return 0;

	/* Basic packet information */
	rx_bytes = EFX_QWORD_FIELD(*event, ESF_DZ_RX_BYTES);
	next_ptr_lbits = EFX_QWORD_FIELD(*event, ESF_DZ_RX_DSC_PTR_LBITS);
	rx_queue_label = EFX_QWORD_FIELD(*event, ESF_DZ_RX_QLABEL);
#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	rx_eth_tag_class = EFX_QWORD_FIELD(*event, ESF_DZ_RX_ETH_TAG_CLASS);
#endif
	rx_l3_class = EFX_QWORD_FIELD(*event, ESF_DZ_RX_L3_CLASS);
	rx_l4_class = EFX_QWORD_FIELD(*event, ESF_FZ_RX_L4_CLASS);
	rx_cont = EFX_QWORD_FIELD(*event, ESF_DZ_RX_CONT);
	rx_encap_hdr = (efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE) ||
			efx_ef10_has_cap(nic_data->datapath_caps2, L3XUDP_SUPPORT)) ?
		       EFX_QWORD_FIELD(*event, ESF_EZ_RX_ENCAP_HDR) :
		       ESE_EZ_ENCAP_HDR_NONE;


	if (EFX_QWORD_FIELD(*event, ESF_DZ_RX_DROP_EVENT))
		netdev_WARN(efx->net_dev, "saw RX_DROP_EVENT: event="
			    EFX_QWORD_FMT "\n",
			    EFX_QWORD_VAL(*event));

	rx_queue = efx_channel_get_rx_queue(channel);

	if (unlikely(rx_queue_label != efx_rx_queue_index(rx_queue) %
		     (1 << ESF_DZ_RX_QLABEL_WIDTH)))
		efx_ef10_handle_rx_wrong_queue(rx_queue, rx_queue_label);

	n_descs = ((next_ptr_lbits - rx_queue->removed_count) &
		   ((1 << ESF_DZ_RX_DSC_PTR_LBITS_WIDTH) - 1));

	if (n_descs != rx_queue->scatter_n + 1) {
		struct efx_ef10_nic_data *nic_data = efx->nic_data;

		/* detect rx abort */
		if (unlikely(n_descs == rx_queue->scatter_n)) {
			if (rx_queue->scatter_n == 0 || rx_bytes != 0)
				netdev_WARN(efx->net_dev,
					    "invalid RX abort: scatter_n=%u event="
					    EFX_QWORD_FMT "\n",
					    rx_queue->scatter_n,
					    EFX_QWORD_VAL(*event));
			efx_ef10_handle_rx_abort(rx_queue);
			return 0;
		}

		/* Check that RX completion merging is valid, i.e.
		 * the current firmware supports it and this is a
		 * non-scattered packet.
		 */
		if (!efx_ef10_has_cap(nic_data->datapath_caps, RX_BATCHING) ||
		    rx_queue->scatter_n != 0 || rx_cont) {
			efx_ef10_handle_rx_bad_lbits(
				rx_queue, next_ptr_lbits,
				(rx_queue->removed_count +
				 rx_queue->scatter_n + 1) &
				((1 << ESF_DZ_RX_DSC_PTR_LBITS_WIDTH) - 1));
			return 0;
		}

		/* Merged completion for multiple non-scattered packets */
		rx_queue->scatter_n = 1;
		rx_queue->scatter_len = 0;
		n_packets = n_descs;
		++rx_queue->n_rx_merge_events;
		rx_queue->n_rx_merge_packets += n_packets;
		flags |= EFX_RX_PKT_PREFIX_LEN;
	} else {
		++rx_queue->scatter_n;
		rx_queue->scatter_len += rx_bytes;
		if (rx_cont)
			return 0;
		n_packets = 1;
	}

	EFX_POPULATE_QWORD_5(errors, ESF_DZ_RX_ECRC_ERR, 1,
				     ESF_DZ_RX_IPCKSUM_ERR, 1,
				     ESF_DZ_RX_TCPUDP_CKSUM_ERR, 1,
				     ESF_EZ_RX_IP_INNER_CHKSUM_ERR, 1,
				     ESF_EZ_RX_TCP_UDP_INNER_CHKSUM_ERR, 1);
	EFX_AND_QWORD(errors, *event, errors);
	if (unlikely(!EFX_QWORD_IS_ZERO(errors))) {
		flags |= efx_ef10_handle_rx_event_errors(rx_queue, n_packets,
							 rx_encap_hdr,
							 rx_l3_class, rx_l4_class,
							 event);
	} else {
		bool tcpudp = rx_l4_class == ESE_FZ_L4_CLASS_TCP ||
			      rx_l4_class == ESE_FZ_L4_CLASS_UDP;

		if (rx_l3_class == ESE_DZ_L3_CLASS_IP4)
			flags |= EFX_RX_PKT_IPV4;
		else if (rx_l3_class == ESE_DZ_L3_CLASS_IP6)
			flags |= EFX_RX_PKT_IPV6;

		switch (rx_encap_hdr) {
		case ESE_EZ_ENCAP_HDR_VXLAN: /* VxLAN, GENEVE or L3xUDP */
			flags |= EFX_RX_PKT_CSUMMED; /* outer UDP csum */
			if (tcpudp)
				flags |= EFX_RX_PKT_CSUM_LEVEL; /* inner L4 */
			break;
		case ESE_EZ_ENCAP_HDR_NONE:
			if (rx_l4_class == ESE_FZ_L4_CLASS_TCP)
				flags |= EFX_RX_PKT_TCP;
			fallthrough;
		case ESE_EZ_ENCAP_HDR_GRE:
			if (tcpudp)
				flags |= EFX_RX_PKT_CSUMMED;
			break;
		default:
			netdev_WARN(efx->net_dev,
				   "unknown encapsulation type: event="
				   EFX_QWORD_FMT "\n",
				   EFX_QWORD_VAL(*event));
		}
	}

#if defined(EFX_NOT_UPSTREAM) && defined(EFX_USE_FAKE_VLAN_RX_ACCEL)
	if (rx_eth_tag_class == ESE_DZ_ETH_TAG_CLASS_VLAN1 ||
	    rx_eth_tag_class == ESE_DZ_ETH_TAG_CLASS_VLAN2)
		flags |= EFX_RX_PKT_VLAN;
#endif

	channel->irq_mod_score += 2 * n_packets;

	/* XXX for bug 37073 */
	if (rx_queue->added_count - rx_queue->removed_count < n_descs)
		netdev_WARN(efx->net_dev,
			    "invalid completion index: added_count=%#x removed_count=%#x n_packets=%u scatter_n=%u\n",
			    rx_queue->added_count, rx_queue->removed_count,
			    n_packets, rx_queue->scatter_n);

	/* Handle received packet(s) */
	for (i = 0; i < n_packets; i++) {
		efx_rx_packet(rx_queue,
			      rx_queue->removed_count & rx_queue->ptr_mask,
			      rx_queue->scatter_n, rx_queue->scatter_len,
			      flags);
		rx_queue->removed_count += rx_queue->scatter_n;
	}

	rx_queue->scatter_n = 0;
	rx_queue->scatter_len = 0;

	return n_packets;
}

static u32 efx_ef10_extract_event_ts(efx_qword_t *event)
{
	u32 tstamp;

	tstamp = EFX_QWORD_FIELD(*event, TX_TIMESTAMP_EVENT_TSTAMP_DATA_HI);
	tstamp <<= 16;
	tstamp |= EFX_QWORD_FIELD(*event, TX_TIMESTAMP_EVENT_TSTAMP_DATA_LO);

	return tstamp;
}

static void
efx_ef10_handle_tx_event(struct efx_channel *channel, efx_qword_t *event)
{
	struct efx_nic *efx = channel->efx;
	struct efx_tx_queue *tx_queue;
	unsigned int tx_ev_desc_ptr;
	unsigned int tx_ev_q_label;
	unsigned int tx_ev_type;
	u64 ts_part;

	if (unlikely(READ_ONCE(efx->reset_pending)))
		return;

	if (unlikely(EFX_QWORD_FIELD(*event, ESF_DZ_TX_DROP_EVENT)))
		return;

	/* Get the transmit queue */
	tx_ev_q_label = EFX_QWORD_FIELD(*event, ESF_DZ_TX_QLABEL);
	tx_queue = efx_channel_get_tx_queue(channel, tx_ev_q_label);

	if (!tx_queue->timestamping) {
		tx_ev_desc_ptr = EFX_QWORD_FIELD(*event, ESF_DZ_TX_DESCR_INDX);
		efx_xmit_done(tx_queue, tx_ev_desc_ptr & tx_queue->ptr_mask);
		return;
	}

	/* Transmit timestamps are only available for 8XXX series. They result
	 * in up to three events per packet. These occur in order, and are:
	 *  - the normal completion event (may be omitted)
	 *  - the low part of the timestamp
	 *  - the high part of the timestamp
	 *
	 * It's possible for multiple completion events to appear before the
	 * corresponding timestamps. So we can for example get:
	 *  COMP N
	 *  COMP N+1
	 *  TS_LO N
	 *  TS_HI N
	 *  TS_LO N+1
	 *  TS_HI N+1
	 *
	 * In addition it's also possible for the adjacent completions to be
	 * merged, so we may not see COMP N above. As such, the completion
	 * events are not very useful here.
	 *
	 * Each part of the timestamp is itself split across two 16 bit
	 * fields in the event.
	 */
	tx_ev_type = EFX_QWORD_FIELD(*event, ESF_EZ_TX_SOFT1);

	switch (tx_ev_type) {
	case TX_TIMESTAMP_EVENT_TX_EV_COMPLETION:
		/* Ignore this event - see above. */
		break;

	case TX_TIMESTAMP_EVENT_TX_EV_TSTAMP_LO:
		ts_part = efx_ef10_extract_event_ts(event);
		tx_queue->completed_timestamp_minor = ts_part;
		break;

	case TX_TIMESTAMP_EVENT_TX_EV_TSTAMP_HI:
		ts_part = efx_ef10_extract_event_ts(event);
		tx_queue->completed_timestamp_major = ts_part;
		efx_xmit_done_single(tx_queue);
		break;

	default:
		netif_err(efx, hw, efx->net_dev,
			  "channel %d unknown tx event type %d (data "
			  EFX_QWORD_FMT ")\n",
			  channel->channel, tx_ev_type,
			  EFX_QWORD_VAL(*event));
		break;
	}
}

static int
efx_ef10_handle_driver_event(struct efx_channel *channel,
			     efx_qword_t *event, int budget)
{
	struct efx_nic *efx = channel->efx;
	int subcode;

	subcode = EFX_QWORD_FIELD(*event, ESF_DZ_DRV_SUB_CODE);

	switch (subcode) {
	case ESE_DZ_DRV_TIMER_EV:
	case ESE_DZ_DRV_WAKE_UP_EV:
#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
		return efx_dl_handle_event(&efx->dl_nic, event, budget);
#endif
#endif
		break;
	case ESE_DZ_DRV_START_UP_EV:
		/* event queue init complete. ok. */
		break;
	default:
		netif_err(efx, hw, efx->net_dev,
			  "channel %d unknown driver event type %d"
			  " (data " EFX_QWORD_FMT ")\n",
			  channel->channel, subcode,
			  EFX_QWORD_VAL(*event));
		return -EINVAL;
	}
	return 0;
}

static bool efx_ef10_port_process_event(struct efx_channel *channel,
					efx_qword_t *event, int *rc, int budget)
{
	struct efx_nic *efx = channel->efx;
	int code = EFX_QWORD_FIELD(*event, MCDI_EVENT_CODE);

	switch (code) {
	case MCDI_EVENT_CODE_SENSOREVT:
		efx_mcdi_sensor_event(efx, event);
		return true;
	}

	return false;
}

static void efx_ef10_handle_driver_generated_event(struct efx_channel *channel,
						   efx_qword_t *event)
{
	struct efx_nic *efx = channel->efx;
	struct efx_rx_queue *rx_queue;
	u32 subcode;

	subcode = EFX_QWORD_FIELD(*event, EFX_DWORD_0);

	switch (EFX_EF10_DRVGEN_CODE(subcode)) {
	case EFX_EF10_TEST:
		channel->event_test_cpu = raw_smp_processor_id();
		break;
	case EFX_EF10_REFILL:
		/* The queue must be empty, so we won't receive any rx
		 * events, so efx_process_channel() won't refill the
		 * queue. Refill it here
		 */
		efx_for_each_channel_rx_queue(rx_queue, channel)
			if (EFX_EF10_DRVGEN_DATA(subcode) ==
			    efx_rx_queue_index(rx_queue))
				efx_fast_push_rx_descriptors(rx_queue, true);
		break;
#ifdef EFX_NOT_UPSTREAM
	case EFX_EF10_RERING_RX_DOORBELL:
		/* For workaround 59975 */
		efx_for_each_channel_rx_queue(rx_queue, channel)
			if (EFX_EF10_DRVGEN_DATA(subcode) ==
			    efx_rx_queue_index(rx_queue))
				_efx_ef10_rx_write(rx_queue);
		break;
#endif
	default:
		netif_err(efx, hw, efx->net_dev,
			  "channel %d unknown driver event type %u"
			  " (data " EFX_QWORD_FMT ")\n",
			  channel->channel, (unsigned int) subcode,
			  EFX_QWORD_VAL(*event));
	}
}

static int efx_ef10_ev_process(struct efx_channel *channel, int quota)
{
	struct efx_nic *efx = channel->efx;
	efx_qword_t cacheline[L1_CACHE_BYTES / sizeof(efx_qword_t)];
	efx_qword_t event, *p_event, *cl_base, *old_cl_base = NULL;
	bool fresh = false;
	unsigned int read_ptr, cr_ptr;
	int ev_code;
	int spent = 0;
	int rc;

	read_ptr = channel->eventq_read_ptr;

	EFX_WARN_ON_ONCE_PARANOID(!IS_ALIGNED((uintptr_t)channel->eventq.addr,
					      L1_CACHE_BYTES));

	for (;;) {
		p_event = efx_event(channel, read_ptr);
		/* We read a whole cacheline at a time, to minimise cache
		 * eviction when hardware and software are in the same
		 * cacheline and DDIO is not present
		 */
		cl_base = (efx_qword_t *)round_down((uintptr_t)p_event, L1_CACHE_BYTES);
		if (cl_base != old_cl_base) {
			/* memcpy could conceivably copy in bytes, which could
			 * lead to holes if the NIC is writing at the same time.
			 * So use open-coded qword copy
			 */
			for (cr_ptr = p_event - cl_base;
			     cr_ptr < ARRAY_SIZE(cacheline); cr_ptr++)
				cacheline[cr_ptr] = cl_base[cr_ptr];
			old_cl_base = cl_base;
			fresh = true;
		}
		event = cacheline[p_event - cl_base];

		if (!efx_event_present(&event)) {
			if (fresh)
				break;
			/* re-read the cacheline, in case the NIC wrote more
			 * events while we were handling the ones we read before
			 */
			old_cl_base = NULL;
			continue;
		}
		fresh = false;

		EFX_SET_QWORD(*p_event);

		++read_ptr;

		ev_code = EFX_QWORD_FIELD(event, ESF_DZ_EV_CODE);

		netif_vdbg(efx, drv, efx->net_dev,
			   "processing event on %d " EFX_QWORD_FMT "\n",
			   channel->channel, EFX_QWORD_VAL(event));

		switch (ev_code) {
		case ESE_DZ_EV_CODE_RX_EV:
			spent += efx_ef10_handle_rx_event(channel, &event);
			if (spent >= quota) {
				/* XXX can we split a merged event to
				 * avoid going over-quota?
				 */
				spent = quota;
				goto out;
			}
			break;
		case ESE_DZ_EV_CODE_TX_EV:
			efx_ef10_handle_tx_event(channel, &event);
			break;
		case ESE_DZ_EV_CODE_MCDI_EV:
			rc = 0;
			if (!efx_mcdi_process_event(channel, &event) &&
			    !efx_mcdi_port_process_event_common(channel,
						&event, &rc, quota - spent) &&
			    !efx_mcdi_port_process_event(channel, &event,
							 &rc, quota - spent) &&
			    !efx_ef10_port_process_event(channel, &event,
							 &rc, quota - spent))
				netif_err(efx, hw, efx->net_dev,
					  "Unknown MCDI event " EFX_QWORD_FMT "\n",
					  EFX_QWORD_VAL(event));

			if (rc > 0)
				spent += rc;
			else if (rc < 0)
				spent++;
			if (spent >= quota)
				goto out;
			break;
		case ESE_DZ_EV_CODE_DRIVER_EV:
			rc = efx_ef10_handle_driver_event(channel, &event,
							  quota - spent);
			if (rc > 0)
				spent += rc;
			else if (rc < 0)
				spent++;
			if (spent >= quota)
				goto out;
			break;
		case EFX_EF10_DRVGEN_EV:
			efx_ef10_handle_driver_generated_event(channel, &event);
			break;
		default:
			netif_err(efx, hw, efx->net_dev,
				  "channel %d unknown event type %d"
				  " (data " EFX_QWORD_FMT ")\n",
				  channel->channel, ev_code,
				  EFX_QWORD_VAL(event));
		}
	}

out:
	channel->eventq_read_ptr = read_ptr;
	return spent;
}

static bool efx_ef10_ev_mcdi_pending(struct efx_channel *channel)
{
	unsigned int read_ptr;
	efx_qword_t event;
	int ev_code;

	read_ptr = channel->eventq_read_ptr;
	for (;;) {
		event = *efx_event(channel, read_ptr++);
		if (!efx_event_present(&event))
			return false;
		ev_code = EFX_QWORD_FIELD(event, ESF_DZ_EV_CODE);
		if (ev_code == ESE_DZ_EV_CODE_MCDI_EV)
			return true;
	}
}

static void efx_ef10_ev_read_ack(struct efx_channel *channel)
{
	struct efx_nic *efx = channel->efx;
	efx_dword_t rptr;

	if (EFX_EF10_WORKAROUND_35388(efx)) {
		BUILD_BUG_ON(EFX_MIN_EVQ_SIZE <
			     (1 << ERF_DD_EVQ_IND_RPTR_WIDTH));
		BUILD_BUG_ON(EFX_MAX_EVQ_SIZE >
			     (1 << 2 * ERF_DD_EVQ_IND_RPTR_WIDTH));

		EFX_POPULATE_DWORD_2(rptr, ERF_DD_EVQ_IND_RPTR_FLAGS,
				     EFE_DD_EVQ_IND_RPTR_FLAGS_HIGH,
				     ERF_DD_EVQ_IND_RPTR,
				     (channel->eventq_read_ptr &
				      channel->eventq_mask) >>
				     ERF_DD_EVQ_IND_RPTR_WIDTH);
		efx_writed_page(efx, &rptr, ER_DD_EVQ_INDIRECT,
				channel->channel);
		EFX_POPULATE_DWORD_2(rptr, ERF_DD_EVQ_IND_RPTR_FLAGS,
				     EFE_DD_EVQ_IND_RPTR_FLAGS_LOW,
				     ERF_DD_EVQ_IND_RPTR,
				     channel->eventq_read_ptr &
				     ((1 << ERF_DD_EVQ_IND_RPTR_WIDTH) - 1));
		efx_writed_page(efx, &rptr, ER_DD_EVQ_INDIRECT,
				channel->channel);
	} else {
		EFX_POPULATE_DWORD_1(rptr, ERF_DZ_EVQ_RPTR,
				     channel->eventq_read_ptr &
				     channel->eventq_mask);
		efx_writed_page(efx, &rptr, ER_DZ_EVQ_RPTR, channel->channel);
	}
}

static void efx_ef10_ev_test_generate(struct efx_channel *channel)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_DRIVER_EVENT_IN_LEN);
	struct efx_nic *efx = channel->efx;
	efx_qword_t event;
	int rc;

	EFX_POPULATE_QWORD_2(event,
			     ESF_DZ_EV_CODE, EFX_EF10_DRVGEN_EV,
			     ESF_DZ_EV_DATA, EFX_EF10_TEST);

	MCDI_SET_DWORD(inbuf, DRIVER_EVENT_IN_EVQ, channel->channel);

	/* MCDI_SET_QWORD is not appropriate here since EFX_POPULATE_* has
	 * already swapped the data to little-endian order.
	 */
	memcpy(MCDI_PTR(inbuf, DRIVER_EVENT_IN_DATA), &event.u64[0],
	       sizeof(efx_qword_t));

	rc = efx_mcdi_rpc(efx, MC_CMD_DRIVER_EVENT, inbuf, sizeof(inbuf),
			  NULL, 0, NULL);
	if (rc && (rc != -ENETDOWN))
		goto fail;

	return;

fail:
	WARN_ON(true);
	netif_err(efx, hw, efx->net_dev, "%s: failed rc=%d\n", __func__, rc);
}

static int efx_ef10_fini_dmaq(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	/* If the MC has just rebooted, the TX/RX queues will have already been
	 * torn down, but efx->active_queues needs to be set to zero.
	 */
	if (nic_data->must_realloc_vis) {
		atomic_set(&efx->active_queues, 0);
		return 0;
	}

	return efx_fini_dmaq(efx);
}

static void efx_ef10_prepare_flr(struct efx_nic *efx)
{
	atomic_set(&efx->active_queues, 0);
}

static int efx_ef10_vport_set_mac_address(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	u8 mac_old[ETH_ALEN];
	int rc, rc2;

	/* Only reconfigure a PF-created vport */
	if (is_zero_ether_addr(nic_data->vport_mac))
		return 0;

	efx_device_detach_sync(efx);
	efx_net_stop(efx->net_dev);
	down_write(&efx->filter_sem);
	efx_mcdi_filter_table_down(efx);
	efx_mcdi_filter_table_fini(efx);
	up_write(&efx->filter_sem);

	rc = efx_ef10_vadaptor_free(efx, efx->vport.vport_id);
	if (rc)
		goto restore_filters;

	ether_addr_copy(mac_old, nic_data->vport_mac);
	rc = efx_ef10_vport_del_mac(efx, efx->vport.vport_id,
				    nic_data->vport_mac);
	if (rc)
		goto restore_vadaptor;

	rc = efx_ef10_vport_add_mac(efx, efx->vport.vport_id,
				    efx->net_dev->dev_addr);
	if (!rc) {
		ether_addr_copy(nic_data->vport_mac, efx->net_dev->dev_addr);
	} else {
		rc2 = efx_ef10_vport_add_mac(efx, efx->vport.vport_id, mac_old);
		if (rc2) {
			/* Failed to add original MAC, so clear vport_mac */
			eth_zero_addr(nic_data->vport_mac);
			goto reset_nic;
		}
	}

restore_vadaptor:
	rc2 = efx_ef10_vadaptor_alloc(efx, efx->vport.vport_id);
	if (rc2)
		goto reset_nic;
restore_filters:
	mutex_lock(&efx->mac_lock);
	down_write(&efx->filter_sem);
	rc2 = efx_ef10_filter_table_init(efx);
	if (!rc2)
		rc2 = efx_ef10_filter_table_up(efx);
	up_write(&efx->filter_sem);
	mutex_unlock(&efx->mac_lock);
	if (rc2)
		goto reset_nic;

	rc2 = efx_net_open(efx->net_dev);
	if (rc2)
		goto reset_nic;

	efx_device_attach_if_not_resetting(efx);

	return rc;

reset_nic:
	netif_err(efx, drv, efx->net_dev,
		  "Failed to restore when changing MAC address - scheduling reset\n");
	efx_schedule_reset(efx, RESET_TYPE_DATAPATH);

	return rc ? rc : rc2;
}

static int efx_ef10_set_mac_address(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_VADAPTOR_SET_MAC_IN_LEN);
	bool was_enabled = efx->port_enabled;
	int rc;

#ifdef CONFIG_SFC_SRIOV
	/* If this function is a VF and we have access to the parent PF,
	 * then use the PF control path to attempt to change the VF MAC address.
	 */
	if (efx->pci_dev->is_virtfn && efx->pci_dev->physfn) {
		struct efx_nic *efx_pf = pci_get_drvdata(efx->pci_dev->physfn);
		struct efx_ef10_nic_data *nic_data = efx->nic_data;
		u8 mac[ETH_ALEN];
		bool reset;

		ether_addr_copy(mac, efx->net_dev->dev_addr);

		rc = efx_ef10_sriov_set_vf_mac(efx_pf, nic_data->vf_index,
					       mac, &reset);
		if (!rc)
			return 0;

		netif_dbg(efx, drv, efx->net_dev,
			  "Updating VF mac via PF failed (%d), %s\n",
			  rc,
			  reset ? "resulting in reset; aborting" :
				  "setting directly");
		if (reset)
			return rc;
	}
#endif

	ether_addr_copy(MCDI_PTR(inbuf, VADAPTOR_SET_MAC_IN_MACADDR),
			efx->net_dev->dev_addr);
	MCDI_SET_DWORD(inbuf, VADAPTOR_SET_MAC_IN_UPSTREAM_PORT_ID,
		       efx->vport.vport_id);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_VADAPTOR_SET_MAC, inbuf,
				sizeof(inbuf), NULL, 0, NULL);

	if (!rc) {
		down_write(&efx->filter_sem);
		efx_mcdi_filter_table_restore(efx);
		up_write(&efx->filter_sem);
	} else if (rc == -EBUSY) {

		/* VADAPTOR_SET_MAC without tearing down queues and
		 * filters not allowed by firmware, try again after
		 * tearing down the queues and filters. This path will
		 * fail in the presence on Onload stack
		 */

		efx_device_detach_sync(efx);
		efx_net_stop(efx->net_dev);

		mutex_lock(&efx->mac_lock);
		down_write(&efx->filter_sem);
		efx_mcdi_filter_table_down(efx);
		efx_ef10_filter_table_fini(efx);

		rc = efx_mcdi_rpc_quiet(efx, MC_CMD_VADAPTOR_SET_MAC, inbuf,
					sizeof(inbuf), NULL, 0, NULL);

		efx_ef10_filter_table_init(efx);
		efx_ef10_filter_table_up(efx);
		up_write(&efx->filter_sem);
		mutex_unlock(&efx->mac_lock);

		if (was_enabled)
			efx_net_open(efx->net_dev);
		efx_device_attach_if_not_resetting(efx);
	}

	if (rc == -EPERM) {
		netif_err(efx, drv, efx->net_dev,
			  "Cannot change MAC address; use sfboot to enable mac-spoofing on this interface\n");
	} else if (rc == -ENOSYS && !efx_ef10_is_vf(efx)) {
		/* If the active MCFW does not support MC_CMD_VADAPTOR_SET_MAC
		 * fall-back to the method of changing the MAC address on the
		 * vport.  This only applies to PFs because such versions of
		 * MCFW do not support VFs.
		 */
		rc = efx_ef10_vport_set_mac_address(efx);
	} else if (rc) {
		efx_mcdi_display_error(efx, MC_CMD_VADAPTOR_SET_MAC,
				       sizeof(inbuf), NULL, 0, rc);
	}

	return rc;
}


static int efx_ef10_mac_reconfigure(struct efx_nic *efx, bool mtu_only)
{
	int rc;
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	WARN_ON(!mutex_is_locked(&efx->mac_lock));

	efx_mcdi_filter_sync_rx_mode(efx);

	if (mtu_only &&
	    efx_ef10_has_cap(nic_data->datapath_caps, SET_MAC_ENHANCED))
		return efx_mcdi_set_mtu(efx);

	rc = efx_mcdi_set_mac(efx);
	if (rc == -EPERM && efx_ef10_is_vf(efx))
		return 0;

	return rc;
}

static unsigned int efx_ef10_mcdi_rpc_timeout(struct efx_nic *efx,
					      unsigned int cmd)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	switch (cmd) {
	case MC_CMD_POLL_BIST:
	case MC_CMD_NVRAM_ERASE:
	case MC_CMD_LICENSING_V3:
	case MC_CMD_NVRAM_UPDATE_FINISH:
		/* Potentially longer running commands. */
		if (efx_ef10_has_cap(nic_data->datapath_caps2,
				     NVRAM_UPDATE_REPORT_VERIFY_RESULT))
			return MCDI_RPC_LONG_TIMEOUT;
		fallthrough;
	default:
		/* Some things take longer shortly after a reset. */
		if (time_before(jiffies,
				efx->last_reset + MCDI_RPC_POST_RST_TIME))
			return MCDI_RPC_POST_RST_TIME;
		return MCDI_RPC_TIMEOUT;
	}
}

static int efx_ef10_start_bist(struct efx_nic *efx, u32 bist_type)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_START_BIST_IN_LEN);

	MCDI_SET_DWORD(inbuf, START_BIST_IN_TYPE, bist_type);
	return efx_mcdi_rpc(efx, MC_CMD_START_BIST, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

/* MC BISTs follow a different poll mechanism to phy BISTs.
 * The BIST is done in the poll handler on the MC, and the MCDI command
 * will block until the BIST is done.
 */
static int efx_ef10_poll_bist(struct efx_nic *efx)
{
	int rc;
	MCDI_DECLARE_BUF(outbuf, MC_CMD_POLL_BIST_OUT_LEN);
	size_t outlen;
	u32 result;

	rc = efx_mcdi_rpc(efx, MC_CMD_POLL_BIST, NULL, 0,
			   outbuf, sizeof(outbuf), &outlen);
	if (rc != 0)
		return rc;

	if (outlen < MC_CMD_POLL_BIST_OUT_LEN)
		return -EIO;

	result = MCDI_DWORD(outbuf, POLL_BIST_OUT_RESULT);
	switch (result) {
	case MC_CMD_POLL_BIST_PASSED:
		netif_dbg(efx, hw, efx->net_dev, "BIST passed.\n");
		return 0;
	case MC_CMD_POLL_BIST_TIMEOUT:
		netif_err(efx, hw, efx->net_dev, "BIST timed out\n");
		return -EIO;
	case MC_CMD_POLL_BIST_FAILED:
		netif_err(efx, hw, efx->net_dev, "BIST failed.\n");
		return -EIO;
	default:
		netif_err(efx, hw, efx->net_dev,
			  "BIST returned unknown result %u", result);
		return -EIO;
	}
}

static int efx_ef10_run_bist(struct efx_nic *efx, u32 bist_type)
{
	int rc;

	netif_dbg(efx, drv, efx->net_dev, "starting BIST type %u\n", bist_type);

	rc = efx_ef10_start_bist(efx, bist_type);
	if (rc != 0)
		return rc;

	return efx_ef10_poll_bist(efx);
}

static int
efx_ef10_test_chip(struct efx_nic *efx, struct efx_self_tests *tests)
{
	int rc, rc2;

	efx_reset_down(efx, RESET_TYPE_WORLD);

	rc = efx_mcdi_rpc(efx, MC_CMD_ENABLE_OFFLINE_BIST,
			  NULL, 0, NULL, 0, NULL);
	if (rc != 0)
		goto out;

	tests->memory = efx_ef10_run_bist(efx, MC_CMD_MC_MEM_BIST) ? -1 : 1;
	tests->registers = efx_ef10_run_bist(efx, MC_CMD_REG_BIST) ? -1 : 1;

	rc = efx_mcdi_reset(efx, RESET_TYPE_WORLD);

out:
	if (rc == -EPERM)
		rc = 0;
	rc2 = efx_reset_up(efx, RESET_TYPE_WORLD, rc == 0);
	return rc ? rc : rc2;
}

#ifdef CONFIG_SFC_MTD

struct efx_ef10_nvram_type_info {
	u16 type, type_mask;
	u8 port;
	const char *name;
};

static const struct efx_ef10_nvram_type_info efx_ef10_nvram_types[] = {
#define NAME(name) \
	(BUILD_BUG_ON_ZERO(sizeof(name) > NVRAM_PARTITION_NAME_MAX_LEN) + (name))

	{ NVRAM_PARTITION_TYPE_MC_FIRMWARE,	   0,    0, NAME("sfc_mcfw") },
	{ NVRAM_PARTITION_TYPE_MC_FIRMWARE_BACKUP, 0,    0, NAME("sfc_mcfw_backup") },
	{ NVRAM_PARTITION_TYPE_EXPANSION_ROM,	   0,    0, NAME("sfc_exp_rom") },
	{ NVRAM_PARTITION_TYPE_STATIC_CONFIG,	   0,    0, NAME("sfc_static_cfg") },
	{ NVRAM_PARTITION_TYPE_DYNAMIC_CONFIG,	   0,    0, NAME("sfc_dynamic_cfg") },
	{ NVRAM_PARTITION_TYPE_EXPROM_CONFIG_PORT0, 0,   0, NAME("sfc_exp_rom_cfg") },
	{ NVRAM_PARTITION_TYPE_EXPROM_CONFIG_PORT1, 0,   1, NAME("sfc_exp_rom_cfg") },
	{ NVRAM_PARTITION_TYPE_EXPROM_CONFIG_PORT2, 0,   2, NAME("sfc_exp_rom_cfg") },
	{ NVRAM_PARTITION_TYPE_EXPROM_CONFIG_PORT3, 0,   3, NAME("sfc_exp_rom_cfg") },
	{ NVRAM_PARTITION_TYPE_LICENSE,		   0,    0, NAME("sfc_license") },
	{ NVRAM_PARTITION_TYPE_PHY_MIN,		   0xff, 0, NAME("sfc_phy_fw") },
	{ NVRAM_PARTITION_TYPE_FPGA,		   0,    0, NAME("sfc_fpga") },
	{ NVRAM_PARTITION_TYPE_FPGA_BACKUP,	   0,    0, NAME("sfc_fpgadiag") },
	{ NVRAM_PARTITION_TYPE_FC_FIRMWARE,	   0,    0, NAME("sfc_fcfw") },
	{ NVRAM_PARTITION_TYPE_MUM_FIRMWARE,	   0,    0, NAME("sfc_mumfw") },
	{ NVRAM_PARTITION_TYPE_EXPANSION_UEFI,	   0,    0, NAME("sfc_uefi") },
	{ NVRAM_PARTITION_TYPE_DYNCONFIG_DEFAULTS, 0,    0, NAME("sfc_dynamic_cfg_dflt") },
	{ NVRAM_PARTITION_TYPE_ROMCONFIG_DEFAULTS, 0,    0, NAME("sfc_exp_rom_cfg_dflt") },
	{ NVRAM_PARTITION_TYPE_STATUS,		   0,    0, NAME("sfc_status") },
	{ NVRAM_PARTITION_TYPE_BUNDLE,		   0,    0, NAME("sfc_bundle") },
	{ NVRAM_PARTITION_TYPE_BUNDLE_METADATA,    0,    0, NAME("sfc_bundle_metadata") }

#undef NAME
};
#define EF10_NVRAM_PARTITION_COUNT	ARRAY_SIZE(efx_ef10_nvram_types)

static int efx_ef10_mtd_probe_partition(struct efx_nic *efx,
					struct efx_mtd_partition *part,
					unsigned int type,
					unsigned long *found)
{
	const struct efx_ef10_nvram_type_info *info;
	size_t size, erase_size, write_size;
	int type_idx = 0;
	bool protected;
	int rc;

	for (type_idx = 0; ; type_idx++) {
		if (type_idx == EF10_NVRAM_PARTITION_COUNT)
			return -ENODEV;
		info = efx_ef10_nvram_types + type_idx;
		if ((type & ~info->type_mask) == info->type)
			break;
	}
	if (info->port != efx_port_num(efx))
		return -ENODEV;

	rc = efx_mcdi_nvram_info(efx, type, &size, &erase_size, &write_size,
				 &protected);
	if (rc)
		return rc;
	if (protected && !efx_allow_nvconfig_writes &&
	    (type != NVRAM_PARTITION_TYPE_DYNCONFIG_DEFAULTS &&
	     type != NVRAM_PARTITION_TYPE_ROMCONFIG_DEFAULTS))
		return -ENODEV; /* hide it */
	if (protected)
		erase_size = 0;	/* Protected partitions are read-only */

	/* If we've already exposed a partition of this type, hide this
	 * duplicate.  All operations on MTDs are keyed by the type anyway,
	 * so we can't act on the duplicate.
	 */
	if (__test_and_set_bit(type_idx, found))
		return -EEXIST;

	part->nvram_type = type;

	rc = efx_mcdi_nvram_metadata(efx, type, &part->fw_subtype, NULL, NULL,
				     0);
	if (rc) {
		/* The metadata command fails if the dynamic config is empty.
		 * In this situation we want to block a firmware upgrade until
		 * the problem has been fixed.
		 */
		if (type == NVRAM_PARTITION_TYPE_MC_FIRMWARE)
			part->fw_subtype = 0xff;
		else
			part->fw_subtype = 0;
	}

	part->dev_type_name = "EF10 NVRAM manager";
	part->type_name = info->name;

	part->mtd.type = MTD_NORFLASH;
	part->mtd.flags = MTD_CAP_NORFLASH;
	part->mtd.size = size;
	part->mtd.erasesize = erase_size;
	if (!erase_size)
		part->mtd.flags |= MTD_NO_ERASE;

	part->mtd.writesize = write_size;

	return 0;
}

static int efx_ef10_mtd_probe(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_NVRAM_PARTITIONS_OUT_LENMAX);
	DECLARE_BITMAP(found, EF10_NVRAM_PARTITION_COUNT) = { 0 };
	struct efx_mtd_partition *parts;
	size_t outlen, n_parts_total, i, n_parts;
	unsigned int type;
	int rc;

	ASSERT_RTNL();

	BUILD_BUG_ON(MC_CMD_NVRAM_PARTITIONS_IN_LEN != 0);
	rc = efx_mcdi_rpc(efx, MC_CMD_NVRAM_PARTITIONS, NULL, 0,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;
	if (outlen < MC_CMD_NVRAM_PARTITIONS_OUT_LENMIN)
		return -EIO;

	n_parts_total = MCDI_DWORD(outbuf, NVRAM_PARTITIONS_OUT_NUM_PARTITIONS);
	if (n_parts_total >
	    MCDI_VAR_ARRAY_LEN(outlen, NVRAM_PARTITIONS_OUT_TYPE_ID))
		return -EIO;

	parts = kcalloc(n_parts_total, sizeof(*parts), GFP_KERNEL);
	if (!parts)
		return -ENOMEM;

	n_parts = 0;
	for (i = 0; i < n_parts_total; i++) {
		type = MCDI_ARRAY_DWORD(outbuf, NVRAM_PARTITIONS_OUT_TYPE_ID,
					i);
		rc = efx_ef10_mtd_probe_partition(efx, &parts[n_parts], type,
						  found);
		if (rc == -EEXIST || rc == -ENODEV)
			continue;
		if (rc)
			goto fail_free;
		n_parts++;
	}

	/* Once we've passed parts to efx_mtd_add it becomes responsible for
	 * freeing it.
	 */
	return efx_mtd_add(efx, parts, n_parts);

fail_free:
	kfree(parts);
	return rc;
}

#endif /* CONFIG_SFC_MTD */

#ifdef CONFIG_SFC_PTP

static void efx_ef10_ptp_write_host_time(struct efx_nic *efx, u32 host_time)
{
	_efx_writed(efx, cpu_to_le32(host_time), ER_DZ_MC_DB_LWRD);
}
#endif /* CONFIG_SFC_PTP */

#ifdef EFX_NOT_UPSTREAM

int efx_ef10_update_keys(struct efx_nic *efx,
			 struct efx_update_license2 *key_stats)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_LICENSING_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_LICENSING_OUT_LEN);
	int rc;

	MCDI_SET_DWORD(inbuf, LICENSING_IN_OP,
		       MC_CMD_LICENSING_IN_OP_UPDATE_LICENSE);
	rc = efx_mcdi_rpc(efx, MC_CMD_LICENSING, inbuf, sizeof(inbuf),
			  NULL, 0, NULL);
	if (rc)
		return rc;

	MCDI_SET_DWORD(inbuf, LICENSING_IN_OP,
		       MC_CMD_LICENSING_IN_OP_GET_KEY_STATS);
	rc = efx_mcdi_rpc(efx, MC_CMD_LICENSING, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), NULL);
	if (rc)
		return rc;

	key_stats->valid_keys =
		MCDI_DWORD(outbuf, LICENSING_OUT_VALID_APP_KEYS);
	key_stats->invalid_keys =
		MCDI_DWORD(outbuf, LICENSING_OUT_INVALID_APP_KEYS);
	key_stats->blacklisted_keys =
		MCDI_DWORD(outbuf, LICENSING_OUT_BLACKLISTED_APP_KEYS);
	key_stats->unverifiable_keys =
		MCDI_DWORD(outbuf, LICENSING_OUT_UNVERIFIABLE_APP_KEYS);
	key_stats->wrong_node_keys =
		MCDI_DWORD(outbuf, LICENSING_OUT_WRONG_NODE_APP_KEYS);
	return 0;
}

int efx_ef10_licensed_app_state(struct efx_nic *efx,
				struct efx_licensed_app_state *app_state)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_LICENSED_APP_STATE_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_LICENSED_APP_STATE_OUT_LEN);
	int rc;

	MCDI_SET_DWORD(inbuf, LICENSING_IN_OP,MC_CMD_GET_LICENSED_APP_STATE);
	MCDI_SET_DWORD(inbuf, GET_LICENSED_APP_STATE_IN_APP_ID,
		       app_state->app_id);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_LICENSED_APP_STATE, inbuf,
			  sizeof(inbuf), outbuf, sizeof(outbuf), NULL);
	if (!rc)
		app_state->state =
			MCDI_DWORD(outbuf, GET_LICENSED_APP_STATE_OUT_STATE);
	return rc;
}

#endif /* EFX_NOT_UPSTREAM */

#ifdef CONFIG_SFC_PTP
static int efx_ef10_rx_enable_timestamping(struct efx_channel *channel,
					   bool temp)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_TIME_EVENT_SUBSCRIBE_LEN);
	int rc;
	u32 qid;

	if (channel->sync_events_state == SYNC_EVENTS_REQUESTED ||
	    channel->sync_events_state == SYNC_EVENTS_VALID ||
	    (temp && channel->sync_events_state == SYNC_EVENTS_DISABLED))
		return 0;
	channel->sync_events_state = SYNC_EVENTS_REQUESTED;

	/* Try to subscribe with sync status reporting enabled. If this fails,
	 * fallback to using the old scheme */
	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_TIME_EVENT_SUBSCRIBE);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);
	qid = channel->channel |
	      (1 << MC_CMD_PTP_IN_TIME_EVENT_SUBSCRIBE_REPORT_SYNC_STATUS_LBN);
	MCDI_SET_DWORD(inbuf, PTP_IN_TIME_EVENT_SUBSCRIBE_QUEUE, qid);

	rc = efx_mcdi_rpc(channel->efx, MC_CMD_PTP,
			  inbuf, sizeof(inbuf), NULL, 0, NULL);
	if (rc == -ERANGE) {
		MCDI_SET_DWORD(inbuf, PTP_IN_TIME_EVENT_SUBSCRIBE_QUEUE,
			       channel->channel);

		rc = efx_mcdi_rpc(channel->efx, MC_CMD_PTP,
				  inbuf, sizeof(inbuf), NULL, 0, NULL);
	}

	if (rc != 0)
		channel->sync_events_state = temp ? SYNC_EVENTS_QUIESCENT :
						    SYNC_EVENTS_DISABLED;

	return rc;
}

static int efx_ef10_rx_disable_timestamping(struct efx_channel *channel,
					    bool temp)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PTP_IN_TIME_EVENT_UNSUBSCRIBE_LEN);
	int rc;

	if (channel->sync_events_state == SYNC_EVENTS_DISABLED ||
	    (temp && channel->sync_events_state == SYNC_EVENTS_QUIESCENT))
		return 0;
	if (channel->sync_events_state == SYNC_EVENTS_QUIESCENT) {
		channel->sync_events_state = SYNC_EVENTS_DISABLED;
		return 0;
	}
	channel->sync_events_state = temp ? SYNC_EVENTS_QUIESCENT :
					    SYNC_EVENTS_DISABLED;

	MCDI_SET_DWORD(inbuf, PTP_IN_OP, MC_CMD_PTP_OP_TIME_EVENT_UNSUBSCRIBE);
	MCDI_SET_DWORD(inbuf, PTP_IN_PERIPH_ID, 0);
	MCDI_SET_DWORD(inbuf, PTP_IN_TIME_EVENT_UNSUBSCRIBE_CONTROL,
		       MC_CMD_PTP_IN_TIME_EVENT_UNSUBSCRIBE_SINGLE);
	MCDI_SET_DWORD(inbuf, PTP_IN_TIME_EVENT_UNSUBSCRIBE_QUEUE,
		       channel->channel);

	rc = efx_mcdi_rpc(channel->efx, MC_CMD_PTP,
			  inbuf, sizeof(inbuf), NULL, 0, NULL);

	return rc;
}

static int efx_ef10_ptp_set_ts_sync_events(struct efx_nic *efx, bool en,
					   bool temp)
{
	int (*set)(struct efx_channel *channel, bool temp);
	struct efx_channel *channel;
	int rc;

	set = en ?
	      efx_ef10_rx_enable_timestamping :
	      efx_ef10_rx_disable_timestamping;

	if (efx_ptp_uses_separate_channel(efx)) {
		channel = efx_ptp_channel(efx);
		if (channel) {
			rc = set(channel, temp);
			if (en && rc != 0) {
				efx_ef10_ptp_set_ts_sync_events(efx, false, temp);
				return rc;
			}
		}
	}
	else {
		efx_for_each_channel(channel, efx) {
			rc = set(channel, temp);
			if (en && rc != 0) {
				efx_ef10_ptp_set_ts_sync_events(efx, false, temp);
				return rc;
			}
		}
	}

	return 0;
}

static int efx_ef10_ptp_set_ts_config(struct efx_nic *efx,
				      struct kernel_hwtstamp_config *init)
{
	int rc;

	switch (init->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		efx_ef10_ptp_set_ts_sync_events(efx, false, false);
		/* if TX timestamping is still requested then leave PTP on */
		return efx_ptp_change_mode(efx,
					   init->tx_type != HWTSTAMP_TX_OFF, 0);
	case HWTSTAMP_FILTER_ALL:
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		init->rx_filter = HWTSTAMP_FILTER_ALL;
		rc = efx_ptp_change_mode(efx, true, MC_CMD_PTP_MODE_V2);
		if (!rc)
			rc = efx_ef10_ptp_set_ts_sync_events(efx, true, false);
		if (rc)
			efx_ptp_change_mode(efx, false, 0);
		return rc;
	default:
		return -ERANGE;
	}
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_ID)
static int efx_ef10_get_phys_port_id(struct efx_nic *efx,
				     struct netdev_phys_item_id *ppid)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	if (!is_valid_ether_addr(nic_data->port_id))
		return -EOPNOTSUPP;

	ppid->id_len = ETH_ALEN;
	memcpy(ppid->id, nic_data->port_id, ppid->id_len);

	return 0;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
/* We rely on the MCDI wiping out our TX rings if it made any changes to the
 * ports table, ensuring that any TSO descriptors that were made on a now-
 * removed tunnel port will be blown away and won't break things when we try
 * to transmit them using the new ports table.
 */
static int efx_ef10_set_udp_tnl_ports(struct efx_nic *efx, bool unloading)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_LENMAX);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_OUT_LEN);
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	efx_dword_t flags_and_num_entries;
	size_t inlen, outlen, num_entries;
	bool will_reset = false;
	size_t i;
	int rc;

	WARN_ON(!mutex_is_locked(&nic_data->udp_tunnels_lock));

	nic_data->udp_tunnels_dirty = false;

	if (!efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE)) {
		efx_device_attach_if_not_resetting(efx);
		return 0;
	}

	BUILD_BUG_ON(ARRAY_SIZE(nic_data->udp_tunnels) >
		     MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_ENTRIES_MAXNUM);

	num_entries = 0;
	if (!unloading) {
		for (i = 0; i < ARRAY_SIZE(nic_data->udp_tunnels); ++i) {
			efx_dword_t entry;

			if (nic_data->udp_tunnels[i].type ==
			    TUNNEL_ENCAP_UDP_PORT_ENTRY_INVALID)
				continue;

			EFX_POPULATE_DWORD_2(entry,
				TUNNEL_ENCAP_UDP_PORT_ENTRY_UDP_PORT,
					ntohs(nic_data->udp_tunnels[i].port),
				TUNNEL_ENCAP_UDP_PORT_ENTRY_PROTOCOL,
					nic_data->udp_tunnels[i].type);
			*_MCDI_ARRAY_DWORD(inbuf,
				SET_TUNNEL_ENCAP_UDP_PORTS_IN_ENTRIES,
				num_entries++) = entry;
		}
	}

	/* Adding/removing a UDP tunnel can cause an MC reboot. We must
	 * prevent causing too many reboots in a second.
	 */
	efx->reset_count = 0;

	BUILD_BUG_ON((MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_NUM_ENTRIES_OFST -
		      MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_FLAGS_OFST) * 8 !=
		     EFX_WORD_1_LBN);
	BUILD_BUG_ON(MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_NUM_ENTRIES_LEN * 8 !=
		     EFX_WORD_1_WIDTH);
	EFX_POPULATE_DWORD_2(flags_and_num_entries,
			     MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_UNLOADING,
				!!unloading,
			     EFX_WORD_1, num_entries);
	*_MCDI_DWORD(inbuf, SET_TUNNEL_ENCAP_UDP_PORTS_IN_FLAGS) =
		flags_and_num_entries;

	inlen = MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_LEN(num_entries);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS,
				inbuf, inlen, outbuf, sizeof(outbuf), &outlen);
	if (rc == -EIO) {
		/* Most likely the MC rebooted due to another function also
		 * setting its tunnel port list. Mark the tunnel port list as
		 * dirty, so it will be pushed upon coming up from the reboot.
		 */
		nic_data->udp_tunnels_dirty = true;
		/* We detached earlier, expecting an MC reset to trigger a
	         * re-attach. If we haven't allocated event queues, we won't
		 * see the notification. In this case we're not using any
		 * resources, so we don't actually need to do any reset
		 * handling except to forget some resources and reattach.
		 */
		if (!unloading && !efx_net_allocated(efx->state)) {
			efx_device_attach_if_not_resetting(efx);
			efx_ef10_mcdi_reboot_detected(efx);
		}
		return 0;
	}

	if (rc) {
		/* expected not available on unprivileged functions */
		if (rc != -EPERM)
			netif_warn(efx, drv, efx->net_dev,
				   "Unable to set UDP tunnel ports; rc=%d.\n", rc);
	} else if (MCDI_DWORD(outbuf, SET_TUNNEL_ENCAP_UDP_PORTS_OUT_FLAGS) &
		   (1 << MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_OUT_RESETTING_LBN)) {
		netif_info(efx, drv, efx->net_dev,
			   "Rebooting MC due to UDP tunnel port list change\n");
		will_reset = true;
		if (unloading)
			/* Delay for the MC reset to complete. This will make
			 * unloading other functions a bit smoother. This is a
			 * race, but the other unload will work whichever way
			 * it goes, this just avoids an unnecessary error
			 * message.
			 */
			msleep(100);
	}
	/* We detached earlier, expecting an MC reset to trigger a
	 * re-attach.
	 * But, there are two cases this won't happen: If the MC tells
	 * us it's not going to reset, just reattach and carry on.
	 * Alternatively, if the MC tells us it will reset but we haven't
	 * allocated event queues, we won't see the notification. In this
	 * case we're not using any resources, so we don't actually
	 * need to do any reset handling except to forget some
	 * resources and reattach.
	 */
	if (!unloading) {
		if (will_reset && !efx_net_allocated(efx->state))
			efx_ef10_mcdi_reboot_detected(efx);
		if (!will_reset || !efx_net_allocated(efx->state))
			efx_device_attach_if_not_resetting(efx);
	}

	return rc;
}

static int efx_ef10_udp_tnl_push_ports(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	int rc = 0;

	mutex_lock(&nic_data->udp_tunnels_lock);
	if (nic_data->udp_tunnels_dirty) {
		/* Make sure all TX are stopped while we modify the table, else
		 * we might race against an efx_features_check().
		 * If we fail early in probe, we won't have set up our TXQs yet,
		 * in which case we don't need to do this (and trying wouldn't
		 * end well).  So check we've called register_netdevice().
		 */
		if (efx->net_dev->reg_state == NETREG_REGISTERED)
			efx_device_detach_sync(efx);
		rc = efx_ef10_set_udp_tnl_ports(efx, false);
	}
	mutex_unlock(&nic_data->udp_tunnels_lock);
	return rc;
}

static int efx_ef10_udp_tnl_set_port(struct net_device *dev,
				     unsigned int table, unsigned int entry,
				     struct udp_tunnel_info *ti)
{
	struct efx_nic *efx = efx_netdev_priv(dev);
	struct efx_ef10_nic_data *nic_data;
	int efx_tunnel_type, rc;

	if (ti->type == UDP_TUNNEL_TYPE_VXLAN)
		efx_tunnel_type = TUNNEL_ENCAP_UDP_PORT_ENTRY_VXLAN;
	else
		efx_tunnel_type = TUNNEL_ENCAP_UDP_PORT_ENTRY_GENEVE;

	nic_data = efx->nic_data;
	if (!efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE))
		return -EOPNOTSUPP;

	mutex_lock(&nic_data->udp_tunnels_lock);
	/* Make sure all TX are stopped while we modify the table, else
	 * we might race against an efx_features_check().
	 * If we fail early in probe, we won't have set up our TXQs yet,
	 * in which case we don't need to do this (and trying wouldn't
	 * end well).  So check we've called register_netdevice().
	 */
	if (efx_dev_registered(efx))
		efx_device_detach_sync(efx);
	nic_data->udp_tunnels[entry].type = efx_tunnel_type;
	nic_data->udp_tunnels[entry].port = ti->port;
	rc = efx_ef10_set_udp_tnl_ports(efx, false);
	mutex_unlock(&nic_data->udp_tunnels_lock);

	return rc;
}

/* Called under the TX lock with the TX queue running, hence no-one can be
 * in the middle of updating the UDP tunnels table.  However, they could
 * have tried and failed the MCDI, in which case they'll have set the dirty
 * flag before dropping their locks.
 */
static bool efx_ef10_udp_tnl_has_port(struct efx_nic *efx, __be16 port)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	size_t i;

	if (!efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE))
		return false;

	if (nic_data->udp_tunnels_dirty)
		/* SW table may not match HW state, so just assume we can't
		 * use any UDP tunnel offloads.
		 */
		return false;

	for (i = 0; i < ARRAY_SIZE(nic_data->udp_tunnels); ++i)
		if (nic_data->udp_tunnels[i].type !=
		    TUNNEL_ENCAP_UDP_PORT_ENTRY_INVALID &&
		    nic_data->udp_tunnels[i].port == port)
			return true;

	return false;
}

static int efx_ef10_udp_tnl_unset_port(struct net_device *dev,
				       unsigned int table __always_unused,
				       unsigned int entry,
				       struct udp_tunnel_info *ti __always_unused)
{
	struct efx_nic *efx = efx_netdev_priv(dev);
	struct efx_ef10_nic_data *nic_data;
	int rc;

	nic_data = efx->nic_data;

	mutex_lock(&nic_data->udp_tunnels_lock);
	/* Make sure all TX are stopped while we remove from the table, else we
	 * might race against an efx_features_check().
	 */
	efx_device_detach_sync(efx);
	nic_data->udp_tunnels[entry].type = TUNNEL_ENCAP_UDP_PORT_ENTRY_INVALID;
	nic_data->udp_tunnels[entry].port = 0;
	rc = efx_ef10_set_udp_tnl_ports(efx, false);
	mutex_unlock(&nic_data->udp_tunnels_lock);

	return rc;
}

static const struct udp_tunnel_nic_info efx_ef10_udp_tunnels = {
	.set_port	= efx_ef10_udp_tnl_set_port,
	.unset_port	= efx_ef10_udp_tnl_unset_port,
	.flags          = UDP_TUNNEL_NIC_INFO_MAY_SLEEP,
	.tables         = {
		{
			.n_entries = 16,
			.tunnel_types = UDP_TUNNEL_TYPE_VXLAN |
					UDP_TUNNEL_TYPE_GENEVE,
		},
	},
};
#else
/* We rely on the MCDI wiping out our TX rings if it made any changes to the
 * ports table, ensuring that any TSO descriptors that were made on a now-
 * removed tunnel port will be blown away and won't break things when we try
 * to transmit them using the new ports table.
 */
static int efx_ef10_set_udp_tnl_ports(struct efx_nic *efx, bool unloading)
	__releases(nic_data->udp_tunnels_lock)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_LENMAX);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_OUT_LEN);
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	bool adding[ARRAY_SIZE(nic_data->udp_tunnels)] = {0};
	size_t num_entries, inlen, outlen;
	struct efx_udp_tunnel *tnl;
	bool will_reset = false;
	bool done = false;
	size_t i;
	int rc;
	efx_dword_t flags_and_num_entries;

	if (!efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE)) {
		spin_unlock_bh(&nic_data->udp_tunnels_lock);
		return 0;
	}

	BUILD_BUG_ON(ARRAY_SIZE(nic_data->udp_tunnels) >
		     MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_ENTRIES_MAXNUM);

	if (!unloading) {
		if (nic_data->udp_tunnels_busy) {
			/* someone else is doing it for us */
			spin_unlock_bh(&nic_data->udp_tunnels_lock);
			return 0;
		}
	}
again:
	num_entries = 0;
	for (i = 0; i < ARRAY_SIZE(nic_data->udp_tunnels); ++i) {
		tnl = nic_data->udp_tunnels + i;
		if (!unloading && tnl->count && !tnl->removing && tnl->port) {
			efx_dword_t entry;

			adding[i] = true;
			EFX_POPULATE_DWORD_2(entry,
				TUNNEL_ENCAP_UDP_PORT_ENTRY_UDP_PORT,
					ntohs(tnl->port),
				TUNNEL_ENCAP_UDP_PORT_ENTRY_PROTOCOL, tnl->type);
			*_MCDI_ARRAY_DWORD(inbuf,
				SET_TUNNEL_ENCAP_UDP_PORTS_IN_ENTRIES,
				num_entries++) = entry;
		} else {
			adding[i] = false;
		}
	}
	nic_data->udp_tunnels_busy = true;
	spin_unlock_bh(&nic_data->udp_tunnels_lock);

	/* Adding/removing a UDP tunnel can cause an MC reboot. We must
	 * prevent causing too many reboots in a second.
	 */
	efx->reset_count = 0;

	BUILD_BUG_ON((MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_NUM_ENTRIES_OFST -
		      MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_FLAGS_OFST) * 8 !=
		     EFX_WORD_1_LBN);
	BUILD_BUG_ON(MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_NUM_ENTRIES_LEN * 8 !=
		     EFX_WORD_1_WIDTH);
	EFX_POPULATE_DWORD_2(flags_and_num_entries,
			     MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_UNLOADING,
				!!unloading,
			     EFX_WORD_1, num_entries);
	*_MCDI_DWORD(inbuf, SET_TUNNEL_ENCAP_UDP_PORTS_IN_FLAGS) =
		flags_and_num_entries;

	WARN_ON(unloading && num_entries);

	inlen = MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_IN_LEN(num_entries);

	/* Make sure all TX are stopped while we modify the table, else
	 * we might race against an efx_features_check().
	 * If we fail early in probe, we won't have set up our TXQs yet,
	 * in which case we don't need to do this (and trying wouldn't
	 * end well).  So check we've called register_netdevice().
	 */
	if (efx->net_dev->reg_state == NETREG_REGISTERED)
		efx_device_detach_sync(efx);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS,
				inbuf, inlen, outbuf, sizeof(outbuf), &outlen);
	if (rc == -EIO) {
		/* Most likely the MC rebooted due to another function also
		 * setting its tunnel port list. Mark all tunnel ports as not
		 * present; they will be added upon coming up from the reboot.
		 */
		spin_lock_bh(&nic_data->udp_tunnels_lock);
		for (i = 0; i < ARRAY_SIZE(nic_data->udp_tunnels); i++) {
			tnl = nic_data->udp_tunnels + i;
			if (tnl->count)
				tnl->adding = true;
			tnl->removing = false;
		}
		nic_data->udp_tunnels_busy = false;
		spin_unlock_bh(&nic_data->udp_tunnels_lock);
		/* We detached earlier, expecting an MC reset to trigger a
	         * re-attach. If we haven't allocated event queues, we won't
		 * see the notification. In this case we're not using any
		 * resources, so we don't actually need to do any reset
		 * handling except to forget some resources and reattach.
		 */
		if (!unloading && !efx_net_allocated(efx->state)) {
			efx_device_attach_if_not_resetting(efx);
			efx_ef10_mcdi_reboot_detected(efx);
		}
		return 0;
	}

	if (rc) {
		/* expected not available on unprivileged functions */
		if (rc != -EPERM)
			netif_warn(efx, drv, efx->net_dev,
				   "Unable to set UDP tunnel ports; rc=%d.\n", rc);
	} else if (MCDI_DWORD(outbuf, SET_TUNNEL_ENCAP_UDP_PORTS_OUT_FLAGS) &
		   (1 << MC_CMD_SET_TUNNEL_ENCAP_UDP_PORTS_OUT_RESETTING_LBN)) {
		netif_info(efx, drv, efx->net_dev,
			   "Rebooting MC due to UDP tunnel port list change\n");
		will_reset = true;
	}
	/* We detached earlier, expecting an MC reset to trigger a
	 * re-attach.
	 * But, there are two cases this won't happen: If the MC tells
	 * us it's not going to reset, just reattach and carry on.
	 * Alternatively, if the MC tells us it will reset but we haven't
	 * allocated event queues, we won't see the notification. In this
	 * case we're not using any resources, so we don't actually
	 * need to do any reset handling except to forget some
	 * resources and reattach.
	 */
	if (!unloading) {
		if (will_reset && !efx_net_allocated(efx->state))
			efx_ef10_mcdi_reboot_detected(efx);
		if (!will_reset || !efx_net_allocated(efx->state))
			efx_device_attach_if_not_resetting(efx);
	}
	spin_lock_bh(&nic_data->udp_tunnels_lock);
	if (!rc) {
		done = true;
		/* Mark the adds/removes as done */
		for (i = 0; i < ARRAY_SIZE(nic_data->udp_tunnels); i++) {
			tnl = nic_data->udp_tunnels + i;
			if (adding[i])
				/* it's added */
				tnl->adding = false;
			else
				/* it's not added, so if you wanted a remove
				 * you got it
				 */
				tnl->removing = false;
			if (tnl->adding || tnl->removing)
				done = false;
		}
		if (!done)
			/* Someone requested more changes, let's go and do them */
			goto again;
	}
	nic_data->udp_tunnels_busy = false;
	spin_unlock_bh(&nic_data->udp_tunnels_lock);
	return rc;
}

static void efx_ef10_udp_tnl_push_ports_sync(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	spin_lock_bh(&nic_data->udp_tunnels_lock);
	efx_ef10_set_udp_tnl_ports(nic_data->efx, false);
}

static void efx_ef10__udp_tnl_push_ports(struct work_struct *data)
{
	struct efx_ef10_nic_data *nic_data;

	nic_data = container_of(data, struct efx_ef10_nic_data,
				udp_tunnel_work);

	efx_ef10_udp_tnl_push_ports_sync(nic_data->efx);
}

static void efx_ef10_udp_tnl_push_ports_async(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	schedule_work(&nic_data->udp_tunnel_work);
}

static struct efx_udp_tunnel *_efx_ef10_udp_tnl_lookup_port(struct efx_nic *efx,
							    __be16 port)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(nic_data->udp_tunnels); ++i) {
		if (!nic_data->udp_tunnels[i].count)
			continue;
		if (nic_data->udp_tunnels[i].port == port)
			return &nic_data->udp_tunnels[i];
	}
	return NULL;
}

static void efx_ef10_udp_tnl_add_port(struct efx_nic *efx,
				      struct efx_udp_tunnel tnl)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	struct efx_udp_tunnel *match;
	char typebuf[8];
	size_t i;
	bool possible_reboot = false;

	if (!efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE))
		return;

	efx_get_udp_tunnel_type_name(tnl.type, typebuf, sizeof(typebuf));
	netif_dbg(efx, drv, efx->net_dev, "Adding UDP tunnel (%s) port %d\n",
		  typebuf, ntohs(tnl.port));

	spin_lock_bh(&nic_data->udp_tunnels_lock);

	match = _efx_ef10_udp_tnl_lookup_port(efx, tnl.port);
	if (match) {
		if (match->type == tnl.type) {
			netif_dbg(efx, drv, efx->net_dev,
				  "Referencing existing tunnel entry\n");
			/* Saturate at max value to prevent overflow. */
			if (match->count < EFX_UDP_TUNNEL_COUNT_MAX)
				match->count++;
			/* Yell if our refcounts are getting huge */
			WARN_ON_ONCE(match->count & EFX_UDP_TUNNEL_COUNT_WARN);
			if (match->removing) {
				/* This was due to be removed as its count had
				 * fallen to 0.  We don't know how far the
				 * removal has got; mark it for re-add.
				 */
				match->removing = false;
				match->adding = true;
				/* The thread currently doing the update will
				 * see this in its post-MCDI checking and so
				 * will re-do the MCDI.  Thus we don't need to
				 * schedule one ourselves.
				 */
			} else {
				/* Nothing to do.  This can only happen in the
				 * case of OVS tunnels, because regular kernel
				 * tunnels refcount their sockets and thus only
				 * ever ask for a port once.
				 */
			}
			goto out_unlock;
		}
		efx_get_udp_tunnel_type_name(match->type,
					     typebuf, sizeof(typebuf));
		netif_dbg(efx, drv, efx->net_dev,
			  "UDP port %d is already in use by %s\n",
			  ntohs(tnl.port), typebuf);
		goto out_unlock;
	}

	/* find an empty slot and use it */
	for (i = 0; i < ARRAY_SIZE(nic_data->udp_tunnels); ++i) {
		match = nic_data->udp_tunnels + i;
		/* Unused slot? */
		if (!match->count && !match->adding && !match->removing) {
			*match = tnl;
			match->adding = true;
			match->removing = false;
			match->count = 1;
			/* schedule an update */
			efx_ef10_udp_tnl_push_ports_async(efx);
			possible_reboot = true;
			goto out_unlock;
		}
	}

	netif_dbg(efx, drv, efx->net_dev,
		  "Unable to add UDP tunnel (%s) port %d; insufficient resources.\n",
		  typebuf, ntohs(tnl.port));

out_unlock:
	spin_unlock_bh(&nic_data->udp_tunnels_lock);
	if (possible_reboot)	/* Wait for a reboot to complete */
		msleep(200);
}

/* Called under the TX lock with the TX queue running, hence no-one can be
 * in the middle of updating the UDP tunnels table.  However, they could
 * have tried and failed the MCDI, in which case they'll have set appropriate
 * adding/removing flags before dropping their locks.
 */
static bool efx_ef10_udp_tnl_has_port(struct efx_nic *efx, __be16 port)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	struct efx_udp_tunnel *tnl;

	if (!efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE))
		return false;

	/* We're not under the spinlock, but that's OK because we're only
	 * reading.  See above comment.
	 */
	tnl = _efx_ef10_udp_tnl_lookup_port(efx, port);
	return tnl && !tnl->adding && !tnl->removing;
}

static void efx_ef10_udp_tnl_del_port(struct efx_nic *efx,
				      struct efx_udp_tunnel tnl)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	struct efx_udp_tunnel *match;
	char typebuf[8];
	bool possible_reboot = false;

	if (!efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE))
		return;

	efx_get_udp_tunnel_type_name(tnl.type, typebuf, sizeof(typebuf));
	netif_dbg(efx, drv, efx->net_dev, "Removing UDP tunnel (%s) port %d\n",
		  typebuf, ntohs(tnl.port));

	spin_lock_bh(&nic_data->udp_tunnels_lock);

	match = _efx_ef10_udp_tnl_lookup_port(efx, tnl.port);
	if (match) {
		if (match->type == tnl.type) {
			/* if we hit the max value, we stopped counting, so
			 * saturate and keep this port forever
			 */
			if (match->count != EFX_UDP_TUNNEL_COUNT_MAX)
				match->count--;
			if (match->count) {
				netif_dbg(efx, drv, efx->net_dev,
					  "Keeping UDP tunnel (%s) port %d, refcount %u\n",
					  typebuf, ntohs(tnl.port),
					  match->count);
				/* No MCDI to do */
				goto out_unlock;
			}
			if (match->adding)
				/* This was still waiting to be added, and we
				 * don't want it any more.  We don't know how
				 * far the add has got; unmark it.
				 */
				match->adding = false;
			match->removing = true;
			/* schedule an update */
			efx_ef10_udp_tnl_push_ports_async(efx);
			possible_reboot = true;
			goto out_unlock;
		}
		efx_get_udp_tunnel_type_name(match->type,
					     typebuf, sizeof(typebuf));
		netif_warn(efx, drv, efx->net_dev,
			   "UDP port %d is actually in use by %s, not removing\n",
			   ntohs(tnl.port), typebuf);
	} else {
		/* nothing to do */
		netif_dbg(efx, drv, efx->net_dev,
			  "UDP port %d was not previously offloaded\n",
			  ntohs(tnl.port));
	}

out_unlock:
	spin_unlock_bh(&nic_data->udp_tunnels_lock);
	if (possible_reboot)	/* Wait for a reboot to complete */
		msleep(200);
}
#endif

#ifdef EFX_NOT_UPSTREAM
static ssize_t forward_fcs_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));

	if (!(efx->net_dev->features & NETIF_F_RXFCS) !=
	    !(efx->net_dev->features & NETIF_F_RXALL))
		return scnprintf(buf, PAGE_SIZE, "mixed\n");

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 !!(efx->net_dev->features & NETIF_F_RXFCS));
}

static ssize_t forward_fcs_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));

	if (sysfs_streq(buf, "1"))
		efx->net_dev->wanted_features |= NETIF_F_RXFCS | NETIF_F_RXALL;
	else if (sysfs_streq(buf, "0"))
		efx->net_dev->wanted_features &= ~(NETIF_F_RXFCS |
						   NETIF_F_RXALL);
	else
		return -EINVAL;

	/* will call our ndo_set_features to actually make the change */
	rtnl_lock();
	netdev_update_features(efx->net_dev);
	rtnl_unlock();

	return count;
}
static DEVICE_ATTR_RW(forward_fcs);

static ssize_t physical_port_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));

	return scnprintf(buf, PAGE_SIZE, "%d\n", efx->port_num);
}
static DEVICE_ATTR_RO(physical_port);
#endif

static ssize_t link_control_flag_show(struct device *dev,
				      struct device_attribute *attr, char *buf)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));

	return scnprintf(buf, PAGE_SIZE, "%d\n",
		       ((efx->mcdi->fn_flags) &
			(1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_LINKCTRL))
		       ? 1 : 0);
}
static DEVICE_ATTR_RO(link_control_flag);

static ssize_t primary_flag_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct efx_nic *efx = pci_get_drvdata(to_pci_dev(dev));

	return scnprintf(buf, PAGE_SIZE, "%d\n",
		       ((efx->mcdi->fn_flags) &
			(1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_PRIMARY))
		       ? 1 : 0);
}
static DEVICE_ATTR_RO(primary_flag);

/*	NIC probe and remove
 */
static void efx_ef10_remove_post_io(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	int i;

	if (!nic_data)
		return;

	efx_mcdi_filter_table_remove(efx);

	efx_mcdi_mon_remove(efx);

#ifdef EFX_NOT_UPSTREAM
	device_remove_file(&efx->pci_dev->dev, &dev_attr_physical_port);

	if (efx_ef10_has_cap(nic_data->datapath_caps, RX_INCLUDE_FCS))
		device_remove_file(&efx->pci_dev->dev, &dev_attr_forward_fcs);
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
	for (i = 0; i < ARRAY_SIZE(nic_data->udp_tunnels); ++i) {
		nic_data->udp_tunnels[i].type =
			TUNNEL_ENCAP_UDP_PORT_ENTRY_INVALID;
		nic_data->udp_tunnels[i].port = 0;
	}
	mutex_lock(&nic_data->udp_tunnels_lock);
	(void)efx_ef10_set_udp_tnl_ports(efx, true);
	mutex_unlock(&nic_data->udp_tunnels_lock);
#else
	cancel_work_sync(&nic_data->udp_tunnel_work);

	/* mark all UDP tunnel ports for remove... */
	spin_lock_bh(&nic_data->udp_tunnels_lock);
	/* Since the udp_tunnel_work has been finished, no-one can still be
	 * busy.
	 */
	WARN_ON(nic_data->udp_tunnels_busy);
	nic_data->udp_tunnels_busy = true;
	for (i = 0; i < ARRAY_SIZE(nic_data->udp_tunnels); i++)
		nic_data->udp_tunnels[i].removing = true;
	/* ... then remove them */
	efx_ef10_set_udp_tnl_ports(efx, true); /* drops the lock */
#endif
}

static int efx_ef10_probe_post_io(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	unsigned int bar_size = efx_ef10_bar_size(efx);
	int rc;

	rc = efx_get_fn_info(efx, &nic_data->pf_index, &nic_data->vf_index);
	if (rc)
		return rc;

	/* License checking on the firmware must finish before we can trust the
	 * capabilities. Before that some will not be set.
	 */
	efx_ef10_read_licensed_features(efx);

	rc = efx_ef10_init_datapath_caps(efx);
	if (rc < 0)
		return rc;

	efx->tx_queues_per_channel = 1;
	efx->select_tx_queue = efx_ef10_select_tx_queue;
#ifdef EFX_USE_OVERLAY_TX_CSUM
	if (efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE) &&
	    !efx_ef10_is_vf(efx)) {
		efx->tx_queues_per_channel = 2;
		efx->select_tx_queue = efx_ef10_select_tx_queue_overlay;
	}
#endif
#ifdef EFX_NOT_UPSTREAM
	if (tx_non_csum_queue) {
		efx->tx_queues_per_channel = 2;
		efx->select_tx_queue = efx_ef10_select_tx_queue_non_csum;
#ifdef EFX_USE_OVERLAY_TX_CSUM
		if (efx_ef10_has_cap(nic_data->datapath_caps, VXLAN_NVGRE) &&
		    !efx_ef10_is_vf(efx)) {
			efx->tx_queues_per_channel = 3;
			efx->select_tx_queue =
				efx_ef10_select_tx_queue_non_csum_overlay;
		}
#endif
	}
#endif

	/* We can have one VI for each vi_stride-byte region.
	 * Note we have more TX queues than channels, so TX queues are the
	 * limit on the number of channels we can have with our VIs.
	 */
	efx->max_vis = bar_size / efx->vi_stride;
	if (!efx->max_vis) {
		netif_err(efx, drv, efx->net_dev, "error determining max VIs\n");
		return -EIO;
	}
	efx->max_channels = min_t(unsigned int, efx->max_channels,
				  (bar_size / (efx->vi_stride *
					       efx->tx_queues_per_channel)));
	efx->max_tx_channels = efx->max_channels;
	if (efx->max_channels == 0) {
		netif_err(efx, drv, efx->net_dev, "error determining max channels\n");
		return -EIO;
	}

	efx->rx_packet_len_offset =
		ES_DZ_RX_PREFIX_PKTLEN_OFST - ES_DZ_RX_PREFIX_SIZE;

	if (efx_ef10_has_cap(nic_data->datapath_caps, RX_INCLUDE_FCS))
		efx->net_dev->hw_features |= NETIF_F_RXFCS;

	rc = efx_mcdi_port_get_number(efx);
	if (rc < 0)
		return rc;
	efx->port_num = rc;

	rc = efx->type->get_mac_address(efx, efx->net_dev->perm_addr);
	if (rc)
		return rc;

	rc = efx_ef10_get_timer_config(efx);
	if (rc < 0)
		return rc;

	rc = efx_mcdi_mon_probe(efx);
	if (rc && rc != -EPERM)
		return rc;

#ifdef CONFIG_SFC_SRIOV
	efx_sriov_init_max_vfs(efx, nic_data->pf_index);
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_ID)
#ifdef CONFIG_SFC_SRIOV
	if (efx->pci_dev->physfn && !efx->pci_dev->is_physfn) {
		struct pci_dev *pci_dev_pf = efx->pci_dev->physfn;
		struct efx_nic *efx_pf = pci_get_drvdata(pci_dev_pf);

		efx_pf->type->get_mac_address(efx_pf, nic_data->port_id);
	} else
#endif
		ether_addr_copy(nic_data->port_id, efx->net_dev->perm_addr);
#endif
	/* If tx_coalesce_doorbell=Y disable tx_push, we do this here to avoid
	 * additional checks on the fast path.
	 */
	if (tx_coalesce_doorbell) {
		netif_info(efx, drv, efx->net_dev,
			   "Tx push disabled due to tx_coalesce_doorbell=Y\n");
		tx_push_max_fill = 0;
	}

	rc = efx_ef10_filter_table_probe(efx);
	if (rc)
		return rc;

	/* Add unspecified VID to support VLAN filtering being disabled */
	rc = efx_mcdi_filter_add_vlan(efx, EFX_FILTER_VID_UNSPEC);
	if (rc)
		return rc;

	/* If VLAN filtering is enabled, we need VID 0 to get untagged
	 * traffic.  It is added automatically if 8021q module is loaded,
	 * but we can't rely on it since module may be not loaded.
	 */
	return efx_mcdi_filter_add_vlan(efx, 0);
}

static int efx_ef10_probe(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data;
	unsigned int bar_size = efx_ef10_bar_size(efx);
	int i, rc;

	if (WARN_ON(bar_size == 0))
		return -EIO;

	nic_data = kzalloc(sizeof(*nic_data), GFP_KERNEL);
	if (!nic_data)
		return -ENOMEM;
	efx->nic_data = nic_data;
	nic_data->efx = efx;

	/* we assume later that we can copy from this buffer in dwords */
	BUILD_BUG_ON(MCDI_CTL_SDU_LEN_MAX_V2 % 4);

	/* MCDI buffers must be 256 byte aligned, so pad the first N-1
	 * buffers and add the last on the end.
	 */
	rc = efx_nic_alloc_buffer(efx, &nic_data->mcdi_buf,
				  ALIGN(MCDI_BUF_LEN, 256) *
					(EF10_NUM_MCDI_BUFFERS - 1) +
				  MCDI_BUF_LEN,
				  GFP_KERNEL);
	if (rc)
		return rc;

	/* Get the MC's warm boot count.  In case it's rebooting right
	 * now, be prepared to retry.
	 */
	i = 0;
	for (;;) {
		rc = efx_ef10_get_warm_boot_count(efx);
		if (rc >= 0)
			break;
		if (++i == 5)
			return rc;
		ssleep(1);
	}
	nic_data->warm_boot_count = rc;

	/* In case we're recovering from a crash (kexec), we want to
	 * cancel any outstanding request by the previous user of this
	 * function.  We send a special message using the least
	 * significant bits of the 'high' (doorbell) register.
	 */
	_efx_writed(efx, cpu_to_le32(1), ER_DZ_MC_DB_HWRD);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
	mutex_init(&nic_data->udp_tunnels_lock);
	for (i = 0; i < ARRAY_SIZE(nic_data->udp_tunnels); ++i)
		nic_data->udp_tunnels[i].type =
			TUNNEL_ENCAP_UDP_PORT_ENTRY_INVALID;
#else
	spin_lock_init(&nic_data->udp_tunnels_lock);
	nic_data->udp_tunnels_busy = false;
	INIT_WORK(&nic_data->udp_tunnel_work, efx_ef10__udp_tnl_push_ports);
#endif

	/* retry probe 3 times on EF10 due to UDP tunnel ports
	 * sometimes causing a reset during probe.
	 */
	rc = efx_pci_probe_post_io(efx, efx_ef10_probe_post_io);
	if (rc) {
		/* On failure, retry once immediately.
		 * If we aborted probe due to a scheduled reset, dismiss it.
		 */
		efx->reset_pending = 0;
		efx_pci_remove_post_io(efx, efx_ef10_remove_post_io);
		rc = efx_pci_probe_post_io(efx, efx_ef10_probe_post_io);
		if (rc) {
			/* On another failure, retry once more
			 * after a 50-305ms delay.
			 */
			unsigned char r;

			get_random_bytes(&r, 1);
			msleep((unsigned int)r + 50);

			efx->reset_pending = 0;
			efx_pci_remove_post_io(efx, efx_ef10_remove_post_io);
			rc = efx_pci_probe_post_io(efx, efx_ef10_probe_post_io);
		}
	}
	if (rc) {
		netif_err(efx, drv, efx->net_dev,
			  "Failed too many attempts to probe. Aborting.\n");
		return rc;
	}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
	if (efx_has_cap(efx, VXLAN_NVGRE) &&
	    efx->mcdi->fn_flags &
	    (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_TRUSTED))
		efx->net_dev->udp_tunnel_nic_info = &efx_ef10_udp_tunnels;
#endif

#ifdef EFX_NOT_UPSTREAM
	if (efx->mcdi->fn_flags &
	    (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_NO_ACTIVE_PORT))
		return 0;
#endif

#ifdef EFX_NOT_UPSTREAM
	if (efx_rss_use_fixed_key) {
		BUILD_BUG_ON(sizeof(efx_rss_fixed_key) <
			     sizeof(efx->rss_context.rx_hash_key));
		memcpy(&efx->rss_context.rx_hash_key, efx_rss_fixed_key,
		       sizeof(efx->rss_context.rx_hash_key));
	} else
#endif
	netdev_rss_key_fill(efx->rss_context.rx_hash_key,
			    sizeof(efx->rss_context.rx_hash_key));

	/* Don't fail init if RSS setup doesn't work. */
	efx_mcdi_push_default_indir_table(efx, efx->n_rss_channels);

#ifdef EFX_NOT_UPSTREAM
	if (efx_ef10_has_cap(nic_data->datapath_caps, RX_INCLUDE_FCS))
		rc = device_create_file(&efx->pci_dev->dev,
					&dev_attr_forward_fcs);
	if (rc)
		return rc;

	rc = device_create_file(&efx->pci_dev->dev, &dev_attr_physical_port);
	if (rc)
		return rc;
#endif

	rc = device_create_file(&efx->pci_dev->dev,
				&dev_attr_link_control_flag);
	if (rc)
		return rc;

	return device_create_file(&efx->pci_dev->dev, &dev_attr_primary_flag);
}

static int efx_ef10_probe_pf(struct efx_nic *efx)
{
#ifdef EFX_NOT_UPSTREAM
	unsigned int desired_bandwidth;

	switch (efx->pci_dev->device) {
	case 0x0923:
		/* Greenport devices can make use of 8 lanes of Gen3. */
		desired_bandwidth = EFX_BW_PCIE_GEN3_X8;
		break;
	case 0x0a03:
	case 0x0b03:
		/* Medford and Medford2 devices want 16 lanes, even though
		 * not all have that.
		 * We suppress this optimism in efx_nic_check_pcie_link().
		 */
		desired_bandwidth = EFX_BW_PCIE_GEN3_X16;
		break;
	default:
		desired_bandwidth = EFX_BW_PCIE_GEN2_X8;
	}

	efx_nic_check_pcie_link(efx, desired_bandwidth, NULL, NULL);
#endif
	return efx_ef10_probe(efx);
}

static void efx_ef10_remove(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;

	if (!nic_data)
		return;

	device_remove_file(&efx->pci_dev->dev, &dev_attr_link_control_flag);
	device_remove_file(&efx->pci_dev->dev, &dev_attr_primary_flag);

	efx_pci_remove_post_io(efx, efx_ef10_remove_post_io);

	efx_nic_free_buffer(efx, &nic_data->mcdi_buf);

	kfree(nic_data);
	efx->nic_data = NULL;
}

#if defined(CONFIG_SFC_SRIOV)
static void efx_ef10_remove_vf(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data = efx->nic_data;
	struct efx_ef10_nic_data *nic_data_pf;
	struct pci_dev *pci_dev_pf;
	struct efx_nic *efx_pf;
	struct ef10_vf *vf;

	efx_ef10_remove(efx);

	/* If PCI probe fails early there is no NIC specific data yet */
	if (!nic_data)
		return;

	if (efx->pci_dev->is_virtfn) {
		pci_dev_pf = efx->pci_dev->physfn;
		if (pci_dev_pf) {
			efx_pf = pci_get_drvdata(pci_dev_pf);
			nic_data_pf = efx_pf->nic_data;
			vf = nic_data_pf->vf + nic_data->vf_index;
			vf->efx = NULL;
		}
	}
}

static int efx_ef10_probe_vf(struct efx_nic *efx)
{
	struct efx_ef10_nic_data *nic_data;
	struct efx_nic *efx_pf;
	int rc = efx_vf_parent(efx, &efx_pf);

	/* Fail if the parent is not a Solarflare PF */
	if (rc)
		return rc;

	/* If the parent PF has no VF data structure, it doesn't know about this
	 * VF so fail probe.  The VF needs to be re-created.  This can happen
	 * if the PF driver is unloaded while the VF is assigned to a guest.
	 */
	if (efx_pf) {
		nic_data = efx_pf->nic_data;
		if (!nic_data->vf) {
			netif_info(efx, drv, efx->net_dev,
				   "The VF cannot link to its parent PF; "
				   "please destroy and re-create the VF\n");
			return -EBUSY;
		}
	}

	rc = efx_ef10_probe(efx);
	if (rc)
		goto fail;

	nic_data = efx->nic_data;

	if (efx->pci_dev->physfn) {
		struct efx_nic *efx_pf = pci_get_drvdata(efx->pci_dev->physfn);
		struct efx_ef10_nic_data *nic_data_pf = efx_pf->nic_data;

		nic_data_pf->vf[nic_data->vf_index].efx = efx;
		nic_data_pf->vf[nic_data->vf_index].pci_dev =
			efx->pci_dev;
	} else {
		netif_info(efx, drv, efx->net_dev,
			   "Could not get the PF id from VF\n");
	}

	INIT_DELAYED_WORK(&nic_data->vf_stats_work,
			  efx_ef10_vf_update_stats_work);

	return 0;

fail:
	efx_ef10_remove_vf(efx);
	return rc;
}
#endif /* CONFIG_SFC_SRIOV */

static unsigned int ef10_check_caps(const struct efx_nic *efx,
				    u8 flag,
				    u32 offset)
{
	const struct efx_ef10_nic_data *nic_data = efx->nic_data;

	switch (offset) {
	case(MC_CMD_GET_CAPABILITIES_V8_OUT_FLAGS1_OFST):
		return nic_data->datapath_caps & BIT_ULL(flag);
	case(MC_CMD_GET_CAPABILITIES_V8_OUT_FLAGS2_OFST):
		return nic_data->datapath_caps2 & BIT_ULL(flag);
	default:
		return 0;
	}
}

static unsigned int efx_ef10_recycle_ring_size(const struct efx_nic *efx)
{
	unsigned int ret = EFX_RECYCLE_RING_SIZE_10G;

	/* There is no difference between PFs and VFs. The size is based on
	 * the maximum link speed of a given NIC.
	 */
	switch (efx->pci_dev->device & 0xfff) {
	case 0x0903:	/* Farmingdale can do up to 10G */
		break;
	case 0x0923:	/* Greenport can do up to 40G */
	case 0x0a03:	/* Medford can do up to 40G */
		ret *= 4;
		break;
	default:	/* Medford2 can do up to 100G */
		ret *= 10;
	}

	if (IS_ENABLED(CONFIG_PPC64))
		ret *= 4;

	return ret;
}

#define EF10_OFFLOAD_FEATURES		\
	(NETIF_F_IP_CSUM |		\
	 NETIF_F_HW_VLAN_CTAG_FILTER |	\
	 NETIF_F_IPV6_CSUM |		\
	 NETIF_F_RXHASH |		\
	 NETIF_F_NTUPLE)

#ifdef CONFIG_SFC_SRIOV
const struct efx_nic_type efx_hunt_a0_vf_nic_type = {
	.is_vf = true,
	.mem_bar = efx_ef10_vf_mem_bar,
	.mem_map_size = efx_ef10_initial_mem_map_size,
	.probe = efx_ef10_probe_vf,
	.remove = efx_ef10_remove_vf,
	.dimension_resources = efx_ef10_dimension_resources,
	.net_alloc = __efx_net_alloc,
	.net_dealloc = __efx_net_dealloc,
	.init = efx_ef10_init_nic,
	.fini = efx_ef10_fini_nic,
	.monitor = efx_ef10_monitor,
	.hw_unavailable = efx_ef10_hw_unavailable,
	.map_reset_reason = efx_ef10_map_reset_reason,
	.map_reset_flags = efx_ef10_map_reset_flags,
	.reset = efx_ef10_reset,
	.probe_port = efx_mcdi_port_probe,
	.remove_port = efx_mcdi_port_remove,
	.fini_dmaq = efx_ef10_fini_dmaq,
	.prepare_flr = efx_ef10_prepare_flr,
	.finish_flr = efx_port_dummy_op_void,
	.describe_stats = efx_ef10_describe_stats,
	.update_stats = efx_ef10_update_stats_vf,
	.start_stats = efx_ef10_start_stats_vf,
	.pull_stats = efx_ef10_pull_stats_vf,
	.stop_stats = efx_ef10_stop_stats_vf,
	.update_stats_period = efx_ef10_vf_schedule_stats_work,
	.push_irq_moderation = efx_ef10_push_irq_moderation,
	.reconfigure_mac = efx_ef10_mac_reconfigure,
	.check_mac_fault = efx_mcdi_mac_check_fault,
	.reconfigure_port = efx_mcdi_port_reconfigure,
	.get_wol = efx_ef10_get_wol_vf,
	.set_wol = efx_ef10_set_wol_vf,
	.resume_wol = efx_port_dummy_op_void,
	.mcdi_request = efx_ef10_mcdi_request,
	.mcdi_poll_response = efx_ef10_mcdi_poll_response,
	.mcdi_read_response = efx_ef10_mcdi_read_response,
	.mcdi_poll_reboot = efx_ef10_mcdi_poll_reboot,
	.mcdi_record_bist_event = efx_ef10_mcdi_record_bist_event,
	.mcdi_poll_bist_end = efx_ef10_mcdi_poll_bist_end,
	.mcdi_reboot_detected = efx_ef10_mcdi_reboot_detected,
	.mcdi_get_buf = efx_ef10_mcdi_get_buf,
	.mcdi_put_buf = efx_ef10_mcdi_put_buf,
	.irq_enable_master = efx_port_dummy_op_void,
	.irq_test_generate = efx_ef10_irq_test_generate,
	.irq_disable_non_ev = efx_port_dummy_op_void,
	.irq_handle_msi = efx_ef10_msi_interrupt,
	.tx_probe = efx_ef10_tx_probe,
	.tx_init = efx_ef10_tx_init,
	.tx_write = efx_ef10_tx_write,
	.tx_notify = efx_ef10_notify_tx_desc,
	.tx_limit_len = efx_ef10_tx_limit_len,
	.tx_enqueue = __efx_enqueue_skb,
	.tx_max_skb_descs = efx_ef10_tx_max_skb_descs,
	.rx_push_rss_config = efx_ef10_vf_rx_push_rss_config,
	.rx_pull_rss_config = efx_mcdi_rx_pull_rss_config,
	.rx_probe = efx_mcdi_rx_probe,
	.rx_init = efx_ef10_rx_init,
	.rx_remove = efx_mcdi_rx_remove,
	.rx_write = efx_ef10_rx_write,
	.rx_defer_refill = efx_ef10_rx_defer_refill,
	.rx_packet = __efx_rx_packet,
	.ev_probe = efx_mcdi_ev_probe,
	.ev_init = efx_ef10_ev_init,
	.ev_fini = efx_mcdi_ev_fini,
	.ev_remove = efx_mcdi_ev_remove,
	.ev_process = efx_ef10_ev_process,
	.ev_mcdi_pending = efx_ef10_ev_mcdi_pending,
	.ev_read_ack = efx_ef10_ev_read_ack,
	.ev_test_generate = efx_ef10_ev_test_generate,
	.filter_table_probe = efx_ef10_filter_table_init,
	.filter_table_up = efx_ef10_filter_table_up,
	.filter_table_restore = efx_mcdi_filter_table_restore,
	.filter_table_down = efx_ef10_filter_table_down,
	.filter_table_remove = efx_ef10_filter_table_fini,
	.filter_match_supported = efx_mcdi_filter_match_supported,
	.filter_insert = efx_mcdi_filter_insert,
	.filter_remove_safe = efx_mcdi_filter_remove_safe,
	.filter_get_safe = efx_mcdi_filter_get_safe,
	.filter_clear_rx = efx_mcdi_filter_clear_rx,
	.filter_count_rx_used = efx_mcdi_filter_count_rx_used,
	.filter_get_rx_id_limit = efx_mcdi_filter_get_rx_id_limit,
	.filter_get_rx_ids = efx_mcdi_filter_get_rx_ids,
#ifdef CONFIG_RFS_ACCEL
	.filter_rfs_expire_one = efx_mcdi_filter_rfs_expire_one,
#endif
#ifdef EFX_NOT_UPSTREAM
	.filter_redirect = efx_mcdi_filter_redirect,
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	.filter_block_kernel = efx_mcdi_filter_block_kernel,
	.filter_unblock_kernel = efx_mcdi_filter_unblock_kernel,
#endif
#endif
#ifdef CONFIG_SFC_MTD
	.mtd_probe = efx_port_dummy_op_int,
#endif
#ifdef CONFIG_SFC_PTP
	.ptp_write_host_time = efx_ef10_ptp_write_host_time,
	.ptp_set_ts_config = efx_ef10_ptp_set_ts_config,
#endif
	.vlan_rx_add_vid = efx_mcdi_filter_add_vid,
	.vlan_rx_kill_vid = efx_mcdi_filter_del_vid,
	.vswitching_probe = efx_ef10_vswitching_probe_vf,
	.vswitching_restore = efx_ef10_vswitching_restore_vf,
	.vswitching_remove = efx_ef10_vswitching_remove_vf,
	.get_mac_address = efx_ef10_get_mac_address_vf,
	.set_mac_address = efx_ef10_set_mac_address,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_ID)
	.get_phys_port_id = efx_ef10_get_phys_port_id,
#endif
	.revision = EFX_REV_HUNT_A0,
	.max_dma_mask = DMA_BIT_MASK(ESF_DZ_TX_KER_BUF_ADDR_WIDTH),
	.rx_prefix_size = ES_DZ_RX_PREFIX_SIZE,
	.rx_hash_offset = ES_DZ_RX_PREFIX_HASH_OFST,
	.rx_ts_offset = ES_DZ_RX_PREFIX_TSTAMP_OFST,
	.can_rx_scatter = true,
	.always_rx_scatter = true,
	.option_descriptors = true,
	.copy_break = true,
	.supported_interrupt_modes = BIT(EFX_INT_MODE_MSIX),
	.timer_period_max = 1 << ERF_DD_EVQ_IND_TIMER_VAL_WIDTH,
#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	.ef10_resources = {
		.hdr.next = ((struct efx_dl_device_info *)
			     &efx_hunt_a0_nic_type.dl_hash_insertion.hdr),
		.hdr.type = EFX_DL_EF10_RESOURCES,
		.vi_base = 0,
		.vi_shift = 0,
		.vi_min = 0,
		.vi_lim = 0,
		.flags = 0
	},
	.dl_hash_insertion = {
		.hdr.type = EFX_DL_HASH_INSERTION,
		.data_offset = ES_DZ_RX_PREFIX_SIZE,
		.hash_offset = ES_DZ_RX_PREFIX_HASH_OFST,
		.flags = (EFX_DL_HASH_TOEP_TCPIP4 | EFX_DL_HASH_TOEP_IP4 |
			  EFX_DL_HASH_TOEP_TCPIP6 | EFX_DL_HASH_TOEP_IP6),
	},
#endif
#endif
	.offload_features = EF10_OFFLOAD_FEATURES,
	.mcdi_max_ver = 2,
	.mcdi_rpc_timeout = efx_ef10_mcdi_rpc_timeout,
	.max_rx_ip_filters = EFX_MCDI_FILTER_TBL_ROWS,
	.hwtstamp_filters = 1 << HWTSTAMP_FILTER_NONE |
			    1 << HWTSTAMP_FILTER_ALL,
	.rx_hash_key_size = 40,
	.check_caps = ef10_check_caps,
	.rx_recycle_ring_size = efx_ef10_recycle_ring_size,
};
#endif

const struct efx_nic_type efx_hunt_a0_nic_type = {
	.is_vf = false,
	.mem_bar = efx_ef10_pf_mem_bar,
	.mem_map_size = efx_ef10_initial_mem_map_size,
	.probe = efx_ef10_probe_pf,
	.remove = efx_ef10_remove,
	.dimension_resources = efx_ef10_dimension_resources,
	.free_resources = efx_ef10_free_resources,
	.net_alloc = __efx_net_alloc,
	.net_dealloc = __efx_net_dealloc,
	.init = efx_ef10_init_nic,
	.fini = efx_ef10_fini_nic,
	.monitor = efx_ef10_monitor,
	.hw_unavailable = efx_ef10_hw_unavailable,
	.map_reset_reason = efx_ef10_map_reset_reason,
	.map_reset_flags = efx_ef10_map_reset_flags,
	.reset = efx_ef10_reset,
	.probe_port = efx_mcdi_port_probe,
	.remove_port = efx_mcdi_port_remove,
	.fini_dmaq = efx_ef10_fini_dmaq,
	.prepare_flr = efx_ef10_prepare_flr,
	.finish_flr = efx_port_dummy_op_void,
	.describe_stats = efx_ef10_describe_stats,
	.update_stats = efx_ef10_update_stats_pf,
	.pull_stats = efx_ef10_pull_stats_pf,
	.push_irq_moderation = efx_ef10_push_irq_moderation,
	.reconfigure_mac = efx_ef10_mac_reconfigure,
	.check_mac_fault = efx_mcdi_mac_check_fault,
	.reconfigure_port = efx_mcdi_port_reconfigure,
	.get_wol = efx_ef10_get_wol,
	.set_wol = efx_ef10_set_wol,
	.resume_wol = efx_port_dummy_op_void,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_FECSTATS)
	.get_fec_stats = efx_ef10_get_fec_stats,
#endif
	.test_chip = efx_ef10_test_chip,
	.test_nvram = efx_mcdi_nvram_test_all,
	.mcdi_request = efx_ef10_mcdi_request,
	.mcdi_poll_response = efx_ef10_mcdi_poll_response,
	.mcdi_read_response = efx_ef10_mcdi_read_response,
	.mcdi_poll_reboot = efx_ef10_mcdi_poll_reboot,
	.mcdi_record_bist_event = efx_ef10_mcdi_record_bist_event,
	.mcdi_poll_bist_end = efx_ef10_mcdi_poll_bist_end,
	.mcdi_reboot_detected = efx_ef10_mcdi_reboot_detected,
	.mcdi_get_buf = efx_ef10_mcdi_get_buf,
	.mcdi_put_buf = efx_ef10_mcdi_put_buf,
	.irq_enable_master = efx_port_dummy_op_void,
	.irq_test_generate = efx_ef10_irq_test_generate,
	.irq_disable_non_ev = efx_port_dummy_op_void,
	.irq_handle_msi = efx_ef10_msi_interrupt,
	.tx_probe = efx_ef10_tx_probe,
	.tx_init = efx_ef10_tx_init,
	.tx_write = efx_ef10_tx_write,
	.tx_notify = efx_ef10_notify_tx_desc,
	.tx_limit_len = efx_ef10_tx_limit_len,
	.tx_max_skb_descs = efx_ef10_tx_max_skb_descs,
	.tx_enqueue = __efx_enqueue_skb,
	.rx_push_rss_config = efx_ef10_pf_rx_push_rss_config,
	.rx_pull_rss_config = efx_mcdi_rx_pull_rss_config,
	.rx_push_rss_context_config = efx_mcdi_rx_push_rss_context_config,
	.rx_pull_rss_context_config = efx_mcdi_rx_pull_rss_context_config,
	.rx_restore_rss_contexts = efx_mcdi_rx_restore_rss_contexts,
	.rx_get_default_rss_flags = efx_mcdi_get_default_rss_flags,
	.rx_set_rss_flags = efx_mcdi_set_rss_context_flags,
	.rx_get_rss_flags = efx_mcdi_get_rss_context_flags,
	.rx_probe = efx_mcdi_rx_probe,
	.rx_init = efx_ef10_rx_init,
	.rx_remove = efx_mcdi_rx_remove,
	.rx_write = efx_ef10_rx_write,
	.rx_defer_refill = efx_ef10_rx_defer_refill,
	.rx_packet = __efx_rx_packet,
	.ev_probe = efx_mcdi_ev_probe,
	.ev_init = efx_ef10_ev_init,
	.ev_fini = efx_mcdi_ev_fini,
	.ev_remove = efx_mcdi_ev_remove,
	.ev_process = efx_ef10_ev_process,
	.ev_mcdi_pending = efx_ef10_ev_mcdi_pending,
	.ev_read_ack = efx_ef10_ev_read_ack,
	.ev_test_generate = efx_ef10_ev_test_generate,
	.filter_table_probe = efx_ef10_filter_table_init,
	.filter_table_up = efx_ef10_filter_table_up,
	.filter_table_restore = efx_mcdi_filter_table_restore,
	.filter_table_down = efx_ef10_filter_table_down,
	.filter_table_remove = efx_ef10_filter_table_fini,
	.filter_match_supported = efx_mcdi_filter_match_supported,
	.filter_insert = efx_mcdi_filter_insert,
	.filter_remove_safe = efx_mcdi_filter_remove_safe,
	.filter_get_safe = efx_mcdi_filter_get_safe,
	.filter_clear_rx = efx_mcdi_filter_clear_rx,
	.filter_count_rx_used = efx_mcdi_filter_count_rx_used,
	.filter_get_rx_id_limit = efx_mcdi_filter_get_rx_id_limit,
	.filter_get_rx_ids = efx_mcdi_filter_get_rx_ids,
#ifdef CONFIG_RFS_ACCEL
	.filter_rfs_expire_one = efx_mcdi_filter_rfs_expire_one,
#endif
#ifdef EFX_NOT_UPSTREAM
	.filter_redirect = efx_mcdi_filter_redirect,
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	.filter_block_kernel = efx_mcdi_filter_block_kernel,
	.filter_unblock_kernel = efx_mcdi_filter_unblock_kernel,
#endif
#endif
#ifdef CONFIG_SFC_MTD
	.mtd_probe = efx_ef10_mtd_probe,
	.mtd_rename = efx_mcdi_mtd_rename,
	.mtd_read = efx_mcdi_mtd_read,
	.mtd_erase = efx_mcdi_mtd_erase,
	.mtd_write = efx_mcdi_mtd_write,
	.mtd_sync = efx_mcdi_mtd_sync,
#endif
#ifdef CONFIG_SFC_PTP
	.ptp_write_host_time = efx_ef10_ptp_write_host_time,
	.ptp_set_ts_sync_events = efx_ef10_ptp_set_ts_sync_events,
	.ptp_set_ts_config = efx_ef10_ptp_set_ts_config,
#ifdef EFX_NOT_UPSTREAM
	.pps_reset = efx_ptp_pps_reset,
#endif
#endif
	.vlan_rx_add_vid = efx_mcdi_filter_add_vid,
	.vlan_rx_kill_vid = efx_mcdi_filter_del_vid,
	.udp_tnl_has_port = efx_ef10_udp_tnl_has_port,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_UDP_TUNNEL_NIC_INFO)
	.udp_tnl_push_ports = efx_ef10_udp_tnl_push_ports,
#else
	.udp_tnl_push_ports = efx_ef10_udp_tnl_push_ports_sync,
	.udp_tnl_add_port = efx_ef10_udp_tnl_add_port,
	.udp_tnl_del_port = efx_ef10_udp_tnl_del_port,
#endif
	.vport_add = efx_ef10_vport_alloc,
	.vport_del = efx_ef10_vport_free,
#ifdef CONFIG_SFC_SRIOV
	.sriov_configure = efx_ef10_sriov_configure,
	.sriov_init = efx_ef10_sriov_init,
	.sriov_fini = efx_ef10_sriov_fini,
	.sriov_wanted = efx_ef10_sriov_wanted,
	.sriov_set_vf_mac = efx_ef10_sriov_set_vf_mac,
	.sriov_set_vf_vlan = efx_ef10_sriov_set_vf_vlan,
	.sriov_set_vf_spoofchk = efx_ef10_sriov_set_vf_spoofchk,
	.sriov_get_vf_config = efx_ef10_sriov_get_vf_config,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_VF_LINK_STATE)
	.sriov_set_vf_link_state = efx_ef10_sriov_set_vf_link_state,
#endif
#endif
	.vswitching_probe = efx_ef10_vswitching_probe_pf,
	.vswitching_restore = efx_ef10_vswitching_restore_pf,
	.vswitching_remove = efx_ef10_vswitching_remove_pf,
	.get_mac_address = efx_ef10_get_mac_address_pf,
	.set_mac_address = efx_ef10_set_mac_address,
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_NDO_GET_PHYS_PORT_ID)
	.get_phys_port_id = efx_ef10_get_phys_port_id,
#endif
	.revision = EFX_REV_HUNT_A0,
	.max_dma_mask = DMA_BIT_MASK(ESF_DZ_TX_KER_BUF_ADDR_WIDTH),
	.rx_prefix_size = ES_DZ_RX_PREFIX_SIZE,
	.rx_hash_offset = ES_DZ_RX_PREFIX_HASH_OFST,
	.rx_ts_offset = ES_DZ_RX_PREFIX_TSTAMP_OFST,
	.can_rx_scatter = true,
	.always_rx_scatter = true,
	.option_descriptors = true,
	.copy_break = true,
	.supported_interrupt_modes = BIT(EFX_INT_MODE_MSIX) |
				     BIT(EFX_INT_MODE_MSI),
    .timer_period_max = 1 << ERF_DD_EVQ_IND_TIMER_VAL_WIDTH,
#ifdef EFX_NOT_UPSTREAM
#if IS_MODULE(CONFIG_SFC_DRIVERLINK)
	.ef10_resources = {
		.hdr.next = ((struct efx_dl_device_info *)
			     &efx_hunt_a0_nic_type.dl_hash_insertion.hdr),
		.hdr.type = EFX_DL_EF10_RESOURCES,
		.vi_base = 0,
		.vi_shift = 0,
		.vi_min = 0,
		.vi_lim = 0,
		.flags = 0
	},
	.dl_hash_insertion = {
		.hdr.type = EFX_DL_HASH_INSERTION,
		.data_offset = ES_DZ_RX_PREFIX_SIZE,
		.hash_offset = ES_DZ_RX_PREFIX_HASH_OFST,
		.flags = (EFX_DL_HASH_TOEP_TCPIP4 | EFX_DL_HASH_TOEP_IP4 |
			  EFX_DL_HASH_TOEP_TCPIP6 | EFX_DL_HASH_TOEP_IP6),
	},
#endif
#endif
	.offload_features = EF10_OFFLOAD_FEATURES,
	.mcdi_max_ver = 2,
	.mcdi_rpc_timeout = efx_ef10_mcdi_rpc_timeout,
	.max_rx_ip_filters = EFX_MCDI_FILTER_TBL_ROWS,
	.hwtstamp_filters = 1 << HWTSTAMP_FILTER_NONE |
			    1 << HWTSTAMP_FILTER_ALL,
	.rx_hash_key_size = 40,
	.check_caps = ef10_check_caps,
	.rx_recycle_ring_size = efx_ef10_recycle_ring_size,
};
