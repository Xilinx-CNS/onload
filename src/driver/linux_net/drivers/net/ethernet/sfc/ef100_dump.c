/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2021 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include "ef100_dump.h"
#include "mcdi_pcol.h"
#include "mcdi.h"

struct efx_mc_reg_table {
	const char *name;
	u32 addr;
	u32 size;
};

/* Tables of addresses to dump.  These are for SN1022 p7g images, and
 * may not be correct for other EF100 NICs.  TODO replace all this with
 * something more robust before such other NICs arrive.
 */

static struct efx_mc_reg_table efx_dump_misc[] = {
	{"FPGA hardware version", 0xFD200004, 1},
};

static struct efx_mc_reg_table efx_dump_sss_host_tx[] = {
	{"DMAC-S2IC(Towards SSS) PKT CNT", 0x88001008, 1},
	{"Host Hub A PKTS IN", 0x8c010000, 32},
	{"Host Hub A plugin PKTS IN", 0x8c010200, 32},
	{"Host Hub A PKTS_OUT", 0x8c010400, 32},
	{"VNTX SP control dbg sticky reg1", 0x8f1ff104, 1},
	{"VNTX SP control dbg sticky reg2", 0x8f1ff108, 1},
	{"VNTX SP control chker csum error frm cnt", 0x8f1ff10c, 1},
	{"VNTX SP control chker csum error", 0x8f1ff110, 1},
	{"VNTX SP control chker protocol err reg0", 0x8f1ff114, 1},
	{"VNTX SP control chker protocol err reg1", 0x8f1ff118, 1},
	{"VNTX SP control ic2s ingress pkt count", 0x8f1ff014, 1},
	{"VNTX SP control s2ic egress pkt count", 0x8f1ff054, 1},
	{"Host Hub B PKTS IN", 0x8c410000, 40},
	{"Host Hub B plugin PKTS IN", 0x8c410400, 40},
	{"Host Hub B PKTS_OUT (from host and net)", 0x8c410800, 40},
	{"ME SP control dbg sticky reg1", 0x8f3ff104, 1},
	{"ME SP control dbg sticky reg2", 0x8f3ff108, 1},
	{"ME SP control chker csum error frm cnt", 0x8f3ff10c, 1},
	{"ME SP control chker csum error", 0x8f3ff110, 1},
	{"ME SP control chker protocol err reg0", 0x8f3ff114, 1},
	{"ME SP control chker protocol err reg1", 0x8f3ff118, 1},
	{"ME SP control ic2s ingress pkt count", 0x8f3ff014, 1},
	{"ME SP control s2ic egress pkt count", 0x8f3ff054, 1},
	{"Host Hub RP PKTS IN", 0x8b800000, 32},
	{"Host Hub RP PKTS_OUT", 0x8b800100, 32},
	{"Replay hub sticky", 0x8b801010, 1},
	{"AE SP control dbg sticky reg1", 0x8f5ff104, 1},
	{"AE SP control dbg sticky reg2", 0x8f5ff108, 1},
	{"AE SP control chker csum error frm cnt", 0x8f5ff10c, 1},
	{"AE SP control chker csum error", 0x8f5ff110, 1},
	{"AE SP control chker protocol err reg0", 0x8f5ff114, 1},
	{"AE SP control chker protocol err reg1", 0x8f5ff118, 1},
	{"AE SP control ic2s ingress pkt count", 0x8f5ff014, 1},
	{"AE SP control s2ic egress pkt count", 0x8f5ff054, 1},
	{"Net Hub C N0 net PKTS IN", 0x8cc15800, 40},
	{"Net Hub C N0 net PKTS_OUT", 0x8cc15c00, 40},
	{"Net Hub C N1 net PKTS IN", 0x8cc15000, 40},
	{"Net Hub C N1 net PKTS_OUT", 0x8cc15400, 40},
};

static struct efx_mc_reg_table efx_dump_sss_rx_path[] = {
	{"Net Hub A missing EOP sticky", 0x8d410e40, 32},
	{"Net Hub A PKTS IN0", 0x8d410000, 32},
	{"Net Hub A PKTS IN1", 0x8d411000, 32},
	{"Net Hub A PKTS_OUT", 0x8d410600, 32},
	{"Net Hub A PKTS DROP0", 0x8d410200, 32},
	{"Net Hub A PKTS DROP1", 0x8d411200, 32},
	{"Net  Hub B PKTS IN", 0x8c410200, 40},
	{"Net  Hub B plugin PKTS IN", 0x8c410600, 40},
	{"Host Hub C PKTS IN", 0x8cc11000, 40},
	{"Host Hub C PKTS_OUT", 0x8cc11100, 40},
	{"VNRX SP control dbg sticky reg1", 0x8f7ff104, 1},
	{"VNRX SP control dbg sticky reg2", 0x8f7ff108, 1},
	{"VNRX SP control chker csum error frm cnt", 0x8f7ff10c, 1},
	{"VNRX SP control chker csum error", 0x8f7ff110, 1},
	{"VNRX SP control chker protocol err reg0", 0x8f7ff114, 1},
	{"VNRX SP control chker protocol err reg1", 0x8f7ff118, 1},
	{"VNRX SP control ic2s ingress pkt count", 0x8f7ff014, 1},
	{"VNRX SP control s2ic egress pkt count", 0x8f7ff054, 1},
	{"Host Hub D PKTS IN host", 0x8d010000, 32},
	{"Host Hub D PKTS IN plugin", 0x8d010100, 32},
	{"Host Hub D PKTS IN OVS counter", 0x8d010200, 32},
	{"Host Hub D PKTS_OUT", 0x8d010300, 32},
};

static struct efx_mc_reg_table efx_dump_sss_host_rx[] = {
	{"DMAC-IC2S(Frm SSS) PKT CNT", 0x88001108, 1},
	{"DMAC_ALERT", 0x8800007c, 1},
	{"DMAC_ERR_STICKY_REG", 0x880000c0, 1},
	{"DMAC_C2H_DROP_CTR_REG", 0x88000108, 1},
	{"EVC ERR STICKY", 0x880000cc, 1},
	{"EVC Total events", 0x88001f10, 1},
	{"EVC RX event packt count (unmoderated)", 0x88001fac, 1},
	{"EVC TX event DSC (unmoderated)", 0x88001fb0, 1},
	{"EVC RX event stimulus (EF100)", 0x88001fb4, 1},
	{"EVC TX event stimulus (per packet)", 0x88001fb8, 1},
	{"QDMA C2H stat debug", 0xfe068b1c, 1},
	{"QDMA C2H ERR STAT", 0xfe068af0, 1},
	{"QDMA STAT WRB IN", 0xfe068b34, 1},
	{"QDMA STAT WRB OUT", 0xfe068b38, 1},
	{"QDMA STAT WRB DRP", 0xfe068b3c, 1},
	{"HAH cnt_nw_tx_dbl", 0xfd154800, 1},
	{"HAH cnt_nw_rx_dbl", 0xfd154804, 1},
	{"HAH cnt_nw_virtio_dbl", 0xfd154808, 1},
};

/* indir_table read sequence:
 * write %base+8 %addr
 * if (%read_base) read %base
 * val = read %base+4
 */
struct efx_mc_reg_indir_table {
	const char *name;
	u32 base;
	u32 addr;
	bool read_base;
};

static struct efx_mc_reg_indir_table efx_dump_sched_dest_creds[] = {
	{"Hub-H2C scheduler destination credit ID 0", 0x8b020060, 0x620e0004, true},
	{"Hub-H2C scheduler destination credit ID 1", 0x8b020060, 0x620e000c, true},
	{"Hub-HA TX to hub-b scheduler destination credit ID 0", 0x8c000060, 0x620e0004, true},
	{"Hub-HB TX/PL to hub-R scheduler destination credit ID 0", 0x8c400060, 0x620e0004, true},
	{"Hub-HB RX Net to hub-R scheduler destination credit ID 1", 0x8c400060, 0x620e000c, true},
	{"Hub-R host to net to hub-C scheduler destination credit ID 0", 0x8c800060, 0x620e0004, true},
	{"Hub-R net to host to hub-C scheduler destination credit ID 0", 0x8c800060, 0x620e000c, true},
	{"Hub-NetTX net to MAC scheduler destination credit ID 0", 0x8cc40060, 0x620e0004, true},
	{"Hub-NA from MAC to hub-B scheduler destination credit ID 0", 0x8d400060, 0x620e0004, true},
	{"Hub-HC hub-C to hub D scheduler destination credit ID 0", 0x8cc00060, 0x620e0004, true},
	{"Hub-D scheduler destination credit ID 0", 0x8d000060, 0x620e0004, true},
	{"Hub-D scheduler destination credit ID 1", 0x8d000060, 0x620e000c, true},
};

static struct efx_mc_reg_table efx_dump_xon_xoff[] = {
	{"XOFF Count", 0x8a1006bc, 1},
	{"XON Count", 0x8a1006b8, 1},
};
static struct efx_mc_reg_indir_table efx_dump_xon_state[] = {
	{"XON", 0x8cc40060, 0x600E0004, false},
};

static int efx_mcdi_dump_reg(struct efx_nic *efx, struct efx_mc_reg_table *reg)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_READ32_IN_LEN);
	efx_dword_t *outbuf;
	unsigned int i;
	size_t outlen;
	int rc;

	outbuf = kzalloc(MC_CMD_READ32_OUT_LEN(reg->size), GFP_KERNEL);
	if (!outbuf)
		return -ENOMEM;
	MCDI_SET_DWORD(inbuf, READ32_IN_ADDR, reg->addr);
	MCDI_SET_DWORD(inbuf, READ32_IN_NUMWORDS, reg->size);
	rc = efx_mcdi_rpc(efx, MC_CMD_READ32, inbuf, sizeof(inbuf),
			  outbuf, MC_CMD_READ32_OUT_LEN(reg->size), &outlen);
	if (rc < 0)
		goto out_free;
	if (reg->size == 1 && outlen >= MC_CMD_READ32_OUT_LEN(1))
		netif_err(efx, tx_err, efx->net_dev,
			  "reg %s: %#010x\n", reg->name,
			  MCDI_ARRAY_DWORD(outbuf, READ32_OUT_BUFFER, 0));
	else
		for (i = 0; i < outlen && i < reg->size; i++) {
			u32 val = MCDI_ARRAY_DWORD(outbuf, READ32_OUT_BUFFER, i);

			if (val || !i)
				netif_err(efx, tx_err, efx->net_dev,
					  "reg %s [%#06x]: %#010x\n", reg->name, i,
					  val);
		}
out_free:
	kfree(outbuf);
	return rc;
}

static int efx_mcdi_dump_reg_table(struct efx_nic *efx,
				   struct efx_mc_reg_table *regs,
				   unsigned int nregs)
{
	int rc, fails = 0;
	unsigned int i;

	for (i = 0; i < nregs; i++) {
		rc = efx_mcdi_dump_reg(efx, regs + i);
		/* If too many failures, give up (and return
		 * the last failure's rc)
		 */
		if (rc < 0 && ++fails >= 3)
			return rc;
	}
	return 0;
}

static int efx_mcdi_write32(struct efx_nic *efx, u32 addr, u32 value)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_WRITE32_IN_LEN(1));

	BUILD_BUG_ON(MC_CMD_WRITE32_OUT_LEN);
	MCDI_SET_DWORD(inbuf, WRITE32_IN_ADDR, addr);
	MCDI_SET_DWORD(inbuf, WRITE32_IN_BUFFER, value);
	return efx_mcdi_rpc(efx, MC_CMD_WRITE32, inbuf, sizeof(inbuf),
			    NULL, 0, NULL);
}

static int efx_mcdi_dump_reg_indir(struct efx_nic *efx, struct efx_mc_reg_indir_table *reg)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_READ32_OUT_LEN(1));
	MCDI_DECLARE_BUF(inbuf, MC_CMD_READ32_IN_LEN);
	size_t outlen;
	int rc;

	rc = efx_mcdi_write32(efx, reg->base + 8, reg->addr);
	if (rc < 0)
		return rc;
	if (reg->read_base) {
		MCDI_SET_DWORD(inbuf, READ32_IN_ADDR, reg->base);
		MCDI_SET_DWORD(inbuf, READ32_IN_NUMWORDS, 1);
		rc = efx_mcdi_rpc(efx, MC_CMD_READ32, inbuf, sizeof(inbuf),
				  NULL, 0, NULL);
		if (rc < 0)
			return rc;
	}
	MCDI_SET_DWORD(inbuf, READ32_IN_ADDR, reg->base + 4);
	MCDI_SET_DWORD(inbuf, READ32_IN_NUMWORDS, 1);
	rc = efx_mcdi_rpc(efx, MC_CMD_READ32, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc < 0)
		return rc;
	if (outlen < sizeof(outbuf))
		return -EIO;
	netif_err(efx, tx_err, efx->net_dev,
		  "reg %s: %#010x\n", reg->name,
		  MCDI_ARRAY_DWORD(outbuf, READ32_OUT_BUFFER, 0));
	return 0;
}

static int efx_mcdi_dump_reg_indir_table(struct efx_nic *efx,
					 struct efx_mc_reg_indir_table *regs,
					 unsigned int nregs)
{
	int rc, fails = 0;
	unsigned int i;

	for (i = 0; i < nregs; i++) {
		rc = efx_mcdi_dump_reg_indir(efx, regs + i);
		/* If too many failures, give up (and return
		 * the last failure's rc)
		 */
		if (rc < 0 && ++fails >= 3)
			return rc;
	}
	return 0;
}

static const char *efx_mcdi_dump_sched_names[] = {
  [SCHED_CREDIT_CHECK_RESULT_HUB_HOST_A] = "HUB_HOST_A",
  [SCHED_CREDIT_CHECK_RESULT_HUB_NET_A] = "HUB_NET_A",
  [SCHED_CREDIT_CHECK_RESULT_HUB_B] = "HUB_B",
  [SCHED_CREDIT_CHECK_RESULT_HUB_HOST_C] = "HUB_HOST_C",
  [SCHED_CREDIT_CHECK_RESULT_HUB_NET_TX] = "HUB_NET_TX",
  [SCHED_CREDIT_CHECK_RESULT_HUB_HOST_D] = "HUB_HOST_D",
  [SCHED_CREDIT_CHECK_RESULT_HUB_REPLAY] = "HUB_REPLAY",
  [SCHED_CREDIT_CHECK_RESULT_DMAC_H2C] = "DMAC_H2C",
};

/* Returns number of pages, or negative error */
static int efx_mcdi_dump_sched_cred_page(struct efx_nic *efx, u32 page,
					 u32 flags, u32 *generation_count)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_CHECK_SCHEDULER_CREDITS_IN_LEN);
	u32 gen_count_actual, num_results, i;
	efx_dword_t *outbuf;
	size_t outlen;
	int rc;

	outbuf = kzalloc(MC_CMD_CHECK_SCHEDULER_CREDITS_OUT_LENMAX_MCDI2, GFP_KERNEL);
	if (!outbuf)
		return -ENOMEM;

	MCDI_SET_DWORD(inbuf, CHECK_SCHEDULER_CREDITS_IN_FLAGS, flags);
	MCDI_SET_DWORD(inbuf, CHECK_SCHEDULER_CREDITS_IN_PAGE, page);

	rc = efx_mcdi_rpc(efx, MC_CMD_CHECK_SCHEDULER_CREDITS,
			  inbuf, sizeof(inbuf), outbuf,
			  MC_CMD_CHECK_SCHEDULER_CREDITS_OUT_LENMAX_MCDI2, &outlen);
	if (rc)
		goto out_free;
	if (outlen < MC_CMD_CHECK_SCHEDULER_CREDITS_OUT_RESULTS_OFST)
		goto out_free;
	gen_count_actual = MCDI_DWORD(outbuf, CHECK_SCHEDULER_CREDITS_OUT_GENERATION);
	if (!page)
		*generation_count = gen_count_actual;
	if (gen_count_actual != *generation_count) {
		rc = -EAGAIN;
		goto out_free;
	}
	num_results = MCDI_DWORD(outbuf, CHECK_SCHEDULER_CREDITS_OUT_RESULTS_THIS_PAGE);
	for (i = 0; i < num_results; i++) {
		MCDI_DECLARE_STRUCT_PTR(result) = MCDI_ARRAY_STRUCT_PTR(outbuf,
					CHECK_SCHEDULER_CREDITS_OUT_RESULTS, i);
		u8 sched_idx = MCDI_STRUCT_BYTE(result, SCHED_CREDIT_CHECK_RESULT_SCHED_INSTANCE);
		u8 node_type = MCDI_STRUCT_BYTE(result, SCHED_CREDIT_CHECK_RESULT_NODE_TYPE);

		netif_err(efx, tx_err, efx->net_dev,
			  "%10s: %s id %d level %d: Exp %#x got %#x\n",
			  sched_idx < ARRAY_SIZE(efx_mcdi_dump_sched_names) ?
					efx_mcdi_dump_sched_names[sched_idx] : "???",
			  node_type == SCHED_CREDIT_CHECK_RESULT_DEST ? "  Dest" : "Source",
			  MCDI_STRUCT_DWORD(result, SCHED_CREDIT_CHECK_RESULT_NODE_INDEX),
			  MCDI_STRUCT_WORD(result, SCHED_CREDIT_CHECK_RESULT_NODE_LEVEL),
			  MCDI_STRUCT_DWORD(result, SCHED_CREDIT_CHECK_RESULT_EXPECTED_CREDITS),
			  MCDI_STRUCT_DWORD(result, SCHED_CREDIT_CHECK_RESULT_ACTUAL_CREDITS));
	}
	rc = MCDI_DWORD(outbuf, CHECK_SCHEDULER_CREDITS_OUT_NUM_PAGES);
out_free:
	kfree(outbuf);
	return rc;
}

static int efx_mcdi_dump_sched_cred(struct efx_nic *efx)
{
	u32 generation_count = 0, num_pages = 1, page;
	int rc;

	for (page = 0; page < num_pages; page++) {
		rc = efx_mcdi_dump_sched_cred_page(efx, page, 0,
						   &generation_count);
		if (rc == -EAGAIN) {
			/* Someone else started a dump in the middle of ours,
			 * causing generation counts to mismatch.  Start over.
			 */
			netif_err(efx, tx_err, efx->net_dev, "***RETRY***\n");
			page = -1;
			continue;
		}
		if (rc < 0)
			return rc;
		if (!page)
			num_pages = rc;
	}
	return 0;
}

int efx_ef100_dump_sss_regs(struct efx_nic *efx)
{
	efx_mcdi_dump_reg_table(efx, efx_dump_misc,
				ARRAY_SIZE(efx_dump_misc));
	efx_mcdi_dump_reg_table(efx, efx_dump_sss_host_tx,
				ARRAY_SIZE(efx_dump_sss_host_tx));
	efx_mcdi_dump_reg_table(efx, efx_dump_sss_rx_path,
				ARRAY_SIZE(efx_dump_sss_rx_path));
	efx_mcdi_dump_reg_table(efx, efx_dump_sss_host_rx,
				ARRAY_SIZE(efx_dump_sss_host_rx));
	efx_mcdi_dump_reg_indir_table(efx, efx_dump_sched_dest_creds,
				      ARRAY_SIZE(efx_dump_sched_dest_creds));
	efx_mcdi_dump_sched_cred(efx);
	efx_mcdi_dump_reg_table(efx, efx_dump_xon_xoff,
				ARRAY_SIZE(efx_dump_xon_xoff));
	efx_mcdi_dump_reg_indir_table(efx, efx_dump_xon_state,
				      ARRAY_SIZE(efx_dump_xon_state));
	return 0;
}

#ifdef SFC_NAPI_DEBUG
#include "ef100_nic.h"
#include "ef100_regs.h"

#define MAX_EVENTS_TO_DUMP 0xffff

static unsigned int ef100_dump_pending_events(struct efx_channel *channel,
					      bool print)
{
	unsigned int spent = 0;
	struct efx_nic *efx = channel->efx;
	struct ef100_nic_data *nic_data;
	bool evq_phase, old_evq_phase;
	unsigned int read_ptr;
	efx_qword_t *p_event;
	bool ev_phase;

	nic_data = efx->nic_data;
	evq_phase = test_bit (channel->channel, nic_data->evq_phases);
	old_evq_phase = evq_phase;
	read_ptr = channel->eventq_read_ptr;

	for (;;) {
		p_event = efx_event(channel, read_ptr);

                ev_phase = !!EFX_QWORD_FIELD(*p_event, ESF_GZ_EV_RXPKTS_PHASE);
                if (ev_phase != evq_phase)
                        break;

		if (print && spent < MAX_EVENTS_TO_DUMP) {
			netif_dbg(efx, drv, efx->net_dev,
				  "unprocessed event on %d " EFX_QWORD_FMT "\n",
	                          channel->channel, EFX_QWORD_VAL(*p_event));
		}
		++spent;

		++read_ptr;
                if ((read_ptr & channel->eventq_mask) == 0)
                        evq_phase = !evq_phase;
	}

	return spent;
}

/* dump time since last irq,
 * time since last napi poll,
 * and unprocessed events
 */
void efx_ef100_dump_napi_debug(struct efx_nic *efx)
{
	struct efx_channel *channel;

	int now = jiffies;

	efx_for_each_channel(channel, efx) {
		unsigned int remaining_events = ef100_dump_pending_events(channel, false);

		netif_dbg(efx, drv, efx->net_dev,
			  "channel %d irq %u ms ago, poll start %u ms ago, poll end %u ms ago, spent/budget/done = %d/%d/%d, reprime %u ms ago, %u events pending\n",
			  channel->channel,
			  jiffies_to_msecs(now - channel->last_irq_jiffies),
			  jiffies_to_msecs(now - channel->last_napi_poll_jiffies),
			  jiffies_to_msecs(now - channel->last_napi_poll_end_jiffies),
			  channel->last_spent, channel->last_budget, channel->last_complete_done,
			  jiffies_to_msecs(now - channel->last_irq_reprime_jiffies),
			  remaining_events);
	}
	efx_for_each_channel(channel, efx)
		ef100_dump_pending_events(channel, true);
}
#else
void efx_ef100_dump_napi_debug(struct efx_nic *efx) {}
#endif

