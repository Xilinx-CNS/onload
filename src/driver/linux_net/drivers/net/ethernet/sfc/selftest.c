/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/kernel_stat.h>
#include <linux/pci.h>
#include <linux/ethtool.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include "net_driver.h"
#include "efx.h"
#include "nic.h"
#include "efx_common.h"
#include "efx_channels.h"
#include "tx_common.h"
#include "selftest.h"
#include "workarounds.h"
#include "mcdi_port_common.h"

/* IRQ latency can be enormous because:
 * - All IRQs may be disabled on a CPU for a *long* time by e.g. a
 *   slow serial console or an old IDE driver doing error recovery
 * - The PREEMPT_RT patches mostly deal with this, but also allow a
 *   tasklet or normal task to be given higher priority than our IRQ
 *   threads
 * Try to avoid blaming the hardware for this.
 */
#define IRQ_TIMEOUT HZ

/*
 * Loopback test packet structure
 *
 * The self-test should stress every RSS vector, and unfortunately
 * Falcon only performs RSS on TCP/UDP packets.
 */
struct efx_loopback_payload {
	struct ethhdr header;
	struct iphdr ip;
	struct udphdr udp;
	__be16 iteration;
	char msg[64];
} __packed;

/* Loopback test source MAC address */
static const u8 payload_source[ETH_ALEN] __aligned(2) = {
	0x00, 0x0f, 0x53, 0x1b, 0x1b, 0x1b,
};
/* Loopback test dest MAC address */
static const u8 payload_dest[ETH_ALEN] __aligned(2) = {
	0x00, 0x0f, 0x53, 0x1c, 0x1c, 0x1c,
};

static const char payload_msg[] =
	"Hello world! This is an Efx loopback test in progress!";

/**
 * efx_loopback_state - persistent state during a loopback selftest
 * @flush:		Drop all packets in efx_loopback_rx_packet
 * @packet_count:	Number of packets being used in this test
 * @skbs:		An array of skbs transmitted
 * @offload_csum:	Checksums are being offloaded
 * @rx_good:		RX good packet count
 * @rx_bad:		RX bad packet count
 * @payload:		Payload used in tests
 */
struct efx_loopback_state {
	bool flush;
	int packet_count;
	struct sk_buff **skbs;
	bool offload_csum;
	atomic_t rx_good;
	atomic_t rx_bad;
	struct efx_loopback_payload payload;
};

/* How long to wait for all the packets to arrive (in ms) */
#define LOOPBACK_TIMEOUT_MS 1000

/**************************************************************************
 *
 * MII, NVRAM and register tests
 *
 **************************************************************************/

static int efx_test_phy_alive(struct efx_nic *efx, struct efx_self_tests *tests)
{
	int rc = 0;

	rc = efx_mcdi_phy_test_alive(efx);
	netif_dbg(efx, drv, efx->net_dev, "%s PHY liveness selftest\n",
		  rc ? "Failed" : "Passed");
	tests->phy_alive = rc ? -1 : 1;

	return rc;
}

static int efx_test_nvram(struct efx_nic *efx, struct efx_self_tests *tests)
{
	int rc = 0;

	if (efx->type->test_nvram) {
		rc = efx->type->test_nvram(efx);
		if (rc == -EPERM)
			rc = 0;
		else
			tests->nvram = rc ? -1 : 1;
	}

	return rc;
}

static void memtest_simple(unsigned int id, efx_qword_t *reg, int a, int b)
{
	EFX_POPULATE_QWORD_2(*reg, EFX_DWORD_0, a, EFX_DWORD_1, b);
}

static void memtest_changing_bytes(unsigned int id, efx_qword_t *reg,
				   int a, int b)
{
	int i;
	u8 *byte;
	for (i = 0; i < sizeof(efx_qword_t); i++) {
		unsigned int addr = id * sizeof(efx_qword_t) + i;
		byte = (u8 *)reg + i;
		if ((addr >> 8) == 0)
			*byte = (u8) (addr % 257);
		else
			*byte = (u8) ~((addr >> 8) % 257);

		if (addr & 0x40)
			*byte = ~*byte;
	}
}

static void memtest_bit_sweep(unsigned int id, efx_qword_t *reg,
			      int a, int b)
{
	int bit = id % 64;
	int xor = (id & 64) ? ~0 : 0;

	EFX_POPULATE_QWORD_2(*reg,
			     EFX_DWORD_0, (bit < 32 ? bit : 0) ^ xor,
			     EFX_DWORD_1, (bit >= 32 ? bit - 32 : 0) ^ xor);
}

struct memtest {
	void (*pattern)(unsigned int id, efx_qword_t *reg, int a, int b);
	int a;
	int b;
};

static struct memtest memtests[] = {
	{memtest_simple, 0x55AA55AA, 0x55AA55AA},
	{memtest_simple, 0xAA55AA55, 0xAA55AA55},
	{memtest_changing_bytes, 0, 0},
	{memtest_bit_sweep, 0, 0},
};

int efx_test_memory(struct efx_nic *efx)
{
	int rc, i;

	/* Test SRAM and register tables */
	for (i = 0; i < ARRAY_SIZE(memtests); ++i) {
		rc = efx->type->test_memory(efx, memtests[i].pattern,
					    memtests[i].a, memtests[i].b);
		if (rc)
			break;
	}
	return rc;
}

/**************************************************************************
 *
 * Interrupt and event queue testing
 *
 **************************************************************************/

/* Test generation and receipt of interrupts */
static int efx_test_interrupts(struct efx_nic *efx,
			       struct efx_self_tests *tests)
{
	unsigned long timeout, wait;
	int cpu;
	int rc;

	netif_dbg(efx, drv, efx->net_dev, "testing interrupts\n");
	tests->interrupt = -1;

	rc = efx_nic_irq_test_start(efx);
	if (rc == -EOPNOTSUPP) {
		netif_dbg(efx, drv, efx->net_dev,
			  "direct interrupt testing not supported\n");
		tests->interrupt = 0;
		return 0;
	}

	timeout = jiffies + IRQ_TIMEOUT;
	wait = 1;

	/* Wait for arrival of test interrupt. */
	netif_dbg(efx, drv, efx->net_dev, "waiting for test interrupt\n");
	do {
		schedule_timeout_uninterruptible(wait);
		cpu = efx_nic_irq_test_irq_cpu(efx);
		if (cpu >= 0)
			goto success;
		wait *= 2;
	} while (time_before(jiffies, timeout));

	netif_err(efx, drv, efx->net_dev, "timed out waiting for interrupt\n");
	return -ETIMEDOUT;

 success:
	netif_dbg(efx, drv, efx->net_dev, "%s test interrupt seen on CPU%d\n",
		  INT_MODE(efx), cpu);
	tests->interrupt = 1;
	return 0;
}

/* Test generation and receipt of interrupting events */
static int efx_test_eventq_irq(struct efx_nic *efx,
			       struct efx_self_tests *tests)
{
	unsigned long *napi_ran, *dma_pend, *int_pend;
	int dma_pending_count, int_pending_count;
	unsigned long timeout, wait;
	struct efx_channel *channel;
	unsigned int *read_ptr;
	int bitmap_size;
	int rc;

	read_ptr = kcalloc(efx_channels(efx), sizeof(*read_ptr), GFP_KERNEL);

	bitmap_size = DIV_ROUND_UP(efx_channels(efx), BITS_PER_LONG);

	napi_ran = kzalloc(bitmap_size * sizeof(unsigned long), GFP_KERNEL);
	dma_pend = kzalloc(bitmap_size * sizeof(unsigned long), GFP_KERNEL);
	int_pend = kzalloc(bitmap_size * sizeof(unsigned long), GFP_KERNEL);

	if (!read_ptr || !napi_ran || !dma_pend || !int_pend) {
		rc = -ENOMEM;
		goto out_free;
	}

	dma_pending_count = 0;
	int_pending_count = 0;

	efx_for_each_channel(channel, efx) {
		read_ptr[channel->channel] = channel->eventq_read_ptr;
		set_bit(channel->channel, dma_pend);
		set_bit(channel->channel, int_pend);
		efx_nic_event_test_start(channel);
		dma_pending_count++;
		int_pending_count++;
	}

	timeout = jiffies + IRQ_TIMEOUT;
	wait = 1;

	/* Wait for arrival of interrupts.  NAPI processing may or may
	 * not complete in time, but we can cope in any case.
	 */
	do {
		schedule_timeout_uninterruptible(wait);

		efx_for_each_channel(channel, efx) {
			efx_stop_eventq(channel);
			if (channel->eventq_read_ptr !=
			    read_ptr[channel->channel]) {
				set_bit(channel->channel, napi_ran);
				clear_bit(channel->channel, dma_pend);
				clear_bit(channel->channel, int_pend);
				dma_pending_count--;
				int_pending_count--;
			} else {
				if (efx_nic_event_present(channel)) {
					clear_bit(channel->channel, dma_pend);
					dma_pending_count--;
				}
				if (efx_nic_event_test_irq_cpu(channel) >= 0) {
					clear_bit(channel->channel, int_pend);
					int_pending_count--;
				}
			}
			efx_start_eventq(channel);
		}

		wait *= 2;
	} while ((dma_pending_count || int_pending_count) &&
		 time_before(jiffies, timeout));

	efx_for_each_channel(channel, efx) {
		bool dma_seen = !test_bit(channel->channel, dma_pend);
		bool int_seen = !test_bit(channel->channel, int_pend);

		tests->eventq_dma[channel->channel] = dma_seen ? 1 : -1;
		tests->eventq_int[channel->channel] = int_seen ? 1 : -1;

		if (dma_seen && int_seen) {
			netif_dbg(efx, drv, efx->net_dev,
				  "channel %d event queue passed (with%s NAPI)\n",
				  channel->channel,
				  test_bit(channel->channel, napi_ran) ?
				  "" : "out");
		} else {
			/* Report failure and whether either interrupt or DMA
			 * worked
			 */
			netif_err(efx, drv, efx->net_dev,
				  "channel %d timed out waiting for event queue\n",
				  channel->channel);
			if (int_seen)
				netif_err(efx, drv, efx->net_dev,
					  "channel %d saw interrupt "
					  "during event queue test\n",
					  channel->channel);
			if (dma_seen)
				netif_err(efx, drv, efx->net_dev,
					  "channel %d event was generated, but "
					  "failed to trigger an interrupt\n",
					  channel->channel);
		}
	}

	rc = (dma_pending_count || int_pending_count) ? -ETIMEDOUT : 0;

out_free:
	kfree(int_pend);
	kfree(dma_pend);
	kfree(napi_ran);
	kfree(read_ptr);

	return rc;
}

static int efx_test_phy(struct efx_nic *efx, struct efx_self_tests *tests,
			unsigned int flags)
{
	int rc;

	mutex_lock(&efx->mac_lock);
	rc = efx_mcdi_phy_run_tests(efx, tests->phy_ext, flags);
	mutex_unlock(&efx->mac_lock);
	if (rc == -EPERM)
		rc = 0;
	else
		netif_info(efx, drv, efx->net_dev,
			   "%s phy selftest\n", rc ? "Failed" : "Passed");
	return rc;
}

/**************************************************************************
 *
 * Loopback testing
 * NB Only one loopback test can be executing concurrently.
 *
 **************************************************************************/

/* Loopback test RX callback
 * This is called for each received packet during loopback testing.
 */
void efx_loopback_rx_packet(struct efx_nic *efx,
			    const char *buf_ptr, int pkt_len)
{
	struct efx_loopback_state *state = efx->loopback_selftest;
	struct efx_loopback_payload *received;
	struct efx_loopback_payload *payload;

	BUG_ON(!buf_ptr);

	/* If we are just flushing, then drop the packet */
	if ((state == NULL) || state->flush)
		return;

	payload = &state->payload;

	received = (struct efx_loopback_payload *) buf_ptr;
	received->ip.saddr = payload->ip.saddr;
	if (state->offload_csum)
		received->ip.check = payload->ip.check;

	/* Check that header exists */
	if (pkt_len < sizeof(received->header)) {
		netif_err(efx, drv, efx->net_dev,
			  "saw runt RX packet (length %d) in %s loopback "
			  "test\n", pkt_len, LOOPBACK_MODE(efx));
		goto err;
	}

	/* Check that the ethernet header exists */
	if (memcmp(&received->header, &payload->header, ETH_HLEN) != 0) {
		netif_err(efx, drv, efx->net_dev,
			  "saw non-loopback RX packet in %s loopback test\n",
			  LOOPBACK_MODE(efx));
		goto err;
	}

	/* Check packet length */
	if (pkt_len != sizeof(*payload)) {
		netif_err(efx, drv, efx->net_dev,
			  "saw incorrect RX packet length %d (wanted %d) in "
			  "%s loopback test\n", pkt_len, (int)sizeof(*payload),
			  LOOPBACK_MODE(efx));
		goto err;
	}

	/* Check that IP header matches */
	if (memcmp(&received->ip, &payload->ip, sizeof(payload->ip)) != 0) {
		netif_err(efx, drv, efx->net_dev,
			  "saw corrupted IP header in %s loopback test\n",
			  LOOPBACK_MODE(efx));
		goto err;
	}

	/* Check that msg and padding matches */
	if (memcmp(&received->msg, &payload->msg, sizeof(received->msg)) != 0) {
		netif_err(efx, drv, efx->net_dev,
			  "saw corrupted RX packet in %s loopback test\n",
			  LOOPBACK_MODE(efx));
		goto err;
	}

	/* Check that iteration matches */
	if (received->iteration != payload->iteration) {
		netif_err(efx, drv, efx->net_dev,
			  "saw RX packet from iteration %d (wanted %d) in "
			  "%s loopback test\n", ntohs(received->iteration),
			  ntohs(payload->iteration), LOOPBACK_MODE(efx));
		goto err;
	}

	/* Increase correct RX count */
	netif_vdbg(efx, drv, efx->net_dev,
		   "got loopback RX in %s loopback test\n", LOOPBACK_MODE(efx));

	atomic_inc(&state->rx_good);
	return;

 err:
#ifdef DEBUG
	if (atomic_read(&state->rx_bad) == 0) {
		netif_err(efx, drv, efx->net_dev, "received packet:\n");
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_OFFSET, 0x10, 1,
			       buf_ptr, pkt_len, 0);
		netif_err(efx, drv, efx->net_dev, "expected packet:\n");
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_OFFSET, 0x10, 1,
			       &state->payload, sizeof(state->payload), 0);
	}
#endif
	atomic_inc(&state->rx_bad);
}

/* Initialise an efx_selftest_state for a new iteration */
static void efx_iterate_state(struct efx_nic *efx)
{
	struct efx_loopback_state *state = efx->loopback_selftest;
	struct efx_loopback_payload *payload = &state->payload;

	/* Initialise the layerII header */
	ether_addr_copy((u8 *)&payload->header.h_dest, payload_dest);
	ether_addr_copy((u8 *)&payload->header.h_source, payload_source);
	payload->header.h_proto = htons(ETH_P_IP);

	/* saddr set later and used as incrementing count */
	payload->ip.daddr = htonl(INADDR_LOOPBACK);
	payload->ip.ihl = 5;
	payload->ip.check = (__force __sum16) htons(0xdead);
	payload->ip.tot_len = htons(sizeof(*payload) - sizeof(struct ethhdr));
	payload->ip.version = IPVERSION;
	payload->ip.protocol = IPPROTO_UDP;

	/* Initialise udp header */
	payload->udp.source = 0;
	payload->udp.len = htons(sizeof(*payload) - sizeof(struct ethhdr) -
				 sizeof(struct iphdr));
	payload->udp.check = 0;	/* checksum ignored */

	/* Fill out payload */
	payload->iteration = htons(ntohs(payload->iteration) + 1);
	memcpy(&payload->msg, payload_msg, sizeof(payload_msg));

	/* Fill out remaining state members */
	atomic_set(&state->rx_good, 0);
	atomic_set(&state->rx_bad, 0);
	smp_wmb();
}

static int efx_begin_loopback(struct efx_tx_queue *tx_queue)
{
	struct efx_nic *efx = tx_queue->efx;
	struct efx_loopback_state *state = efx->loopback_selftest;
	struct efx_loopback_payload *payload;
	struct sk_buff *skb;
	int i;
	int rc;

	/* Transmit N copies of buffer */
	for (i = 0; i < state->packet_count; i++) {
		/* Allocate an skb, holding an extra reference for
		 * transmit completion counting */
		skb = alloc_skb(sizeof(state->payload), GFP_KERNEL);
		if (!skb)
			return -ENOMEM;
		state->skbs[i] = skb;
		skb_get(skb);

		/* Copy the payload in, incrementing the source address to
		 * exercise the rss vectors */
		payload = skb_put(skb, sizeof(state->payload));
		memcpy(payload, &state->payload, sizeof(state->payload));
		payload->ip.saddr = htonl(INADDR_LOOPBACK | (i << 2));

		/* Ensure everything we've written is visible to the
		 * interrupt handler. */
		smp_wmb();

		netif_tx_lock_bh(efx->net_dev);
		rc = efx_enqueue_skb(tx_queue, skb);
		netif_tx_unlock_bh(efx->net_dev);

		if (rc) {
			netif_err(efx, drv, efx->net_dev,
				  "TX queue %d could not transmit packet %d of "
				  "%d in %s loopback test\n", tx_queue->queue,
				  i + 1, state->packet_count,
				  LOOPBACK_MODE(efx));

			/* Defer cleaning up the other skbs for the caller */
			kfree_skb(skb);
			return -EPIPE;
		}
	}

	return 0;
}

static int efx_poll_loopback(struct efx_nic *efx)
{
	struct efx_loopback_state *state = efx->loopback_selftest;

	return atomic_read(&state->rx_good) == state->packet_count;
}

static int efx_end_loopback(struct efx_tx_queue *tx_queue,
			    struct efx_loopback_self_tests *lb_tests)
{
	struct efx_nic *efx = tx_queue->efx;
	struct efx_loopback_state *state = efx->loopback_selftest;
	struct sk_buff *skb;
	int tx_done = 0, rx_good, rx_bad;
	int i, rc = 0;

	netif_tx_lock_bh(efx->net_dev);

	/* Count the number of tx completions, and decrement the refcnt. Any
	 * skbs not already completed will be free'd when the queue is flushed */
	for (i = 0; i < state->packet_count; i++) {
		skb = state->skbs[i];
		if (skb && !skb_shared(skb))
			++tx_done;
		dev_kfree_skb(skb);
	}

	netif_tx_unlock_bh(efx->net_dev);

	/* Check TX completion and received packet counts */
	rx_good = atomic_read(&state->rx_good);
	rx_bad = atomic_read(&state->rx_bad);
	if (tx_done != state->packet_count) {
		netif_err(efx, drv, efx->net_dev,
			  "TX queue %d saw only %d out of an expected %d "
			  "TX completion events in %s loopback test\n",
			  tx_queue->queue, tx_done, state->packet_count,
			  LOOPBACK_MODE(efx));
		rc = -ETIMEDOUT;
		efx_purge_tx_queue(tx_queue);
		/* Allow to fall through so we see the RX errors as well */
	}

	/* We may always be up to a flush away from our desired packet total */
	if (rx_good != state->packet_count) {
		netif_dbg(efx, drv, efx->net_dev,
			  "TX queue %d saw only %d out of an expected %d "
			  "received packets in %s loopback test\n",
			  tx_queue->queue, rx_good, state->packet_count,
			  LOOPBACK_MODE(efx));
		rc = -ETIMEDOUT;
		/* Fall through */
	}

	/* Update loopback test structure */
	lb_tests->tx_sent[tx_queue->queue] += state->packet_count;
	lb_tests->tx_done[tx_queue->queue] += tx_done;
	lb_tests->rx_good += rx_good;
	lb_tests->rx_bad += rx_bad;

	return rc;
}

static int
efx_test_loopback(struct efx_tx_queue *tx_queue,
		  struct efx_loopback_self_tests *lb_tests)
{
	struct efx_nic *efx = tx_queue->efx;
	struct efx_loopback_state *state = efx->loopback_selftest;
	int i, begin_rc, end_rc;

	for (i = 0; i < 3; i++) {
		/* Determine how many packets to send */
		state->packet_count = efx->txq_entries / 3;
		state->packet_count = min(1 << (i << 2), state->packet_count);
		state->skbs = kcalloc(state->packet_count,
				      sizeof(state->skbs[0]), GFP_KERNEL);
		if (!state->skbs)
			return -ENOMEM;
		state->flush = false;

		netif_dbg(efx, drv, efx->net_dev,
			  "TX queue %d testing %s loopback with %d packets\n",
			  tx_queue->queue, LOOPBACK_MODE(efx),
			  state->packet_count);

		efx_iterate_state(efx);
		begin_rc = efx_begin_loopback(tx_queue);

		/* This will normally complete very quickly, but be
		 * prepared to wait much longer. */
		msleep(1);
		if (!efx_poll_loopback(efx)) {
			msleep(LOOPBACK_TIMEOUT_MS);
			efx_poll_loopback(efx);
		}

		end_rc = efx_end_loopback(tx_queue, lb_tests);
		kfree(state->skbs);

		if (begin_rc || end_rc) {
			/* Wait a while to ensure there are no packets
			 * floating around after a failure. */
			schedule_timeout_uninterruptible(HZ / 10);
			return begin_rc ? begin_rc : end_rc;
		}
	}

	netif_dbg(efx, drv, efx->net_dev,
		  "TX queue %d passed %s loopback test with a burst length "
		  "of %d packets\n", tx_queue->queue, LOOPBACK_MODE(efx),
		  state->packet_count);

	return 0;
}

/* Wait for link up. On Falcon, we would prefer to rely on efx_monitor, but
 * any contention on the mac lock (via e.g. efx_mac_mcast_work) causes it
 * to delay and retry. Therefore, it's safer to just poll directly. Wait
 * for link up and any faults to dissipate. */
static int efx_wait_for_link(struct efx_nic *efx)
{
	struct efx_link_state *link_state = &efx->link_state;
	int count, link_up_count = 0;
	bool link_up;

	for (count = 0; count < 40; count++) {
		schedule_timeout_uninterruptible(HZ / 10);

		if (efx->type->monitor != NULL) {
			mutex_lock(&efx->mac_lock);
			efx->type->monitor(efx);
			mutex_unlock(&efx->mac_lock);
		}

		mutex_lock(&efx->mac_lock);
		link_up = link_state->up;
		if (link_up)
			link_up = !efx->type->check_mac_fault(efx);
		mutex_unlock(&efx->mac_lock);

		if (link_up) {
			if (++link_up_count == 2)
				return 0;
		} else {
			link_up_count = 0;
		}
	}

	return -ETIMEDOUT;
}

static int efx_test_loopbacks(struct efx_nic *efx, struct efx_self_tests *tests,
			      unsigned int loopback_modes)
{
	enum efx_loopback_mode mode;
	struct efx_loopback_state *state;
	struct efx_channel *channel =
		efx_get_channel(efx, efx->tx_channel_offset);
	struct efx_tx_queue *tx_queue;
	int rc = 0;
	bool retry;
	s32 temp_filter_id = -1;

	/* Set the port loopback_selftest member. From this point on
	 * all received packets will be dropped. Mark the state as
	 * "flushing" so all inflight packets are dropped */
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (state == NULL)
		return -ENOMEM;
	BUG_ON(efx->loopback_selftest);

	if (loopback_modes) {
		struct efx_filter_spec spec;

		efx_filter_init_rx(&spec, EFX_FILTER_PRI_REQUIRED,
			EFX_FILTER_FLAG_RX_RSS | EFX_FILTER_FLAG_LOOPBACK,
			0);
		efx_filter_set_eth_local(&spec, EFX_FILTER_VID_UNSPEC,
					 payload_dest);

		temp_filter_id = efx_filter_insert_filter(efx, &spec, false);
		/* RSS filters are not supported in some firmware variants */
		if (temp_filter_id == -EOPNOTSUPP)
			return 0;
		else if (temp_filter_id < 0)
			return temp_filter_id;
	}

	state->flush = true;
	efx->loopback_selftest = state;

	/* Test all supported loopback modes */
	for (mode = LOOPBACK_NONE; mode <= LOOPBACK_TEST_MAX; mode++) {
		if (!(loopback_modes & (1 << mode)))
			continue;

		retry = EFX_WORKAROUND_8568(efx);
	set_loopback:
		/* Move the port into the specified loopback mode. */
		state->flush = true;
		mutex_lock(&efx->mac_lock);
		efx->loopback_mode = mode;
		rc = __efx_reconfigure_port(efx);
		mutex_unlock(&efx->mac_lock);
		if (rc) {
			netif_err(efx, drv, efx->net_dev,
				  "unable to move into %s loopback\n",
				  LOOPBACK_MODE(efx));
			goto out;
		}

		rc = efx_wait_for_link(efx);
		if (rc) {
			netif_err(efx, drv, efx->net_dev,
				  "loopback %s never came up\n",
				  LOOPBACK_MODE(efx));
			goto out;
		}

		/* Test both types of TX queue */
		efx_for_each_channel_tx_queue(tx_queue, channel) {
			state->offload_csum =
				tx_queue->csum_offload ==
					EFX_TXQ_TYPE_CSUM_OFFLOAD;
			rc = efx_test_loopback(tx_queue,
					       &tests->loopback[mode]);
			if (rc && !retry)
				goto out;
			if (rc) {
				/* Give the PHY a kick by moving into
				 * a Falcon internal loopback mode and
				 * then back out */
				int first = ffs(efx->loopback_modes) - 1;

				netif_info(efx, drv, efx->net_dev,
					   "retrying %s loopback\n",
					   LOOPBACK_MODE(efx));

				state->flush = true;
				mutex_lock(&efx->mac_lock);
				efx->loopback_mode = first;
				__efx_reconfigure_port(efx);
				mutex_unlock(&efx->mac_lock);

				memset(&tests->loopback[mode], 0,
				       sizeof(tests->loopback[mode]));
				retry = false;
				goto set_loopback;
			}
		}
	}

 out:
	if (temp_filter_id >= 0)
		efx_filter_remove_id_safe(efx, EFX_FILTER_PRI_REQUIRED,
					  temp_filter_id);

	/* Remove the flush. The caller will remove the loopback setting */
	state->flush = true;
	efx->loopback_selftest = NULL;
	wmb();
	kfree(state);

	if (rc == -EPERM)
		rc = 0;

	return rc;
}

/**************************************************************************
 *
 * Entry point
 *
 *************************************************************************/

int efx_selftest(struct efx_nic *efx, struct efx_self_tests *tests,
		 unsigned int flags)
{
	enum efx_loopback_mode loopback_mode = efx->loopback_mode;
	int phy_mode = efx->phy_mode;
	int rc_test = 0, rc_reset, rc;

	efx_selftest_async_cancel(efx);

	/* Online (i.e. non-disruptive) testing
	 * This checks interrupt generation, event delivery and PHY presence. */

	rc = efx_test_phy_alive(efx, tests);
	if (rc && !rc_test)
		rc_test = rc;

	rc = efx_test_nvram(efx, tests);
	if (rc && !rc_test)
		rc_test = rc;

	rc = efx_test_interrupts(efx, tests);
	if (rc && !rc_test)
		rc_test = rc;

	rc = efx_test_eventq_irq(efx, tests);
	if (rc && !rc_test)
		rc_test = rc;

	if (rc_test)
		return rc_test;

	if (!(flags & ETH_TEST_FL_OFFLINE))
		return efx_test_phy(efx, tests, flags);

	/* Offline (i.e. disruptive) testing
	 * This checks MAC and PHY loopback on the specified port. */

	/* Detach the device so the kernel doesn't transmit during the
	 * loopback test and the watchdog timeout doesn't fire.
	 */
	efx_device_detach_sync(efx);

	if (efx->type->test_chip) {
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
		efx_dl_reset_suspend(&efx->dl_nic);
#endif
#endif
		rc_reset = efx->type->test_chip(efx, tests);
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
		efx_dl_reset_resume(&efx->dl_nic, rc_reset == 0);
#endif
#endif

		if (rc_reset) {
			netif_err(efx, hw, efx->net_dev,
				  "Unable to recover from chip test\n");
			efx_schedule_reset(efx, RESET_TYPE_DISABLE);
			return rc_reset;
		}

		if ((tests->memory < 0 || tests->registers < 0) && !rc_test)
			rc_test = -EIO;
	}

	/* Ensure that the phy is powered and out of loopback
	 * for the bist and loopback tests */
	mutex_lock(&efx->mac_lock);
	efx->phy_mode &= ~PHY_MODE_LOW_POWER;
	efx->loopback_mode = LOOPBACK_NONE;
	__efx_reconfigure_port(efx);
	mutex_unlock(&efx->mac_lock);

	rc = efx_test_phy(efx, tests, flags);
	if (rc && !rc_test)
		rc_test = rc;

	rc = efx_test_loopbacks(efx, tests, efx->loopback_modes);
	if (rc && !rc_test)
		rc_test = rc;

	/* restore the PHY to the previous state */
	mutex_lock(&efx->mac_lock);
	efx->phy_mode = phy_mode;
	efx->loopback_mode = loopback_mode;
	__efx_reconfigure_port(efx);
	mutex_unlock(&efx->mac_lock);

	efx_device_attach_if_not_resetting(efx);

	return rc_test;
}

void efx_selftest_async_start(struct efx_nic *efx)
{
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx)
		efx_nic_event_test_start(channel);
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
	schedule_delayed_work(&efx->selftest_work, IRQ_TIMEOUT);
#else
	queue_delayed_work(efx_workqueue, &efx->selftest_work, IRQ_TIMEOUT);
#endif
}

void efx_selftest_async_cancel(struct efx_nic *efx)
{
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_CANCEL_DELAYED_WORK_SYNC)
	cancel_delayed_work_sync(&efx->selftest_work);
#else
	cancel_delayed_work(&efx->selftest_work);
	flush_workqueue(efx_workqueue);
#endif
}

static void efx_selftest_async_work(struct work_struct *data)
{
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_NEED_WORK_API_WRAPPERS)
	struct efx_nic *efx = container_of(data, struct efx_nic,
					   selftest_work.work);
#else
	struct efx_nic *efx = container_of(data, struct efx_nic,
					   selftest_work);
#endif
	struct efx_channel *channel;
	int cpu;

	efx_for_each_channel(channel, efx) {
		cpu = efx_nic_event_test_irq_cpu(channel);
		if (cpu < 0)
			netif_err(efx, ifup, efx->net_dev,
				  "channel %d failed to trigger an interrupt\n",
				  channel->channel);
		else
			netif_dbg(efx, ifup, efx->net_dev,
				  "channel %d triggered interrupt on CPU %d\n",
				  channel->channel, cpu);
	}
}

void efx_selftest_async_init(struct efx_nic *efx)
{
	INIT_DELAYED_WORK(&efx->selftest_work, efx_selftest_async_work);
}

