/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2018 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include <linux/module.h>
#include <linux/netdevice.h>
#include "net_driver.h"
#include "mcdi.h"
#include "nic.h"
#include "selftest.h"
#include "ethtool_common.h"
#include "efx_common.h"
#include "efx_channels.h"
#include "rx_common.h"
#include "mcdi_port_common.h"
#include "mcdi_filters.h"
#include "tc.h"

struct efx_sw_stat_desc {
	const char *name;
	enum {
		EFX_ETHTOOL_STAT_SOURCE_nic,
		EFX_ETHTOOL_STAT_SOURCE_channel,
		EFX_ETHTOOL_STAT_SOURCE_rx_queue,
		EFX_ETHTOOL_STAT_SOURCE_tx_queue
	} source;
	unsigned int offset;
	u64(*get_stat) (void *field); /* Reader function */
};

/* Initialiser for a struct efx_sw_stat_desc with type-checking */
#define EFX_ETHTOOL_STAT(stat_name, source_name, field, field_type, \
				get_stat_function) {			\
	.name = #stat_name,						\
	.source = EFX_ETHTOOL_STAT_SOURCE_##source_name,		\
	.offset = ((((field_type *) 0) ==				\
		      &((struct efx_##source_name *)0)->field) ?	\
		    offsetof(struct efx_##source_name, field) :		\
		    offsetof(struct efx_##source_name, field)),		\
	.get_stat = get_stat_function,					\
}

/* MAC address mask including only I/G bit */
static const u8 mac_addr_ig_mask[ETH_ALEN] __aligned(2) = {0x01, 0, 0, 0, 0, 0};

static u64 efx_get_uint_stat(void *field)
{
	return *(unsigned int *)field;
}

static u64 efx_get_atomic_stat(void *field)
{
	return atomic_read((atomic_t *) field);
}

#define EFX_ETHTOOL_ATOMIC_NIC_ERROR_STAT(field)		\
	EFX_ETHTOOL_STAT(field, nic, errors.field,		\
			 atomic_t, efx_get_atomic_stat)

#define EFX_ETHTOOL_UINT_CHANNEL_STAT(field)			\
	EFX_ETHTOOL_STAT(field, channel, n_##field,		\
			 unsigned int, efx_get_uint_stat)
#define EFX_ETHTOOL_UINT_CHANNEL_STAT_NO_N(field)		\
	EFX_ETHTOOL_STAT(field, channel, field,			\
			 unsigned int, efx_get_uint_stat)

#define EFX_ETHTOOL_UINT_RXQ_STAT(field)			\
	EFX_ETHTOOL_STAT(field, rx_queue, n_##field,		\
			 unsigned int, efx_get_uint_stat)
#define EFX_ETHTOOL_UINT_TXQ_STAT(field)			\
	EFX_ETHTOOL_STAT(tx_##field, tx_queue, field,		\
			 unsigned int, efx_get_uint_stat)

static const struct efx_sw_stat_desc efx_sw_stat_desc[] = {
	EFX_ETHTOOL_UINT_TXQ_STAT(merge_events),
	EFX_ETHTOOL_UINT_TXQ_STAT(tso_bursts),
	EFX_ETHTOOL_UINT_TXQ_STAT(tso_long_headers),
	EFX_ETHTOOL_UINT_TXQ_STAT(tso_packets),
	EFX_ETHTOOL_UINT_TXQ_STAT(tso_fallbacks),
	EFX_ETHTOOL_UINT_TXQ_STAT(pushes),
	EFX_ETHTOOL_UINT_TXQ_STAT(pio_packets),
	EFX_ETHTOOL_UINT_TXQ_STAT(cb_packets),
	EFX_ETHTOOL_ATOMIC_NIC_ERROR_STAT(rx_reset),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_tobe_disc),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_ip_hdr_chksum_err),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_tcp_udp_chksum_err),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_inner_ip_hdr_chksum_err),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_inner_tcp_udp_chksum_err),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_outer_ip_hdr_chksum_err),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_outer_tcp_udp_chksum_err),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_eth_crc_err),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_mcast_mismatch),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_frm_trunc),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_merge_events),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_merge_packets),
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP)
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_xdp_drops),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_xdp_bad_drops),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_xdp_tx),
	EFX_ETHTOOL_UINT_RXQ_STAT(rx_xdp_redirect),
#endif
#ifdef CONFIG_RFS_ACCEL
	EFX_ETHTOOL_UINT_CHANNEL_STAT_NO_N(rfs_filter_count),
	EFX_ETHTOOL_UINT_CHANNEL_STAT(rfs_succeeded),
	EFX_ETHTOOL_UINT_CHANNEL_STAT(rfs_failed),
#endif
};

#define EFX_ETHTOOL_SW_STAT_COUNT ARRAY_SIZE(efx_sw_stat_desc)

static const char efx_ethtool_priv_flags_strings[][ETH_GSTRING_LEN] = {
	"phy-power-follows-link",
	"link-down-on-reset",
	"xdp-tx",
	"log-tc-errors",
	"tc-match-ignore-ttl",
};

#define EFX_ETHTOOL_PRIV_FLAGS_PHY_POWER		BIT(0)
#define EFX_ETHTOOL_PRIV_FLAGS_LINK_DOWN_ON_RESET	BIT(1)
#define EFX_ETHTOOL_PRIV_FLAGS_XDP			BIT(2)
#define EFX_ETHTOOL_PRIV_FLAGS_LOG_TC_ERRS		BIT(3)
#define EFX_ETHTOOL_PRIV_FLAGS_TC_MATCH_IGNORE_TTL	BIT(4)

#define EFX_ETHTOOL_PRIV_FLAGS_COUNT ARRAY_SIZE(efx_ethtool_priv_flags_strings)

void efx_ethtool_get_common_drvinfo(struct efx_nic *efx,
				    struct ethtool_drvinfo *info)
{
#ifdef EFX_NOT_UPSTREAM
	/* This is not populated on RHEL 6 */
	if (efx->pci_dev->driver)
		strscpy(info->driver, efx->pci_dev->driver->name,
			sizeof(info->driver));
	else
		strscpy(info->driver, KBUILD_MODNAME, sizeof(info->driver));
	strscpy(info->version, EFX_DRIVER_VERSION, sizeof(info->version));
#else
	strscpy(info->driver, efx->pci_dev->driver->name, sizeof(info->driver));
#endif
	strscpy(info->fw_version, "N/A", sizeof(info->fw_version));
	strscpy(info->bus_info, pci_name(efx->pci_dev), sizeof(info->bus_info));
	info->n_priv_flags = EFX_ETHTOOL_PRIV_FLAGS_COUNT;
}

void efx_ethtool_get_drvinfo(struct net_device *net_dev,
			     struct ethtool_drvinfo *info)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	efx_ethtool_get_common_drvinfo(efx, info);
	if (!in_interrupt())
		efx_mcdi_print_fwver(efx, info->fw_version,
				     sizeof(info->fw_version));
}

/* Identify device by flashing LEDs */
int efx_ethtool_phys_id(struct net_device *net_dev,
			enum ethtool_phys_id_state state)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	enum efx_led_mode mode = EFX_LED_DEFAULT;

	switch (state) {
	case ETHTOOL_ID_ON:
		mode = EFX_LED_ON;
		break;
	case ETHTOOL_ID_OFF:
		mode = EFX_LED_OFF;
		break;
	case ETHTOOL_ID_INACTIVE:
		mode = EFX_LED_DEFAULT;
		break;
	case ETHTOOL_ID_ACTIVE:
		return 1;	/* cycle on/off once per second */
	}

	return efx_mcdi_set_id_led(efx, mode);
}

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_SET_PHYS_ID)
int efx_ethtool_phys_id_loop(struct net_device *net_dev, u32 count)
{
	/* Driver expects to be called at twice the frequency in rc */
	int rc = efx_ethtool_phys_id(net_dev, ETHTOOL_ID_ACTIVE);
	int n = rc * 2, i, interval = HZ / n;

	/* Count down seconds */
	do {
		/* Count down iterations per second */
		i = n;
		do {
			efx_ethtool_phys_id(net_dev,
					    (i & 1) ? ETHTOOL_ID_OFF
					    : ETHTOOL_ID_ON);
			schedule_timeout_interruptible(interval);
		} while (!signal_pending(current) && --i != 0);
	} while (!signal_pending(current) &&
		 (count == 0 || --count != 0));

	(void)efx_ethtool_phys_id(net_dev, ETHTOOL_ID_INACTIVE);
	return 0;
}
#endif

u32 efx_ethtool_get_msglevel(struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	return efx->msg_enable;
}

void efx_ethtool_set_msglevel(struct net_device *net_dev, u32 msg_enable)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	efx->msg_enable = msg_enable;
#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	efx->dl_nic.msg_enable = efx->msg_enable;
#endif
#endif
}

void efx_ethtool_self_test(struct net_device *net_dev,
				  struct ethtool_test *test, u64 *data)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	struct efx_self_tests *efx_tests;
	bool already_up;
	int rc = -ENOMEM;

	efx_tests = kzalloc(sizeof(*efx_tests), GFP_KERNEL);
	if (!efx_tests)
		goto fail;

	efx_tests->eventq_dma = kcalloc(efx_channels(efx),
					sizeof(*efx_tests->eventq_dma),
					GFP_KERNEL);
	efx_tests->eventq_int = kcalloc(efx_channels(efx),
					sizeof(*efx_tests->eventq_int),
					GFP_KERNEL);

	if (!efx_tests->eventq_dma || !efx_tests->eventq_int) {
		goto fail;
	}

	if (!efx_net_active(efx->state)) {
		rc = -EBUSY;
		goto out;
	}

	/* We need rx buffers and interrupts. */
	already_up = (efx->net_dev->flags & IFF_UP);
	if (!already_up && test->flags & ETH_TEST_FL_OFFLINE) {
		netif_info(efx, drv, efx->net_dev,
			    "cannot perform offline selftest while down\n");
		test->flags &= ~ETH_TEST_FL_OFFLINE;
	}

	netif_info(efx, drv, efx->net_dev, "starting %sline testing\n",
		   (test->flags & ETH_TEST_FL_OFFLINE) ? "off" : "on");

	/* We need rx buffers and interrupts. */
	if (!already_up) {
		rc = dev_open(efx->net_dev, NULL);
		if (rc) {
			netif_err(efx, drv, efx->net_dev,
				  "failed opening device.\n");
			goto out;
		}
	}

	rc = efx_selftest(efx, efx_tests, test->flags);

	if (!already_up)
		dev_close(efx->net_dev);

	netif_info(efx, drv, efx->net_dev, "%s %sline self-tests\n",
		   rc == 0 ? "passed" : "failed",
		   (test->flags & ETH_TEST_FL_OFFLINE) ? "off" : "on");

out:
	efx_ethtool_fill_self_tests(efx, efx_tests, NULL, data);

fail:
	if (efx_tests) {
		kfree(efx_tests->eventq_dma);
		kfree(efx_tests->eventq_int);
		kfree(efx_tests);
	}

	if (rc)
		test->flags |= ETH_TEST_FL_FAILED;
}

/* Restart autonegotiation */
int efx_ethtool_nway_reset(struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	u32 flags = efx_get_mcdi_phy_flags(efx);
	int rc;

	flags |= (1 << MC_CMD_SET_LINK_IN_POWEROFF_LBN);

	rc = efx_mcdi_set_link(efx, efx_get_mcdi_caps(efx), flags,
			       efx->loopback_mode, false,
			       SET_LINK_SEQ_IGNORE);
	if (rc)
		return rc;

	flags &= ~(1 << MC_CMD_SET_LINK_IN_POWEROFF_LBN);
	flags &= ~(1 << MC_CMD_SET_LINK_IN_LOWPOWER_LBN);

	return efx_mcdi_set_link(efx, efx_get_mcdi_caps(efx), flags,
				 efx->loopback_mode, false,
				 SET_LINK_SEQ_IGNORE);
}

void efx_ethtool_get_pauseparam(struct net_device *net_dev,
				struct ethtool_pauseparam *pause)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	pause->rx_pause = !!(efx->wanted_fc & EFX_FC_RX);
	pause->tx_pause = !!(efx->wanted_fc & EFX_FC_TX);
	pause->autoneg = !!(efx->wanted_fc & EFX_FC_AUTO);
}

int efx_ethtool_set_pauseparam(struct net_device *net_dev,
			       struct ethtool_pauseparam *pause)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	u8 wanted_fc, old_fc;
	u32 old_adv;
	int rc = 0;

	mutex_lock(&efx->mac_lock);

	wanted_fc = ((pause->rx_pause ? EFX_FC_RX : 0) |
		     (pause->tx_pause ? EFX_FC_TX : 0) |
		     (pause->autoneg ? EFX_FC_AUTO : 0));

	if ((wanted_fc & EFX_FC_TX) && !(wanted_fc & EFX_FC_RX)) {
		netif_dbg(efx, drv, efx->net_dev,
			  "Flow control unsupported: tx ON rx OFF\n");
		rc = -EINVAL;
		goto out;
	}

	if ((wanted_fc & EFX_FC_AUTO) &&
	    !(efx->link_advertising[0] & ADVERTISED_Autoneg)) {
		netif_dbg(efx, drv, efx->net_dev,
			  "Autonegotiation is disabled\n");
		rc = -EINVAL;
		goto out;
	}

	old_adv = efx->link_advertising[0];
	old_fc = efx->wanted_fc;
	efx_link_set_wanted_fc(efx, wanted_fc);
	if (efx->link_advertising[0] != old_adv ||
	    (efx->wanted_fc ^ old_fc) & EFX_FC_AUTO) {
		rc = efx_mcdi_port_reconfigure(efx);
		if (rc) {
			netif_err(efx, drv, efx->net_dev,
				  "Unable to advertise requested flow "
				  "control setting\n");
			efx->link_advertising[0] = old_adv;
			efx->wanted_fc = old_fc;
			goto out;
		}
	}

	/* Reconfigure the MAC. The PHY *may* generate a link state change event
	 * if the user just changed the advertised capabilities, but there's no
	 * harm doing this twice */
	(void)efx_mac_reconfigure(efx, false);

out:
	mutex_unlock(&efx->mac_lock);

	return rc;
}

/**
 * efx_fill_test - fill in an individual self-test entry
 * @test_index:		Index of the test
 * @strings:		Ethtool strings, or %NULL
 * @data:		Ethtool test results, or %NULL
 * @test:		Pointer to test result (used only if data != %NULL)
 * @unit_format:	Unit name format (e.g. "chan\%d")
 * @unit_id:		Unit id (e.g. 0 for "chan0")
 * @test_format:	Test name format (e.g. "loopback.\%s.tx.sent")
 * @test_id:		Test id (e.g. "PHYXS" for "loopback.PHYXS.tx_sent")
 *
 * Fill in an individual self-test entry.
 */
static void efx_fill_test(unsigned int test_index, u8 *strings, u64 *data,
			  int *test, const char *unit_format, int unit_id,
			  const char *test_format, const char *test_id)
{
	char unit_str[ETH_GSTRING_LEN], test_str[ETH_GSTRING_LEN];

	/* Fill data value, if applicable */
	if (data)
		data[test_index] = *test;

	/* Fill string, if applicable */
	if (strings) {
		if (strchr(unit_format, '%'))
			snprintf(unit_str, sizeof(unit_str),
				 unit_format, unit_id);
		else
			strcpy(unit_str, unit_format);
		snprintf(test_str, sizeof(test_str), test_format, test_id);
		snprintf(strings + test_index * ETH_GSTRING_LEN,
			 ETH_GSTRING_LEN,
			 "%-6s %-24s", unit_str, test_str);
	}
}

#define EFX_LOOPBACK_NAME(_mode, _counter)			\
	"loopback.%s." _counter, STRING_TABLE_LOOKUP(_mode, efx_loopback_mode)

/**
 * efx_fill_loopback_test - fill in a block of loopback self-test entries
 * @efx:		Efx NIC
 * @lb_tests:		Efx loopback self-test results structure
 * @mode:		Loopback test mode
 * @test_index:		Starting index of the test
 * @strings:		Ethtool strings, or %NULL
 * @data:		Ethtool test results, or %NULL
 *
 * Fill in a block of loopback self-test entries.
 *
 * Return: new test index.
 */
static int efx_fill_loopback_test(struct efx_nic *efx,
				  struct efx_loopback_self_tests *lb_tests,
				  enum efx_loopback_mode mode,
				  unsigned int test_index,
				  u8 *strings, u64 *data)
{
	if (efx->tx_channel_offset < efx_channels(efx)) {
		struct efx_channel *channel =
			efx_get_channel(efx, efx->tx_channel_offset);
		struct efx_tx_queue *tx_queue;

		efx_for_each_channel_tx_queue(tx_queue, channel) {
			efx_fill_test(test_index++, strings, data,
				      &lb_tests->tx_sent[tx_queue->queue],
				      EFX_TX_QUEUE_NAME(tx_queue),
				      EFX_LOOPBACK_NAME(mode, "tx_sent"));
			efx_fill_test(test_index++, strings, data,
				      &lb_tests->tx_done[tx_queue->queue],
				      EFX_TX_QUEUE_NAME(tx_queue),
				      EFX_LOOPBACK_NAME(mode, "tx_done"));
		}
	}
	efx_fill_test(test_index++, strings, data,
		      &lb_tests->rx_good,
		      "rx", 0,
		      EFX_LOOPBACK_NAME(mode, "rx_good"));
	efx_fill_test(test_index++, strings, data,
		      &lb_tests->rx_bad,
		      "rx", 0,
		      EFX_LOOPBACK_NAME(mode, "rx_bad"));

	return test_index;
}

/**
 * efx_ethtool_fill_self_tests - get self-test details
 * @efx:		Efx NIC
 * @tests:		Efx self-test results structure, or %NULL
 * @strings:		Ethtool strings, or %NULL
 * @data:		Ethtool test results, or %NULL
 *
 * Get self-test number of strings, strings, and/or test results.
 *
 * The reason for merging these three functions is to make sure that
 * they can never be inconsistent.
 *
 * Return: number of strings (equals number of test results).
 */
int efx_ethtool_fill_self_tests(struct efx_nic *efx,
				struct efx_self_tests *tests,
				u8 *strings, u64 *data)
{
	struct efx_channel *channel;
	unsigned int n = 0, i;
	enum efx_loopback_mode mode;

	efx_fill_test(n++, strings, data, &tests->phy_alive,
		      "phy", 0, "alive", NULL);
	efx_fill_test(n++, strings, data, &tests->nvram,
		      "core", 0, "nvram", NULL);
	efx_fill_test(n++, strings, data, &tests->interrupt,
		      "core", 0, "interrupt", NULL);

	/* Event queues */
	efx_for_each_channel(channel, efx) {
		efx_fill_test(n++, strings, data,
			      tests ? &tests->eventq_dma[channel->channel] : NULL,
			      EFX_CHANNEL_NAME(channel),
			      "eventq.dma", NULL);
		efx_fill_test(n++, strings, data,
			      tests ? &tests->eventq_int[channel->channel] : NULL,
			      EFX_CHANNEL_NAME(channel),
			      "eventq.int", NULL);
	}

	efx_fill_test(n++, strings, data, &tests->memory,
		      "core", 0, "memory", NULL);
	efx_fill_test(n++, strings, data, &tests->registers,
		      "core", 0, "registers", NULL);

	for (i = 0; true; ++i) {
		const char *name;

		EFX_WARN_ON_PARANOID(i >= EFX_MAX_PHY_TESTS);
		name = efx_mcdi_phy_test_name(efx, i);
		if (name == NULL)
			break;

		efx_fill_test(n++, strings, data, &tests->phy_ext[i],
			      "phy", 0, name, NULL);
	}

	/* Loopback tests */
	for (mode = LOOPBACK_NONE; mode <= LOOPBACK_TEST_MAX; mode++) {
		if (!(efx->loopback_modes & (1 << mode)))
			continue;
		n = efx_fill_loopback_test(efx,
					   &tests->loopback[mode], mode, n,
					   strings, data);
	}

	return n;
}

static size_t efx_describe_per_queue_stats(struct efx_nic *efx, u8 *strings)
{
	size_t n_stats = 0;
	const char *q_name;
	struct efx_channel *channel;

	efx_for_each_channel(channel, efx) {
		if (efx_channel_has_tx_queues(channel)) {
			n_stats++;
			if (strings != NULL) {
				unsigned int core_txq = channel->channel -
							efx->tx_channel_offset;

				if (channel->type->get_queue_name)
					q_name = channel->type->get_queue_name(channel, true);
				else
					q_name = "tx_packets";

				snprintf(strings, ETH_GSTRING_LEN,
					 "tx-%u.%s", core_txq, q_name);
				strings += ETH_GSTRING_LEN;
			}
		}
	}
	efx_for_each_channel(channel, efx) {
		if (efx_channel_has_rx_queue(channel)) {
			n_stats++;
			if (strings != NULL) {
				if (channel->type->get_queue_name)
					q_name = channel->type->get_queue_name(channel, false);
				else
					q_name = "rx_packets";

				snprintf(strings, ETH_GSTRING_LEN,
					 "rx-%d.%s", channel->channel, q_name);
				strings += ETH_GSTRING_LEN;
			}
		}
	}
	if (efx->xdp_tx_queue_count && efx->xdp_tx_queues) {
		unsigned short xdp;

		for (xdp = 0; xdp < efx->xdp_tx_queue_count; xdp++) {
			if (efx->xdp_tx_queues[xdp]) {
				n_stats++;
				if (strings != NULL) {
					snprintf(strings, ETH_GSTRING_LEN,
						 "tx-xdp-cpu-%hu.tx_packets",
						 xdp);
					strings += ETH_GSTRING_LEN;
				}
			}
		}
	}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
	efx_for_each_channel(channel, efx) {
		unsigned int core_txq = channel->channel -
			efx->tx_channel_offset;
		n_stats++;
		if (strings) {
			snprintf(strings, ETH_GSTRING_LEN,
				 "tx-xsk-%u.tx_packets",
				 core_txq);
			strings += ETH_GSTRING_LEN;
		}
	}
#endif
#endif

	return n_stats;
}

int efx_ethtool_get_sset_count(struct net_device *net_dev, int string_set)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	switch (string_set) {
	case ETH_SS_STATS:
		return efx->type->describe_stats(efx, NULL) +
		       EFX_ETHTOOL_SW_STAT_COUNT +
		       efx_describe_per_queue_stats(efx, NULL) +
		       efx_ptp_describe_stats(efx, NULL);
	case ETH_SS_TEST:
		return efx_ethtool_fill_self_tests(efx, NULL, NULL, NULL);
	case ETH_SS_PRIV_FLAGS:
		return EFX_ETHTOOL_PRIV_FLAGS_COUNT;
	default:
		return -EINVAL;
	}
}

void efx_ethtool_get_strings(struct net_device *net_dev, u32 string_set,
			     u8 *strings)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	int i;

	switch (string_set) {
	case ETH_SS_STATS:
		strings += (efx->type->describe_stats(efx, strings) *
			    ETH_GSTRING_LEN);
		for (i = 0; i < EFX_ETHTOOL_SW_STAT_COUNT; i++)
			strscpy(strings + i * ETH_GSTRING_LEN,
				efx_sw_stat_desc[i].name, ETH_GSTRING_LEN);
		strings += EFX_ETHTOOL_SW_STAT_COUNT * ETH_GSTRING_LEN;
		strings += (efx_describe_per_queue_stats(efx, strings) *
			    ETH_GSTRING_LEN);
		efx_ptp_describe_stats(efx, strings);
		break;
	case ETH_SS_TEST:
		efx_ethtool_fill_self_tests(efx, NULL, strings, NULL);
		break;
	case ETH_SS_PRIV_FLAGS:
		for (i = 0; i < EFX_ETHTOOL_PRIV_FLAGS_COUNT; i++)
			strscpy(strings + i * ETH_GSTRING_LEN,
				efx_ethtool_priv_flags_strings[i],
				ETH_GSTRING_LEN);
		break;
	default:
		/* No other string sets */
		break;
	}
}

u32 efx_ethtool_get_priv_flags(struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	u32 ret_flags = 0;

	if (efx->phy_power_follows_link)
		ret_flags |= EFX_ETHTOOL_PRIV_FLAGS_PHY_POWER;

	if (efx->link_down_on_reset)
		ret_flags |= EFX_ETHTOOL_PRIV_FLAGS_LINK_DOWN_ON_RESET;

	if (efx->xdp_tx)
		ret_flags |= EFX_ETHTOOL_PRIV_FLAGS_XDP;

	if (efx->log_tc_errs)
		ret_flags |= EFX_ETHTOOL_PRIV_FLAGS_LOG_TC_ERRS;

	if (efx->tc_match_ignore_ttl)
		ret_flags |= EFX_ETHTOOL_PRIV_FLAGS_TC_MATCH_IGNORE_TTL;

	return ret_flags;
}

int efx_ethtool_set_priv_flags(struct net_device *net_dev, u32 flags)
{
	u32 prev_flags = efx_ethtool_get_priv_flags(net_dev);
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	bool is_up = !efx_check_disabled(efx) && netif_running(efx->net_dev);
	bool xdp_change =
		(flags & EFX_ETHTOOL_PRIV_FLAGS_XDP) !=
		(prev_flags & EFX_ETHTOOL_PRIV_FLAGS_XDP);

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (xdp_change && efx->open_count > is_up) {
		netif_err(efx, drv, efx->net_dev,
			  "unable to set XDP. device in use by driverlink stack\n");
		return -EBUSY;
	}
#endif
#endif

	/* can't change XDP state when interface is up */
	if (is_up && xdp_change)
		dev_close(net_dev);

	efx->phy_power_follows_link =
		!!(flags & EFX_ETHTOOL_PRIV_FLAGS_PHY_POWER);
	efx->link_down_on_reset =
		!!(flags & EFX_ETHTOOL_PRIV_FLAGS_LINK_DOWN_ON_RESET);
	efx->xdp_tx =
		!!(flags & EFX_ETHTOOL_PRIV_FLAGS_XDP);
	efx->log_tc_errs =
		!!(flags & EFX_ETHTOOL_PRIV_FLAGS_LOG_TC_ERRS);
	efx->tc_match_ignore_ttl =
		!!(flags & EFX_ETHTOOL_PRIV_FLAGS_TC_MATCH_IGNORE_TTL);

	if (is_up && xdp_change)
		return dev_open(net_dev, NULL);

	return 0;
}

void efx_ethtool_get_stats(struct net_device *net_dev,
			   struct ethtool_stats *stats __attribute__ ((unused)),
			   u64 *data)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	const struct efx_sw_stat_desc *stat;
	struct efx_channel *channel;
	struct efx_tx_queue *tx_queue;
	struct efx_rx_queue *rx_queue;
	int i;

	/* Get NIC statistics */
	data += efx->type->update_stats(efx, data, NULL);
	/* efx->stats is obtained in update_stats and held */

	/* Get software statistics */
	for (i = 0; i < EFX_ETHTOOL_SW_STAT_COUNT; i++) {
		stat = &efx_sw_stat_desc[i];
		switch (stat->source) {
		case EFX_ETHTOOL_STAT_SOURCE_nic:
			data[i] = stat->get_stat((void *)efx + stat->offset);
			break;
		case EFX_ETHTOOL_STAT_SOURCE_channel:
			data[i] = 0;
			efx_for_each_channel(channel, efx)
				data[i] += stat->get_stat((void *)channel +
							  stat->offset);
			break;
		case EFX_ETHTOOL_STAT_SOURCE_rx_queue:
			data[i] = 0;
			efx_for_each_channel(channel, efx) {
				efx_for_each_channel_rx_queue(rx_queue, channel)
					data[i] +=
						stat->get_stat((void *)rx_queue
							       + stat->offset);
			}
			break;
		case EFX_ETHTOOL_STAT_SOURCE_tx_queue:
			data[i] = 0;
			efx_for_each_channel(channel, efx) {
				efx_for_each_channel_tx_queue(tx_queue, channel)
					data[i] +=
						stat->get_stat((void *)tx_queue
							       + stat->offset);
			}
			break;
		}
	}
	data += EFX_ETHTOOL_SW_STAT_COUNT;

	/* release stats_lock obtained in update_stats */
	spin_unlock_bh(&efx->stats_lock);

	efx_for_each_channel(channel, efx) {
		if (efx_channel_has_tx_queues(channel)) {
			data[0] = 0;
			efx_for_each_channel_tx_queue(tx_queue, channel) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
				if (!efx_is_xsk_tx_queue(tx_queue))
#endif
					data[0] += tx_queue->tx_packets;
#else
				data[0] += tx_queue->tx_packets;
#endif
			}
			data++;
		}
	}
	efx_for_each_channel(channel, efx) {
		if (efx_channel_has_rx_queue(channel)) {
			data[0] = 0;
			efx_for_each_channel_rx_queue(rx_queue, channel) {
				data[0] += rx_queue->rx_packets;
			}
			data++;
		}
	}
	if (efx->xdp_tx_queue_count && efx->xdp_tx_queues) {
		int xdp;

		for (xdp = 0; xdp < efx->xdp_tx_queue_count; xdp++) {
			if (efx->xdp_tx_queues[xdp]) {
				data[0] = efx->xdp_tx_queues[xdp]->tx_packets;
				data++;
			}
		}
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XDP_SOCK)
#if defined(CONFIG_XDP_SOCKETS)
		efx_for_each_channel(channel, efx) {
			tx_queue = efx_channel_get_xsk_tx_queue(channel);
			if (tx_queue)
				data[0] = tx_queue->tx_packets;
			data++;
		}
#endif
#endif
	}

	efx_ptp_update_stats(efx, data);
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_CHANNELS) || defined(EFX_HAVE_ETHTOOL_EXT_CHANNELS)
void efx_ethtool_get_channels(struct net_device *net_dev,
			      struct ethtool_channels *channels)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	channels->combined_count = efx->n_combined_channels;
	channels->rx_count = efx->n_rx_only_channels;
	channels->tx_count = efx->n_tx_only_channels;

	/* count up 'other' channels */
	channels->max_other = efx_xdp_channels(efx) + efx->n_extra_channels;
	channels->other_count = channels->max_other;

	if (efx->n_tx_only_channels && efx->n_rx_only_channels) {
		channels->max_combined = 0;
		channels->max_rx = efx->n_rx_only_channels;
		channels->max_tx = efx->n_tx_only_channels;
	} else {
		channels->max_combined = efx->max_tx_channels -
					 channels->max_other;
		channels->max_rx = 0;
		channels->max_tx = 0;
	}
}

int efx_ethtool_set_channels(struct net_device *net_dev,
			     struct ethtool_channels *channels)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	bool is_up = !efx_check_disabled(efx) && netif_running(efx->net_dev);
	int rc, rc2 = 0;

	/* Cannot change special channels yet */
	if (channels->other_count != channels->max_other)
		return -EINVAL;

	/* If we're in a separate TX channels config then reject any changes.
	 * If we're not then reject an attempt to make these non-zero.
	 */
	if (channels->rx_count != channels->max_rx ||
	    channels->tx_count != channels->max_tx)
		return -EINVAL;

#ifdef EFX_NOT_UPSTREAM
#ifdef CONFIG_SFC_DRIVERLINK
	if (efx->open_count > is_up) {
		netif_err(efx, drv, efx->net_dev,
			  "unable to set channels. device in use by driverlink stack\n");
		return -EBUSY;
	}
#endif
#endif

	if (is_up)
		dev_close(net_dev);

	efx->n_combined_channels = channels->combined_count;
	efx->n_tx_only_channels = 0;
	efx->n_rx_only_channels = 0;

	/* Update the default RSS spread shown by ethtool -x */
	rc = efx_mcdi_push_default_indir_table(efx,
					       efx->n_combined_channels);

	/* changing the queue setup invalidates ntuple filters */
	if (!rc)
		efx_filter_clear_ntuple(efx);

	/* Update the datapath with the new settings */
	if (is_up)
		rc2 = dev_open(net_dev, NULL);
	return (rc ? rc : rc2);
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_LINKSETTINGS)
int efx_ethtool_get_link_ksettings(struct net_device *net_dev,
				   struct ethtool_link_ksettings *out)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	mutex_lock(&efx->mac_lock);
	efx_mcdi_phy_get_ksettings(efx, out);
	mutex_unlock(&efx->mac_lock);

	return 0;
}

int efx_ethtool_set_link_ksettings(struct net_device *net_dev,
				   const struct ethtool_link_ksettings *settings)
{
	__ETHTOOL_DECLARE_LINK_MODE_MASK(advertising);
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	int rc;

	mutex_lock(&efx->mac_lock);
	rc = efx_mcdi_phy_set_ksettings(efx, settings, advertising);
	if (rc > 0) {
		efx_link_set_advertising(efx, advertising);
		rc = 0;
	}
	mutex_unlock(&efx->mac_lock);

	return rc;
}
#endif

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_LINKSETTINGS) || defined(EFX_HAVE_ETHTOOL_LEGACY)
/* This must be called with rtnl_lock held. */
int efx_ethtool_get_settings(struct net_device *net_dev,
			     struct ethtool_cmd *ecmd)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	struct efx_link_state *link_state = &efx->link_state;

	mutex_lock(&efx->mac_lock);
	efx_mcdi_phy_get_settings(efx, ecmd);
	mutex_unlock(&efx->mac_lock);

	/* Both MACs support pause frames (bidirectional and respond-only) */
	ecmd->supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;

	if (LOOPBACK_INTERNAL(efx)) {
		ethtool_cmd_speed_set(ecmd, link_state->speed);
		ecmd->duplex = link_state->fd ? DUPLEX_FULL : DUPLEX_HALF;
	}

	return 0;
}

/* This must be called with rtnl_lock held. */
int efx_ethtool_set_settings(struct net_device *net_dev,
			     struct ethtool_cmd *ecmd)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(new_adv);
	int rc;

	/* GMAC does not support 1000Mbps HD */
	if ((ethtool_cmd_speed(ecmd) == SPEED_1000) &&
	    (ecmd->duplex != DUPLEX_FULL)) {
		netif_dbg(efx, drv, efx->net_dev,
			  "rejecting unsupported 1000Mbps HD setting\n");
		return -EINVAL;
	}

	mutex_lock(&efx->mac_lock);
	rc = efx_mcdi_phy_set_settings(efx, ecmd, new_adv);
	if (rc > 0) {
		efx_link_set_advertising(efx, new_adv);
		rc = 0;
	}
	mutex_unlock(&efx->mac_lock);
	return rc;
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_FECSTATS)
void efx_ethtool_get_fec_stats(struct net_device *net_dev,
			       struct ethtool_fec_stats *fec_stats)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx->type->get_fec_stats)
		efx->type->get_fec_stats(efx, fec_stats);
}
#endif

int efx_ethtool_get_fecparam(struct net_device *net_dev,
			       struct ethtool_fecparam *fecparam)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	int rc;

	mutex_lock(&efx->mac_lock);
	rc = efx_mcdi_phy_get_fecparam(efx, fecparam);
	mutex_unlock(&efx->mac_lock);

	return rc;
}

int efx_ethtool_set_fecparam(struct net_device *net_dev,
			       struct ethtool_fecparam *fecparam)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	int rc;

	mutex_lock(&efx->mac_lock);
	rc = efx_mcdi_phy_set_fecparam(efx, fecparam);
	mutex_unlock(&efx->mac_lock);
	return rc;
}

/* Convert old-style _EN RSS flags into new style _MODE flags */
static u32 efx_ethtool_convert_old_rss_flags(u32 old_flags)
{
	u32 flags = 0;

	if (old_flags & (1 << MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TOEPLITZ_IPV4_EN_LBN))
		flags |= RSS_MODE_HASH_ADDRS << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_UDP_IPV4_RSS_MODE_LBN |\
			 RSS_MODE_HASH_ADDRS << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_OTHER_IPV4_RSS_MODE_LBN;
	if (old_flags & (1 << MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TOEPLITZ_TCPV4_EN_LBN))
		flags |= RSS_MODE_HASH_4TUPLE << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TCP_IPV4_RSS_MODE_LBN;
	if (old_flags & (1 << MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TOEPLITZ_IPV6_EN_LBN))
		flags |= RSS_MODE_HASH_ADDRS << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_UDP_IPV6_RSS_MODE_LBN |\
			 RSS_MODE_HASH_ADDRS << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_OTHER_IPV6_RSS_MODE_LBN;
	if (old_flags & (1 << MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TOEPLITZ_TCPV6_EN_LBN))
		flags |= RSS_MODE_HASH_4TUPLE << MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TCP_IPV6_RSS_MODE_LBN;
	return flags;
}

static int efx_ethtool_set_rss_flags(struct efx_nic *efx,
#ifdef EFX_USE_KCOMPAT
				     struct efx_ethtool_rxnfc *info)
#else
				     struct ethtool_rxnfc *info)
#endif
{
	struct efx_rss_context *ctx = &efx->rss_context;
	u32 flags, mode = 0;
	int shift, rc = 0;

	if (!efx->type->rx_set_rss_flags)
		return -EOPNOTSUPP;
	if (!efx->type->rx_get_rss_flags)
		return -EOPNOTSUPP;
	mutex_lock(&efx->rss_lock);
	if (info->flow_type & FLOW_RSS && info->rss_context) {
		ctx = efx_find_rss_context_entry(efx, info->rss_context);
		if (!ctx) {
			rc = -ENOENT;
			goto out_unlock;
		}
	}
	efx->type->rx_get_rss_flags(efx, ctx);
	flags = ctx->flags;
	if (!(flags & RSS_CONTEXT_FLAGS_ADDITIONAL_MASK))
		flags = efx_ethtool_convert_old_rss_flags(flags);
	/* In case we end up clearing all additional flags (meaning we
	 * want no RSS), make sure the old-style flags are cleared too.
	 */
	flags &= RSS_CONTEXT_FLAGS_ADDITIONAL_MASK;

	switch (info->flow_type & ~FLOW_RSS) {
	case TCP_V4_FLOW:
		shift = MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TCP_IPV4_RSS_MODE_LBN;
		break;
	case UDP_V4_FLOW:
		shift = MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_UDP_IPV4_RSS_MODE_LBN;
		break;
	case SCTP_V4_FLOW:
	case AH_ESP_V4_FLOW:
		/* Can't configure independently of other-IPv4 */
		rc = -EOPNOTSUPP;
		goto out_unlock;
	case IPV4_FLOW:
		shift = MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_OTHER_IPV4_RSS_MODE_LBN;
		break;
	case TCP_V6_FLOW:
		shift = MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TCP_IPV6_RSS_MODE_LBN;
		break;
	case UDP_V6_FLOW:
		shift = MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_UDP_IPV6_RSS_MODE_LBN;
		break;
	case SCTP_V6_FLOW:
	case AH_ESP_V6_FLOW:
		/* Can't configure independently of other-IPv6 */
		rc = -EOPNOTSUPP;
		goto out_unlock;
	case IPV6_FLOW:
		shift = MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_OTHER_IPV6_RSS_MODE_LBN;
		break;
	default:
		rc = -EOPNOTSUPP;
		goto out_unlock;
	}

	/* Clear the old flags for this flow_type */
	BUILD_BUG_ON(MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TCP_IPV4_RSS_MODE_WIDTH != 4);
	flags &= ~(0xf << shift);
	/* Construct new flags */
	if (info->data & RXH_IP_SRC)
		mode |= 1 << RSS_MODE_HASH_SRC_ADDR_LBN;
	if (info->data & RXH_IP_DST)
		mode |= 1 << RSS_MODE_HASH_DST_ADDR_LBN;
	if (info->data & RXH_L4_B_0_1)
		mode |= 1 << RSS_MODE_HASH_SRC_PORT_LBN;
	if (info->data & RXH_L4_B_2_3)
		mode |= 1 << RSS_MODE_HASH_DST_PORT_LBN;
	flags |= mode << shift;
	rc = efx->type->rx_set_rss_flags(efx, ctx, flags);
out_unlock:
	mutex_unlock(&efx->rss_lock);
	return rc;
}

static int efx_ethtool_get_class_rule(struct efx_nic *efx,
#ifdef EFX_USE_KCOMPAT
				      struct efx_ethtool_rx_flow_spec *rule,
#else
				      struct ethtool_rx_flow_spec *rule,
#endif
				      u32 *rss_context)
{
	struct ethtool_tcpip4_spec *ip_entry = &rule->h_u.tcp_ip4_spec;
	struct ethtool_tcpip4_spec *ip_mask = &rule->m_u.tcp_ip4_spec;
	struct ethtool_usrip4_spec *uip_entry = &rule->h_u.usr_ip4_spec;
	struct ethtool_usrip4_spec *uip_mask = &rule->m_u.usr_ip4_spec;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_IPV6_NFC)
	struct ethtool_tcpip6_spec *ip6_entry = (void *)&rule->h_u;
	struct ethtool_tcpip6_spec *ip6_mask = (void *)&rule->m_u;
	struct ethtool_usrip6_spec *uip6_entry = (void *)&rule->h_u;
	struct ethtool_usrip6_spec *uip6_mask = (void *)&rule->m_u;
#else
	struct ethtool_tcpip6_spec *ip6_entry = &rule->h_u.tcp_ip6_spec;
	struct ethtool_tcpip6_spec *ip6_mask = &rule->m_u.tcp_ip6_spec;
	struct ethtool_usrip6_spec *uip6_entry = &rule->h_u.usr_ip6_spec;
	struct ethtool_usrip6_spec *uip6_mask = &rule->m_u.usr_ip6_spec;
#endif
	struct ethhdr *mac_entry = &rule->h_u.ether_spec;
	struct ethhdr *mac_mask = &rule->m_u.ether_spec;
	struct efx_filter_spec spec;
	int rc;

	rc = efx_filter_ntuple_get(efx, rule->location, &spec);
	if (rc)
		return rc;

	if (spec.dmaq_id == EFX_FILTER_RX_DMAQ_ID_DROP)
		rule->ring_cookie = RX_CLS_FLOW_DISC;
	else
		rule->ring_cookie = spec.dmaq_id;

	if ((spec.match_flags & EFX_FILTER_MATCH_ETHER_TYPE) &&
	    spec.ether_type == htons(ETH_P_IP) &&
	    (spec.match_flags & EFX_FILTER_MATCH_IP_PROTO) &&
	    (spec.ip_proto == IPPROTO_TCP || spec.ip_proto == IPPROTO_UDP) &&
	    !(spec.match_flags &
	      ~(EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_OUTER_VID |
		EFX_FILTER_MATCH_LOC_HOST | EFX_FILTER_MATCH_REM_HOST |
		EFX_FILTER_MATCH_IP_PROTO |
		EFX_FILTER_MATCH_LOC_PORT | EFX_FILTER_MATCH_REM_PORT))) {
		rule->flow_type = ((spec.ip_proto == IPPROTO_TCP) ?
				   TCP_V4_FLOW : UDP_V4_FLOW);
		if (spec.match_flags & EFX_FILTER_MATCH_LOC_HOST) {
			ip_entry->ip4dst = spec.loc_host[0];
			ip_mask->ip4dst = IP4_ADDR_FULL_MASK;
		}
		if (spec.match_flags & EFX_FILTER_MATCH_REM_HOST) {
			ip_entry->ip4src = spec.rem_host[0];
			ip_mask->ip4src = IP4_ADDR_FULL_MASK;
		}
		if (spec.match_flags & EFX_FILTER_MATCH_LOC_PORT) {
			ip_entry->pdst = spec.loc_port;
			ip_mask->pdst = PORT_FULL_MASK;
		}
		if (spec.match_flags & EFX_FILTER_MATCH_REM_PORT) {
			ip_entry->psrc = spec.rem_port;
			ip_mask->psrc = PORT_FULL_MASK;
		}
	} else if ((spec.match_flags & EFX_FILTER_MATCH_ETHER_TYPE) &&
	    spec.ether_type == htons(ETH_P_IPV6) &&
	    (spec.match_flags & EFX_FILTER_MATCH_IP_PROTO) &&
	    (spec.ip_proto == IPPROTO_TCP || spec.ip_proto == IPPROTO_UDP) &&
	    !(spec.match_flags &
	      ~(EFX_FILTER_MATCH_ETHER_TYPE | EFX_FILTER_MATCH_OUTER_VID |
		EFX_FILTER_MATCH_LOC_HOST | EFX_FILTER_MATCH_REM_HOST |
		EFX_FILTER_MATCH_IP_PROTO |
		EFX_FILTER_MATCH_LOC_PORT | EFX_FILTER_MATCH_REM_PORT))) {
		rule->flow_type = ((spec.ip_proto == IPPROTO_TCP) ?
				   TCP_V6_FLOW : UDP_V6_FLOW);
		if (spec.match_flags & EFX_FILTER_MATCH_LOC_HOST) {
			memcpy(ip6_entry->ip6dst, spec.loc_host,
			       sizeof(ip6_entry->ip6dst));
			ip6_fill_mask(ip6_mask->ip6dst);
		}
		if (spec.match_flags & EFX_FILTER_MATCH_REM_HOST) {
			memcpy(ip6_entry->ip6src, spec.rem_host,
			       sizeof(ip6_entry->ip6src));
			ip6_fill_mask(ip6_mask->ip6src);
		}
		if (spec.match_flags & EFX_FILTER_MATCH_LOC_PORT) {
			ip6_entry->pdst = spec.loc_port;
			ip6_mask->pdst = PORT_FULL_MASK;
		}
		if (spec.match_flags & EFX_FILTER_MATCH_REM_PORT) {
			ip6_entry->psrc = spec.rem_port;
			ip6_mask->psrc = PORT_FULL_MASK;
		}
	} else if (!(spec.match_flags &
		     ~(EFX_FILTER_MATCH_LOC_MAC | EFX_FILTER_MATCH_LOC_MAC_IG |
		       EFX_FILTER_MATCH_REM_MAC | EFX_FILTER_MATCH_ETHER_TYPE |
		       EFX_FILTER_MATCH_OUTER_VID))) {
		rule->flow_type = ETHER_FLOW;
		if (spec.match_flags &
		    (EFX_FILTER_MATCH_LOC_MAC | EFX_FILTER_MATCH_LOC_MAC_IG)) {
			ether_addr_copy(mac_entry->h_dest, spec.loc_mac);
			if (spec.match_flags & EFX_FILTER_MATCH_LOC_MAC)
				eth_broadcast_addr(mac_mask->h_dest);
			else
				ether_addr_copy(mac_mask->h_dest,
						mac_addr_ig_mask);
		}
		if (spec.match_flags & EFX_FILTER_MATCH_REM_MAC) {
			ether_addr_copy(mac_entry->h_source, spec.rem_mac);
			eth_broadcast_addr(mac_mask->h_source);
		}
		if (spec.match_flags & EFX_FILTER_MATCH_ETHER_TYPE) {
			mac_entry->h_proto = spec.ether_type;
			mac_mask->h_proto = ETHER_TYPE_FULL_MASK;
		}
	} else if (spec.match_flags & EFX_FILTER_MATCH_ETHER_TYPE &&
		   spec.ether_type == htons(ETH_P_IP)) {
		rule->flow_type = IP_USER_FLOW;
		uip_entry->ip_ver = ETH_RX_NFC_IP4;
		if (spec.match_flags & EFX_FILTER_MATCH_IP_PROTO) {
			uip_mask->proto = IP_PROTO_FULL_MASK;
			uip_entry->proto = spec.ip_proto;
		}
		if (spec.match_flags & EFX_FILTER_MATCH_LOC_HOST) {
			uip_entry->ip4dst = spec.loc_host[0];
			uip_mask->ip4dst = IP4_ADDR_FULL_MASK;
		}
		if (spec.match_flags & EFX_FILTER_MATCH_REM_HOST) {
			uip_entry->ip4src = spec.rem_host[0];
			uip_mask->ip4src = IP4_ADDR_FULL_MASK;
		}
	} else if (spec.match_flags & EFX_FILTER_MATCH_ETHER_TYPE &&
		   spec.ether_type == htons(ETH_P_IPV6)) {
		rule->flow_type = IPV6_USER_FLOW;
		if (spec.match_flags & EFX_FILTER_MATCH_IP_PROTO) {
			uip6_mask->l4_proto = IP_PROTO_FULL_MASK;
			uip6_entry->l4_proto = spec.ip_proto;
		}
		if (spec.match_flags & EFX_FILTER_MATCH_LOC_HOST) {
			memcpy(uip6_entry->ip6dst, spec.loc_host,
			       sizeof(uip6_entry->ip6dst));
			ip6_fill_mask(uip6_mask->ip6dst);
		}
		if (spec.match_flags & EFX_FILTER_MATCH_REM_HOST) {
			memcpy(uip6_entry->ip6src, spec.rem_host,
			       sizeof(uip6_entry->ip6src));
			ip6_fill_mask(uip6_mask->ip6src);
		}
	} else {
		/* The above should handle all filters that we insert */
		WARN_ON(1);
		return -EINVAL;
	}

	if (spec.match_flags & EFX_FILTER_MATCH_OUTER_VID) {
		rule->flow_type |= FLOW_EXT;
		rule->h_ext.vlan_tci = spec.outer_vid;
		rule->m_ext.vlan_tci = htons(0xfff);
	}

	if (spec.flags & EFX_FILTER_FLAG_RX_RSS) {
		rule->flow_type |= FLOW_RSS;
		*rss_context = spec.rss_context;
	}

	return rc;
}

int efx_ethtool_get_rxnfc(struct net_device *net_dev,
#ifdef EFX_USE_KCOMPAT
			  struct efx_ethtool_rxnfc *info,
#else
			  struct ethtool_rxnfc *info,
#endif
			  u32 *rule_locs)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	u32 rss_context = 0;
	s32 rc = 0;

	switch (info->cmd) {
	case ETHTOOL_GRXRINGS:
		info->data = efx->n_rss_channels;
		if (!info->data)
			return -ENOENT;
		return 0;

	case ETHTOOL_GRXFH: {
		struct efx_rss_context *ctx = &efx->rss_context;

		mutex_lock(&efx->rss_lock);
		if (info->flow_type & FLOW_RSS && info->rss_context) {
			ctx = efx_find_rss_context_entry(efx,
							 info->rss_context);
			if (!ctx) {
				rc = -ENOENT;
				goto out_unlock;
			}
		}
		info->data = 0;
		if (!efx_rss_active(ctx)) /* No RSS */
			goto out_unlock;
		if (efx->type->rx_get_rss_flags) {
			int rc;

			rc = efx->type->rx_get_rss_flags(efx, ctx);
			if (rc)
				goto out_unlock;
		}
		if (ctx->flags & RSS_CONTEXT_FLAGS_ADDITIONAL_MASK) {
			int shift;
			u8 mode;

			switch (info->flow_type & ~FLOW_RSS) {
			case TCP_V4_FLOW:
				shift = MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TCP_IPV4_RSS_MODE_LBN;
				break;
			case UDP_V4_FLOW:
				shift = MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_UDP_IPV4_RSS_MODE_LBN;
				break;
			case SCTP_V4_FLOW:
			case AH_ESP_V4_FLOW:
			case IPV4_FLOW:
				shift = MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_OTHER_IPV4_RSS_MODE_LBN;
				break;
			case TCP_V6_FLOW:
				shift = MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_TCP_IPV6_RSS_MODE_LBN;
				break;
			case UDP_V6_FLOW:
				shift = MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_UDP_IPV6_RSS_MODE_LBN;
				break;
			case SCTP_V6_FLOW:
			case AH_ESP_V6_FLOW:
			case IPV6_FLOW:
				shift = MC_CMD_RSS_CONTEXT_GET_FLAGS_OUT_OTHER_IPV6_RSS_MODE_LBN;
				break;
			default:
				goto out_unlock;
			}
			mode = ctx->flags >> shift;
			if (mode & (1 << RSS_MODE_HASH_SRC_ADDR_LBN))
				info->data |= RXH_IP_SRC;
			if (mode & (1 << RSS_MODE_HASH_DST_ADDR_LBN))
				info->data |= RXH_IP_DST;
			if (mode & (1 << RSS_MODE_HASH_SRC_PORT_LBN))
				info->data |= RXH_L4_B_0_1;
			if (mode & (1 << RSS_MODE_HASH_DST_PORT_LBN))
				info->data |= RXH_L4_B_2_3;
		} else {
			switch (info->flow_type & ~FLOW_RSS) {
			case TCP_V4_FLOW:
				info->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;
				fallthrough;
			case UDP_V4_FLOW:
			case SCTP_V4_FLOW:
			case AH_ESP_V4_FLOW:
			case IPV4_FLOW:
				info->data |= RXH_IP_SRC | RXH_IP_DST;
				break;
			case TCP_V6_FLOW:
				info->data |= RXH_L4_B_0_1 | RXH_L4_B_2_3;
				fallthrough;
			case UDP_V6_FLOW:
			case SCTP_V6_FLOW:
			case AH_ESP_V6_FLOW:
			case IPV6_FLOW:
				info->data |= RXH_IP_SRC | RXH_IP_DST;
				break;
			default:
				break;
			}
		}
out_unlock:
		mutex_unlock(&efx->rss_lock);
		return rc;
	}

	case ETHTOOL_GRXCLSRLCNT:
		info->data = efx_filter_get_rx_id_limit(efx);
		if (info->data == 0)
			return -EOPNOTSUPP;
		info->data |= RX_CLS_LOC_SPECIAL;
		info->rule_cnt = efx_filter_count_ntuple(efx);
		return 0;

	case ETHTOOL_GRXCLSRULE:
		if (efx_filter_get_rx_id_limit(efx) == 0)
			return -EOPNOTSUPP;
		rc = efx_ethtool_get_class_rule(efx, &info->fs, &rss_context);
		if (rc < 0)
			return rc;
		if (info->fs.flow_type & FLOW_RSS)
			info->rss_context = rss_context;
		return 0;

	case ETHTOOL_GRXCLSRLALL:
		info->data = efx_filter_get_rx_id_limit(efx);
		if (info->data == 0)
			return -EOPNOTSUPP;
		info->rule_cnt = efx_filter_count_ntuple(efx);
		efx_filter_get_ntuple_ids(efx, rule_locs, info->rule_cnt);
		return 0;

	default:
		return -EOPNOTSUPP;
	}
}

static inline bool ip6_mask_is_full(__be32 mask[4])
{
	return !~(mask[0] & mask[1] & mask[2] & mask[3]);
}

static inline bool ip6_mask_is_empty(__be32 mask[4])
{
	return !(mask[0] | mask[1] | mask[2] | mask[3]);
}

#ifdef EFX_USE_KCOMPAT
static int efx_ethtool_set_class_rule(struct efx_nic *efx,
				      struct efx_ethtool_rx_flow_spec *rule,
				      u32 rss_context)
#else
static int efx_ethtool_set_class_rule(struct efx_nic *efx,
				      struct ethtool_rx_flow_spec *rule,
				      u32 rss_context)
#endif
{
	struct ethtool_tcpip4_spec *ip_entry = &rule->h_u.tcp_ip4_spec;
	struct ethtool_tcpip4_spec *ip_mask = &rule->m_u.tcp_ip4_spec;
	struct ethtool_usrip4_spec *uip_entry = &rule->h_u.usr_ip4_spec;
	struct ethtool_usrip4_spec *uip_mask = &rule->m_u.usr_ip4_spec;
#if defined(EFX_USE_KCOMPAT) && defined(EFX_NEED_IPV6_NFC)
	struct ethtool_tcpip6_spec *ip6_entry = (void *)&rule->h_u;
	struct ethtool_tcpip6_spec *ip6_mask = (void *)&rule->m_u;
	struct ethtool_usrip6_spec *uip6_entry = (void *)&rule->h_u;
	struct ethtool_usrip6_spec *uip6_mask = (void *)&rule->m_u;
#else
	struct ethtool_tcpip6_spec *ip6_entry = &rule->h_u.tcp_ip6_spec;
	struct ethtool_tcpip6_spec *ip6_mask = &rule->m_u.tcp_ip6_spec;
	struct ethtool_usrip6_spec *uip6_entry = &rule->h_u.usr_ip6_spec;
	struct ethtool_usrip6_spec *uip6_mask = &rule->m_u.usr_ip6_spec;
#endif
	u32 flow_type = rule->flow_type & ~(FLOW_EXT | FLOW_RSS);
	struct ethhdr *mac_entry = &rule->h_u.ether_spec;
	struct ethhdr *mac_mask = &rule->m_u.ether_spec;
	enum efx_filter_flags flags = 0;
	struct efx_filter_spec spec;
	int rc;

	/* Check that user wants us to choose the location */
	if (rule->location != RX_CLS_LOC_ANY)
		return -EINVAL;

	/* Range-check ring_cookie */
	if (rule->ring_cookie >= efx_rx_channels(efx) &&
	    rule->ring_cookie != RX_CLS_FLOW_DISC)
		return -EINVAL;

	/* Check for unsupported extensions */
	if ((rule->flow_type & FLOW_EXT) &&
	    (rule->m_ext.vlan_etype || rule->m_ext.data[0] ||
	     rule->m_ext.data[1]))
		return -EINVAL;

	if (efx->rx_scatter)
		flags |= EFX_FILTER_FLAG_RX_SCATTER;
	if (rule->flow_type & FLOW_RSS)
		flags |= EFX_FILTER_FLAG_RX_RSS;

	efx_filter_init_rx(&spec, EFX_FILTER_PRI_MANUAL, flags,
			   (rule->ring_cookie == RX_CLS_FLOW_DISC) ?
			   EFX_FILTER_RX_DMAQ_ID_DROP : rule->ring_cookie);

	if (rule->flow_type & FLOW_RSS)
		spec.rss_context = rss_context;

	switch (flow_type) {
	case TCP_V4_FLOW:
	case UDP_V4_FLOW:
		spec.match_flags = (EFX_FILTER_MATCH_ETHER_TYPE |
				    EFX_FILTER_MATCH_IP_PROTO);
		spec.ether_type = htons(ETH_P_IP);
		spec.ip_proto = flow_type == TCP_V4_FLOW ? IPPROTO_TCP
							 : IPPROTO_UDP;
		if (ip_mask->ip4dst) {
			if (ip_mask->ip4dst != IP4_ADDR_FULL_MASK)
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_LOC_HOST;
			spec.loc_host[0] = ip_entry->ip4dst;
		}
		if (ip_mask->ip4src) {
			if (ip_mask->ip4src != IP4_ADDR_FULL_MASK)
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_REM_HOST;
			spec.rem_host[0] = ip_entry->ip4src;
		}
		if (ip_mask->pdst) {
			if (ip_mask->pdst != PORT_FULL_MASK)
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_LOC_PORT;
			spec.loc_port = ip_entry->pdst;
		}
		if (ip_mask->psrc) {
			if (ip_mask->psrc != PORT_FULL_MASK)
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_REM_PORT;
			spec.rem_port = ip_entry->psrc;
		}
		if (ip_mask->tos)
			return -EINVAL;
		break;

	case TCP_V6_FLOW:
	case UDP_V6_FLOW:
		spec.match_flags = (EFX_FILTER_MATCH_ETHER_TYPE |
				    EFX_FILTER_MATCH_IP_PROTO);
		spec.ether_type = htons(ETH_P_IPV6);
		spec.ip_proto = flow_type == TCP_V6_FLOW ? IPPROTO_TCP
							 : IPPROTO_UDP;
		if (!ip6_mask_is_empty(ip6_mask->ip6dst)) {
			if (!ip6_mask_is_full(ip6_mask->ip6dst))
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_LOC_HOST;
			memcpy(spec.loc_host, ip6_entry->ip6dst,
			       sizeof(spec.loc_host));
		}
		if (!ip6_mask_is_empty(ip6_mask->ip6src)) {
			if (!ip6_mask_is_full(ip6_mask->ip6src))
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_REM_HOST;
			memcpy(spec.rem_host, ip6_entry->ip6src,
			       sizeof(spec.rem_host));
		}
		if (ip6_mask->pdst) {
			if (ip6_mask->pdst != PORT_FULL_MASK)
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_LOC_PORT;
			spec.loc_port = ip6_entry->pdst;
		}
		if (ip6_mask->psrc) {
			if (ip6_mask->psrc != PORT_FULL_MASK)
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_REM_PORT;
			spec.rem_port = ip6_entry->psrc;
		}
		if (ip6_mask->tclass)
			return -EINVAL;
		break;

	case IP_USER_FLOW:
		if (uip_mask->l4_4_bytes || uip_mask->tos || uip_mask->ip_ver ||
		    uip_entry->ip_ver != ETH_RX_NFC_IP4)
			return -EINVAL;
		spec.match_flags = EFX_FILTER_MATCH_ETHER_TYPE;
		spec.ether_type = htons(ETH_P_IP);
		if (uip_mask->ip4dst) {
			if (uip_mask->ip4dst != IP4_ADDR_FULL_MASK)
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_LOC_HOST;
			spec.loc_host[0] = uip_entry->ip4dst;
		}
		if (uip_mask->ip4src) {
			if (uip_mask->ip4src != IP4_ADDR_FULL_MASK)
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_REM_HOST;
			spec.rem_host[0] = uip_entry->ip4src;
		}
		if (uip_mask->proto) {
			if (uip_mask->proto != IP_PROTO_FULL_MASK)
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_IP_PROTO;
			spec.ip_proto = uip_entry->proto;
		}
		break;

	case IPV6_USER_FLOW:
		if (uip6_mask->l4_4_bytes || uip6_mask->tclass)
			return -EINVAL;
		spec.match_flags = EFX_FILTER_MATCH_ETHER_TYPE;
		spec.ether_type = htons(ETH_P_IPV6);
		if (!ip6_mask_is_empty(uip6_mask->ip6dst)) {
			if (!ip6_mask_is_full(uip6_mask->ip6dst))
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_LOC_HOST;
			memcpy(spec.loc_host, uip6_entry->ip6dst,
			       sizeof(spec.loc_host));
		}
		if (!ip6_mask_is_empty(uip6_mask->ip6src)) {
			if (!ip6_mask_is_full(uip6_mask->ip6src))
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_REM_HOST;
			memcpy(spec.rem_host, uip6_entry->ip6src,
			       sizeof(spec.rem_host));
		}
		if (uip6_mask->l4_proto) {
			if (uip6_mask->l4_proto != IP_PROTO_FULL_MASK)
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_IP_PROTO;
			spec.ip_proto = uip6_entry->l4_proto;
		}
		break;

	case ETHER_FLOW:
		if (!is_zero_ether_addr(mac_mask->h_dest)) {
			if (ether_addr_equal(mac_mask->h_dest,
					     mac_addr_ig_mask))
				spec.match_flags |= EFX_FILTER_MATCH_LOC_MAC_IG;
			else if (is_broadcast_ether_addr(mac_mask->h_dest))
				spec.match_flags |= EFX_FILTER_MATCH_LOC_MAC;
			else
				return -EINVAL;
			ether_addr_copy(spec.loc_mac, mac_entry->h_dest);
		}
		if (!is_zero_ether_addr(mac_mask->h_source)) {
			if (!is_broadcast_ether_addr(mac_mask->h_source))
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_REM_MAC;
			ether_addr_copy(spec.rem_mac, mac_entry->h_source);
		}
		if (mac_mask->h_proto) {
			if (mac_mask->h_proto != ETHER_TYPE_FULL_MASK)
				return -EINVAL;
			spec.match_flags |= EFX_FILTER_MATCH_ETHER_TYPE;
			spec.ether_type = mac_entry->h_proto;
		}
		break;

	default:
		return -EINVAL;
	}

	if ((rule->flow_type & FLOW_EXT) && rule->m_ext.vlan_tci) {
		if (rule->m_ext.vlan_tci != htons(0xfff))
			return -EINVAL;
		spec.match_flags |= EFX_FILTER_MATCH_OUTER_VID;
		spec.outer_vid = rule->h_ext.vlan_tci;
	}

	rc = efx_filter_ntuple_insert(efx, &spec);
	if (rc < 0)
		return rc;

	rule->location = rc;
	return 0;
}

int efx_ethtool_set_rxnfc(struct net_device *net_dev,
#ifdef EFX_USE_KCOMPAT
			  struct efx_ethtool_rxnfc *info)
#else
			  struct ethtool_rxnfc *info)
#endif
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	if (efx_filter_get_rx_id_limit(efx) == 0)
		return -EOPNOTSUPP;

	switch (info->cmd) {
	case ETHTOOL_SRXCLSRLINS:
		return efx_ethtool_set_class_rule(efx, &info->fs,
						  info->rss_context);

	case ETHTOOL_SRXCLSRLDEL:
		return efx_filter_ntuple_remove(efx, info->fs.location);

	case ETHTOOL_SRXFH:
		return efx_ethtool_set_rss_flags(efx, info);

	default:
		return -EOPNOTSUPP;
	}
}

#if defined(EFX_USE_KCOMPAT) && defined(EFX_HAVE_ETHTOOL_RXNFC)
int efx_ethtool_get_rxnfc_wrapper(struct net_device *net_dev,
					 struct ethtool_rxnfc *info,
#ifdef EFX_HAVE_OLD_ETHTOOL_GET_RXNFC
					 void *rules)
#else
					 u32 *rules)
#endif
{
	return efx_ethtool_get_rxnfc(net_dev, (struct efx_ethtool_rxnfc *)info,
				     rules);
}

int efx_ethtool_set_rxnfc_wrapper(struct net_device *net_dev,
					 struct ethtool_rxnfc *info)
{
	return efx_ethtool_set_rxnfc(net_dev, (struct efx_ethtool_rxnfc *)info);
}
#endif

u32 efx_ethtool_get_rxfh_indir_size(struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	return ARRAY_SIZE(efx->rss_context.rx_indir_table);
}


u32 efx_ethtool_get_rxfh_key_size(struct net_device *net_dev)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

	return efx->type->rx_hash_key_size;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_GET_RXFH) || defined(EFX_HAVE_ETHTOOL_GET_RXFH_INDIR) || !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)
int efx_ethtool_get_rxfh(struct net_device *net_dev, u32 *indir, u8 *key,
			 u8 *hfunc)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
#else
int efx_sfctool_get_rxfh(struct efx_nic *efx, u32 *indir, u8 *key,
			 u8 *hfunc)
{
#endif
	int rc;

	if (!efx->type->rx_pull_rss_config)
		return -EOPNOTSUPP;

	rc = efx->type->rx_pull_rss_config(efx);
	if (rc)
		return rc;

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;
	if (indir)
		memcpy(indir, efx->rss_context.rx_indir_table,
		       sizeof(efx->rss_context.rx_indir_table));
	if (key)
		memcpy(key, efx->rss_context.rx_hash_key,
		       efx->type->rx_hash_key_size);
	return 0;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_GET_RXFH) || defined(EFX_HAVE_ETHTOOL_GET_RXFH_INDIR) || !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)
int efx_ethtool_set_rxfh(struct net_device *net_dev,
			 const u32 *indir, const u8 *key, const u8 hfunc)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);

#else
int efx_sfctool_set_rxfh(struct efx_nic *efx,
			 const u32 *indir, const u8 *key, const u8 hfunc)
{
#endif
	if (!efx->type->rx_push_rss_config)
		return -EOPNOTSUPP;

	/* We do not allow change in unsupported parameters */
	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;
	if (!indir && !key)
		return 0;

	if (!key)
		key = efx->rss_context.rx_hash_key;
	if (!indir)
		indir = efx->rss_context.rx_indir_table;

	return efx->type->rx_push_rss_config(efx, true, indir, key);
}


#if defined(EFX_HAVE_ETHTOOL_GET_RXFH) && !defined(EFX_HAVE_CONFIGURABLE_RSS_HASH)
/* Wrappers without hash function getting and setting. */
int efx_ethtool_get_rxfh_no_hfunc(struct net_device *net_dev,
				  u32 *indir, u8 *key)
{
	return efx_ethtool_get_rxfh(net_dev, indir, key, NULL);
}

# if defined(EFX_HAVE_ETHTOOL_SET_RXFH_NOCONST)
/* RH backported version doesn't have const for arguments. */
int efx_ethtool_set_rxfh_no_hfunc(struct net_device *net_dev,
				  u32 *indir, u8 *key)
{
	return efx_ethtool_set_rxfh(net_dev, indir, key,
				    ETH_RSS_HASH_NO_CHANGE);
}
# else
int efx_ethtool_set_rxfh_no_hfunc(struct net_device *net_dev,
				  const u32 *indir, const u8 *key)
{
	return efx_ethtool_set_rxfh(net_dev, indir, key,
				    ETH_RSS_HASH_NO_CHANGE);
}
# endif
#endif

#if defined(EFX_HAVE_OLD_ETHTOOL_RXFH_INDIR) || !defined(EFX_HAVE_ETHTOOL_RXFH_INDIR)
int efx_ethtool_old_get_rxfh_indir(struct net_device *net_dev,
				   struct ethtool_rxfh_indir *indir)
{
	u32 user_size = indir->size, dev_size;

	dev_size = efx_ethtool_get_rxfh_indir_size(net_dev);
	if (dev_size == 0)
		return -EOPNOTSUPP;

	if (user_size < dev_size) {
		indir->size = dev_size;
		return user_size == 0 ? 0 : -EINVAL;
	}

	return efx_ethtool_get_rxfh(net_dev, indir->ring_index, NULL, NULL);
}

int efx_ethtool_old_set_rxfh_indir(struct net_device *net_dev,
				   const struct ethtool_rxfh_indir *indir)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	u32 user_size = indir->size, dev_size, i;

	dev_size = efx_ethtool_get_rxfh_indir_size(net_dev);
	if (dev_size == 0)
		return -EOPNOTSUPP;

	if (user_size != dev_size)
		return -EINVAL;

	/* Validate ring indices */
	for (i = 0; i < dev_size; i++)
		if (indir->ring_index[i] >= efx_rx_channels(efx))
			return -EINVAL;

	return efx_ethtool_set_rxfh(net_dev, indir->ring_index, NULL,
			ETH_RSS_HASH_NO_CHANGE);
}
#endif

#if defined(EFX_USE_KCOMPAT)
#if defined(EFX_HAVE_ETHTOOL_GET_RXFH_INDIR) && !defined(EFX_HAVE_ETHTOOL_GET_RXFH) && !defined(EFX_HAVE_OLD_ETHTOOL_RXFH_INDIR)
/* Wrappers that only set the indirection table, not the key. */
int efx_ethtool_get_rxfh_indir(struct net_device *net_dev, u32 *indir)
{
	return efx_ethtool_get_rxfh(net_dev, indir, NULL, NULL);
}

int efx_ethtool_set_rxfh_indir(struct net_device *net_dev, const u32 *indir)
{
	return efx_ethtool_set_rxfh(net_dev, indir, NULL,
				    ETH_RSS_HASH_NO_CHANGE);
}
#endif
#endif

/*	sfctool
 */
#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXFH_CONTEXT)
int efx_sfctool_get_rxnfc(struct efx_nic *efx,
			  struct efx_ethtool_rxnfc *info, u32 *rule_locs)
{
	return efx_ethtool_get_rxnfc(efx->net_dev, info, rule_locs);
}
#endif

#if defined(EFX_USE_KCOMPAT) && !defined(EFX_HAVE_ETHTOOL_RXFH_CONTEXT)
u32 efx_sfctool_get_rxfh_indir_size(struct efx_nic *efx)
{
	return efx_ethtool_get_rxfh_indir_size(efx->net_dev);
}

u32 efx_sfctool_get_rxfh_key_size(struct efx_nic *efx)
{
	return efx_ethtool_get_rxfh_key_size(efx->net_dev);
}
#endif

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_RXFH_CONTEXT)
int efx_ethtool_get_rxfh_context(struct net_device *net_dev, u32 *indir,
				 u8 *key, u8 *hfunc, u32 rss_context)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
#else
int efx_sfctool_get_rxfh_context(struct efx_nic *efx, u32 *indir,
				 u8 *key, u8 *hfunc, u32 rss_context)
{
#endif
	struct efx_rss_context *ctx;
	int rc = 0;

	if (!efx->type->rx_pull_rss_context_config)
		return -EOPNOTSUPP;

	mutex_lock(&efx->rss_lock);
	ctx = efx_find_rss_context_entry(efx, rss_context);
	if (!ctx) {
		rc = -ENOENT;
		goto out_unlock;
	}
	rc = efx->type->rx_pull_rss_context_config(efx, ctx);
	if (rc)
		goto out_unlock;

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;
	if (indir)
		memcpy(indir, ctx->rx_indir_table, sizeof(ctx->rx_indir_table));
	if (key)
		memcpy(key, ctx->rx_hash_key, efx->type->rx_hash_key_size);
out_unlock:
	mutex_unlock(&efx->rss_lock);
	return rc;
}

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_RXFH_CONTEXT)
int efx_ethtool_set_rxfh_context(struct net_device *net_dev,
				 const u32 *indir, const u8 *key,
				 const u8 hfunc, u32 *rss_context,
				 bool delete)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
#else
int efx_sfctool_set_rxfh_context(struct efx_nic *efx,
				 const u32 *indir, const u8 *key,
				 const u8 hfunc, u32 *rss_context,
				 bool delete)
{
#endif
	struct efx_rss_context *ctx;
	bool allocated = false;
	int rc;

	if (!efx->type->rx_push_rss_context_config)
		return -EOPNOTSUPP;
	/* Hash function is Toeplitz, cannot be changed */
	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EOPNOTSUPP;

	mutex_lock(&efx->rss_lock);

	if (*rss_context == ETH_RXFH_CONTEXT_ALLOC) {
		if (delete) {
			/* alloc + delete == Nothing to do */
			rc = -EINVAL;
			goto out_unlock;
		}
		ctx = efx_alloc_rss_context_entry(efx);
		if (!ctx) {
			rc = -ENOMEM;
			goto out_unlock;
		}
		ctx->context_id = EFX_MCDI_RSS_CONTEXT_INVALID;
		/* Initialise indir table and key to defaults */
		efx_set_default_rx_indir_table(efx, ctx);
		netdev_rss_key_fill(ctx->rx_hash_key, sizeof(ctx->rx_hash_key));
		allocated = true;
	} else {
		ctx = efx_find_rss_context_entry(efx, *rss_context);
		if (!ctx) {
			rc = -ENOENT;
			goto out_unlock;
		}
	}

	if (delete) {
		/* delete this context */
		rc = efx->type->rx_push_rss_context_config(efx, ctx, NULL, NULL);
		if (!rc)
			efx_free_rss_context_entry(ctx);
		goto out_unlock;
	}

	if (!key)
		key = ctx->rx_hash_key;
	if (!indir)
		indir = ctx->rx_indir_table;

	rc = efx->type->rx_push_rss_context_config(efx, ctx, indir, key);
	if (rc && allocated)
		efx_free_rss_context_entry(ctx);
	else
		*rss_context = ctx->user_id;
out_unlock:
	mutex_unlock(&efx->rss_lock);
	return rc;
}

int efx_ethtool_reset(struct net_device *net_dev, u32 *flags)
{
	struct efx_nic *efx = efx_netdev_priv(net_dev);
	u32 reset_flags = *flags;
	int rc;

	rc = efx->type->map_reset_flags(&reset_flags);
	if (rc >= 0) {
		rc = efx_reset(efx, rc);
		/* Manual resets can be done as often as you like */
		efx->reset_count = 0;
		/* update *flags if reset succeeded */
		if (!rc)
			*flags = reset_flags;
	}

	if (*flags & ETH_RESET_MAC) {
		netif_info(efx, drv, efx->net_dev,
			   "Resetting statistics.\n");
		efx->stats_initialised = false;
		efx->type->pull_stats(efx);
		*flags &= ~ETH_RESET_MAC;
		rc = 0;
	}

	return rc;
}

int efx_ethtool_get_module_eeprom(struct net_device *net_dev,
				  struct ethtool_eeprom *ee,
				  u8 *data)
{
	return efx_mcdi_phy_get_module_eeprom(efx_netdev_priv(net_dev), ee, data);
}

int efx_ethtool_get_module_info(struct net_device *net_dev,
				struct ethtool_modinfo *modinfo)
{
	return efx_mcdi_phy_get_module_info(efx_netdev_priv(net_dev), modinfo);
}
