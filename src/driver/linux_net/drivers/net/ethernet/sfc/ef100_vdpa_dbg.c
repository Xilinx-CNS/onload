// SPDX-License-Identifier: GPL-2.0
/* Driver for AMD network controllers and boards
 * Copyright(C) 2023, Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "ef100_vdpa.h"
#include "ef100_vdpa_dbg.h"

#define SIZE 100

struct bit_label {
	u8 bit;
	char *str;
};

static const struct bit_label virtio_net_features[] = {
	{VIRTIO_F_NOTIFY_ON_EMPTY, "VIRTIO_F_NOTIFY_ON_EMPTY"},
	{VIRTIO_F_ANY_LAYOUT, "VIRTIO_F_ANY_LAYOUT"},
	{VIRTIO_F_VERSION_1, "VIRTIO_F_VERSION_1"},
	{VIRTIO_F_ACCESS_PLATFORM, "VIRTIO_F_ACCESS_PLATFORM"},
	{VIRTIO_F_RING_PACKED, "VIRTIO_F_RING_PACKED"},
	{VIRTIO_F_ORDER_PLATFORM, "VIRTIO_F_ORDER_PLATFORM"},
	{VIRTIO_F_IN_ORDER, "VIRTIO_F_IN_ORDER"},
	{VIRTIO_F_SR_IOV, "VIRTIO_F_SR_IOV"},
	{VIRTIO_NET_F_CSUM, "VIRTIO_NET_F_CSUM"},
	{VIRTIO_NET_F_GUEST_CSUM, "VIRTIO_NET_F_GUEST_CSUM"},
	{VIRTIO_NET_F_CTRL_GUEST_OFFLOADS, "VIRTIO_NET_F_CTRL_GUEST_OFFLOADS"},
	{VIRTIO_NET_F_MTU, "VIRTIO_NET_F_MTU"},
	{VIRTIO_NET_F_MAC, "VIRTIO_NET_F_MAC"},
	{VIRTIO_NET_F_GUEST_TSO4, "VIRTIO_NET_F_GUEST_TSO4"},
	{VIRTIO_NET_F_GUEST_TSO6, "VIRTIO_NET_F_GUEST_TSO6"},
	{VIRTIO_NET_F_GUEST_ECN, "VIRTIO_NET_F_GUEST_ECN"},
	{VIRTIO_NET_F_GUEST_UFO, "VIRTIO_NET_F_GUEST_UFO"},
	{VIRTIO_NET_F_HOST_TSO4, "VIRTIO_NET_F_HOST_TSO4"},
	{VIRTIO_NET_F_HOST_TSO6, "VIRTIO_NET_F_HOST_TSO6"},
	{VIRTIO_NET_F_HOST_ECN, "VIRTIO_NET_F_HOST_ECN"},
	{VIRTIO_NET_F_HOST_UFO, "VIRTIO_NET_F_HOST_UFO"},
	{VIRTIO_NET_F_MRG_RXBUF, "VIRTIO_NET_F_MRG_RXBUF"},
	{VIRTIO_NET_F_STATUS, "VIRTIO_NET_F_STATUS"},
	{VIRTIO_NET_F_CTRL_VQ, "VIRTIO_NET_F_CTRL_VQ"},
	{VIRTIO_NET_F_CTRL_RX, "VIRTIO_NET_F_CTRL_RX"},
	{VIRTIO_NET_F_CTRL_VLAN, "VIRTIO_NET_F_CTRL_VLAN"},
	{VIRTIO_NET_F_CTRL_RX_EXTRA, "VIRTIO_NET_F_CTRL_RX_EXTRA"},
	{VIRTIO_NET_F_GUEST_ANNOUNCE, "VIRTIO_NET_F_GUEST_ANNOUNCE"},
	{VIRTIO_NET_F_MQ, "VIRTIO_NET_F_MQ"},
	{VIRTIO_NET_F_CTRL_MAC_ADDR, "VIRTIO_NET_F_CTRL_MAC_ADDR"},
	{VIRTIO_NET_F_HASH_REPORT, "VIRTIO_NET_F_HASH_REPORT"},
	{VIRTIO_NET_F_RSS, "VIRTIO_NET_F_RSS"},
	{VIRTIO_NET_F_RSC_EXT, "VIRTIO_NET_F_RSC_EXT"},
	{VIRTIO_NET_F_STANDBY, "VIRTIO_NET_F_STANDBY"},
	{VIRTIO_NET_F_SPEED_DUPLEX, "VIRTIO_NET_F_SPEED_DUPLEX"},
	{VIRTIO_NET_F_GSO, "VIRTIO_NET_F_GSO"},
};

static const struct bit_label virtio_net_status[] = {
	{VIRTIO_CONFIG_S_ACKNOWLEDGE, "ACKNOWLEDGE"},
	{VIRTIO_CONFIG_S_DRIVER, "DRIVER"},
	{VIRTIO_CONFIG_S_FEATURES_OK, "FEATURES_OK"},
	{VIRTIO_CONFIG_S_DRIVER_OK, "DRIVER_OK"},
	{VIRTIO_CONFIG_S_FAILED, "FAILED"}
};

void print_status_str(u8 status, struct vdpa_device *vdev)
{
	u16 table_len =  ARRAY_SIZE(virtio_net_status);
	char concat_str[] = ", ";
	char buf[SIZE] = {0};
	u16 i;

	if (status == 0) {
		dev_info(&vdev->dev, "RESET\n");
		return;
	}
	for (i = 0; (i < table_len) && status; i++) {
		if (status & virtio_net_status[i].bit) {
			snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
				 "%s", virtio_net_status[i].str);
			status &= ~virtio_net_status[i].bit;
			snprintf(buf + strlen(buf),
				 sizeof(buf) - strlen(buf), "%s", concat_str);
		}
	}
	dev_info(&vdev->dev, "%s\n", buf);
	if (status)
		dev_info(&vdev->dev, "Unknown status:0x%x\n", status);
}

void print_features_str(u64 features, struct vdpa_device *vdev)
{
	int table_len = ARRAY_SIZE(virtio_net_features);
	int i;

	for (i = 0; (i < table_len) && features; i++) {
		if (features & BIT_ULL(virtio_net_features[i].bit)) {
			dev_info(&vdev->dev, "%s: %s\n", __func__,
				 virtio_net_features[i].str);
			features &= ~BIT_ULL(virtio_net_features[i].bit);
		}
	}
	if (features) {
		dev_info(&vdev->dev,
			 "%s: Unknown Features:0x%llx\n",
			 __func__, features);
	}
}

void print_vring_state(u16 state, struct vdpa_device *vdev)
{
	bool addr_conf = state & EF100_VRING_ADDRESS_CONFIGURED;
	bool size_conf = state & EF100_VRING_SIZE_CONFIGURED;
	bool ready_conf = state & EF100_VRING_READY_CONFIGURED;
	bool vring_created = state & EF100_VRING_CREATED;

	dev_info(&vdev->dev,
		 "%s: addr_conf: %u, sz_conf: %u, rdy_conf: %u, created: %u\n",
		 __func__, addr_conf, size_conf, ready_conf, vring_created);
}
