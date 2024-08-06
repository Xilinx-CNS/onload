/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* xdp_tstamp.c -- xdp program that reads optional hw rx timestamp
 *
 * See also https://docs.kernel.org/networking/xdp-rx-metadata.html
 *
 *
 * # BUILD
 *
 * clang -target bpf -O2 -g -c xdp_tstamp.c -o ./xdp_tstamp.o
 *
 * # RUN
 *
 * # insert the xdp prog *before* loading the onload kernel modules
 * ./xdp_onload_prepare $DEV xdp_tstamp.o
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdp/xdp_helpers.h>

/* must match map created by onload/src/lib/efhw/af_xdp.c
 *
 * max_entries matches the number passed to
 * /sys/module/sfc_resource/afxdp/register
 */
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 4);
} onload_xdp_xsk SEC(".maps");

struct onload_xdp_rx_meta {
#define ONLOAD_XDP_RX_META_TSTAMP 0x1
	__u64 flags;
	__u64 tstamp;
};

extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx,
					 __u64 *timestamp) __ksym;

SEC("xdp")
int xdp_onload_prog(struct xdp_md *ctx)
{
	struct onload_xdp_rx_meta *meta;
	void *data, *data_meta;
	int ret;

	ret = bpf_xdp_adjust_meta(ctx, -(int)(sizeof(struct onload_xdp_rx_meta)));
	if (ret != 0)
		return XDP_PASS;

	data = (void *)(long)ctx->data;
	data_meta = (void *)(long)ctx->data_meta;

	if ((data_meta + sizeof(*meta)) > data)
		return XDP_PASS;

	meta = data_meta;

	meta->tstamp = 0;
	if (!bpf_xdp_metadata_rx_timestamp(ctx, &meta->tstamp))
		meta->flags = ONLOAD_XDP_RX_META_TSTAMP;
	else
		meta->flags = 0;

	return bpf_redirect_map(&onload_xdp_xsk, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
