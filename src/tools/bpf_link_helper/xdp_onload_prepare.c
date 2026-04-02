/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* xdp_onload_prepare -- load an XDP ELF object with xsk map and program
 *
 * gcc -Wall -o xdp_onload_prepare xdp_onload_prepare.c -lbpf
 */

#include <errno.h>
#include <error.h>
#include <linux/ethtool.h>
#include <linux/if_link.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static int get_num_rxq(char *ifname)
{
	struct ethtool_channels ch = {
		.cmd = ETHTOOL_GCHANNELS,
	};
	struct ifreq ifr = {
		.ifr_data = (void *)&ch,
	};
	int fd, ret;

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		error(1, errno, "socket");

	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	if (ret < 0)
		error(1, errno, "ioctl SIOCETHTOOL");

	close(fd);

	return ch.rx_count + ch.combined_count;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map_xsk;
	int prog_fd, ifindex;
	char *ifname;

	if (argc != 3)
		error(1, 0, "Usage: %s [ifname] [bpf_file]\n", argv[0]);

	ifname = argv[1];
	ifindex = if_nametoindex(ifname);
	if (!ifindex)
		error(1, errno, "if_nametoindex %s", argv[1]);

	obj = bpf_object__open(argv[2]);
	if (!obj)
		error(1, errno, "bpf_object_open %s", argv[2]);

	map_xsk = bpf_object__find_map_by_name(obj, "onload_xdp_xsk");
	if (!map_xsk)
		error(1, 0, "bpf_object__find_map_by_name onload_xdp_xsk");

	bpf_map__set_max_entries(map_xsk, get_num_rxq(ifname));

	prog = bpf_object__find_program_by_name(obj, "xdp_onload_prog");
	if (!prog)
		error(1, 0, "bpf_object__find_program_by_name");

	bpf_program__set_ifindex(prog, ifindex);
	bpf_program__set_flags(prog, BPF_F_XDP_DEV_BOUND_ONLY);

	if (bpf_object__load(obj) < 0)
		error(1, errno, "bpf_object__load");

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0)
		error(1, 0, "bpf_program__fd");

	if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL))
		error(1, 0, "bpf_program__attach_xdp");

	if (bpf_object__pin_maps(obj, "/sys/fs/bpf"))
		error(1, 0, "bpf_object__pin_maps");

	printf("OK\n");
	return 0;
}
