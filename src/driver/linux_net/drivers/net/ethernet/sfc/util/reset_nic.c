/* SPDX-License-Identifier: BSD-2-Clause */
/* (c) Copyright 2005-2013 Xilinx, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include "../ioctl.h"
#include "req.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

static void
usage(char* prog) {
	eprintf("Syntax: %s [-m mode] ethX\n", prog);
	eprintf("      mode      invisible (exc phy)\n");
	eprintf("                all (default) (inc phy)\n");
	eprintf("                world (inc pcie)\n");
	eprintf("                disable\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	union efx_ioctl_data req;
	enum reset_type method = RESET_TYPE_ALL;
	__u32 flags = (ETH_RESET_DMA | ETH_RESET_FILTER |
		       ETH_RESET_OFFLOAD | ETH_RESET_MAC |
		       ETH_RESET_PHY);
	char* ifname = NULL;
	int i, rc;

	for (i=1; i < argc; i++) {
		if (strcmp(argv[i], "-m") == 0) {
			if (i+1 == argc)
				usage(argv[0]);
			++i;
			if (!strcmp(argv[i], "invisible")) {
				method = RESET_TYPE_INVISIBLE;
				flags = (ETH_RESET_DMA | ETH_RESET_FILTER |
					 ETH_RESET_OFFLOAD | ETH_RESET_MAC);
			} else if (!strcmp(argv[i], "all")) {
				method = RESET_TYPE_ALL;
				flags = (ETH_RESET_DMA | ETH_RESET_FILTER |
					 ETH_RESET_OFFLOAD | ETH_RESET_MAC |
					 ETH_RESET_PHY |
					 (ETH_RESET_MAC | ETH_RESET_PHY) <<
					 ETH_RESET_SHARED_SHIFT);
			} else if (!strcmp(argv[i], "world")) {
				method = RESET_TYPE_WORLD;
				flags = ETH_RESET_ALL;
			} else if (!strcmp(argv[i], "disable")) {
				method = RESET_TYPE_DISABLE;
				/* can't be done with EFX_RESET_FLAGS */
				flags = 0;
			} else {
				usage(argv[0]);
			}

			continue;
		}
			
		/* any other option is a call for help */
		if (argv[i][0] == '-')
			usage(argv[0]);

		/* this must be the interface name. Make sure it hasn't been set twice */
		if (ifname)
			usage(argv[0]);
		ifname = argv[i];
	}
	if (ifname == NULL)
		usage(argv[0]);

	memset(&req, 0, sizeof(req));
	if (flags) {
		struct ethtool_value value = { ETHTOOL_RESET, flags };
		rc = ethtool_ioctl(ifname, &value);
		if (rc == -EOPNOTSUPP) {
			req.reset_flags.flags = flags;
			rc = efx_ioctl(ifname, EFX_RESET_FLAGS, &req);
		}
	} else {
		rc = -EOPNOTSUPP;
	}
	if (rc == -EOPNOTSUPP) {
		req.reset.method = method;
		rc = efx_ioctl(ifname, EFX_RESET, &req);
	}
	if (rc != 0) {
		eprintf("Reset failed: %s\n", strerror(-rc));
		exit(1);
	}

	return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 *  indent-tabs-mode: 1
 * End:
 */
