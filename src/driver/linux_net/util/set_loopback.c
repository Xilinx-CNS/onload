#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "../ioctl.h"
#include "req.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

static const char * mode_names[] = {
	[LOOPBACK_NONE]		= "NONE",
	[LOOPBACK_DATA]		= "DATAPATH",
	[LOOPBACK_GMAC]		= "GMAC",
	[LOOPBACK_XGMII]	= "XGMII",
	[LOOPBACK_XGXS]		= "XGXS",
	[LOOPBACK_XAUI]  	= "XAUI",
	[LOOPBACK_GMII] 	= "GMII",
	[LOOPBACK_SGMII] 	= "SGMII",
	[LOOPBACK_XGBR]		= "XGBR",
	[LOOPBACK_XFI]		= "XFI",
	[LOOPBACK_XAUI_FAR]	= "XAUI_FAR",
	[LOOPBACK_GMII_FAR]	= "GMII_FAR",
	[LOOPBACK_SGMII_FAR]	= "SGMII_FAR",
	[LOOPBACK_XFI_FAR]	= "XFI_FAR",
	[LOOPBACK_GPHY]		= "GPHY",
	[LOOPBACK_PHYXS]	= "PHYXS",
	[LOOPBACK_PCS]	 	= "PCS",
	[LOOPBACK_PMAPMD] 	= "PMA_PMD",
	[LOOPBACK_XPORT]	= "XPORT",
	[LOOPBACK_XGMII_WS]	= "XGMII_WS",
	[LOOPBACK_XAUI_WS]  	= "XAUI_WS",
	[LOOPBACK_XAUI_WS_FAR]  = "XAUI_WS_FAR",
	[LOOPBACK_XAUI_WS_NEAR] = "XAUI_WS_NEAR",
	[LOOPBACK_GMII_WS] 	= "GMII_WS",
	[LOOPBACK_XFI_WS]	= "XFI_WS",
	[LOOPBACK_XFI_WS_FAR]	= "XFI_WS_FAR",
	[LOOPBACK_PHYXS_WS]  	= "PHYXS_WS",
	NULL,
};

static int
get_loopback_mode(const char *mode_name)
{
	int mode;

	if (strcasecmp("NEAR", mode_name) == 0)
		return LOOPBACK_NEAR;
	if (strcasecmp("FAR", mode_name) == 0)
		return LOOPBACK_FAR;

	for (mode = 0; mode_names[mode] != NULL; mode++) {
		if (strcasecmp(mode_names[mode], mode_name) == 0)
			return mode;
	}
	
	return -1;
}

int
main(int argc, char **argv)
{
	union efx_ioctl_data req;
	int i, mode, rc;

	if (argc < 3) {
		eprintf("Syntax: %s ethX <loopback type>\n", argv[0]);
		eprintf("  pseudo:  none  | near | far\n");
		eprintf("  1G MAC:  gmac\n");
		eprintf("  1G PHY:  gphy\n");
		eprintf("  10G MAC: xgmii | xgxs | xaui | xport\n");
		eprintf("  10G PHY: phyxs | pcs  | pma_pmd\n");

		eprintf("Full list (case insensitive):\n" );
		for (i=0 ; mode_names[i] != NULL; i++)
			eprintf("  %s\n", mode_names[i]);

		exit(1);
	}

	mode = get_loopback_mode(argv[2]);
	if (mode < 0) {
		eprintf("Invalid mode name \"%s\"\n", argv[2]);
		exit(1);
	}

	memset(&req, 0, sizeof(req));
	req.set_loopback.mode = mode;
	rc = efx_ioctl(argv[1], EFX_SET_LOOPBACK, &req);
	if (rc != 0) {
		eprintf("Set loopback mode failed: %s\n", strerror(-rc));
		exit(1);
	}

	return 0;
}
