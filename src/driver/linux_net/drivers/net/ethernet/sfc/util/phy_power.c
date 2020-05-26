#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "../ioctl.h"
#include "req.h"

#define eprintf(...) fprintf ( stderr, __VA_ARGS__ )

int
main(int argc, char **argv)
{
	union efx_ioctl_data req;
	int phy_on = 1;
	int rc;

	if (argc < 3) {
		eprintf("Syntax: %s ethX on|off\n", argv[0]);
		exit(1);
	}
	
	if (strcmp("on", argv[2]) == 0) {
		phy_on = 1;
	} else if (strcmp("off", argv[2]) == 0) {
		phy_on = 0;
	} else {
		eprintf("Invalid command \"%s\"\n", argv[2]);
		exit(1);
	}

	req.set_phy_power.on = phy_on;
	rc = efx_ioctl(argv[1], EFX_SET_PHY_POWER, &req);
	if (rc != 0) {
		eprintf("Set phy power failed: %s\n", strerror(-rc));
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
