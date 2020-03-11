#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "../ioctl.h"
#include "req.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

int
main(int argc, char **argv)
{
	union efx_ioctl_data req;
	int rc;

	if (argc < 3) {
		eprintf("Syntax: %s ethX <channel>\n", argv[0]);
		exit(1);
	}

	memset(&req, 0, sizeof(req));
	req.evq_ack.channel = strtoul(argv[2], NULL, 10);
	rc = efx_ioctl(argv[1], EFX_EVQ_ACK, &req);
	if (rc != 0) {
		eprintf ( "Event queue ACK failed: %s\n", strerror(-rc));
		exit(1);
	}

	return 0;
}
