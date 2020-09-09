/* SPDX-License-Identifier: BSD-2-Clause */
/* (c) Copyright 2010-2011 Xilinx, Inc. */

#ifndef _UTIL_REQ_H
#define _UTIL_REQ_H

static inline int
efx_sock_ioctl(const char *ifname, __u16 cmd, union efx_ioctl_data *u)
{
	struct efx_sock_ioctl req;
 	struct ifreq ifr;
	int sock;
	int rc = 0;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
 	if (sock < 0) {
 		fprintf(stderr, "Could not open socket: %m\n");
  		exit(1);
  	}

	memset(&ifr, 0, sizeof(ifr));
 	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&req;
	memset(&req, 0, sizeof(req));
	req.cmd = cmd;
	memcpy(&req.u, u, sizeof(*u));
	if (ioctl(sock, SIOCEFX, &ifr) == -1)
		rc = -errno;
	close(sock);
	return rc;
}

static inline int
efx_char_ioctl(const char *ifname, __u16 cmd, union efx_ioctl_data *u)
{
	struct efx_ioctl req;
	int fd;
	int rc = 0;

	fd = open("/dev/sfc_control", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Could not open /dev/sfc_control: %m\n");
		exit(1);
	}

	memset(&req, 0, sizeof(req));
	strncpy(req.if_name, ifname, sizeof(req.if_name));
	req.cmd = cmd;
	memcpy(&req.u, u, sizeof(*u));
	if (ioctl(fd, SIOCEFX, &req) == -1)
		rc = -errno;
	close(fd);
	return rc;
}      

static inline int
efx_ioctl(const char *ifname, __u16 cmd, union efx_ioctl_data *u)
{
	int rc;

	/* Try the socket ioctl first:
	 *  - It supports drivers not loaded via load.sh [no /dev/sfc_control]
	 *  - 32bit compatability comes for free.
	 * Then try /dev/sfc_control, so these tools run on vmware.
	 */
	rc = efx_sock_ioctl(ifname, cmd, u);
	if (rc == -EOPNOTSUPP && access("/dev/sfc_control", O_RDWR) == 0)
		rc = efx_char_ioctl(ifname, cmd, u);

	return rc;
}

static inline int
ethtool_ioctl(const char *ifname, void *u)
{
 	struct ifreq ifr;
	int sock;
	int rc = 0;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
 	if (sock < 0) {
 		fprintf(stderr, "Could not open socket: %m\n");
  		exit(1);
  	}

	memset(&ifr, 0, sizeof(ifr));
 	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)u;
	if (ioctl(sock, SIOCETHTOOL, &ifr) == -1)
		rc = -errno;
	close(sock);
	return rc;
}

#endif
