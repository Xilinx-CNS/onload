/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This header describes the interface between the open source parts
 * of Onload and the binary-only control plane server.
 *
 * We use an md5sum over certain headers to ensure that userland and
 * kernel drivers are built against a compatible interface. The
 * control plane server and its clients will verify this hash against
 * the kernel module and refuse to start if there is a version
 * mismatch.
 *
 * Users should therefore not modify these headers because the
 * supplied control plane server will refuse to operate with the
 * resulting module.
 */

#ifndef __ONLOAD_CPLANE_MIBDUMP_SOCK_H__
#define __ONLOAD_CPLANE_MIBDUMP_SOCK_H__

#include <sys/un.h>

static void cp_init_mibdump_addr(struct sockaddr_un* addr,
                                 ci_uint32 server_pid)
{
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 2,
           "onload_cp_server_mibdump.%d", server_pid);
}

#endif /* __ONLOAD_CPLANE_MIBDUMP_SOCK_H__ */
