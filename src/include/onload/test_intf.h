/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  kjm
**  \brief  Onload APIs for internal tests only
**   \date  2010/12/20
**    \cop  (c) Solarflare Communications Ltd.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_TEST_INTF_H__
#define __ONLOAD_TEST_INTF_H__

#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
/**********************************************************************
 * oo_raw_send: send a raw packet with full ethernet header.
 *
 * The file descriptor should be an Onload socket file descriptor.
 * Data size should not exceed the packet size (~1800 bytes); otherwise,
 * -1(errno=EMSGSIZE) is returned.
 * This function can send packets larger that MTU.
 *
 * If hwport == -1, the interface used by the socket is used (if Onload can
 * detect one).  You can find hwport number via
 * /proc/driver/onload/mib-llap.  -1(errno=ENETDOWN) is returned if hwport
 * is invalid.
 *
 * Returns 0 in case of success, -1 with errno in case of failure.
 *
 * This function exists mostly for Onload debugging.  You probably want to
 * use EF_VI API if you need low-latency raw send.
 */
extern int
oo_raw_send(int fd, int hwport, const struct iovec *iov, int iovlen);

#ifdef __cplusplus
}
#endif
#endif /* __ONLOAD_EXTENSIONS_H__ */
