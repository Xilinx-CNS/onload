/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author djr
**  \brief Helpers for filter code.
**   \date 20090317
**    \cop (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __TCP_FILTERS_INTERNAL_H__
#define __TCP_FILTERS_INTERNAL_H__


#define FMT_PROTOCOL(p)    ((p) == IPPROTO_TCP ? "TCP":         \
                            (p) == IPPROTO_UDP ? "UDP" : "???")

#define FMT_PORT(p)        ((int) CI_BSWAP_BE16(p))

#define IP_FMT             CI_IP_PRINTF_FORMAT
#define IP_ARG(ip)         CI_IP_PRINTF_ARGS(&(ip))

#define IPPORT_FMT         IP_FMT":%d"
#define IPPORT_ARG(ip,p)   IP_ARG(ip), FMT_PORT(p)

#endif  /* __TCP_FILTERS_INTERNAL_H__ */
