/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  jmj
**  \brief  Definition of ipv4 stack statistics
**   \date  2018/07/03
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/


OO_STAT("Total number of recieved datagrams.",
        CI_IP_STATS_TYPE, in_recvs,count)

OO_STAT("Number of datagrams discarded due to errors in their IP headers.",
        CI_IP_STATS_TYPE, in_hdr_errs,count)

OO_STAT("Number of input IP datagrams for which no problems were "
        "encountered to prevent their continued processing, but which "
        "were discarded (e.g., for lack of buffer space).",
        CI_IP_STATS_TYPE, in_discards,count)

OO_STAT("Total number of input datagrams successfully delivered to IP "
        "user-protocols.",
        CI_IP_STATS_TYPE, in_delivers,count)

#if CI_CFG_IPV6
OO_STAT("Total number of recieved IPv6 datagrams.",
        CI_IP_STATS_TYPE, in6_recvs,count)

OO_STAT("Number of datagrams discarded due to errors in their IPv6 headers.",
        CI_IP_STATS_TYPE, in6_hdr_errs,count)

OO_STAT("Number of input IPV6 datagrams for which no problems were "
        "encountered to prevent their continued processing, but which "
        "were discarded (e.g., for lack of buffer space).",
        CI_IP_STATS_TYPE, in6_discards,count)

OO_STAT("Total number of input datagrams successfully delivered to IPv6 "
        "user-protocols.",
        CI_IP_STATS_TYPE, in6_delivers,count)

#endif
