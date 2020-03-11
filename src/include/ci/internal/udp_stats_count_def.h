/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  jmj
**  \brief  Definition of udp stack statistics
**   \date  2018/07/03
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

OO_STAT("Total number of UDP datagrams delivered to UDP users.",
        CI_IP_STATS_TYPE, udp_in_dgrams, count)

OO_STAT("Total number of received UDP datagrams for which "
        "there was no application at the destination port.",
        CI_IP_STATS_TYPE, udp_no_ports, count)

OO_STAT("Number of received UDP datagrams that could not be delivered "
        "for reason other than the lack of an application at the destination "
        "port.",
        CI_IP_STATS_TYPE, udp_in_errs, count)

OO_STAT("Total number of UDP datagrams sent from this entity.",
        CI_IP_STATS_TYPE, udp_out_dgrams, count)
