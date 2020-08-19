/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  ctk
**  \brief  Socket options for setsockopt and getsockopt
**          compatability layer
**   \date  2004/1/15
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_net  */

#ifndef __CI_NET_SOCKOPTS_H__
#define __CI_NET_SOCKOPTS_H__

/* setsockopt and getsockopt option numbers for compatability layer */

#define __SO_L5_BASE       0x55500
#define CI_SO_L5_GET_SOCK_STATS       (__SO_L5_BASE+0x01)
#define CI_SO_L5_GET_NETIF_STATS      (__SO_L5_BASE+0x02)
#define CI_SO_L5_DUMP_SOCK_STATS      (__SO_L5_BASE+0x03)
#define CI_SO_L5_DUMP_NETIF_STATS     (__SO_L5_BASE+0x04)
#define CI_SO_L5_CONFIG_SOCK_STATS    (__SO_L5_BASE+0x05)
#define CI_SO_L5_CONFIG_NETIF_STATS   (__SO_L5_BASE+0x06)

/* CI_UDP_ENCAP types. Encapsulation for IPSec/NAT */
#define CI_UDP_ENCAP_ESPINUDP_NON_IKE 1
#define CI_UDP_ENCAP_ESPINUDP         2


/* For CI_TCP_INFO */

#define CI_TCPI_OPT_TIMESTAMPS  1
#define CI_TCPI_OPT_SACK        2
#define CI_TCPI_OPT_WSCALE      4
#define CI_TCPI_OPT_ECN         8


struct ci_tcp_info
{
  ci_uint8  tcpi_state;
  ci_uint8  tcpi_ca_state;
  ci_uint8  tcpi_retransmits;
  ci_uint8  tcpi_probes;
  ci_uint8  tcpi_backoff;
  ci_uint8  tcpi_options;
  ci_uint8  tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

  ci_uint32 tcpi_rto;
  ci_uint32 tcpi_ato;
  ci_uint32 tcpi_snd_mss;
  ci_uint32 tcpi_rcv_mss;

  ci_uint32 tcpi_unacked;
  ci_uint32 tcpi_sacked;
  ci_uint32 tcpi_lost;
  ci_uint32 tcpi_retrans;
  ci_uint32 tcpi_fackets;

  ci_uint32 tcpi_last_data_sent;
  ci_uint32 tcpi_last_ack_sent;
  ci_uint32 tcpi_last_data_recv;
  ci_uint32 tcpi_last_ack_recv;

  ci_uint32 tcpi_pmtu;
  ci_uint32 tcpi_rcv_ssthresh;
  ci_uint32 tcpi_rtt;
  ci_uint32 tcpi_rttvar;
  ci_uint32 tcpi_snd_ssthresh;
  ci_uint32 tcpi_snd_cwnd;
  ci_uint32 tcpi_advmss;
  ci_uint32 tcpi_reordering;

  ci_uint32 tcpi_rcv_rtt;
  ci_uint32 tcpi_rcv_space;

  ci_uint32 tcpi_total_retrans;
};

#endif /* __CI_NET_SOCKOPTS_H__ */

/*! \cidoxg_end */
