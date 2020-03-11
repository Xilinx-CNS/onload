/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Dump a "struct tcp_info".
**   \date  2006/01/30
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */
#include <ci/app.h>
#include <netinet/tcp.h>

#ifdef TCP_INFO

/* We use ci_tcp_info instead of tcp_info because we know which fields
 * exist in the structure and which do not.  For tcp_info it depends on the
 * kernel version used when libc was build, and hardly predictable. */
void ci_dump_tcp_info(ci_log_fn_t l, const struct ci_tcp_info* i)
{
  char s[80];

#define dump(x)  do {				\
    sprintf(s, "%20s: %d", #x, (int) i->x);	\
    l(s);					\
  } while(0)

  dump(tcpi_state);
  dump(tcpi_ca_state);
  dump(tcpi_retransmits);
  dump(tcpi_probes);
  dump(tcpi_backoff);
  dump(tcpi_options);
  dump(tcpi_snd_wscale);
  dump(tcpi_rcv_wscale);

  dump(tcpi_rto);
  dump(tcpi_ato);
  dump(tcpi_snd_mss);
  dump(tcpi_rcv_mss);

  dump(tcpi_unacked);
  dump(tcpi_sacked);
  dump(tcpi_lost);
  dump(tcpi_retrans);
  dump(tcpi_fackets);

  dump(tcpi_last_data_sent);
  dump(tcpi_last_ack_sent);
  dump(tcpi_last_data_recv);
  dump(tcpi_last_ack_recv);

  dump(tcpi_pmtu);
  dump(tcpi_rcv_ssthresh);
  dump(tcpi_rtt);
  dump(tcpi_rttvar);
  dump(tcpi_snd_ssthresh);
  dump(tcpi_snd_cwnd);
  dump(tcpi_advmss);
  dump(tcpi_reordering);

  dump(tcpi_rcv_rtt);
  dump(tcpi_rcv_space);
  dump(tcpi_total_retrans);
}

#endif

/*! \cidoxg_end */
