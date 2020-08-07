/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2018-2019 Xilinx, Inc. */
#ifndef __CI_INTERNAL_LIBSTACK_TYPES_H__
#define __CI_INTERNAL_LIBSTACK_TYPES_H__

#include <ci/internal/ip_shared_types.h>


#define N_STATES  (CI_TCP_STATE_NUM(CI_TCP_STATE_ACTIVE_WILD) + 1)

typedef struct {
#define OO_STAT(desc, type, name, kind)  type name CI_ALIGN(sizeof(type));
  union {
    unsigned states[N_STATES + 1];
    struct {
#include "more_stats_def.h"
    };
  };
} more_stats_t;
#undef OO_STAT


static inline void get_more_stats(ci_netif* ni, more_stats_t* s)
{
  unsigned i;
  memset(s, 0, sizeof(*s));
  for( i = 0; i < ni->state->n_ep_bufs; ++i ) {
    citp_waitable_obj* wo = SP_TO_WAITABLE_OBJ(ni, i);
    citp_waitable* w = &wo->waitable;
    unsigned state = w->state;
    if( CI_TCP_STATE_NUM(state) >= N_STATES ) {
      ++s->states[N_STATES];
      continue;
    }
    ++s->states[CI_TCP_STATE_NUM(state)];
    if( state == CI_TCP_STATE_FREE || state == CI_TCP_STATE_AUXBUF ||
        state == CI_TCP_STATE_ACTIVE_WILD )
      continue;
    if( w->sb_aflags & CI_SB_AFLAG_ORPHAN       )  ++s->sock_orphans;
    if( w->wake_request & CI_SB_FLAG_WAKE_RX )  ++s->sock_wake_needed_rx;
    if( w->wake_request & CI_SB_FLAG_WAKE_TX )  ++s->sock_wake_needed_tx;
    if( state == CI_TCP_LISTEN ) {
      ci_tcp_socket_listen* tls = &wo->tcp_listen;
      s->tcp_n_in_listenq += tls->n_listenq;
      s->tcp_n_in_acceptq += ci_tcp_acceptq_n(tls);
    }
    else if( state & CI_TCP_STATE_TCP ) {
      ci_tcp_state* ts = &wo->tcp;
      if( tcp_rcv_usr(ts) ) {
        ++s->tcp_has_recvq;
        s->tcp_recvq_bytes += tcp_rcv_usr(ts);
      }
      /* NB. Can have pkts even if no bytes... */
      s->tcp_recvq_pkts += ts->recv1.num + ts->recv2.num;
      if( ci_tcp_inflight(ts) ) {
        ++s->tcp_has_inflight;
        s->tcp_inflight_bytes += ci_tcp_inflight(ts);
        s->tcp_inflight_pkts += ts->retrans.num;
      }
      if( ts->rob.num ) {
        ++s->tcp_has_recv_reorder;
        s->tcp_recv_reorder_pkts += ts->rob.num;
      }
      if( SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_nxt(ts)) ) {
        ++s->tcp_has_sendq;
        s->tcp_sendq_bytes += SEQ_SUB(tcp_enq_nxt(ts), tcp_snd_nxt(ts));
        s->tcp_sendq_pkts += ci_tcp_sendq_n_pkts(ts);
      }
    }
    else if( state == CI_TCP_STATE_UDP ) {
      ci_udp_state* us = &wo->udp;
      if( ci_udp_recv_q_not_empty(&us->recv_q) ) {
        ++s->udp_has_recvq;
        s->udp_recvq_pkts += ci_udp_recv_q_pkts(&us->recv_q);
      }
      if( us->tx_count ) {
        ++s->udp_has_sendq;
        s->udp_sendq_bytes += us->tx_count;
      }
      s->udp_tot_recv_pkts_ul += us->recv_q.pkts_added;
      s->udp_tot_recv_drops_ul += us->stats.n_rx_overflow;
      s->udp_tot_recv_pkts_os += us->stats.n_rx_os;
      s->udp_tot_send_pkts_ul += us->stats.n_tx_onload_uc;
      s->udp_tot_send_pkts_ul += us->stats.n_tx_onload_c;
      s->udp_tot_send_pkts_os += us->stats.n_tx_os;
    }
  }

  s->ef_vi_rx_ev_lost = ni->state->vi_stats.rx_ev_lost;
  s->ef_vi_rx_ev_bad_desc_i = ni->state->vi_stats.rx_ev_bad_desc_i;
  s->ef_vi_rx_ev_bad_q_label = ni->state->vi_stats.rx_ev_bad_q_label;
  s->ef_vi_evq_gap = ni->state->vi_stats.evq_gap;
}


#endif
