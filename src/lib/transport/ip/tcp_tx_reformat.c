/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  TCP transmit - reformat packet functions
**   \date  2003/08/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/transport_config_opt.h>
#include "iovec_ptr.h"
#include "netif_tx.h"

#define LPF "TCP TX RFMT "


#if OO_DO_STACK_POLL

/* CVS history for all these functions is in tcp_tx.c v1.382 
** A unit testbench for this code is available in 
**   tests/ip/unit/tcp_split_coalesce 
*/


/* "Copies" payload from [src_seg] in [src_pkt] onto the end of [dest_pkt].
** This is the guts of the coalescing and splitting code.
** Whether copying actually occurs or not is controlled by the [do_copy]
** flag (the code in ci_tcp_tx_insert_option_space() does its own copying,
** but uses this routine to recalculate the segment pointers.)
*/
static int ci_tcp_tx_merge_segment(ci_netif* ni, ci_ip_pkt_fmt* dest_pkt,
                                   ci_ip_pkt_fmt* src_pkt, ef_iovec* src_seg,
                                   int do_copy)
{
  int n;
  char *src, *dest;
  int src_off = (int)(src_seg->iov_base -
                      (pkt_dma_addr(ni, src_pkt, src_pkt->intf_i) +
                       src_pkt->pkt_start_off));

  /* [dest_pkt] must have space to put stuff in, and [src_seg] must point
  ** to some data to put there!
  */
  ci_assert_gt(oo_offbuf_left(&dest_pkt->buf), 0);
  ci_assert_gt(src_seg->iov_len, 0);
  ci_assert_equal(src_pkt->n_buffers, 1);
  ci_assert_equal(dest_pkt->n_buffers, 1);
  ci_assert_gt(src_off, 0);
  ci_assert_lt((unsigned) src_off, CI_CFG_PKT_BUF_SIZE);

  src = PKT_START(src_pkt) + src_off;
  dest = oo_offbuf_ptr(&dest_pkt->buf);

  n = oo_offbuf_left(&dest_pkt->buf);
  n = CI_MIN((unsigned)n, src_seg->iov_len);

  if( do_copy ) {
    if( dest_pkt == src_pkt ) {
      /* Same packet: may be overlapping. */
      memmove(dest, src, n);
    }
    else
      memcpy(dest, src, n);
  }

  dest_pkt->buf_len += n;
  dest_pkt->pay_len += n;
  oo_offbuf_advance(&dest_pkt->buf, n);
  dest_pkt->pf.tcp_tx.end_seq += n;
  src_seg->iov_base += n;
  src_seg->iov_len -= n;

  return n;
}

/* Allocate a packet, copy headers, correct flags and seq nums */
static ci_ip_pkt_fmt* ci_tcp_tx_allocate_pkt(ci_netif* ni, ci_tcp_state* ts,
					     ci_ip_pkt_queue* qu, ci_ip_pkt_fmt* pkt,
					     int hdrlen, int old_len, int new_paylen)
{
  ci_ip_pkt_fmt* next;

  next = ci_netif_pkt_tx_tcp_alloc(ni, ts);
  if( ! next )  return NULL;
  oo_tx_pkt_layout_init(next);
  ci_ipcache_update_flowlabel(ni, &ts->s);
  ci_pkt_init_from_ipcache_len(next, &ts->s.pkt, hdrlen);

  /* Initially make a buffer large enough to fit all the data in, since we
  ** may have to put more than [eff_mss] into [next].
  */
  oo_offbuf_init(&next->buf, (uint8_t*) oo_tx_l3_hdr(next) + hdrlen, old_len);

  /* ?? todo: put pkt hdr initialisation in an inline fn shared w tcp_send */
  next->buf_len = next->pay_len = oo_tx_ether_hdr_size(next) + hdrlen;
  ci_assert_equal(next->n_buffers, 1);
  /* Initialise headers, and set the sequence numbers. */
  pkt->pf.tcp_tx.end_seq    = pkt->pf.tcp_tx.start_seq + new_paylen;
  next->pf.tcp_tx.start_seq = pkt->pf.tcp_tx.end_seq;
  next->pf.tcp_tx.end_seq   = next->pf.tcp_tx.start_seq;
  next->pf.tcp_tx.block_end = OO_PP_NULL;
  next->pf.tcp_tx.sock_id   = pkt->pf.tcp_tx.sock_id;

  /* Flags in [next] match those in [pkt], with the exception of the SENDPAGE
  ** flag, which may be different depending on the distribution of zerocopied
  ** segments across the two packets.  The code earlier in this function set
  ** it correctly for [pkt], and ci_tcp_tx_merge_segment() will set it below
  ** for [next] if necessary.
  */
  next->flags = pkt->flags;

  return next;
}


/* Add a packet to a queue adjusting tail if necessary */
static void ci_tcp_tx_add_to_queue(ci_ip_pkt_queue* qu, ci_ip_pkt_fmt* pkt,
                                   ci_ip_pkt_fmt* next) {
  /* Insert the new packet into the queue. */
  next->next = pkt->next;
  pkt->next  = OO_PKT_P(next);
  ++qu->num;
  if( OO_PP_IS_NULL(next->next) ) {
    ci_assert(OO_PP_EQ(qu->tail, OO_PKT_P(pkt)));
    qu->tail = OO_PKT_P(next);
  }  
}


/* Split a packet into two packets.  The final length of [pkt] will be
** [new_paylen] (which should be <= [eff_mss], and < the current length).
**
** The new packet may be larger than [eff_mss] if the original was more
** than twice [eff_mss].
**
** This function does not (and cannot) preserve the SACK block data
** structure in the retransmit queue.
**
** Return non-zero on failure (packet inflight, or could not allocate a
** packet buffer).
*/
extern int ci_tcp_tx_split(ci_netif* ni, ci_tcp_state* ts, ci_ip_pkt_queue* qu,
                           ci_ip_pkt_fmt* pkt, int new_paylen, 
                           ci_boolean_t is_sendq)
{
  int af = ipcache_af(&ts->s.pkt);
  ci_tcp_hdr* pkt_tcp = TX_PKT_IPX_TCP(af, pkt);
  ci_tcp_hdr* next_tcp;
  int old_len = PKT_TCP_TX_SEQ_SPACE(pkt)
     - ((pkt_tcp->tcp_flags & CI_TCP_FLAG_FIN) >> CI_TCP_FLAG_FIN_BIT);
  int n, old_last_seg_size;
  int hdrlen = ts->outgoing_hdrs_len;
  ci_ip_pkt_fmt *next;
  ef_iovec_ptr segs;
  ef_iovec iov[CI_IP_PKT_SEGMENTS_MAX];

  ci_assert_le((unsigned)new_paylen, tcp_eff_mss(ts));
  ci_assert_le(new_paylen, old_len);   /* <= not < to cope with FIN case */

  if( pkt->flags & CI_PKT_FLAG_TX_PENDING )  return -1;

  next = ci_tcp_tx_allocate_pkt(ni, ts, qu, pkt, hdrlen, old_len, new_paylen);
  if( next == NULL )  return -1;
  next_tcp = TX_PKT_IPX_TCP(af, next);

  n = new_paylen + hdrlen + oo_tx_pre_l3_len(pkt);
  /* Assume that we have all we need in the first segment */
  ci_assert_ge(pkt->buf_len, n);
  ci_assert_equal(pkt->n_buffers, 1);
  pkt->intf_i = 0;
  ci_netif_pkt_to_iovec(ni, pkt, iov, sizeof(iov) / sizeof(iov[0]));
  ef_iovec_ptr_init_nz(&segs, iov, pkt->n_buffers);
  ef_iovec_ptr_advance(&segs, n);
  old_last_seg_size = pkt->buf_len;
  pkt->buf_len = n;
  pkt->pay_len -= (old_last_seg_size - n);

  while( ! ef_iovec_ptr_is_empty_proper(&segs) ) {
#ifndef NDEBUG
    int moved = ci_tcp_tx_merge_segment(ni, next, pkt, &segs.io, 1);
    ci_assert_nequal(moved, 0);
#else
    ci_tcp_tx_merge_segment(ni, next, pkt, &segs.io, 1);
#endif
  }

  /* There should still be just one segment in pkt */
  ci_assert_equal(pkt->n_buffers, 1);

  /* Reposition the "end" of the packet buffer to where it should be. */
  ci_tcp_tx_pkt_set_end(ts, next);
  oo_offbuf_set_start(&(pkt->buf),
                      (char*) oo_tx_l3_hdr(pkt) + ts->outgoing_hdrs_len
                      + new_paylen);

  ci_tcp_tx_add_to_queue(qu, pkt, next);
  if( is_sendq )
    ++ts->send_in;

  /* Move the flags as necessary */
  next_tcp->tcp_flags = pkt_tcp->tcp_flags &
                        (CI_TCP_FLAG_ACK | CI_TCP_FLAG_PSH | CI_TCP_FLAG_FIN);
  pkt_tcp->tcp_flags &= ~(CI_TCP_FLAG_PSH | CI_TCP_FLAG_FIN);
  if( next_tcp->tcp_flags & CI_TCP_FLAG_FIN )
    next->pf.tcp_tx.end_seq++;

  ASSERT_VALID_PKT(ni, pkt);
  CITP_DETAILED_CHECKS(ci_tcp_tx_pkt_assert_valid(ni, ts, pkt,
                                                  __FILE__, __LINE__));
  ASSERT_VALID_PKT(ni, next);
  CITP_DETAILED_CHECKS(ci_tcp_tx_pkt_assert_valid(ni, ts, next,
                                                  __FILE__, __LINE__));

  return 0;
}


/* Chomp [bytes] of payload from the front of [pkt].  The segments are
** updated as necessary.
*/
static void ci_tcp_tx_chomp(ci_netif* ni, ci_tcp_state* ts,
                            ci_ip_pkt_fmt* pkt, int bytes)
{
  ef_iovec one_segment; /* save stack space: only one seg is pre-alloced */
  ef_iovec_ptr segs;
  int n;

  ci_assert_gt(bytes, 0);
  ci_assert_equal(pkt->n_buffers, 1);
  ci_assert_equal(TX_PKT_IPX_TCP(ipcache_af(&ts->s.pkt), pkt)->tcp_flags &
                  (CI_TCP_FLAG_SYN | CI_TCP_FLAG_FIN), 0);

  pkt->intf_i = 0;
  ci_netif_pkt_to_iovec(ni, pkt, &one_segment, 1);
  ef_iovec_ptr_init_nz(&segs, &one_segment, pkt->n_buffers);
  ef_iovec_ptr_advance(&segs, oo_tx_pre_l3_len(pkt) + ts->outgoing_hdrs_len);

  /* Advance through the bytes we're skipping. */
  do {
    n = CI_MIN(segs.io.iov_len, (unsigned) bytes);
    ef_iovec_ptr_advance(&segs, n);
    bytes -= n;
    ci_assert_gt(segs.io.iov_len, 0);
  } while( bytes );

  pkt->buf_len = pkt->pay_len = oo_tx_pre_l3_len(pkt) + ts->outgoing_hdrs_len;
  pkt->pf.tcp_tx.end_seq = pkt->pf.tcp_tx.start_seq;

  /* We need to initialise an over large buffer here, because the size of
  ** the payload is permitted to exceed [eff_mss].
  */
  oo_offbuf_init2(&pkt->buf, PKT_START(pkt) + pkt->buf_len,
                  (char*) pkt + CI_CFG_PKT_BUF_SIZE);

  /* Copy the data back in. */
  while( ! ef_iovec_ptr_is_empty_proper(&segs) )
    ci_tcp_tx_merge_segment(ni, pkt, pkt, &segs.io, 1);

  /* Reset end of buffer pointer to reflect [eff_mss]. */
  ci_tcp_tx_pkt_set_end(ts, pkt);
  ASSERT_VALID_PKT(ni, pkt);
  CITP_DETAILED_CHECKS(ci_tcp_tx_pkt_assert_valid(ni, ts, pkt,
                                                  __FILE__, __LINE__));
}


/* Coalesce packet with the next one, using eff_mss as limit.  There must
** be a next packet!  This function only coalesces two packets.
**
** Returns -1 if either of the packets are inflight or is a SYN or FIN, and
** therefore cannot be coalesced.
*/
int ci_tcp_tx_coalesce(ci_netif* ni, ci_tcp_state* ts,
		       ci_ip_pkt_queue* q, ci_ip_pkt_fmt* pkt,
                       ci_boolean_t is_sendq)
{
  int n, bytes_moved;
  ef_iovec_ptr next_iov;
  ci_ip_pkt_fmt* next = PKT_CHK(ni, pkt->next);
  ef_iovec one_segment; /* save stack space: only one seg is pre-alloced */
  int af = ipcache_af(&ts->s.pkt);

  /* Don't touch packets that are transmitting. */
  if( (pkt->flags | next->flags) & CI_PKT_FLAG_TX_PENDING )
    return -1;

  ci_tcp_tx_pkt_set_end(ts, pkt);
  /* Is there any (enough?) space to move stuff into? */
  if( oo_offbuf_left(&pkt->buf) <= 0 )
    return 0;

  /* Don't attempt to coalesce SYNs or FINs.  May confuse other stacks. */
  if( (TX_PKT_IPX_TCP(af, pkt)->tcp_flags | TX_PKT_IPX_TCP(af, next)->tcp_flags)
      & (CI_TCP_FLAG_SYN | CI_TCP_FLAG_FIN) )
    return -1;

  /* This assertion is only valid if no SYN or FIN */
  /* This is because PKT_TCP_TX_SEQ_SPACE() is really count of sequence space */
  ci_assert_equal(tcp_eff_mss(ts) - PKT_TCP_TX_SEQ_SPACE(pkt),
                  oo_offbuf_left(&pkt->buf));

  ci_assert_equal(pkt->n_buffers, 1);
  bytes_moved = 0;

  /* Initialise iterator for [next]'s segments, and skip over the
  ** headers.
  */
  next->intf_i = 0;
  ci_netif_pkt_to_iovec(ni, next, &one_segment, 1);
  ef_iovec_ptr_init_nz(&next_iov, &one_segment, pkt->n_buffers);
  ef_iovec_ptr_advance(&next_iov,
                       oo_tx_pre_l3_len(pkt) + ts->outgoing_hdrs_len);

  while( 1 ) {
    ci_assert_gt(oo_offbuf_left(&pkt->buf), 0);

    /* Skip over any empty segments, and determine whether we've exhausted
    ** [next].
    */
    if( ef_iovec_ptr_is_empty_proper(&next_iov) )  break;

    n = ci_tcp_tx_merge_segment(ni, pkt, next, &next_iov.io, 1);
    bytes_moved += n;

    ci_assert_ge(oo_offbuf_left(&pkt->buf), 0);

    if( n == 0 || oo_offbuf_left(&pkt->buf) == 0 )  break;
  }

  next->pf.tcp_tx.start_seq += bytes_moved;

  if( SEQ_EQ(next->pf.tcp_tx.start_seq, next->pf.tcp_tx.end_seq) ) {
    /* Preserve the PSH bit. */
    TX_PKT_IPX_TCP(af, pkt)->tcp_flags |= TX_PKT_IPX_TCP(af, next)->tcp_flags;
    pkt->next = next->next;
    if( OO_PP_EQ(q->tail, OO_PKT_P(next)) )  q->tail = OO_PKT_P(pkt);
    ci_netif_pkt_release(ni, next);
    --q->num;
    /* If we've reduced the number of packets in the sendq, increase the
     * out counter to keep track of number of packets in send + prequeue
     */
    if( is_sendq )
      ++ts->send_out;
  }
  else if( bytes_moved ) {
    ci_tcp_tx_chomp(ni, ts, next, bytes_moved);
    ASSERT_VALID_PKT(ni, next);
    CITP_DETAILED_CHECKS(ci_tcp_tx_pkt_assert_valid(ni, ts, next,
                                                    __FILE__, __LINE__));
  }

  ASSERT_VALID_PKT(ni, pkt);
  CITP_DETAILED_CHECKS(ci_tcp_tx_pkt_assert_valid(ni, ts, pkt,
                                                  __FILE__, __LINE__));

  return 0;
}


void ci_tcp_tx_insert_option_space(ci_netif* ni, ci_tcp_state* ts,
                                   ci_ip_pkt_fmt* pkt, int hdrlen,
                                   int extra_opts)
{
  char *old_start, *old_end, *new_start;
  ef_iovec one_segment; /* save stack space: only one seg is pre-alloced */
  ef_iovec_ptr segs;

  ci_assert_gt(hdrlen, 0);
  ci_assert_equal(pkt->n_buffers, 1);

  LOG_U(ci_log(LNT_FMT
               "packet %d (%x-%x) - inserting %d bytes for extra options",
               LNT_PRI_ARGS(ni,ts), OO_PKT_FMT(pkt), pkt->pf.tcp_tx.start_seq,
               pkt->pf.tcp_tx.end_seq, extra_opts));

  /* We need to insert [extra_opts] bytes after the existing header of length
  ** [hdrlen].  This is complicated because the data may be split across
  ** multiple pages...
  **
  ** We can do it by copying up all of the TCP payload data in the buffer here
  ** then using ci_tcp_tx_merge_segment() with copying disabled to recalculate
  ** the correct segment pointers.  (We can't use ci_tcp_tx_merge_segment()'s
  ** copying, because it will only cope with the source and destination
  ** overlapping if the source is ahead of the destination in the buffer.)
  **
  ** This quite possibly creates a packet with a payload larger the the current
  ** MSS, but we don't need to worry about that here -- ci_tcp_tx_advance()
  ** will split the packet later if necessary.
  */
  ci_assert_equal(pkt->n_buffers, 1);

  /* Work out what we're copying. */
  old_start = PKT_START(pkt) + hdrlen;
  old_end = oo_offbuf_ptr(&pkt->buf);
  new_start = old_start + extra_opts;
  memmove(new_start, old_start, old_end - old_start);

  ci_assert_equal(oo_offbuf_ptr(&pkt->buf) - PKT_START(pkt), TX_PKT_LEN(pkt));

  pkt->intf_i = 0;
  ci_netif_pkt_to_iovec(ni, pkt, &one_segment, 1);
  ef_iovec_ptr_init_nz(&segs, &one_segment, pkt->n_buffers);

  /* Skip over the old header in the old segment data. */
  ef_iovec_ptr_advance(&segs, hdrlen);

  /* Reset the packet to include only the old header plus the extra space. */
  pkt->buf_len = pkt->pay_len = hdrlen + extra_opts;
  pkt->pf.tcp_tx.end_seq = pkt->pf.tcp_tx.start_seq;

  /* We need to initialise an over large buffer here, because the size of
  ** the payload is permitted to exceed [eff_mss].
  */
  oo_offbuf_init2(&pkt->buf, PKT_START(pkt) + pkt->buf_len,
                  (char*) pkt + CI_CFG_PKT_BUF_SIZE);

  /* Update the segment pointers. */
  while( ! ef_iovec_ptr_is_empty_proper(&segs) )
    ci_tcp_tx_merge_segment(ni, pkt, pkt, &segs.io, 0);

  /* Reset end of buffer pointer to reflect [eff_mss]. */
  ci_tcp_tx_pkt_set_end(ts, pkt);

  /* Check that everything is OK, as far as possible -- we can't expect
  ** ci_tcp_tx_pkt_assert_valid() to pass here, as this function is called for
  ** packets that are not yet enqueued (and so the sequence number tests will
  ** fail).
  */
  ASSERT_VALID_PKT(ni, pkt);

  return;
}


void ci_tcp_retrans_coalesce_block(ci_netif* ni, ci_tcp_state* ts,
                                   ci_ip_pkt_fmt* pkt)
{
  /* [pkt] must be at the start of a block (SACKed or unSACKed).  This
  ** function will only coalesce packets within said block, and SACK and
  ** retransmit pointers are preserved.
  */
  ci_ip_pkt_queue* rtq = &ts->retrans;
  ci_ip_pkt_fmt* start;
  oo_pkt_p next_id;

  if( OO_PP_EQ(pkt->pf.tcp_tx.block_end, OO_PKT_P(pkt)) )  return;

  start = pkt;

  while( OO_PP_NOT_NULL(pkt->next) &&
         ! OO_PP_EQ(pkt->pf.tcp_tx.block_end, OO_PKT_P(pkt)) ) {
    next_id = pkt->next;

    if( PKT_TCP_TX_SEQ_SPACE(pkt) < tcp_eff_mss(ts) ) {
      if( ci_tcp_tx_coalesce(ni, ts, rtq, pkt, CI_FALSE) )
        /* Coalesce failed...probably inflight. */
        break;

      if( ! OO_PP_EQ(pkt->next, next_id) ) {
        if( OO_PP_EQ(ts->retrans_ptr, next_id) ) {
          /* The packet under the retransmit pointer got coalesced.
          **
          ** NB. This isn't currently needed, as we only call this when
          ** retrans_ptr is at the start of a block.  But that could
          ** change, so let's avoid problems in the future.
          */
          ts->retrans_ptr = OO_PKT_P(pkt);
          ts->retrans_seq = pkt->pf.tcp_tx.start_seq;
        }

        if( OO_PP_EQ(pkt->pf.tcp_tx.block_end, next_id) ) {
          /* End of block was coalesced, so need to fixup pointers. */
          while( 1 ) {
            start->pf.tcp_tx.block_end = OO_PKT_P(pkt);
            if( start == pkt )  break;
            start = PKT_CHK(ni, start->next);
          }
          break;
        }
      }
    }

    if( OO_PP_EQ(pkt->next, next_id) )
      pkt = PKT_CHK(ni, pkt->next);
  }
}
#endif
