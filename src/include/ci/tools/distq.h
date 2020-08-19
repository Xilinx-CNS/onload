/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Distributed message queue.
**   \date  2004/03/30
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_DISTQ_H__
#define __CI_TOOLS_DISTQ_H__


/**********************************************************************
 * Generic ops (receive and transmit).
 */

#define CI_DISTQ_M(q, x)	((x) % (q)->size)
#define ci_distq_capacity(dq)	((dq)->size - 1)
#define ci_distq_q_end(dq)	((dq)->q + (dq)->size)


/**********************************************************************
 * Generic ops (receive).
 */

#define ci_distq_is_empty(rx)		((rx)->rd_i == *(rx)->p_wr_i)
#define ci_distq_not_empty(rx)		((rx)->rd_i != *(rx)->p_wr_i)
#define ci_distq_peek(rx)		((rx)->q[(rx)->rd_i])
#define ci_distq_peekp(rx)		((rx)->q + (rx)->rd_i)
#define ci_distq_rd_sync_needed(rx)	((rx)->rd_i != (rx)->r_rd_i)

#define ci_distq_num(rx)					\
  CI_DISTQ_M((rx), *(rx)->p_wr_i + (rx)->size - (rx)->rd_i)
#define ci_distq_rd_next(rx)					\
  do{ (rx)->rd_i = CI_DISTQ_M((rx), (rx)->rd_i + 1u); }while(0)
#define ci_distq_rd_adv(rx, n)					\
  do{ (rx)->rd_i = CI_DISTQ_M((rx), (rx)->rd_i + (n)); }while(0)
#define ci_distq_rd_sync(rx)					\
  do{ *(rx)->pr_rd_i = (rx)->r_rd_i = (rx)->rd_i; }while(0)

#define ci_distq_get(rx, pv)			\
  do{ *(pv) = ci_distq_peek(rx);		\
      ci_distq_rd_next(rx);			\
  }while(0)

#define CI_DISTQ_RX_FMT		"[rd=%u(%u) wr=%u num=%u]"
#define CI_DISTQ_RX_PRI_ARG(rx)	(rx).rd_i, (rx).r_rd_i,		\
				(unsigned) *(rx).p_wr_i,	\
				ci_distq_num(&(rx))


/**********************************************************************
 * Generic ops (transmit).
 */

#define ci_distq_is_full(tx)	(CI_DISTQ_M((tx),(tx)->wr_i+1)==*(tx)->p_rd_i)
#define ci_distq_not_full(tx)	(CI_DISTQ_M((tx),(tx)->wr_i+1)!=*(tx)->p_rd_i)
#define ci_distq_poke(tx)	((tx)->q[(tx)->wr_i])
#define ci_distq_pokep(tx)	((tx)->q + (tx)->wr_i)
#define ci_distq_wr_reset(tx)	((tx)->wr_i = *(tx)->p_rd_i)
#define ci_distq_wr_sync_needed(tx)	((tx)->wr_i != (tx)->r_wr_i)

#define ci_distq_space(tx)					\
  CI_DISTQ_M((tx), *(tx)->p_rd_i + (tx)->size - (tx)->wr_i - 1)
#define ci_distq_wr_next(tx)					\
  do{ (tx)->wr_i = CI_DISTQ_M((tx), (tx)->wr_i + 1u); }while(0)
#define ci_distq_wr_adv(tx, n)					\
  do{ (tx)->wr_i = CI_DISTQ_M((tx), (tx)->wr_i + (n)); }while(0)
#define ci_distq_wr_sync(tx)					\
  do{ *(tx)->pr_wr_i = (tx)->r_wr_i = (tx)->wr_i; }while(0)
#define ci_distq_unsent(tx)					\
  CI_DISTQ_M((tx), (tx)->wr_i + (tx)->size - (tx)->r_wr_i)
#define ci_distq_unacked(tx)					\
  CI_DISTQ_M((tx), (tx)->wr_i + (tx)->size - *(tx)->p_rd_i)

#define ci_distq_put(tx, v)			\
  do{ ci_distq_poke(tx) = (v);			\
      ci_distq_wr_next(tx);			\
  }while(0)

#define CI_DISTQ_TX_FMT		"[wr=%u(%u) rd=%u spc=%u]"
#define CI_DISTQ_TX_PRI_ARG(tx)	(tx).wr_i, (tx).r_wr_i,		\
				(unsigned) *(tx).p_rd_i,	\
				ci_distq_space(&(tx))

#define CI_DISTQ_TX_ACK_FMT		"[wr=%u(%u) rd=%u ack=%u spc=%u]"
#define CI_DISTQ_TX_ACK_PRI_ARG(tx)	(tx).wr_i, (tx).r_wr_i,		     \
					(unsigned) *(tx).p_rd_i,	     \
					(tx).ack_i, ci_distq_ack_space(&(tx))


/**********************************************************************
 * For queues supporting retransmit:
 */

#define ci_distq_ack_wr_reset(tx)	((tx)->wr_i = (tx)->ack_i)
#define ci_distq_ack_is_full(tx)			\
  (CI_DISTQ_M((tx), (tx)->wr_i+1) == (tx)->ack_i)
#define ci_distq_ack_not_full(tx)			\
  (CI_DISTQ_M((tx), (tx)->wr_i+1) != (tx)->ack_i)
#define ci_distq_ack_space(tx)					\
  CI_DISTQ_M((tx), (tx)->ack_i + (tx)->size - (tx)->wr_i - 1)

#define ci_distq_acked(tx)		((tx)->ack_i != *(tx)->p_rd_i)
#define ci_distq_ack_peek(tx)		((tx)->rt_q[(tx)->ack_i])
#define ci_distq_ack_next(tx)						\
  do{ (tx)->ack_i = CI_DISTQ_M((tx), (tx)->ack_i + 1u); }while(0)

#define ci_distq_rt_poke_rt(tx)		((tx)->rt_q[(tx)->wr_i])

  /*! Read item from retransmit buffer, and advance. */
#define ci_distq_rt_get(rx, pv)			\
  do{ *(pv) = ci_distq_rt_peek(tx);		\
      ci_distq_rt_next(tx);			\
  }while(0)

  /*! Put item into retransmit buffer as well as into distributed queue. */
#define ci_distq_rt_put(tx, v)			\
  do{ ci_distq_rt_poke_rt(tx) = (v);		\
      ci_distq_put((tx), (v));			\
  }while(0)

  /*! Poke item into retransmit buffer and into distributed queue. */
#define ci_distq_rt_poke(tx, v)			\
  do{ ci_distq_rt_poke_rt(tx) = (v);		\
      ci_distq_poke(tx) = (v);			\
  }while(0)


/* Define a distributed queue of bytes if they've not asked to define
** anything specific.
*/
#ifndef CI_DISTQ_MBR
# define CI_DISTQ_MBR		char
# define CI_DISTQ_MK_ID(id)	ci_distq_##id
# define CI_DISTQ_RETRANSMIT	0
# define CI_DISTQ_ACK		0
#endif

#endif  /* __CI_TOOLS_DISTQ_H__ */


#ifdef CI_DISTQ_MBR

#ifndef CI_DISTQ_RETRANSMIT
# define CI_DISTQ_RETRANSMIT	0
#endif
#ifndef CI_DISTQ_ACK
# define CI_DISTQ_ACK		0
#endif
#if CI_DISTQ_ACK
# undef CI_DISTQ_RETRANSMIT
# define CI_DISTQ_RETRANSMIT	1
#endif


/*! Comment? */
typedef struct {
  unsigned		size;
  unsigned		rd_i;
  unsigned		r_rd_i;
  volatile ci_uint32*	p_wr_i;
  volatile ci_uint32*	pr_rd_i;
  CI_DISTQ_MBR*		q;
} CI_DISTQ_MK_ID(rx);


/*! Comment? */
typedef struct {
  unsigned		size;
  unsigned		wr_i;
  unsigned		r_wr_i;
  volatile ci_uint32*	p_rd_i;
  volatile ci_uint32*	pr_wr_i;
  CI_DISTQ_MBR*		q;
#if CI_DISTQ_ACK
  unsigned		ack_i;
#endif
#if CI_DISTQ_RETRANSMIT
  CI_DISTQ_MBR*		rt_q;
#endif
} CI_DISTQ_MK_ID(tx);


/**********************************************************************/
/**********************************************************************/

/*! Comment? */
ci_inline void CI_DISTQ_MK_ID(rx_init)(CI_DISTQ_MK_ID(rx)* q, unsigned size,
				       volatile ci_uint32* p_wr_i,
				       volatile ci_uint32* pr_rd_i,
				       CI_DISTQ_MBR* q_data) {
  q->size = size;
  q->p_wr_i = p_wr_i;
  q->pr_rd_i = pr_rd_i;
  *q->p_wr_i = q->r_rd_i = q->rd_i = 0;
  q->q = q_data;
}

/*! Comment? */
ci_inline int CI_DISTQ_MK_ID(rx_contig_num)(CI_DISTQ_MK_ID(rx)* q) {
  unsigned wr_i = *q->p_wr_i;
  if( wr_i > q->rd_i )	return CI_DISTQ_M(q, wr_i - q->rd_i);
  else			return q->size - q->rd_i;
}

/*! Comment? */
ci_inline int CI_DISTQ_MK_ID(rx_free_space)(CI_DISTQ_MK_ID(rx)* q)
{ return CI_DISTQ_M(q, q->rd_i + q->size - *q->p_wr_i - 1); }


/*! Comment? */
ci_inline CI_DISTQ_MBR CI_DISTQ_MK_ID(rx_get)(CI_DISTQ_MK_ID(rx)* q) {
  CI_DISTQ_MBR tmp = q->q[q->rd_i];
  q->rd_i = CI_DISTQ_M(q, q->rd_i + 1);
  return tmp;
}

/**********************************************************************/

/*! Comment? */
ci_inline void CI_DISTQ_MK_ID(tx_init)(CI_DISTQ_MK_ID(tx)* q, unsigned size,
				       volatile ci_uint32* p_rd_i,
				       volatile ci_uint32* pr_wr_i,
				       CI_DISTQ_MBR* q_data
#if CI_DISTQ_RETRANSMIT
				       , CI_DISTQ_MBR* rt_q_data
#endif
				       ) {
  q->size = size;
  q->p_rd_i = p_rd_i;
  q->pr_wr_i = pr_wr_i;
  *q->p_rd_i = 0;
  q->wr_i = q->size - 1;
  q->q = q_data;
#if CI_DISTQ_RETRANSMIT
  q->rt_q = rt_q_data;
#endif
#if CI_DISTQ_ACK
  q->ack_i = 0;
#endif
}

/*! Comment? */
ci_inline int CI_DISTQ_MK_ID(tx_space)(CI_DISTQ_MK_ID(tx)* q)
{ return CI_DISTQ_M(q, *q->p_rd_i + q->size - q->wr_i - 1); }

/*! Comment? */
ci_inline int CI_DISTQ_MK_ID(tx_contig_space)(CI_DISTQ_MK_ID(tx)* q) {
  unsigned rd_i = *q->p_rd_i;
  if( rd_i > q->wr_i )	return CI_DISTQ_M(q, rd_i - q->wr_i - 1);
  else			return q->size - q->wr_i - !rd_i;
}

/*! Comment? */
ci_inline int CI_DISTQ_MK_ID(tx_unacked)(CI_DISTQ_MK_ID(tx)* q)
{ return CI_DISTQ_M(q, q->wr_i + q->size - *q->p_rd_i); }


/*! Comment? */
ci_inline void CI_DISTQ_MK_ID(tx_put)(CI_DISTQ_MK_ID(tx)* q, CI_DISTQ_MBR v) {
  q->q[q->wr_i] = v;
  q->wr_i = CI_DISTQ_M(q, q->wr_i + 1);
}


#undef CI_DISTQ_MBR
#undef CI_DISTQ_MK_ID
#undef CI_DISTQ_RETRANSMIT
#undef CI_DISTQ_ACK

#endif  /* ifdef CI_DISTQ_MBR */
/*! \cidoxg_end */
