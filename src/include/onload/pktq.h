/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_PKTQ_H__
#define __ONLOAD_PKTQ_H__


#define oo_pktq_is_empty(q)   ((q)->num == 0)
#define oo_pktq_not_empty(q)  ((q)->num)
#define oo_pktq_num(q)        ((q)->num)


#define oo_pktq_init(q)                         \
  do {                                          \
    (q)->head = (q)->tail = OO_PP_NULL;         \
    (q)->num = 0;                               \
  } while(0)


#define __oo_pktq_put(ni, q, pkt, next)                 \
  do {                                                  \
    (pkt)->next = OO_PP_NULL;                           \
    if( (q)->num != 0 )                                 \
      PKT_CHK((ni), (q)->tail)->next = OO_PKT_P(pkt);   \
    else                                                \
      (q)->head = OO_PKT_P(pkt);                        \
    (q)->tail = OO_PKT_P(pkt);                          \
    ++(q)->num;                                         \
  } while(0)


#define __oo_pktq_put_list(ni, q, head_id, tail_pkt, n, next)   \
  do {                                                          \
    (tail_pkt)->next = OO_PP_NULL;                              \
    if( (q)->num != 0 )                                         \
      PKT_CHK((ni), (q)->tail)->next = head_id;                 \
    else                                                        \
      (q)->head = head_id;                                      \
    (q)->tail = OO_PKT_P(tail_pkt);                             \
    (q)->num += (n);                                            \
  } while(0)


#define __oo_pktq_next(ni, q, head_pkt, next)   \
  do {                                          \
    ci_assert(OO_PP_EQ((q)->head, OO_PKT_P(head_pkt)));  \
    ci_assert((q)->num > 0);                    \
    (q)->head = (head_pkt)->next;               \
    --(q)->num;                                 \
  } while(0)



#endif  /* __ONLOAD_PKTQ_H__ */
