/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */
#ifndef __ONLOAD_PKT_P_H__
#define __ONLOAD_PKT_P_H__


/**********************************************************************
 * Pointers to packets.
 */

#if 1 /* This is the main implementation, see comment below for alternative */

typedef ci_int32 oo_pkt_p;

/* Convert to and from integer id.  Users of this are probably depending on
 * the implementation.
 */
#define OO_PP_ID(pp)             ((int) (pp))
#define OO_PP_INIT(ni, pp, iid)  ((pp) = (ci_int32) (iid))
#define OO_PP_ID_NULL            ((ci_int32) -1)
#define OO_PP_ID_INVALID         ((ci_int32) -2)
#define OO_PKT_ID(pkt)           ((int) (pkt)->pp)
#define OO_PKT_PP_INIT(pkt, iid) ((pkt)->pp = (ci_int32) (iid))

/* Public interface. */
#define OO_PP_IS_NULL(pp)     ((pp) < 0)
#define OO_PP_NOT_NULL(pp)    ((pp) >= 0)
#define OO_PP_EQ(ppa, ppb)    ((ppa) == (ppb))
#define OO_PP_FMT(pp)         OO_PP_ID(pp)
#define OO_PKT_FMT(pkt)       OO_PP_FMT((pkt)->pp)
#define OO_PKT_P(pkt)         ((pkt)->pp)

#define OO_PP_NULL            -1
#define OO_PP_INVALID         -2

#else

/* This implementation exists to help verify that code is not looking under
 * the hood.
 */

/* A "pointer" to a packet buffer. */
typedef struct {
  ci_int32 id;
} oo_pkt_p;

/* Convert to and from integer id.  Users of this are probably depending on
 * the implementation.
 */
#define OO_PP_ID(pp)             ((int) (pp).id)
#define OO_PP_INIT(ni, pp, iid)  ((pp).id = (iid))
#define OO_PP_ID_NULL            -1
#define OO_PP_ID_INVALID         -2
#define OO_PKT_ID(pkt)           ((int) (pkt)->pp.id)
#define OO_PKT_PP_INIT(pkt, iid) ((pkt)->pp.id = (iid))

/* Public interface. */
#define OO_PP_IS_NULL(pp)     ((pp).id < 0)
#define OO_PP_NOT_NULL(pp)    ((pp).id >= 0)
#define OO_PP_EQ(ppa, ppb)    ((ppa).id == (ppb).id)
#define OO_PP_FMT(pp)         OO_PP_ID(pp)
#define OO_PKT_FMT(pkt)       OO_PP_FMT((pkt)->pp)
#define OO_PKT_P(pkt)         ((pkt)->pp)

extern oo_pkt_p OO_PP_NULL;
extern oo_pkt_p OO_PP_INVALID;

#endif


#endif  /* __ONLOAD_PKT_P_H__ */
