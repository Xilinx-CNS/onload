/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Xilinx, Inc. */

#ifndef __CI_INTERNAL_SEQ_H__
#define __CI_INTERNAL_SEQ_H__

#define SEQ_EQ(s1, s2)      ((ci_uint32)((s1) - (s2)) == 0u)
#define SEQ_LT(s1, s2)      ((ci_int32)((s1) - (s2)) < 0)
#define SEQ_LE(s1, s2)      ((ci_int32)((s1) - (s2)) <= 0)
#define SEQ_GT(s1, s2)      ((ci_int32)((s1) - (s2)) > 0)
#define SEQ_GE(s1, s2)      ((ci_int32)((s1) - (s2)) >= 0)
#define SEQ_SUB(s1, s2)     ((ci_int32)((s1) - (s2)))
#define SEQ(s)              ((unsigned) (s))

/* Is [s] between [sl] and [sh] (inclusive) */
#define SEQ_BTW(s, sl, sh)  ((sh) - (sl) >= (s) - (sl))

#define SEQ_MIN(x, y)           (SEQ_LE(x, y) ? (x) : (y))
#define SEQ_MAX(x, y)           (SEQ_LE(x, y) ? (y) : (x))

#endif /* __CI_INTERNAL_SEQ_H__ */
