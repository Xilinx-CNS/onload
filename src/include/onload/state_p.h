/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_STATE_P_H__
#define __ONLOAD_STATE_P_H__


#if 1

typedef ci_int32 oo_p;

# define OO_P_INIT(p, ni, off)   ((p) = (off))
# define OO_P_OFF(p)             (p)

# define OO_P_IS_NULL(p)         ((p) < 0)
# define OO_P_NOT_NULL(p)        ((p) >= 0)
# define OO_P_EQ(pa, pb)         ((pa) == (pb))
# define OO_P_FMT(p)             ((int) (p))
# define OO_P_ADD(p, off)        do{ (p) += (off); }while(0)

# define OO_P_NULL               -1
# define OO_P_INVALID            -2

#else

/* This implementation exists to help verify that code is not looking under
 * the hood.
 */

typedef struct {
  ci_int32 off;
} oo_p;

# define OO_P_INIT(p, ni, _off)   ((p).off = (_off))

ci_inline int OO_P_OFF(oo_p p)        { return p.off; }
ci_inline int OO_P_IS_NULL(oo_p p)    { return p.off < 0; }
ci_inline int OO_P_NOT_NULL(oo_p p)   { return p.off >= 0; }
ci_inline int OO_P_EQ(oo_p a, oo_p b) { return a.off == b.off; }
ci_inline int OO_P_FMT(oo_p p)        { return p.off; }
# define OO_P_ADD(p, _off)            do{ (p).off += (_off); }while(0)

extern oo_p OO_P_NULL;
extern oo_p OO_P_INVALID;

#endif


#endif  /* __ONLOAD_STATE_P_H__ */
