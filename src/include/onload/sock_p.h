/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_SOCK_P_H__
#define __ONLOAD_SOCK_P_H__

#if 1

typedef ci_int32 oo_sp;

# define OO_SP_FROM_INT(ni, id)   (id)
# define OO_SP_TO_INT(p)          (p)

# define OO_SP_IS_NULL(p)         ((p) < 0)
# define OO_SP_NOT_NULL(p)        ((p) >= 0)
# define OO_SP_EQ(pa, pb)         ((pa) == (pb))
# define OO_SP_FMT(p)             ((int) (p))

# define OO_SP_NULL               -1
# define OO_SP_INVALID            -2

#else
/* This implementation exists to help verify that code is not looking under
 * the hood.
 */
typedef struct {
  ci_int32 id;
} oo_sp;
ci_inline oo_sp OO_SP_FROM_INT(struct ci_netif_s* ni,
                               int id)     { oo_sp sp = { id }; return sp;}
ci_inline int   OO_SP_TO_INT(oo_sp sp)     { return sp.id; }
ci_inline int   OO_SP_IS_NULL(oo_sp sp)    { return sp.id < 0; }
ci_inline int   OO_SP_NOT_NULL(oo_sp sp)   { return sp.id >= 0; }
ci_inline int   OO_SP_EQ(oo_sp a, oo_sp b) { return a.id == b.id; }
ci_inline int   OO_SP_FMT(oo_sp sp)        { return sp.id; }
extern oo_sp OO_SP_NULL;
extern oo_sp OO_SP_INVALID;
#endif


#endif  /* __ONLOAD_SOCK_P_H__ */
