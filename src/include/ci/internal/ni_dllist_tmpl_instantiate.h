/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2019 Xilinx, Inc. */
/* Defines the macros for ni_dllists that parameterise the idllist template.
 * Since idllist.h.tmpl undefines all of these macros when it is finished, this
 * file is written in such a way that it may be included multiple times, with
 * different options defined that affect the behaviour of idllist.h.tmpl. */

#define CI_MK_ID(x)             ci_ni_dllist##x
#define CI_ILL_PTR(ctx, a)      ((ci_ni_dllist_link*) CI_NETIF_PTR((ctx), (a)))
#define CI_ILL_ADDR(ctx, lnk)   oo_ptr_to_statep((ctx), (void*) (lnk))
#define CI_ILL_ADDR_EQ(a, b)    OO_P_EQ((a), (b))
#define CI_ILL_ADDR_T           oo_p
#define CI_ILL_ADDR_NULL        OO_P_NULL
#define CI_ILL_CTX_T            ci_netif*
#define CI_ILL_CAS(p,old,new)   ci_cas32u_succeed((volatile ci_uint32*) (p), \
                                                  (ci_uint32) (old), \
                                                  (ci_uint32) (new))
#define CI_ILL_XCHG(p,new)      ((oo_p) ci_xchg32((volatile ci_uint32*) (p), \
                                                  (ci_uint32) (new)))

#include <ci/tools/idllist.h.tmpl>
