/* SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef CP_MIB_OFF_T
# define CP_MIB_OFF_T    ci_int32
# define CP_MIB_OFF_NULL -1
#endif

/* Forward declaration */
struct cp_tables_dim;


/* Convert a pointer to a mib offset.  This must only be used for a pointer that
 * lies within the contiguous region of the mib memory. dim is always the first
 * part of the mib memory block, so use this as context for the offset. */
ci_inline CP_MIB_OFF_T cp_ptr_to_mib_off(const struct cp_tables_dim* dim,
                                         const void* ptr)
{
  return (CP_MIB_OFF_T)((const char*) ptr - (const char*) dim);
}


/* Convert a mib offset back to a pointer. */
ci_inline void* cp_mib_off_to_ptr(struct cp_tables_dim* dim,
                                  CP_MIB_OFF_T a)
{
  return (char*) dim + a;
}


/* Defines mib_dllist, parameterised from the idllist template.
 * Since idllist.h.tmpl undefines all of these macros when it is finished, this
 * file is written in such a way that it may be included multiple times, with
 * different options defined that affect the behaviour of idllist.h.tmpl. */
#define CI_MK_ID(x)             ci_mib_dllist##x
#define CI_ILL_ADDR_T           CP_MIB_OFF_T
#define CI_ILL_CTX_T            struct cp_tables_dim*
#define CI_ILL_PTR(ctx, a) ((ci_mib_dllist_link*)cp_mib_off_to_ptr((ctx), (a)))
#define CI_ILL_ADDR(ctx, lnk)   cp_ptr_to_mib_off((ctx), (lnk))
#define CI_ILL_ADDR_EQ(a, b)    ((a) == (b))
#define CI_ILL_ADDR_NULL        CP_MIB_OFF_NULL

#include <ci/tools/idllist.h.tmpl>
