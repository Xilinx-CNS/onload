/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2018-2019 Xilinx, Inc. */

#ifndef __CI_INTERNAL_NI_DLLIST_H__
#define __CI_INTERNAL_NI_DLLIST_H__

/*********************************************************************
*********************** Indirected linked lists **********************
*********************************************************************/


/* Get the code for the linked lists. */
#define CI_ILL_NO_TYPES
#include <ci/internal/ni_dllist_tmpl_instantiate.h>


/* Get pointer from an address in the ci_netif_state address space. */
# define ci_ni_dllist_iter(ni, l)           \
            ((l) = (ci_ni_dllist_link*) CI_NETIF_PTR(ni, (l)->next))
# define ci_ni_dllist_backiter(ni, l)       \
            ((l) = (ci_ni_dllist_link*) CI_NETIF_PTR(ni, (l)->prev))


/*! \TODO Move these into their own header. */

#define CI_ILL_UNUSED           -2
#define CI_ILL_END              -1

#define _ci_ill_assert_valid(i, file, line) \
        _ci_assert_ge((int)(i), CI_ILL_END, (file), (line))

/* A singly linked list. */
#define ci_ill_assert_valid(i)  _ci_ill_assert_valid((i), __FILE__, __LINE__)
#define ci_ill_is_empty(i)      ((i) == CI_ILL_END)
#define ci_ill_not_empty(i)     ((i) != CI_ILL_END)

/* A singly linked list with tail pointer. */
#define ci_ill2_assert_valid(h,t)  do{                  \
  ci_assert((h) >= CI_ILL_END);                         \
  ci_assert((h) == CI_ILL_END || (t) >= CI_ILL_END);    \
  }while(0)

/* A double linked list. */
#define ci_idll_assert_valid(h,t)  do{                  \
  ci_assert((h) >= CI_ILL_END);                         \
  ci_assert((t) >= CI_ILL_END);                         \
  ci_assert((h) != CI_ILL_END || (t) == CI_ILL_END);    \
  ci_assert((h) == CI_ILL_END || (t) != CI_ILL_END);    \
  }while(0)

#endif /* __CI_INTERNAL_NI_DLLIST_H__ */
