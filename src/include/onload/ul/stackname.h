/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  kjm
**  \brief  State for stack<->socket mapping configuration
**   \date  2010/12/12
**    \cop  (c) Solarflare Communications Ltd.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_UL_STACKNAME_H__
#define __ONLOAD_UL_STACKNAME_H__

#include <onload/extensions.h>


struct saved_stacks {
  struct saved_stacks* next;
  enum onload_stackname_who who;
  enum onload_stackname_scope context;
  char stackname[CI_CFG_STACK_NAME_LEN];
};


struct oo_stackname_state {
  struct saved_stacks* saved_stacks_head;
  enum onload_stackname_who who;
  enum onload_stackname_scope context;
  char stackname[CI_CFG_STACK_NAME_LEN];
  char scoped_stackname[CI_CFG_STACK_NAME_LEN];

  /* Used to indicate that global state has changed since cached
   * per-thread state was updated 
   */ 
  unsigned sequence; 
};


extern void oo_stackname_init(void) CI_HF;

extern void oo_stackname_get(char **stackname) CI_HF;

extern void oo_stackname_thread_init(struct oo_stackname_state*) CI_HF;

extern void 
oo_stackname_update(struct oo_stackname_state *cache) CI_HF;


#endif /* __ONLOAD_UL_STACKNAME_H__ */
