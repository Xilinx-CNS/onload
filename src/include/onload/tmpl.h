/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  as
**  \brief  Templated sends definitions
**   \date  2013/08/20
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal_tmpl_types */

#ifndef __CI_INTERNAL_TMPL_TYPES_H__
#define __CI_INTERNAL_TMPL_TYPES_H__


struct oo_msg_template {
  /* To verify subsequent templated calls are used with the same socket */
  oo_sp    oomt_sock_id;
};


extern void ci_tcp_tmpl_free_all(ci_netif* ni, ci_tcp_state* ts);
extern void ci_tcp_tmpl_handle_nic_reset(ci_netif* ni);


#endif /* __CI_INTERNAL_TMPL_TYPES_H__ */
/*! \cidoxg_end */
