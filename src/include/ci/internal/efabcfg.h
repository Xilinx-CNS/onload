/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  cgg & ds
**  \brief  Decls & defs for the configuration database libraries.
**   \date  2005/11/17
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */

#ifndef __CI_INTERNAL_EFABCFG_H__
#define __CI_INTERNAL_EFABCFG_H__

#include <ci/compat.h>
#include <ci/tools.h>
#include <ci/internal/ip.h>
#include <ci/internal/citp_opts.h>
#include <onload/common.h>

#if !defined(__KERNEL__)
#include <onload/ul.h>
#endif

#include <ci/internal/ip.h>
#include <ci/internal/citp_opts.h>
#include <ci/internal/user_opts.h>


typedef struct {
  citp_opts_t          citp_opts;
  ci_netif_config_opts netif_opts;
  ci_user_opts_t       user_opts;
} ci_cfg_opts_t;


#define CITP_OPTS (ci_cfg_opts.citp_opts)
extern ci_cfg_opts_t ci_cfg_opts CI_HV;
extern int ci_cfg_query(void);

/* Needed to support list of port numbers in EF_ options */
struct ci_port_list {
  ci_dllink link;
  ci_uint16 port;
};


#endif  /* __CI_INTERNAL_EFABCFG_H__ */

/*! \cidoxg_end */
