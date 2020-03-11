/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  ds
**  \brief  efabcfg UL helper functions
**   \date  2006/01/31
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */

#include "ip_internal.h"
#include <ci/internal/efabcfg.h>


# undef  CI_CFG_OPT
# define CI_CFG_OPT(env, name, type, doc, type_m, group, default, max, min, presn) \
    CI_STRUCT_MBR(name, default),
ci_cfg_opts_t ci_cfg_opts = {
  {
    #include <ci/internal/opts_citp_def.h>
  },
  {
    #include <ci/internal/opts_netif_def.h>
  },
  {
    #include <ci/internal/opts_user_def.h>
  } 
};
# undef CI_CFG_OPT


/*! Setup the global ci_cfg_opts struct.
 */
int ci_cfg_query(void)
{
  /* Install "modified" netif opts default values, the rest
   * (citp_opts, user_opts) don't need any modification of their "original"
   * default values.
   */
  ci_netif_config_opts_defaults(&ci_cfg_opts.netif_opts);

  /* adjust the netif options again... */
  ci_netif_config_opts_getenv(&ci_cfg_opts.netif_opts);
  ci_netif_config_opts_rangecheck(&ci_cfg_opts.netif_opts);
  LOG_S(ci_netif_config_opts_dump(&ci_cfg_opts.netif_opts, NULL, NULL));

  return 0;
}

/*! \cidoxg_end */
