/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  Definition of user-specific options/restrictions
**   \date  2005/12/12
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/


/* For a detailed explanation of how this macro system works, look at
 * <ci/internal/opts_netif_def.h>
 *
 *     CI_CFG_OPT(type, type_modifider, name, group, default,
 *                minimum, maximum, presentation)
 */

#ifdef CI_CFG_OPTFILE_VERSION
CI_CFG_OPTFILE_VERSION(100)
#endif

