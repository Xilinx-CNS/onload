/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file pcap.c
** <L5_PRIVATE L5_SOURCE>
** \author  ak
**  \brief  Interface to common transport logging functions
**   \date  2005/09/22
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_common */

#include <ci/internal/transport_common.h>

/* ***************************
 * Global vars
 */

/*! Current logging level/mask */
unsigned citp_log_level = CI_UL_LOG_E | CI_UL_LOG_U;


/*! \cidoxg_end */
