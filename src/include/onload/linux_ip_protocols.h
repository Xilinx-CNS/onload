/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  ICMP & IGMP & UDP handlers.  UDP handling is
**          for broadcasts which are not (currently) filtered by the NIC.
**          Used by linux/windows/sunos despite the filename
**   \date  2004/06/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_LINUX__IP__PROTOCOLS_H__
#define __CI_DRIVER_EFAB_LINUX__IP__PROTOCOLS_H__

#ifndef __ci_driver__
#error "This is a driver module."
#endif

#include <onload/tcp_helper.h>
#include <onload/ip_protocols.h>
#include <ci/internal/transport_config_opt.h> /* for CI_CFG_ERROR_PASS_UP */


#if CI_CFG_HANDLE_ICMP
/*! efab_handle_ipp_pkt_task -
 * ICMP delivery handler.  Called from netfilter hook.
 */
extern int 
efab_handle_ipp_pkt_task(int thr_id, efab_ipp_addr* addr, ci_icmp_hdr* icmp);

#endif

#endif

/*! \cidoxg_end */
