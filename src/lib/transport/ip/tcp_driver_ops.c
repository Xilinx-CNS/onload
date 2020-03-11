/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
 ** <L5_PRIVATE L5_SOURCE>
 ** \author  djr
 **  \brief  TCP helper dependent driver / kernel specifics for libef.
 **   \date  2006/06/13
 **    \cop  (c) Level 5 Networks Limited.
 ** </L5_PRIVATE>
 *//*
\**************************************************************************/

/*! \cidoxg_lib_ef */

#include <ci/internal/ip.h>
#include <onload/tcp_driver.h>
#include <onload/tcp_helper_fns.h>

#ifndef __KERNEL__
# error "kernel-only source file"
#endif

int ci_tcp_helper_more_bufs(ci_netif* ni)
{
  return efab_tcp_helper_more_bufs(netif2tcp_helper_resource(ni));
}

int ci_tcp_helper_more_socks(ci_netif* ni)
{
  return efab_tcp_helper_more_socks(netif2tcp_helper_resource(ni));
}

/*! \cidoxg_end */
