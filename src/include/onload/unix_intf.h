/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file unix_intf.h
** <L5_PRIVATE L5_HEADER >
** \author  slp
**  \brief  Unix driver entry points.
**     $Id$
**   \date  2007/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab_unix  */

#ifndef __ONLOAD_UNIX_INTF_H__
#define __ONLOAD_UNIX_INTF_H__

#if defined(__KERNEL__)
# error __KERNEL__ not allowed here.
#endif

#include <ci/compat.h>
#include <onload/syscall_unix.h>
#include <ci/driver/efab/open.h>
#include <onload/ioctl.h>
#include <onload/common.h>
#include <onload/mmap.h>


/*! \i_efab_unix */
/* Please do not add any logging here (else citp_log_fn() could recurse) */
ci_inline int
oo_close(ci_fd_t fp)
{
  if( ci_sys_close(fp) < 0 )  return -errno;
  return 0;
}


/*! \i_efab_unix */
ci_inline int
oo_resource_alloc(ci_fd_t fp, ci_resource_onload_alloc_t* io)
{
  return oo_resource_op(fp, OO_IOC_RESOURCE_ONLOAD_ALLOC, io);
}

/*! \i_efab_unix */
ci_inline int
oo_ep_info(ci_fd_t fp, ci_ep_info_t* io)
{
  return oo_resource_op(fp, OO_IOC_EP_INFO, io);
}

ci_inline int
oo_vi_stats_query(ci_fd_t fp, int intf_i, void* data, int data_len,
                  int do_reset)
{
  ci_vi_stats_query_t io;
  io.intf_i = intf_i;
  CI_USER_PTR_SET(io.stats_data, data);
  io.data_len = data_len;
  io.do_reset = do_reset;

  return oo_resource_op(fp, OO_IOC_VI_STATS_QUERY, &io);
}

#if ! CI_CFG_UL_INTERRUPT_HELPER
ci_inline int
oo_debug_op(ci_fd_t fp, ci_debug_onload_op_t *io)
{
  return oo_resource_op(fp, OO_IOC_DEBUG_OP, io);
}
#endif

#endif  /* _CI_DRIVER_UNIX_INTF_H_ */

/*! \cidoxg_end */

