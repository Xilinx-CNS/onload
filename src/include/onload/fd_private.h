/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  EtherFabric NIC FD private info for driver
**   \date  2006/08/25
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */

#ifndef __CI_DRIVER_EFAB_FDPRIVATE_H__
#define __CI_DRIVER_EFAB_FDPRIVATE_H__

/*--------------------------------------------------------------------
 *
 * headers for type dependencies 
 *
 *--------------------------------------------------------------------*/

#include <onload/tcp_helper.h>
#include <onload/osfile.h>

/*--------------------------------------------------------------------
 *
 * ci_private_t - holds the per file descriptor private state - private.c
 *
 *--------------------------------------------------------------------*/

/*! Comment? */
typedef struct ci_private_s {
  tcp_helper_resource_t *thr; /* Keep it first! */

  /* A [ci_private_t] may be specialised so it can handle certain O/S
  ** interfaces.  For example, to handle read, write or select system
  ** calls.  (On Linux this is done by replacing the file_operations.  The
  ** following fields (prefixed with spec_) relate to specialised
  ** endpoints:
  */
  char			fd_type;
  /*! See common.h CI_PRIV_TYPE_* for type definitions. */
  oo_sp                 sock_id;	/*! id of ep */

  ci_os_file  _filp;

  /* List of dshm segments owned by this file. */
  ci_dllist             dshm_list;

  /* Handle to the control plane, and the ID of the fwd table to use.  These
   * are only valid in the case where we don't have a stack. */
  struct oo_cplane_handle* priv_cp;
  cp_fwd_table_id fwd_table_id;
} ci_private_t;

#endif  /* __CI_DRIVER_EFAB_FDPRIVATE_H__ */

/*! \cidoxg_end */
