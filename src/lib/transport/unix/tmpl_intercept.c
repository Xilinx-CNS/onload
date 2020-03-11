/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  as
**  \brief  Intercept of templated-sends API calls
**   \date  2013/10/20
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include "internal.h"

#include <unistd.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include <onload/extensions.h>
#include <onload/extensions_zc.h>


int onload_msg_template_alloc(int fd, const struct iovec* initial_msg,
                              int mlen, onload_template_handle* handlep,
                              unsigned flags)
{
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi = NULL;
  struct oo_msg_template** omt_pp = handlep;
  int rc = 0;

  Log_CALL(ci_log("%s(%d, %p, %d, %p, %d)", __FUNCTION__, fd, initial_msg, mlen,
                  handlep, flags));
  citp_enter_lib(&lib_context);
  if( (fdi = citp_fdtable_lookup(fd)) != NULL ) {
    rc = citp_fdinfo_get_ops(fdi)->
      tmpl_alloc(fdi, initial_msg, mlen, omt_pp, flags);
    citp_fdinfo_release_ref(fdi, 0);
  }
  else {
    rc = -ESOCKTNOSUPPORT;
  }
  citp_exit_lib(&lib_context, TRUE);
  Log_CALL_RESULT(rc);
  return rc;
}


int
onload_msg_template_update(int fd, onload_template_handle handle,
                           const struct onload_template_msg_update_iovec* updates,
                           int ulen, unsigned flags)
{
  struct oo_msg_template* omt = handle;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi = NULL;
  int rc = 0;

  Log_CALL(ci_log("%s(%p, %p, %d, %d)", __FUNCTION__, handle, updates, ulen,
                  flags));

  citp_enter_lib(&lib_context);
  if( (fdi = citp_fdtable_lookup(fd)) != NULL ) {
    rc = citp_fdinfo_get_ops(fdi)->tmpl_update(fdi, omt, updates, ulen, flags);
    citp_fdinfo_release_ref(fdi, 0);
  }
  else {
    rc = -ESOCKTNOSUPPORT;
  }
  citp_exit_lib(&lib_context, TRUE);
  Log_CALL_RESULT(rc);
  return rc;
}


int onload_msg_template_abort(int fd, onload_template_handle handle)
{
  struct oo_msg_template* omt = handle;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi = NULL;
  int rc = 0;

  Log_CALL(ci_log("%s(%p)", __FUNCTION__, handle));

  citp_enter_lib(&lib_context);
  if( (fdi = citp_fdtable_lookup(fd)) != NULL ) {
    rc = citp_fdinfo_get_ops(fdi)->tmpl_abort(fdi, omt);
    citp_fdinfo_release_ref(fdi, 0);
  }
  else {
    rc = -ESOCKTNOSUPPORT;
  }
  citp_exit_lib(&lib_context, TRUE);
  Log_CALL_RESULT(rc);
  return rc;
}
