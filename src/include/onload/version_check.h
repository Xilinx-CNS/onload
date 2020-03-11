/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* Implementation of the oo_version_check_impl() function. This is not a
 * normal header - it should only be included by the files that implement the
 * wrapper of this function, namely tcp_helper_resource.c */

#ifndef ONLOAD_VERSION_CHECK_H_
#define ONLOAD_VERSION_CHECK_H_

#include "version.h"


static int
oo_version_check_impl(const char* user_version, const char* user_intf_ver,
                      int user_debug_lib, const char* kernel_intf_ver)
{
  int ver_chk_bad, intf_chk_bad;
  int rc = 0;

  CI_BUILD_ASSERT(sizeof(ONLOAD_VERSION) <= OO_VER_STR_LEN + 1);
  ci_assert_le(strlen(kernel_intf_ver), CI_CHSUM_STR_LEN);

  if( strnlen(user_version, OO_VER_STR_LEN + 1) > OO_VER_STR_LEN )
    return -EINVAL;
  if( strnlen(user_intf_ver, CI_CHSUM_STR_LEN + 1) > CI_CHSUM_STR_LEN )
    return -EINVAL;

  ver_chk_bad = strncmp(ONLOAD_VERSION, user_version, OO_VER_STR_LEN + 1);
  intf_chk_bad = strncmp(kernel_intf_ver, user_intf_ver, CI_CHSUM_STR_LEN + 1);

  if( ver_chk_bad ) {
    ci_log("ERROR: user/driver version mismatch");
    ci_log("  user-version: %s", user_version);
    ci_log("  driver-version: %s", ONLOAD_VERSION);
    rc = -ELIBACC;
  }
  if( intf_chk_bad ) {
    ci_log("ERROR: user/driver interface mismatch");
    ci_log("  user-interface: %s", user_intf_ver);
    ci_log("  driver-interface: %s", kernel_intf_ver);
    rc = -ELIBACC;
  }
  if( user_debug_lib < 0 )
    ; /* ignore */
#ifdef NDEBUG
  else if( user_debug_lib ) {
#else
  else if( ! user_debug_lib ) {
#endif
    ci_log("ERROR: user/driver build type mismatch");
    ci_log("  user-build: %s", user_debug_lib ? "debug" : "release");
    ci_log("  driver-build: %s", ! user_debug_lib ? "debug" : "release");
    rc = -ELIBACC;
  }
  if( rc != 0 )
    ci_log("HINT: Most likely you need to reload the sfc and onload drivers");

  return rc;
}

#endif
