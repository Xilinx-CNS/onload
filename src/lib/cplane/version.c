/* SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/tools.h>
#include <cplane/cplane.h>

#ifdef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_H__
#error "don't include ci/internal/transport_config_opt.h from binary-only code"
#endif

#ifndef OO_CP_INTF_VER
# error OO_CP_INTF_VER is not defined.
#endif

/* This will be statically linked into the cplane server */
oo_cp_version_check_t oo_cplane_api_version = {
  .in_cp_intf_ver = OO_STRINGIFY(OO_CP_INTF_VER)
};

#ifdef __KERNEL__
int oo_cp_check_version(struct ci_private_s* priv, void* arg)
{
  oo_cp_version_check_t* vc = arg;
  (void)vc;
  (void)priv;

  if( strnlen(vc->in_cp_intf_ver, CP_CHSUM_STR_LEN + 1) > CP_CHSUM_STR_LEN )
    return -EINVAL;

  if( strncmp(vc->in_cp_intf_ver, OO_STRINGIFY(OO_CP_INTF_VER),
              CP_CHSUM_STR_LEN + 1) ) {
    ci_log("ERROR: user/driver cplane interface mismatch");
    ci_log("  user-interface: %s", vc->in_cp_intf_ver);
    ci_log("  driver-interface: %s", OO_STRINGIFY(OO_CP_INTF_VER));
    return -ELIBACC;
  }

  return 0;
}
#endif
