/* SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef __CPLANE_CREATE_H__
#define __CPLANE_CREATE_H__

#ifdef __KERNEL__
# error This file is UL-only.
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <cplane/cplane.h>
#include <ci/tools.h>

#ifndef OO_CP_INTF_VER
# error Define OO_CP_INTF_VER before including this file.
#endif

/* Ensure that clients and the library have the same idea of the control plane
 * interface.  XXX: #define-ing oo_cp_create in this way is ugly, but is quick
 * for the purposes of this RFC.  Directing the linker to alias some symbols
 * would be neater. */
#define __oo_cp_create(ver) oo_cp_create_ ## ver
#define _oo_cp_create(ver) __oo_cp_create(ver)
#define oo_cp_create _oo_cp_create(OO_CP_INTF_VER)

#define CP_CREATE_FLAGS_INIT_NET  0x1u
int oo_cp_create(int fd, struct oo_cplane_handle* cp,
                 enum cp_sync_mode mode, ci_uint32 flags);
void oo_cp_destroy(struct oo_cplane_handle* cp);

#ifdef __cplusplus
}
#endif

#endif /* ! defined(__CPLANE_CREATE_H__) **/
