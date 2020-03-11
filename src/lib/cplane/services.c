/* SPDX-License-Identifier: GPL-2.0 OR Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* worker functions for kubernetes service DNAT operations on cplane server and
 * clients.
 */

#include <ci/tools.h>

#define CI_CFG_IPV6 1
#include <cplane/mib.h>
#include <cplane/cplane.h>


/* Returns a backend endpoint randomly selected from a service's set of
 * backends */
static struct cp_svc_endpoint*
cp_svc_select_backend(const struct cp_mibs* mib, const cicp_mac_rowid_t id)
{
  struct cp_svc_ep_dllist* svc = &mib->svc_ep_table[id];
  cicp_rowid_t element_id;
  struct cp_svc_ep_array* arr;
  cicp_rowid_t index;

  ci_assert_equal(svc->row_type, CP_SVC_SERVICE);
  if( svc->u.service.n_backends <= 0 )
    return NULL;
  ci_assert( CICP_ROWID_IS_VALID(svc->u.service.head_array_id) );

  /* Copy approximate hash generator from oo_cp_multipath_hash */
  element_id = (ci_frc64_get() >> 4) % svc->u.service.n_backends;
  cp_svc_walk_array_chain(mib, svc->u.service.head_array_id, element_id,
                          &arr, &index);

  return &arr->eps[index];
}


/* Performs a DNAT operation on the provided address.  If the address points to
 * a valid service then attempt to replace the address with a backend's.
 * Returns positive if we need DNAT, zero if not, and negative on error. */
int
cp_svc_check_dnat(struct oo_cplane_handle* cp,
                  ci_addr_sh_t* dst_addr, ci_uint16* dst_port)
{
  struct cp_mibs* mib;
  cp_version_t version;
  struct cp_svc_endpoint* svc_backend;
  struct cp_svc_endpoint backend_copy = {};
  int rc;
  cicp_mac_rowid_t id;

  CP_VERLOCK_START(version, mib, cp);
  svc_backend = NULL;
  rc = 0;

  id = cp_svc_find_match(mib, *dst_addr, *dst_port);
  /* Cannot do dnat if the address isn't a service.  Leave address as-is. */
  if( !CICP_MAC_ROWID_IS_VALID(id) ||
      mib->svc_ep_table[id].row_type != CP_SVC_SERVICE )
    goto out;

  svc_backend = cp_svc_select_backend(mib, id);
  if( svc_backend == NULL ) {
    /* Found a service, but could not get a backend.  This is invalid. */
    rc = -ENOENT;
    goto out;
  }
  backend_copy = *svc_backend;
  rc = 1;

 out:
  CP_VERLOCK_STOP(version, mib)

  if( rc > 0 ) {
    /* Use a copy of the backend because table reads need to be completed inside
     * VERLOCK loop, but dst_addr/port can't be modified until loop ends. */
    *dst_addr = backend_copy.addr;
    *dst_port = backend_copy.port;
  }
  return rc;
}
