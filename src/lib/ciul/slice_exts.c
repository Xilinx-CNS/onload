/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/*! \cidoxg_lib_ef */
#include <etherfabric/slice_exts.h>
#include "ef_vi_internal.h"
#include <ci/efch/op_types.h>
#include <ci/efrm/resource_id.h>
#include "driver_access.h"
#include "logging.h"
#include <fcntl.h>
#include <unistd.h>


struct ef_vi_extension_s {
  int dh;
  efch_resource_id_t id;
};

int ef_vi_open_extension(struct ef_pd* pd, ef_driver_handle dh,
                         const ef_vi_uuid_t id, enum ef_ext_flags flags,
                         ef_vi_extension** ext_out)
{
  int rc;
  ci_resource_alloc_t ra;
  ef_vi_extension* out;

  out = calloc(1, sizeof(*out));
  out->dh = pd->pd_cluster_sock != -1 ? pd->pd_cluster_dh : dh;

  memset(&ra, 0, sizeof(ra));
  ef_vi_set_intf_ver(ra.intf_ver, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_SLICE_EXT;
  ra.u.ext.in_pd_rs_id = efch_make_resource_id(pd->pd_resource_id);
  memcpy(ra.u.ext.in_ext_id, id, sizeof(ra.u.ext.in_ext_id));
  ra.u.ext.in_flags = flags;
  rc = ci_resource_alloc(out->dh, &ra);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: ci_resource_alloc %d", __FUNCTION__, rc));
    goto fail;
  }
  out->id = ra.out_id;

  *ext_out = out;
  return 0;
 fail:
  free(out);
  return rc;
}


int ef_vi_close_extension(ef_vi_extension* ext)
{
  int rc;
  ci_resource_op_t op;

  if( ! ext )
    return 0;
  op.op = CI_RSOP_EXT_FREE;
  op.id = ext->id;
  rc = ci_resource_op(ext->dh, &op);
  if( rc == 0 )
    free(ext);
  return rc;
}


int ef_vi_extension_send_message(ef_vi_extension* ext, uint32_t message,
                                 void* payload, size_t payload_size,
                                 unsigned flags)
{
  ci_resource_op_t op;

  op.op = CI_RSOP_EXT_MSG;
  op.id = ext->id;
  op.u.ext_msg.msg_id = message;
  op.u.ext_msg.payload_ptr = (uintptr_t)payload;
  op.u.ext_msg.payload_len = payload_size;
  op.u.ext_msg.flags = flags;
  return ci_resource_op(ext->dh, &op);
}


int ef_vi_extension_destroy_resource(ef_vi_extension* ext,
                                     uint32_t resource_class,
                                     uint32_t resource_id, unsigned flags)
{
  ci_resource_op_t op;

  op.op = CI_RSOP_EXT_DESTROY_RSRC;
  op.id = ext->id;
  op.u.ext_destroy_rsrc.clas = resource_class;
  op.u.ext_destroy_rsrc.id = resource_id;
  op.u.ext_destroy_rsrc.flags = flags;
  return ci_resource_op(ext->dh, &op);
}

/*! \cidoxg_end */
