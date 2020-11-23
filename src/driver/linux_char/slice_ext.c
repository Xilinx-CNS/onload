/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/efrm/efrm_client.h>
#include "efch.h"
#include <ci/efrm/slice_ext.h>
#include <ci/efrm/pd.h>
#include <ci/efch/op_types.h>
#include <ci/efhw/mc_driver_pcol.h>
#include "char_internal.h"


#define INVALID_MSG_IX (~0u)

struct efch_ext_svc_metadata {
  struct efrm_ext_svc_meta base;
  struct efrm_ext_msg_meta msgs[];
};


/* ************************************************************************ */
/*                            ioctl interface                               */

static int
load_basic_metadata(struct efrm_ext* ext, struct efch_ext_svc_metadata **out)
{
  int rc;
  unsigned i;
  struct efch_ext_svc_metadata* m;
  struct efrm_ext_svc_meta base;

  /* Note that it would be possible to share metadata amongst multiple
   * handles, but that introduces a load of synchronisation and cache-expiry
   * complexity which doesn't seem worth it. */

  *out = NULL;
  rc = efrm_ext_get_meta_global(ext, &base);
  if (rc < 0)
    return rc;

  /* totally arbitrary size cap, to prevent memory explosions: */
  if (base.nmsgs >= 4096)
    return -E2BIG;

  m = vzalloc(sizeof(struct efch_ext_svc_metadata) +
              sizeof(m->msgs[0]) * base.nmsgs);
  if (!m)
    return -ENOMEM;

  m->base = base;
  for (i = 0; i < base.nmsgs; ++i)
    m->msgs[i].ix = INVALID_MSG_IX;

  *out = m;
  return 0;
}


static const struct efrm_ext_msg_meta*
get_msg(efch_resource_t* rs, uint32_t id)
{
  int rc;
  uint32_t i;
  struct efrm_ext_msg_meta meta;

  /* consider sorting the array to make this faster, but we never expect more
   * than a few tens of messages at most */
  for (i = 0; i < rs->ext.metadata->base.nmsgs; ++i) {
    if (rs->ext.metadata->msgs[i].id == id &&
        rs->ext.metadata->msgs[i].ix != INVALID_MSG_IX) {
      return &rs->ext.metadata->msgs[i];
    }
  }

  rc = efrm_ext_get_meta_msg(efrm_ext_from_resource(rs->rs_base), id, &meta);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: bad message %u (%d)", __FUNCTION__, id, rc);
    return NULL;
  }
  if (meta.ix >= rs->ext.metadata->base.nmsgs ||
      rs->ext.metadata->msgs[meta.ix].ix != INVALID_MSG_IX) {
    EFCH_ERR("%s: ERROR: MC bug: msg %u (%u) already used",
             __FUNCTION__, id, meta.ix);
    return NULL;
  }

  /* Arbitrary cap for sanity check: */
  if (meta.mcdi_param_size >= 4096) {
    EFCH_ERR("%s: ERROR: message %u has bogus metadata (%u)",
             __FUNCTION__, id, meta.mcdi_param_size);
    return NULL;
  }

  rs->ext.metadata->msgs[meta.ix] = meta;
  return &rs->ext.metadata->msgs[meta.ix];
}


static int
ext_rm_alloc(ci_resource_alloc_t* alloc_, ci_resource_table_t* priv_opt,
             efch_resource_t* rs, int intf_ver_id)
{
  struct efch_ext_alloc* alloc = &alloc_->u.ext;
  struct efrm_ext* ext;
  efch_resource_t* pd_rs;
  int rc;

  if (alloc->in_flags) {
    /* No flags currently */
    return -EINVAL;
  }

  rc = efch_resource_id_lookup(alloc->in_pd_rs_id, priv_opt, &pd_rs);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: id="EFCH_RESOURCE_ID_FMT" (%d)",
             __FUNCTION__,
             EFCH_RESOURCE_ID_PRI_ARG(alloc->in_pd_rs_id), rc);
    return rc;
  }
  if (pd_rs->rs_base->rs_type != EFRM_RESOURCE_PD) {
    EFCH_ERR("%s: ERROR: id="EFCH_RESOURCE_ID_FMT" is not a PD",
             __FUNCTION__,
             EFCH_RESOURCE_ID_PRI_ARG(alloc->in_pd_rs_id));
    return -EINVAL;
  }

  rc = efrm_ext_alloc_rs(efrm_pd_from_resource(pd_rs->rs_base),
                         alloc->in_ext_id, &ext);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: ext_alloc failed (%d)", __FUNCTION__, rc);
    return rc;
  }

  rs->rs_base = efrm_ext_to_resource(ext);

  rc = load_basic_metadata(ext, &rs->ext.metadata);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: loading metadata failed (%d)", __FUNCTION__, rc);
    efrm_ext_release(ext);
    return rc;
  }

  return 0;
}


static void
ext_rm_free(efch_resource_t* rs)
{
  if (!rs->rs_base)
    return;
  vfree(rs->ext.metadata);
  efrm_ext_release(efrm_ext_from_resource(rs->rs_base));
  rs->rs_base = NULL;
}


static int
ext_do_msg(efch_resource_t* rs, uint32_t msg_id,
           void __user * payload_user, size_t len, unsigned flags)
{
  const struct efrm_ext_msg_meta* msg;
  int rc;
  void* payload;

  if (flags) {
    /* No flags currently supported */
    return -EINVAL;
  }
  msg = get_msg(rs, msg_id);
  if (!msg)
    return -ENOMSG;
  /* Too-long lengths are banned here. Too-short lengths are padded with
   * zeros in the firmware (and the eBPF can get hold of the original length).
   * This allows for practical backward compatibilty for plugin authors. */
  if (len > msg->mcdi_param_size)
    return -E2BIG;

  payload = kmalloc(len, GFP_KERNEL);
  if (!payload)
    return -ENOMEM;

  if (copy_from_user(payload, payload_user, len)) {
    rc = -EFAULT;
    goto out;
  }

  rc = efrm_ext_msg(efrm_ext_from_resource(rs->rs_base), msg_id, payload, len);

  if (copy_to_user(payload_user, payload, len))
    rc = -EFAULT;

out:
  kfree(payload);
  return rc;
}


static int
ext_rm_rsops(efch_resource_t* rs, ci_resource_table_t* priv_opt,
             ci_resource_op_t* op, int* copy_out)
{
  if (!rs->rs_base)
    return -EIDRM;

  switch (op->op) {
  case CI_RSOP_EXT_FREE:
    ext_rm_free(rs);
    return 0;

  case CI_RSOP_EXT_MSG:
    return ext_do_msg(rs, op->u.ext_msg.msg_id,
                      (void __user *)op->u.ext_msg.payload_ptr,
                      op->u.ext_msg.payload_len,
                      op->u.ext_msg.flags);

  default:
    EFCH_ERR("%s: Invalid op, expected CI_RSOP_EXT_*", __FUNCTION__);
    return -EINVAL;
  }
}


efch_resource_ops efch_slice_ext_ops = {
  .rm_alloc  = ext_rm_alloc,
  .rm_free   = ext_rm_free,
  .rm_mmap   = NULL,
  .rm_nopage = NULL,
  .rm_dump   = NULL,
  .rm_rsops  = ext_rm_rsops,
};
