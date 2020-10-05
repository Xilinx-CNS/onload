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

struct efch_slice_ext {
  struct efrm_resource rs;
  struct efch_ext_svc_metadata* metadata;
};


static inline struct efch_slice_ext*
rs_to_ext(efch_resource_t* rs)
{
  ci_assert_equal(rs->rs_base->rs_type, EFRM_RESOURCE_SLICE_EXT);
  return container_of(rs->rs_base, struct efch_slice_ext, rs);
}


/* ************************************************************************ */
/*                            ioctl interface                               */

static int
load_basic_metadata(struct efch_slice_ext* ext)
{
  int rc;
  unsigned i;
  struct efch_ext_svc_metadata* m;
  struct efrm_ext_svc_meta base;

  /* Note that it would be possible to share metadata amongst multiple
   * handles, but that introduces a load of synchronisation and cache-expiry
   * complexity which doesn't seem worth it. */

  ext->metadata = NULL;
  rc = efrm_ext_get_meta_global(&ext->rs, ext->rs.rs_instance, &base);
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

  ext->metadata = m;
  return 0;
}


static const struct efrm_ext_msg_meta*
get_msg(struct efch_slice_ext* ext, uint32_t id)
{
  int rc;
  uint32_t i;
  struct efrm_ext_msg_meta meta;

  /* consider sorting the array to make this faster, but we never expect more
   * than a few tens of messages at most */
  for (i = 0; i < ext->metadata->base.nmsgs; ++i) {
    if (ext->metadata->msgs[i].id == id &&
        ext->metadata->msgs[i].ix != INVALID_MSG_IX) {
      return &ext->metadata->msgs[i];
    }
  }

  rc = efrm_ext_get_meta_msg(&ext->rs, ext->rs.rs_instance, id, &meta);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: bad message %u (%d)", __FUNCTION__, id, rc);
    return NULL;
  }
  if (meta.ix >= ext->metadata->base.nmsgs ||
      ext->metadata->msgs[meta.ix].ix != INVALID_MSG_IX) {
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

  ext->metadata->msgs[meta.ix] = meta;
  return &ext->metadata->msgs[meta.ix];
}


static int
ext_rm_alloc(ci_resource_alloc_t* alloc_, ci_resource_table_t* priv_opt,
             efch_resource_t* rs, int intf_ver_id)
{
  struct efch_ext_alloc* alloc = &alloc_->u.ext;
  struct efch_slice_ext* ext;
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

  ext = kmalloc(sizeof(*ext), GFP_KERNEL);
  if (!ext) {
    EFCH_ERR("%s: ERROR: OOM allocating ext", __FUNCTION__);
    return -ENOMEM;
  }

  rc = efrm_ext_alloc_rs(pd_rs->rs_base, &ext->rs, alloc->in_ext_id);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: ext_alloc failed (%d)", __FUNCTION__, rc);
    kfree(ext);
    return rc;
  }

  rs->rs_base = &ext->rs;

  rc = load_basic_metadata(ext);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: loading metadata failed (%d)", __FUNCTION__, rc);
    efrm_ext_free(pd_rs->rs_base, ext->rs.rs_instance);
    efrm_ext_release(&ext->rs);
    kfree(ext);
    return rc;
  }

  return 0;
}


static void
ext_rm_free(efch_resource_t* rs)
{
  int rc;
  struct efch_slice_ext* ext;

  if (!rs->rs_base)
    return;
  ext = rs_to_ext(rs);
  rc = efrm_ext_free(rs->rs_base, rs->rs_base->rs_instance);
  if (rc < 0) {
    EFCH_ERR("%s: ERROR: ext_free failed (%d)", __FUNCTION__, rc);
    /* Ignore the error - there's nothing the caller could do */
  }
  vfree(ext->metadata);
  efrm_ext_release(&ext->rs);
  kfree(ext);
  rs->rs_base = NULL;
}


static int
ext_do_msg(struct efch_slice_ext* ext, uint32_t msg_id,
           void __user * payload_user, size_t len, unsigned flags)
{
  const struct efrm_ext_msg_meta* msg;
  int rc;
  void* payload;

  if (flags) {
    /* No flags currently supported */
    return -EINVAL;
  }
  msg = get_msg(ext, msg_id);
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

  rc = efrm_ext_msg(&ext->rs, ext->rs.rs_instance, msg_id, payload, len);

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
    return ext_do_msg(rs_to_ext(rs), op->u.ext_msg.msg_id,
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
