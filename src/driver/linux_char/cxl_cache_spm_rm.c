/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include <ci/driver/resource/cxl_cache_spm_manager.h>
#include <ci/efrm/cxl_cache_spm_resource.h>
#include <ci/efch/op_types.h>
#include <ci/efrm/private.h>
#include <char_internal.h>
#include "linux_char_internal.h"

static int cxl_cache_spm_rm_alloc(ci_resource_alloc_t* alloc,
                                  ci_resource_table_t* priv_opt,
                                  efch_resource_t* rs,
                                  int intf_ver_id)
{
  struct efrm_cxl_cache_spm_resource *spm_rs;
  int rc;

  if( ! efrm_cxl_cache_spm_exists() )
    return -ENOENT;

  rc = efrm_cxl_cache_spm_resource_create(&spm_rs);
  if( rc < 0 )
    return rc;

  rs->rs_base = cxl_cache_spm_to_resource(spm_rs);

  return 0;
}

struct cxl_cache_spm_vm_priv {
  struct efrm_cxl_cache_spm_resource *spm_rs;
  struct efrm_cxl_cache_spm_allocation *alloc;
};

static void cxl_cache_spm_rm_vma_close(struct vm_area_struct* vma)
{
  struct cxl_cache_spm_vm_priv *priv = vma->vm_private_data;
  efrm_cxl_cache_spm_resource_free(priv->spm_rs, priv->alloc, 0);
  efrm_resource_release(cxl_cache_spm_to_resource(priv->spm_rs));
  kfree(priv);
}

static const struct vm_operations_struct cxl_cache_spm_vma_ops = {
  .close = cxl_cache_spm_rm_vma_close,
};

static int cxl_cache_spm_rm_mmap(struct efrm_resource* rs, unsigned long* bytes,
                                 struct vm_area_struct* vma, int index)
{
  struct efrm_cxl_cache_spm_allocation *alloc;
  struct efrm_cxl_cache_spm_resource *spm_rs;
  struct cxl_cache_spm_vm_priv *priv;
  unsigned long n_pages;
  unsigned long len;
  int numa_node;
  int rc;

  spm_rs = cxl_cache_spm_from_resource(rs);

  numa_node = numa_node_id();
  len = CI_ROUND_UP(*bytes, PAGE_SIZE);
  n_pages = len >> PAGE_SHIFT;

  if( n_pages == 0 )
    return -EINVAL;

  priv = kzalloc(sizeof(*priv), GFP_KERNEL);
  if( ! priv )
    return -ENOMEM;

  rc = efrm_cxl_cache_spm_resource_allocate(spm_rs, numa_node, n_pages, &alloc);
  if( rc < 0 ) {
    EFCH_ERR("%s: failed to allocate CXL.cache SPM pages, rc=%d",
             __FUNCTION__, rc);
    goto fail_allocate;
  }

  rc = vm_insert_pages(vma, vma->vm_start, efrm_cxl_cache_spm_pages(alloc),
                       &n_pages);
  if( rc < 0 || n_pages != 0 ) {
    EFCH_ERR("%s: failed to insert pages (%lu/%lu not inserted), rc=%d",
             __FUNCTION__, n_pages, efrm_cxl_cache_spm_num_pages(alloc), rc);
    rc = rc < 0 ? rc : -EINVAL;
    goto fail_page_insert;
  }

  /* Take a reference to the resource so it doesn't disappear before a user
   * unmaps all mapped memory. */
  efrm_resource_ref(cxl_cache_spm_to_resource(spm_rs));

  /* We overwrite both the ops and private data which efch provide as we don't
   * need the fault handler, but are very much interested in being able to
   * free memory without closing the driver handle this was allocated on. */
  priv->spm_rs = spm_rs;
  priv->alloc = alloc;
  vma->vm_private_data = priv;
  vma->vm_ops = &cxl_cache_spm_vma_ops;
  vm_flags_set(vma, VM_DONTCOPY);

  *bytes -= len;

  return rc;

fail_page_insert:
  n_pages = efrm_cxl_cache_spm_num_pages(alloc) - n_pages;
  zap_special_vma_range(vma, vma->vm_start, n_pages << PAGE_SHIFT);
  efrm_cxl_cache_spm_resource_free(spm_rs, alloc, 0);
fail_allocate:
  kfree(priv);
  return rc;
}

efch_resource_ops efch_cxl_cache_spm_ops = {
  .rm_alloc = cxl_cache_spm_rm_alloc,
  .rm_free = NULL, /* Handled and ref-counted by resource_manager.c */
  .rm_mmap = cxl_cache_spm_rm_mmap,
  .rm_nopage = NULL,
  .rm_dump = NULL,
  .rm_rsops = NULL,
};
