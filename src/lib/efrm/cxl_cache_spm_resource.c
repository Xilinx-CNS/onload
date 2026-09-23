/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include <ci/driver/resource/cxl_cache_spm_manager.h>
#include <ci/efrm/private.h>

struct efrm_cxl_cache_spm_resource_manager {
  struct efrm_resource_manager rm;
  unsigned next_instance;
};

static struct efrm_cxl_cache_spm_resource_manager *spm_rm;

static void
efrm_cxl_cache_spm_resource_manager_dtor(struct efrm_resource_manager *rm)
{
  /* Freeing the allocated resource manager is handled for us but only works
   * if the struct efrm_resource_manager is the first member of our struct. */
  BUILD_BUG_ON(offsetof(struct efrm_cxl_cache_spm_resource_manager, rm) != 0);

  /* That said, we know spm_rm is about to be freed via a different handle, so
   * lets reflect that in our global accessor. */
  spm_rm = NULL;
}

int
efrm_cxl_cache_spm_resource_manager_ctor(struct efrm_resource_manager **rm_out)
{
  struct efrm_cxl_cache_spm_resource_manager *rm;
  int rc;

  rm = kzalloc(sizeof(*rm), GFP_KERNEL);
  if (rm == NULL)
    return -ENOMEM;

  rc = efrm_resource_manager_ctor(&rm->rm,
                                  efrm_cxl_cache_spm_resource_manager_dtor,
                                  "CXL.cache SPM",
                                  EFRM_RESOURCE_CXL_CACHE_SPM);
  if (rc < 0)
    goto fail;

  spm_rm = rm;
  *rm_out = &rm->rm;
  return 0;

fail:
  kfree(rm);
  return rc;
}
