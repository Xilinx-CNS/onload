/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include <ci/driver/resource/cxl_cache_spm_manager.h>
#include <ci/efrm/cxl_cache_spm_resource.h>
#include <ci/efrm/private.h>
#include <efrm_internal.h>

struct efrm_cxl_cache_spm_allocation {
  struct list_head link;
  int numa_node;
  unsigned long n_pages;
  CI_DECLARE_FLEX_ARRAY(struct page*, pages);
};

struct efrm_cxl_cache_spm_resource {
  struct efrm_resource rs;
  struct mutex allocations_lock;
  struct list_head allocations;
};

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

int
efrm_cxl_cache_spm_resource_create(struct efrm_cxl_cache_spm_resource** out)
{
  struct efrm_cxl_cache_spm_resource* spm_rs;
  unsigned instance;

  if( ! spm_rm )
    return -EINVAL;

  spm_rs = kzalloc(sizeof(*spm_rs), GFP_KERNEL);
  if( ! spm_rs )
    return -ENOMEM;

  spin_lock_bh(&spm_rm->rm.rm_lock);
  instance = spm_rm->next_instance++;
  spin_unlock_bh(&spm_rm->rm.rm_lock);

  INIT_LIST_HEAD(&spm_rs->allocations);
  mutex_init(&spm_rs->allocations_lock);

  efrm_resource_init(&spm_rs->rs, EFRM_RESOURCE_CXL_CACHE_SPM, instance);
  efrm_resource_manager_add_resource(&spm_rs->rs);

  *out = spm_rs;

  return 0;
}
EXPORT_SYMBOL(efrm_cxl_cache_spm_resource_create);

void
efrm_cxl_cache_spm_resource_destroy(struct efrm_cxl_cache_spm_resource* spm_rs)
{
  efrm_cxl_cache_spm_resource_free_all(spm_rs);
  mutex_destroy(&spm_rs->allocations_lock);
  kfree(spm_rs);
}
EXPORT_SYMBOL(efrm_cxl_cache_spm_resource_destroy);

struct efrm_resource*
cxl_cache_spm_to_resource(struct efrm_cxl_cache_spm_resource* spm_rs)
{
  return &spm_rs->rs;
}
EXPORT_SYMBOL(cxl_cache_spm_to_resource);

struct efrm_cxl_cache_spm_resource*
cxl_cache_spm_from_resource(struct efrm_resource* rs)
{
  return container_of(rs, struct efrm_cxl_cache_spm_resource, rs);
}
EXPORT_SYMBOL(cxl_cache_spm_from_resource);

int
efrm_cxl_cache_spm_resource_allocate(struct efrm_cxl_cache_spm_resource* spm_rs,
                                     int numa_node, unsigned long n_pages,
                                     struct efrm_cxl_cache_spm_allocation **out)
{
  struct efrm_cxl_cache_spm_allocation *allocation;
  unsigned long pfn;
  unsigned long i;
  int rc;

  allocation = vmalloc(struct_size(allocation, pages, n_pages));
  if( ! allocation )
    return -ENOMEM;

  rc = efrm_cxl_cache_spm_pages_allocate(&numa_node, n_pages, &pfn);
  if( rc < 0 ) {
    vfree(allocation);
    return rc;
  }

  allocation->numa_node = numa_node;
  allocation->n_pages = n_pages;
  for( i = 0; i < n_pages; i++, pfn++ )
    allocation->pages[i] = pfn_to_page(pfn);

  mutex_lock(&spm_rs->allocations_lock);
  list_add_tail(&allocation->link, &spm_rs->allocations);
  mutex_unlock(&spm_rs->allocations_lock);

  *out = allocation;
  return 0;
}
EXPORT_SYMBOL(efrm_cxl_cache_spm_resource_allocate);

void
efrm_cxl_cache_spm_resource_free(struct efrm_cxl_cache_spm_resource* spm_rs,
                                 struct efrm_cxl_cache_spm_allocation* alloc,
                                 int/*bool*/ locked)
{
  if( ! locked )
    mutex_lock(&spm_rs->allocations_lock);
  list_del(&alloc->link);
  if( ! locked )
    mutex_unlock(&spm_rs->allocations_lock);

  efrm_cxl_cache_spm_pages_free(alloc->numa_node, alloc->n_pages,
                                page_to_pfn(alloc->pages[0]));
  vfree(alloc);
}
EXPORT_SYMBOL(efrm_cxl_cache_spm_resource_free);

void
efrm_cxl_cache_spm_resource_free_all(struct efrm_cxl_cache_spm_resource* spm_rs)
{
  struct list_head *entry, *temp;

  mutex_lock(&spm_rs->allocations_lock);
  list_for_each_safe(entry, temp, &spm_rs->allocations) {
    struct efrm_cxl_cache_spm_allocation *allocation =
      container_of(entry, struct efrm_cxl_cache_spm_allocation,
                   link);
    efrm_cxl_cache_spm_resource_free(spm_rs, allocation, 1);
  }
  mutex_unlock(&spm_rs->allocations_lock);
}
EXPORT_SYMBOL(efrm_cxl_cache_spm_resource_free_all);

struct page**
efrm_cxl_cache_spm_pages(struct efrm_cxl_cache_spm_allocation* allocation)
{
  return allocation->pages;
}
EXPORT_SYMBOL(efrm_cxl_cache_spm_pages);

unsigned long
efrm_cxl_cache_spm_num_pages(struct efrm_cxl_cache_spm_allocation* allocation)
{
  return allocation->n_pages;
}
EXPORT_SYMBOL(efrm_cxl_cache_spm_num_pages);
