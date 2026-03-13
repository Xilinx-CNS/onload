/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

/* Access to kernel resources for kernel efct_ubufs */

#include "ef_vi_internal.h"
#include <etherfabric/internal/shrub_client.h>
#include <etherfabric/internal/efct_uk_api.h>
#include <linux/slab.h>
#include <linux/mman.h>

void* efct_ubufs_alloc_mem(size_t size)
{
  return kzalloc(size, GFP_KERNEL);
}

void efct_ubufs_free_mem(void* p)
{
  kfree(p);
}

int efct_ubufs_init_rxq_resource(ef_vi *vi, int qid, unsigned n_superbufs,
                                 bool interrupt_mode,
                                 efch_resource_id_t* resource_id_out)
{
  return -EOPNOTSUPP;
}

void efct_ubufs_free_resource(ef_vi* vi, efch_resource_id_t id)
{
  /* not supported */
}

int efct_ubufs_init_rxq_buffers(ef_vi* vi, int ix, int fd,
                                unsigned n_superbufs,
                                efch_resource_id_t rxq_id,
                                ef_pd* pd, ef_driver_handle pd_dh,
                                efch_resource_id_t* memreg_id,
                                volatile uint64_t** post_buffer_reg_out)
{
  return -EOPNOTSUPP;
}

void efct_ubufs_free_rxq_buffers(ef_vi* vi, int ix, volatile uint64_t* reg)
{
  /* not supported */
}

int efct_ubufs_set_shared_rxq_token(ef_vi* vi, uint64_t token)
{
  return -EOPNOTSUPP;
}

static int map_area_to_kernel(uint64_t* mapping_out, uint64_t user_mapping,
                              size_t bytes, int flags, pgprot_t prot)
{
  /* TBD: do we still need to build for such ancient kernels? */
#ifndef VM_MAP_PUT_PAGES
  return -EOPNOTSUPP;
#else
  unsigned page_count, pages_got, i;
  struct page **pages;
  void* map;

  page_count = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
  pages = kmalloc(page_count * sizeof(*pages), GFP_KERNEL);
  if( pages == NULL )
    return -ENOMEM;

  pages_got = get_user_pages_fast(user_mapping, page_count, flags, pages);
  if( pages_got != page_count )
    goto fail;

  map = vmap(pages, page_count, VM_MAP_PUT_PAGES | VM_USERMAP, prot);
  if( map == NULL )
    goto fail;

  *mapping_out = (uint64_t)map;
  return 0;

fail:
  for( i = 0; i < pages_got; ++i )
    put_page(pages[i]);
  kfree(pages);
  return -EFAULT;
#endif
}

static void put_buffer_pages(const char** buffers, size_t buffer_count)
{
  size_t i;
  if( buffers )
    for( i = 0; i < buffer_count; i += CI_EFCT_SUPERBUFS_PER_PAGE )
      put_page(virt_to_page(buffers[i]));
}

static int
map_buffers_to_kernel(uint64_t* mapping_out, uint64_t user_mapping,
                      const char** buffers, size_t buffer_count)
{
  int rc;
  struct page* page;
  const char* buffer;
  const char* page_end;
  size_t buffers_got = 0;

  while( buffers_got < buffer_count ) {
    rc = get_user_pages_fast(user_mapping, 1, 0, &page);
    if( rc != 1 )
      goto fail;

    buffer = page_address(page);
    page_end = buffer + CI_HUGEPAGE_SIZE;

    while( buffer != page_end && buffers_got != buffer_count ) {
      buffers[buffers_got] = buffer;
      buffer += EFCT_RX_SUPERBUF_BYTES;
      buffers_got += 1;
    }

    user_mapping += CI_HUGEPAGE_SIZE;
  }

  *mapping_out = (uint64_t)buffers;
  return 0;

fail:
  put_buffer_pages(buffers, buffers_got);
  return rc;
}
 
static int map_user_to_kernel(uint64_t* kernel_mappings,
                              uint64_t* user_mappings,
                              const char** buffers)
{
  int i, rc;
  size_t server_bytes, client_bytes;
  struct ef_shrub_client_state state;
  uint64_t user_state = user_mappings[EF_SHRUB_MAP_STATE];
 
  rc = copy_from_user(&state, (void* __user)user_state, sizeof(state));
  if( rc != 0 )
    return -EFAULT;

  server_bytes = state.metrics.server_fifo_size * sizeof(ef_shrub_buffer_id);
  client_bytes = state.metrics.client_fifo_size * sizeof(ef_shrub_buffer_id);

  rc = map_area_to_kernel(&kernel_mappings[EF_SHRUB_MAP_SERVER_FIFO],
                          user_mappings[EF_SHRUB_MAP_SERVER_FIFO],
                          server_bytes, 0, PAGE_KERNEL_RO);
  if( rc < 0 )
    return rc;

  rc = map_area_to_kernel(&kernel_mappings[EF_SHRUB_MAP_CLIENT_FIFO],
                          user_mappings[EF_SHRUB_MAP_CLIENT_FIFO],
                          client_bytes + sizeof(state), FOLL_WRITE, PAGE_KERNEL);
  if( rc < 0 )
    goto fail_client;

  rc = map_buffers_to_kernel(&kernel_mappings[EF_SHRUB_MAP_BUFFERS],
                             user_mappings[EF_SHRUB_MAP_BUFFERS],
                             buffers, state.metrics.buffer_count);
  if( rc < 0 )
    goto fail_buffers;

  kernel_mappings[EF_SHRUB_MAP_STATE] =
    kernel_mappings[EF_SHRUB_MAP_CLIENT_FIFO] + client_bytes;

  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i )
    kernel_mappings[i] = (uint64_t)fget(user_mappings[i]);

  return 0;

fail_buffers:
  vfree((void*)kernel_mappings[EF_SHRUB_MAP_CLIENT_FIFO]);
fail_client:
  vfree((void*)kernel_mappings[EF_SHRUB_MAP_SERVER_FIFO]);
  return rc;
}

static int map_file_to_user(uint64_t* mapping_out, uint64_t file,
                            unsigned long addr, unsigned long bytes,
                            unsigned long prot, unsigned long flags,
                            unsigned long offset)
{
  addr = vm_mmap((struct file*)file, addr, bytes, prot, flags, offset);
  if( IS_ERR((void*)addr) )
    return PTR_ERR((void*)addr);

  *mapping_out = addr;
  return 0;
}

int map_kernel_to_user(uint64_t* kernel_mappings,
                       uint64_t* user_mappings,
                       uint64_t user_buffers)
{
  int rc;
  size_t buffer_bytes, server_bytes, client_bytes;
  const struct ef_shrub_client_state* state =
    (void*)kernel_mappings[EF_SHRUB_MAP_STATE];

  buffer_bytes = state->metrics.buffer_count * state->metrics.buffer_bytes;
  server_bytes = state->metrics.server_fifo_size * sizeof(ef_shrub_buffer_id);
  client_bytes = state->metrics.client_fifo_size * sizeof(ef_shrub_buffer_id);

  rc = map_file_to_user(&user_mappings[EF_SHRUB_MAP_BUFFERS],
                        kernel_mappings[EF_SHRUB_FD_BUFFERS],
                        user_buffers, buffer_bytes, PROT_READ,
                        MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE |
                          MAP_HUGETLB | MAP_HUGE_2MB, 0);
  if( rc < 0 )
    return rc;

  rc = map_file_to_user(&user_mappings[EF_SHRUB_MAP_SERVER_FIFO],
                        kernel_mappings[EF_SHRUB_FD_SERVER_FIFO],
                        0, server_bytes, PROT_READ, MAP_SHARED | MAP_ANONYMOUS,
                        state->metrics.server_fifo_offset);
  if( rc < 0 )
    goto fail_server;

  rc = map_file_to_user(&user_mappings[EF_SHRUB_MAP_CLIENT_FIFO],
                        kernel_mappings[EF_SHRUB_FD_CLIENT_FIFO],
                        0, client_bytes + sizeof(*state),
                        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                        state->metrics.client_fifo_offset);
  if( rc < 0 )
    goto fail_client;

  user_mappings[EF_SHRUB_MAP_STATE] =
    user_mappings[EF_SHRUB_MAP_CLIENT_FIFO] + client_bytes;

  return 0;

fail_client:
  vm_munmap(user_mappings[EF_SHRUB_MAP_SERVER_FIFO], server_bytes);
fail_server:
  vm_munmap(user_mappings[EF_SHRUB_MAP_BUFFERS], buffer_bytes);
  return rc;
}

int efct_ubufs_map_kernel(uint64_t* kernel_mappings,
                          uint64_t* uu_mappings, /* user array of user pointers */
                          const char** kernel_buffers, uint64_t user_buffers)
{
  uint64_t user_mappings[EF_SHRUB_MAP_COUNT];

  if( copy_from_user(user_mappings, uu_mappings, sizeof(user_mappings)) )
      return -EFAULT;

  /* Shrub connection established in userland, map to kernel */
  if( user_mappings[EF_SHRUB_MAP_STATE] != 0 )
    return map_user_to_kernel(kernel_mappings, user_mappings, kernel_buffers);

  /* Shrub connection established in another process, map to userland */
  if( kernel_mappings[EF_SHRUB_MAP_STATE] != 0 ) {
    int rc = map_kernel_to_user(kernel_mappings, user_mappings, user_buffers);
    if( rc < 0 )
      return rc;

    if( copy_to_user(uu_mappings, user_mappings, sizeof(user_mappings)) )
      /* TODO should unmap, although failure is theoretically impossible */
      return -EFAULT;

    return 0;
  }

  /* No shrub connection */
  return -EOPNOTSUPP;
}

void efct_ubufs_unmap_kernel(uint64_t* mappings)
{
  struct ef_shrub_client_state* state = (void*)mappings[EF_SHRUB_MAP_STATE];
  size_t buffer_count;
  int i;

  if( state == NULL )
    return;

  /* Read the state before freeing it along with the client fifo mapping */
  buffer_count = state->metrics.buffer_count;

  put_buffer_pages((void*)mappings[EF_SHRUB_MAP_BUFFERS], buffer_count);
  vfree((void*)mappings[EF_SHRUB_MAP_CLIENT_FIFO]);
  vfree((void*)mappings[EF_SHRUB_MAP_SERVER_FIFO]);
  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i )
    fput((struct file*)mappings[i]);
}

