/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"
#include <etherfabric/internal/shrub_client.h>
#include <etherfabric/internal/shrub_socket.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/skbuff.h>
#include <linux/pagemap.h>
#include <linux/mman.h>
#include <net/af_unix.h>

#include <linux/nsproxy.h> /* TODO ON-16394 see shrub_socket_open */
#include <ci/driver/kernel_compat.h>
#include <driver/linux_onload/onload_kernel_compat.h>
#include <etherfabric/internal/efct_uk_api.h>

// HACK: avoid building various bits of code on ancient kernels
#ifndef VM_MAP_PUT_PAGES
#define ANCIENT_KERNEL_HACK
#endif

int ef_shrub_socket_open(uintptr_t* socket_out)
{
  int rc;
  struct socket* sock;

  /* TODO ON-16394 I don't think Onload will always do this in a user context.
   * We probably need to pass the net namespace in somehow. */
  rc = sock_create_kern(current->nsproxy->net_ns, AF_UNIX, SOCK_SEQPACKET, 0,
                        &sock);
  if( rc < 0 )
    return rc;

  *socket_out = (uintptr_t)sock;
  return 0;
}

int ef_shrub_socket_close_socket(uintptr_t socket)
{
  sock_release((struct socket*)socket);
  return 0;
}

int ef_shrub_socket_close_file(uintptr_t file)
{
  fput((struct file*)file);
  return 0;
}

int ef_shrub_socket_connect(uintptr_t socket, const char* server_addr)
{
  struct sockaddr_un addr;
  int path_len = strlen(server_addr);

  if( path_len >= sizeof(addr.sun_path) )
    return -EINVAL;

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, server_addr);

  return kernel_connect((struct socket*)socket, (struct sockaddr*)&addr,
      offsetof(struct sockaddr_un, sun_path) + path_len + 1, 0);
}

int ef_shrub_socket_send(uintptr_t socket, void* data, size_t bytes)
{
  int rc;
  struct msghdr msg = {};
  struct kvec iov = {
    .iov_base = data,
    .iov_len = bytes
  };

  rc = kernel_sendmsg((struct socket*)socket, &msg, &iov, 1, bytes);
  if( rc < 0 )
    return rc;
  if( rc != bytes )
    return -EIO;
  return 0;
}

int ef_shrub_socket_recv(uintptr_t socket, void* data, size_t bytes)
{
  int rc;
  struct msghdr msg = {};
  struct kvec iov = {
    .iov_base = data,
    .iov_len = bytes
  };

  rc = kernel_recvmsg((struct socket*)socket, &msg, &iov, 1, bytes, 0);
  if( rc < 0 )
    return rc;
  if( rc < bytes )
    return -EPROTO;
  return 0;
}

/* Sadly kernel_recvmsg doesn't offer any way to extract files from a unix
 * socket, so we'll need to dig into the socket buffer to find them.
 */
static int shrub_socket_get_files(struct socket* sock, uintptr_t* files)
{
  int i, rc = 0;
  struct sk_buff* skb;
  struct scm_fp_list* fp;

  skb = efrm_skb_recv_datagram(sock->sk, MSG_PEEK, &rc);
  if( skb == NULL )
    return rc < 0 ? rc : -ENOMSG;

  fp = UNIXCB(skb).fp;

  if( fp == NULL || fp->count != EF_SHRUB_FD_COUNT ) {
    skb_free_datagram(sock->sk, skb);
    return -EPROTO;
  }

  for( i = 0; i < fp->count; ++i )
    files[i] = (uintptr_t)get_file(fp->fp[i]);

  skb_free_datagram(sock->sk, skb);
  return 0;
}

int ef_shrub_socket_recv_metrics(struct ef_shrub_shared_metrics* metrics_out,
                                 uintptr_t* shared_files_out,
                                 uintptr_t socket)
{
  int i, rc;
  struct socket* sock = (struct socket*)socket;

  rc = shrub_socket_get_files(sock, shared_files_out);
  if( rc < 0 )
    return rc;

  rc = ef_shrub_socket_recv(socket, metrics_out, sizeof(*metrics_out));
  if( rc < 0 )
    goto fail;

  if( metrics_out->server_version != EF_SHRUB_VERSION ) {
    rc = -EPROTO;
    goto fail;
  }

  return 0;

fail:
  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i )
    ef_shrub_socket_close_file(shared_files_out[i]);
  return rc;
}

static void put_buffer_pages(const void** buffers, unsigned count)
{
  unsigned i;
  if( buffers )
    for( i = 0; i < count; i += CI_EFCT_SUPERBUFS_PER_PAGE )
      put_page(virt_to_page(buffers[i]));
}

static unsigned bytes_to_buffers(size_t bytes)
{
  return (bytes + EFCT_RX_SUPERBUF_BYTES - 1) / EFCT_RX_SUPERBUF_BYTES;
}

static int map_buffers(uint64_t* addr_out, struct file* file,
                       size_t bytes, const void** buffers)
{
#ifdef ANCIENT_KERNEL_HACK
  return -EOPNOTSUPP;
#else
  unsigned buffer_count, buffers_got;
  struct page* page;
  const char* buffer;
  const char* page_end;
  pgoff_t pgoff = 0;

#ifdef EFRM_HUGETLB_INDEX_BY_PAGE
  pgoff_t pgstride = CI_HUGEPAGE_SIZE / PAGE_SIZE;
#else
  pgoff_t pgstride = 1;
#endif

  buffer_count = bytes_to_buffers(bytes);

  for( buffers_got = 0; buffers_got != buffer_count; pgoff += pgstride ) {
    page = find_or_create_page(file->f_mapping, pgoff, GFP_KERNEL);

    if( page == NULL )
      goto fail_unlocked;

    if( page_size(page) != CI_HUGEPAGE_SIZE )
      goto fail_locked;

    for( buffer = page_address(page), page_end = buffer + CI_HUGEPAGE_SIZE;
         buffer != page_end && buffers_got != buffer_count;
         buffer += EFCT_RX_SUPERBUF_BYTES, ++buffers_got )
      buffers[buffers_got] = buffer;

    unlock_page(page);
  }

  *addr_out = (uint64_t)buffers;
  return 0;

fail_locked:
  unlock_page(page);
fail_unlocked:
  put_buffer_pages(buffers, buffers_got);
  return -EFAULT;
#endif
}

static int map_fifo(uint64_t* addr_out, struct file* file,
                    size_t bytes, pgoff_t pgoff, pgprot_t prot)
{
#ifdef ANCIENT_KERNEL_HACK
  return -EOPNOTSUPP;
#else
  unsigned page_count, pages_got, i;
  struct page **pages;
  void* map;

  page_count = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
  pages = kmalloc(page_count * sizeof(*pages), GFP_KERNEL);
  if( pages == NULL )
    return -ENOMEM;

  for( pages_got = 0; pages_got != page_count; ++pages_got, ++pgoff ) {
    pages[pages_got] = find_or_create_page(file->f_mapping, pgoff, GFP_KERNEL);
    if( pages[pages_got] == NULL )
      goto fail;
  }

  map = vmap(pages, page_count, VM_MAP_PUT_PAGES, prot);
  if( map == NULL )
    goto fail;

  for( i = 0; i < pages_got; ++i )
    unlock_page(pages[i]);

  *addr_out = (uint64_t)map;
  return 0;

fail:
  for( i = 0; i < pages_got; ++i ) {
    unlock_page(pages[i]);
    put_page(pages[i]);
  }
  kfree(pages);
  return -EFAULT;
#endif
}

int ef_shrub_socket_mmap(uint64_t* mapping, void* addr, size_t size,
                         uintptr_t file_, size_t offset, int type)
{
  struct file* file = (struct file*)file_;
  pgoff_t pgoff = offset >> PAGE_SHIFT;

  if( offset & ~PAGE_MASK )
    return -EINVAL;

  switch( type ) {
    case EF_SHRUB_FD_BUFFERS:
      if( offset != 0 )
        return -EINVAL;
      return map_buffers(mapping, file, size, addr);
    case EF_SHRUB_FD_SERVER_FIFO:
      return map_fifo(mapping, file, size, pgoff, PAGE_KERNEL_RO);
    case EF_SHRUB_FD_CLIENT_FIFO:
      return map_fifo(mapping, file, size, pgoff, PAGE_KERNEL);
    default:
      return -EINVAL;
  }
}

void ef_shrub_socket_munmap(uint64_t mapping, size_t size, int type)
{
  switch( type ) {
    case EF_SHRUB_FD_BUFFERS:
      put_buffer_pages((void*)mapping, bytes_to_buffers(size));
      break;
    case EF_SHRUB_FD_SERVER_FIFO:
    case EF_SHRUB_FD_CLIENT_FIFO:
      vfree((void*)mapping);
      break;
  }
}

int ef_shrub_socket_mmap_user(uint64_t __user* user_mapping, uint64_t user_addr,
                              size_t size, uintptr_t file_, size_t offset,
                              int type)
{
  int prot, flag, rc;
  struct file* file = (struct file*)file_;

  switch( type ) {
    case EF_SHRUB_FD_BUFFERS:
      prot = PROT_READ;
      flag = MAP_SHARED | MAP_POPULATE | MAP_HUGETLB | MAP_HUGE_2MB | MAP_FIXED;
      break;
    case EF_SHRUB_FD_SERVER_FIFO:
      prot = PROT_READ;
      flag = MAP_SHARED | MAP_POPULATE;
      break;
    case EF_SHRUB_FD_CLIENT_FIFO:
      prot = PROT_READ | PROT_WRITE;
      flag = MAP_SHARED | MAP_POPULATE;
      break;
    default:
      return -EINVAL;
  }

  user_addr = vm_mmap(file, user_addr, size, prot, flag, offset);
  if( IS_ERR_VALUE(user_addr) )
    return PTR_ERR((void*)user_addr);

  rc = put_user(user_addr, user_mapping);
  if( rc < 0 )
    goto fail;

  if( type == EF_SHRUB_FD_CLIENT_FIFO ) {
    rc = put_user(user_addr + size - sizeof(struct ef_shrub_client_state),
                  user_mapping + 1);
    if( rc < 0 )
      goto fail;
  }

  return 0;

fail:
  vm_munmap(user_addr, size);
  return rc;
}

