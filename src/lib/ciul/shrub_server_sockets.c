/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Enable memfd_create */
#define _GNU_SOURCE

#include "ef_vi_internal.h"
#include "shrub_server_sockets.h"
#include "driver_access.h"

#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/mman.h>

static int ret(int rc) {return rc < 0 ? -errno : rc;}

static int unix_server_epoll_create(struct ef_shrub_server_sockets* sockets)
{
  int rc = epoll_create(1);
  if( rc < 0 )
    return -errno;

  sockets->epoll = rc;
  return 0;
}

static int unix_server_socket(struct ef_shrub_server_sockets* sockets)
{
  int rc = socket(AF_UNIX, SOCK_STREAM, 0);
  if( rc < 0 )
    return -errno;

  sockets->listen = rc;
  return 0;
}

static int unix_server_listen(struct ef_shrub_server_sockets* sockets,
                              const char *server_addr)
{
  int rc;
  struct sockaddr_un addr;
  size_t path_len = strlen(server_addr);

  rc = unix_server_socket(sockets);
  if( rc < 0 )
    return rc;

  if( path_len >= sizeof(addr.sun_path) ) {
    rc = -EINVAL;
    goto fail;
  }

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, server_addr);

  rc = bind(sockets->listen, (struct sockaddr*)&addr,
            offsetof(struct sockaddr_un, sun_path) + path_len + 1);
  if( rc < 0 )
    goto fail;

  rc = chmod(server_addr, 0666);
  if( rc < 0 )
    goto fail;

  return listen(sockets->listen, 32);

fail:
  close(sockets->listen);
  return rc;
}

int ef_shrub_server_epoll_add(struct ef_shrub_server_sockets* sockets,
                              int fd, epoll_data_t data)
{
  int rc;
  struct epoll_event event;

  event.events = EPOLLIN;
  event.data = data;

  rc = epoll_ctl(sockets->epoll, EPOLL_CTL_ADD, fd, &event);
  if( rc < 0 )
    return -errno;

  return 0;
}

int ef_shrub_server_sockets_open(struct ef_shrub_server_sockets* sockets,
                                 const char* server_addr)
{
  int rc;
  epoll_data_t epoll_data;

  rc = unix_server_epoll_create(sockets);
  if( rc < 0 )
    return rc;

  rc = unix_server_listen(sockets, server_addr);
  if( rc < 0 )
    goto fail_server_listen;

  epoll_data.ptr = NULL;
  rc = ef_shrub_server_epoll_add(sockets, sockets->listen, epoll_data);
  if( rc < 0 )
    goto fail_epoll_add;

  return 0;
fail_epoll_add:
  close(sockets->listen);
fail_server_listen:
  close(sockets->epoll);
  return rc;
}

void ef_shrub_server_sockets_close(struct ef_shrub_server_sockets* sockets)
{
  close(sockets->listen);
  close(sockets->epoll);
}

int ef_shrub_server_epoll_wait(struct ef_shrub_server_sockets* sockets,
                               struct epoll_event* event)
{
  return ret(epoll_wait(sockets->epoll, event, 1, 0));
}

int ef_shrub_server_accept(struct ef_shrub_server_sockets* sockets)
{
  return ret(accept(sockets->listen, NULL, NULL));
}

void ef_shrub_server_close_fd(int fd)
{
  close(fd);
}

int ef_shrub_server_recv(int fd, void* data, size_t bytes)
{
  return ret(recv(fd, data, bytes, 0));
}

int ef_shrub_server_send(int fd, void* data, size_t bytes)
{
  return ret(send(fd, data, bytes, 0));
}

int ef_shrub_server_sendmsg(int fd, struct msghdr* msg)
{
  return ret(sendmsg(fd, msg, 0));
}

int ef_shrub_server_remove(const char* path)
{
  return ret(remove(path));
}

int ef_shrub_server_resource_op(int fd, struct ci_resource_op_s* op)
{
  return ci_resource_op(fd, op);
}

int ef_shrub_server_memfd_create(const char* name, size_t size, bool huge)
{
  int fd = memfd_create(name, huge ? MFD_HUGETLB : 0);
  if( fd < 0 )
    return -errno;

  if( size != 0 ) {
    int rc = ret(ftruncate(fd, size));
    if( rc < 0 ) {
      close(fd);
      return rc;
    }
  }

  return fd;
}

int ef_shrub_server_memfd_resize(int fd, size_t size)
{
  return ret(ftruncate(fd, size));
}

int ef_shrub_server_mmap(void** addr_out, size_t size,
                         int prot, int flags, int fd, size_t offset)
{
  void* addr = mmap(NULL, size, prot, flags, fd, offset);
  if( addr == MAP_FAILED)
    return -errno;

  *addr_out = addr;
  return 0;
}

