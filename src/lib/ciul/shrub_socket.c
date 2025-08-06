/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"
#include <etherfabric/shrub_client.h>

#include <ci/tools/sysdep.h>
#include <ci/tools/utils.h>

#include <stddef.h>
#include <etherfabric/internal/shrub_socket.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <linux/mman.h>

int ef_shrub_socket_open(uintptr_t* socket_out)
{
  int rc = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if( rc < 0 )
    return -errno;
  
  *socket_out = rc;
  return 0;
}

int ef_shrub_socket_close_socket(uintptr_t socket)
{
  int rc = close(socket);
  if( rc < 0 )
    return -errno;
  return 0;
}

int ef_shrub_socket_close_file(uintptr_t file)
{
  int rc = close(file);
  if( rc < 0 )
    return -errno;
  return 0;
}

int ef_shrub_socket_bind(uintptr_t socket, const char* server_addr)
{
  struct sockaddr_un addr;
  socklen_t addr_len;
  int rc = ci_init_unix_addr(server_addr, &addr, &addr_len);

  if( rc < 0 )
    return rc;

  rc = bind(socket, (struct sockaddr*)&addr, addr_len);
  if( rc < 0 )
    return -errno;

  return 0;
}

int ef_shrub_socket_listen(uintptr_t socket, int backlog)
{
  int rc = listen(socket, backlog);
  if( rc < 0 )
    return -errno;
  return rc;
}

int ef_shrub_socket_accept(uintptr_t listen_socket, uintptr_t* socket_out)
{
  int rc = accept((int) listen_socket, NULL, NULL);
  if( rc < 0 )
    return -errno;
  *socket_out = (uintptr_t) rc;
  return 0;
}

int ef_shrub_socket_connect(uintptr_t socket, const char* server_addr)
{
  struct sockaddr_un addr;
  socklen_t addr_len;
  int rc = ci_init_unix_addr(server_addr, &addr, &addr_len);
  int i;

  if( rc < 0 )
    return rc;

  /* TBD: do we want a non-blocking option (for this and recv)? */
  /* We can tell that the socket has been created, but we can't detect whether
   * it's started listening yet. If we get ECONNREFUSED we try again to give
   * shrub a chance to start listening. */
  for( i = 0; i < 200; i++ ) {
    rc = connect(socket, (struct sockaddr*)&addr, addr_len);
    if( rc == 0 )
      break;
    if( (errno != ECONNREFUSED) && (errno != ENOENT) )
      break;

    usleep(1000 * 10); /* 10ms */
  }

  return rc < 0 ? -errno : rc;
}

int ef_shrub_socket_send(uintptr_t socket, void* data, size_t bytes)
{
  int rc = send(socket, data, bytes, 0);
  if( rc < 0 )
    return rc;
  if( rc != bytes )
    return -EIO;
  return 0;
}

extern ssize_t (*ci_sys_recv)(int s, void*, size_t, int);

int ef_shrub_socket_recv(uintptr_t socket, void* data, size_t bytes)
{
  int rc = ci_sys_recv(socket, data, bytes, 0);
  if( rc < 0 )
    return rc;
  if( rc < bytes )
    return -EPROTO;
  return 0;
}

int ef_shrub_socket_recv_metrics(struct ef_shrub_shared_metrics* metrics,
                                 uintptr_t* shared_files,
                                 uintptr_t socket)
{
  int rc, i;
  struct iovec iov = {
    .iov_base = metrics,
    .iov_len = sizeof(*metrics)
  };
  int shared_fds[EF_SHRUB_FD_COUNT];
  char cmsg_buf[CMSG_SPACE(sizeof(shared_fds))];
  struct msghdr msg = {
    .msg_iov = &iov,
    .msg_iovlen = 1,
    .msg_control = cmsg_buf,
    .msg_controllen = sizeof(cmsg_buf)
  };
  struct cmsghdr* cmsg;

  rc = recvmsg(socket, &msg, 0);
  if( rc < 0 )
    return -errno;
  if( rc != sizeof(*metrics) || metrics->server_version != EF_SHRUB_VERSION )
    return -EPROTO;

  cmsg = CMSG_FIRSTHDR(&msg);
  if( cmsg == NULL ||
      cmsg->cmsg_level != SOL_SOCKET ||
      cmsg->cmsg_type != SCM_RIGHTS ||
      cmsg->cmsg_len != CMSG_LEN(sizeof(shared_fds)) )
    return -EPROTO;

  memcpy(shared_fds, CMSG_DATA(cmsg), sizeof(shared_fds));
  for( i = 0; i < EF_SHRUB_FD_COUNT; ++i )
    shared_files[i] = shared_fds[i];

  return 0;
}

int ef_shrub_socket_mmap(uint64_t* mapping, void* addr, size_t size,
                         uintptr_t file, size_t offset, int type)
{
  int prot, flag;

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

  addr = mmap(addr, size, prot, flag, file, offset);
  if( addr == MAP_FAILED )
    return -errno;

  *mapping = (uint64_t)addr;
  return 0;
}

void ef_shrub_socket_munmap(uint64_t mapping, size_t size, int type)
{
  munmap((void*)mapping, size);
}

int ef_shrub_socket_mmap_user(uint64_t* user_mapping, uint64_t user_addr,
                              size_t size, uintptr_t file, size_t offset,
                              int type)
{
  return -EOPNOTSUPP;
}

