/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#include <etherfabric/unix_server.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <unistd.h>

static int unix_server_epoll_create(struct unix_server* server)
{
  int rc = epoll_create(1);
  if( rc < 0 )
    return -errno;

  server->epoll = rc;
  return 0;
}

static int unix_server_socket(struct unix_server* server)
{
  int rc = socket(AF_UNIX, SOCK_STREAM, 0);
  if( rc < 0 )
    return -errno;

  server->listen = rc;
  return 0;
}

static int unix_server_listen(struct unix_server* server, const char *server_addr)
{
  int rc;
  struct sockaddr_un addr;
  size_t path_len = strlen(server_addr);

  rc = unix_server_socket(server);
  if( rc < 0 )
    return rc;
  
  if( path_len >= sizeof(addr.sun_path) ) {
    rc = -EINVAL;
    goto fail;
  }

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, server_addr);

  rc = bind(server->listen, (struct sockaddr*)&addr,
            offsetof(struct sockaddr_un, sun_path) + path_len + 1);
  if( rc < 0 )
    goto fail;

  return listen(server->listen, 32);

fail:
  close(server->listen);
  return rc;
}

int unix_server_init(struct unix_server* server, const char* server_addr)
{
  int rc;
  
  rc = unix_server_epoll_create(server);
  if( rc < 0 )
    return rc;

  rc = unix_server_listen(server, server_addr);
  if( rc < 0 )
    goto fail_server_listen;

  rc = unix_server_epoll_add(server, server->listen, NULL);
  if( rc < 0 )
    goto fail_epoll_add;

  return 0;
fail_epoll_add:
  close(server->listen);
fail_server_listen:
  close(server->epoll);
  return rc;
}

void unix_server_fini(struct unix_server* server)
{
  close(server->listen);
  close(server->epoll);
}

int unix_server_poll(struct unix_server* server)
{
  int rc;
  struct epoll_event event;
  rc = epoll_wait(server->epoll, &event, 1, 0);
  if( rc > 0 ) {
    if( event.data.ptr == NULL )
      rc = server->ops.connection_opened(server);

    if( event.events & EPOLLHUP )
      rc = server->ops.connection_closed(server, event.data.ptr);
  }
  return rc;
}

int unix_server_epoll_add(struct unix_server* server, int fd, void* data)
{
  int rc;
  struct epoll_event event;

  event.events = EPOLLIN;
  event.data.ptr = data;

  rc = epoll_ctl(server->epoll, EPOLL_CTL_ADD, fd, &event);
  if( rc < 0 )
    return -errno;

  return 0;
}
