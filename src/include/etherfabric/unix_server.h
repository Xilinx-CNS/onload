/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#ifndef __UNIX_SERVER_H__
#define __UNIX_SERVER_H__

struct unix_server;

struct ef_unix_server_ops {
  int (*connection_opened)(struct unix_server *);
  int (*connection_closed)(struct unix_server *, void *epoll_data);
};

struct unix_server {
  int listen;
  int epoll;
  struct ef_unix_server_ops ops;
};

/* Initialise unix server an bind to address @server_addr. */
int unix_server_init(struct unix_server* server, const char* server_addr);

/* Free server resources. */
void unix_server_fini(struct unix_server* server);

/* Poll unix server running connection_opened on client connect and
 * connection_closed on disconnect if client was added to epoll set through
 * unix_server_epoll_add. */
int unix_server_poll(struct unix_server* server);

/* Add fd to unix_server epoll set. */
int unix_server_epoll_add(struct unix_server* server, int fd, void* data);

#endif /* __UNIX_SERVER_H__ */
