/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Socket management for shrub server */
#include <sys/epoll.h>
struct msghdr;
struct ci_resource_op_s;

struct ef_shrub_server_sockets {
  int listen;
  int epoll;
};

int ef_shrub_server_sockets_open(struct ef_shrub_server_sockets* sockets,
                                 const char* server_addr);
void ef_shrub_server_sockets_close(struct ef_shrub_server_sockets* sockets);
int ef_shrub_server_epoll_add(struct ef_shrub_server_sockets* sockets,
                              int fd, epoll_data_t data);
int ef_shrub_server_epoll_mod(struct ef_shrub_server_sockets* sockets,
                              int fd, epoll_data_t data);
int ef_shrub_server_epoll_wait(struct ef_shrub_server_sockets* sockets,
                               struct epoll_event* event);
int ef_shrub_server_accept(struct ef_shrub_server_sockets* sockets);

void ef_shrub_server_close_socket(int fd);
int ef_shrub_server_recv(int fd, void* data, size_t bytes);
int ef_shrub_server_send(int fd, void* data, size_t bytes);
int ef_shrub_server_sendmsg(int fd, struct msghdr* msg);
int ef_shrub_server_remove(const char* path);

int ef_shrub_server_resource_op(int fd, struct ci_resource_op_s* op);

