/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */

/* Socket management (and other system resources) for shrub server */

#ifndef __CI_CIUL_SHRUB_SERVER_SOCKETS_H__
#define __CI_CIUL_SHRUB_SERVER_SOCKETS_H__

#include <stdint.h>
#include <sys/epoll.h>
#include <sys/mman.h>
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
int ef_shrub_server_epoll_wait(struct ef_shrub_server_sockets* sockets,
                               struct epoll_event* event);
int ef_shrub_server_accept(struct ef_shrub_server_sockets* sockets);

void ef_shrub_server_close_fd(int fd);
int ef_shrub_server_recv(int fd, void* data, size_t bytes);
int ef_shrub_server_send(int fd, void* data, size_t bytes);
int ef_shrub_server_sendmsg(int fd, struct msghdr* msg);

int ef_shrub_server_remove(const char* path);

int ef_shrub_server_resource_op(int fd, struct ci_resource_op_s* op);

int ef_shrub_server_memfd_create(const char* name, size_t size, bool huge);
int ef_shrub_server_memfd_resize(int fd, size_t size);
int ef_shrub_server_mmap(void** addr_out, size_t size,
                         int prot, int flags, int fd, size_t offset);


#endif

