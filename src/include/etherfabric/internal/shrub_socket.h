/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

struct ef_shrub_shared_metrics;

int ef_shrub_socket_open(uintptr_t* socket_out);
int ef_shrub_socket_close_socket(uintptr_t socket);
int ef_shrub_socket_close_file(uintptr_t file);
int ef_shrub_socket_bind(uintptr_t socket, const char* server_addr);
int ef_shrub_socket_listen(uintptr_t socket, int backlog);
int ef_shrub_socket_accept(uintptr_t listen_socket, uintptr_t* socket_out);
int ef_shrub_socket_connect(uintptr_t socket, const char* server_addr);
int ef_shrub_socket_send(uintptr_t socket, void* data, size_t bytes);
int ef_shrub_socket_recv(uintptr_t socket, void* data, size_t bytes);
int ef_shrub_socket_recv_metrics(struct ef_shrub_shared_metrics* metrics_out,
                                 uintptr_t* shared_files_out,
                                 uintptr_t socket);
int ef_shrub_socket_mmap(uint64_t* mapping, void* addr, size_t size,
                         uintptr_t file, size_t offset, int type);
int ef_shrub_socket_mmap_user(uint64_t* user_mapping, uint64_t user_addr,
                              size_t size, uintptr_t file, size_t offset,
                              int type);
void ef_shrub_socket_munmap(uint64_t mapping, size_t size, int type);
