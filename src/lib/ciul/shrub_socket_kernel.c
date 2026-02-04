/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"
#include <etherfabric/internal/shrub_socket.h>

int ef_shrub_socket_open(uintptr_t*) {return -ENOTSUPP;}
int ef_shrub_socket_close_socket(uintptr_t) {return -ENOTSUPP;}
int ef_shrub_socket_close_file(uintptr_t) {return -ENOTSUPP;}
int ef_shrub_socket_connect(uintptr_t, const char*) {return -ENOTSUPP;}
int ef_shrub_socket_send(uintptr_t, void*, size_t) {return -ENOTSUPP;}
int ef_shrub_socket_recv(uintptr_t, void*, size_t) {return -ENOTSUPP;}
int ef_shrub_socket_recv_metrics(struct ef_shrub_shared_metrics*,
                                 uint64_t*, uintptr_t) {return -ENOTSUPP;}
int ef_shrub_socket_mmap(uint64_t*, void*, size_t,
                         uintptr_t, size_t, int) {return -ENOTSUPP;}
int ef_shrub_socket_mmap_user(uint64_t __user*, uint64_t, size_t,
                              uintptr_t, size_t, int) {return -ENOTSUPP;}
void ef_shrub_socket_munmap(uint64_t, size_t, int) {}

