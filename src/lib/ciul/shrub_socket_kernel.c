/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include "ef_vi_internal.h"
#include <etherfabric/internal/shrub_socket.h>

int ef_shrub_socket_open(uintptr_t* s) {return -ENOTSUPP;}
int ef_shrub_socket_close_socket(uintptr_t s) {return -ENOTSUPP;}
int ef_shrub_socket_close_file(uintptr_t f) {return -ENOTSUPP;}
int ef_shrub_socket_connect(uintptr_t s, const char* a) {return -ENOTSUPP;}
int ef_shrub_socket_send(uintptr_t s, void* p, size_t n) {return -ENOTSUPP;}
int ef_shrub_socket_recv(uintptr_t s, void* p, size_t n) {return -ENOTSUPP;}
int ef_shrub_socket_recv_metrics(struct ef_shrub_shared_metrics* m,
                                 uint64_t* p, uintptr_t n) {return -ENOTSUPP;}
int ef_shrub_socket_mmap(uint64_t* m, void* a, size_t s,
                         uintptr_t f, size_t o, int t) {return -ENOTSUPP;}
void ef_shrub_socket_munmap(uint64_t m, size_t n, int t) {}

