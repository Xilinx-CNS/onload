// SPDX-License-Identifier: Apache-2.0
// X-SPDX-Copyright-Text: (c) Copyright 2022 Xilinx, Inc.

#ifndef INCLUDED_XSMARTNIC_STORAGE_TXPLUGIN_H_
#define INCLUDED_XSMARTNIC_STORAGE_TXPLUGIN_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

static const uint8_t XSN_STORAGE_TXPLUGIN[] = {
  0x44, 0xe5, 0x62, 0xd2, 0xdd, 0xc9, 0x4c, 0xb3,
  0xaf, 0x0b, 0xe4, 0xfd, 0x18, 0x79, 0x19, 0x51};

struct xsn_storage_txplugin {
    union {
        uint32_t debug_id;
        uint32_t debug_data;
    };
};

struct xsn_storage_txplugin_create_app {
  uint16_t vi_id;
} __attribute__((aligned(4)));

#define XSN_STORAGE_TXPLUGIN_READ_DEBUG 0
#define XSN_STORAGE_TXPLUGIN_CREATE_APP 1

#endif
