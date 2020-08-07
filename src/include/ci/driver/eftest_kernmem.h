/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2019 Xilinx, Inc. */
/****************************************************************************
 * Eftest support code for handling kernel memory: definitions
 *
 * Copyright 2007:      Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 *
 ****************************************************************************
 */
#ifndef EFTEST_KERNMEM_H
#define EFTEST_KERNMEM_H

#include <asm/ioctl.h>

#define KMCLEAN_ALL ((unsigned)-1)

struct eftest_kmem_req {
  struct {
    struct {
      int pci_domain;
      int pci_bus;
      int pci_dev;
      int pci_func;
    } a;
    unsigned chunk_size;
    unsigned n_chunks;
    unsigned token;
  } in;
  struct {
    unsigned handle;    /* Handle for mmap use. */
  } out;
};

struct eftest_kmclean_req {
  struct {
    unsigned handle;    /* Handle, or -1 for all */
    struct {
      int pci_domain;
      int pci_bus;
      int pci_dev;
      int pci_func;
    } a;                /* PCI address, or -1 for all */
  } in;
  struct {
    int count;          /* Number cleaned up */
  } out;
};

/** Debug ioctls **/

struct eftest_kmcount_req {
  int count_out;
};

struct eftest_kmretrieve_req {
  int count_in_out; /* IN: expected OUT: actual */
  struct eftest_kmem_req reqs_out[0];
} __attribute__((packed));

#define EFTEST_KM_IOC_MAGIC     ('k')

/** Request an allocation */
#define EF_TEST_KM_ALLOC        (1)
#define EF_TEST_KM_CLEAN        (2)
#define EF_TEST_KM_COUNT        (3)
#define EF_TEST_KM_RETRIEVE     (4)

#define EFTEST_KMALLOC_IOC \
    _IOWR(EFTEST_KM_IOC_MAGIC, EF_TEST_KM_ALLOC, struct eftest_kmem_req)

#define EFTEST_KMCLEAN_IOC  \
    _IOWR(EFTEST_KM_IOC_MAGIC, EF_TEST_KM_CLEAN, struct eftest_kmclean_req)

#define EFTEST_KMCOUNT_IOC  \
    _IOWR(EFTEST_KM_IOC_MAGIC, EF_TEST_KM_COUNT, struct eftest_kmcount_req)

#define EFTEST_KMRETRIEVE_IOC  \
    _IOWR(EFTEST_KM_IOC_MAGIC, EF_TEST_KM_RETRIEVE, struct eftest_kmretrieve_req)

#endif
