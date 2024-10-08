/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2024 Advanced Micro Devices, Inc. */

#include <etherfabric/vi.h>

#ifndef __KERNEL__

#include "ef_vi_internal.h"
#include "logging.h"
#include <etherfabric/efct_vi.h>
#include <etherfabric/internal/efct_uk_api.h>
#include <ci/efhw/common.h>
#include <ci/tools/byteorder.h>
#include <ci/tools/sysdep.h>
#include <ci/net/ethernet.h>
#include <stdlib.h>
#include <emmintrin.h>

static void ef_vi_compat_init_ef10_ops(ef_vi* vi)
{
  /* All ops not explicitly set above here will remain the same, and any
   * support for them will be identical to the underlying efct support */
}

int ef_vi_compat_init_ef10(ef_vi* vi)
{
  /* We only care about a compat layer with efct */
  if( vi->nic_type.arch != EF_VI_ARCH_EFCT )
    return 0;

  EF_VI_ASSERT(vi->compat_data == NULL);
  vi->compat_data = malloc(sizeof(struct ef_vi_compat_data));
  if( ! vi->compat_data ) {
    ef_log("ERROR: failed to allocate ef10 compat data");
    return -ENOMEM;
  }

  vi->compat_data->underlying_arch = vi->nic_type.arch;
  vi->compat_data->underlying_ops = vi->ops;

  vi->nic_type.arch = EF_VI_ARCH_EF10;

  ef_vi_compat_init_ef10_ops(vi);

  return 0;
}

int ef_vi_compat_init(ef_vi* vi)
{
  const char *s = NULL;

  s = getenv("EF_VI_COMPAT_MODE");
  if( ! s )
    return 0;

  if( strcasecmp(s, "ef10") == 0 )
    return ef_vi_compat_init_ef10(vi);

  ef_log("Unrecognised EF_VI_COMPAT_MODE %s", s);

  return -EINVAL;
}

void ef_vi_compat_free(ef_vi* vi)
{
  if( ! vi->compat_data )
    return;

  switch( vi->nic_type.arch ) {
  default:
    break;
  }

  free(vi->compat_data);
  vi->compat_data = NULL;
}

#else /* ! __KERNEL__ */

/* If we're in the kernel, then it's probably onload doing things, but onload
 * will never use this compat so just do nothing here. */
int ef_vi_compat_init(ef_vi* vi) { return 0; }
void ef_vi_compat_free(ef_vi* vi) {}

#endif /* ! __KERNEL__ */
