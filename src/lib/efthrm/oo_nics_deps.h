/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */
#ifndef __OO_NICS_DEPS_H__
#define __OO_NICS_DEPS_H__

/* All header dependencies of oo_nics.c are included via this private header,
 * so that the unit test can replace them with stubs by supplying its own
 * copy of this file (see src/tests/onload/oo_nics/). */

#include <ci/internal/transport_config_opt.h>
#include <onload_kernel_compat.h>
#include <onload/linux_onload_internal.h>
#include <ci/driver/kernel_compat.h>
#include <ci/efhw/common.h>
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/nic_set.h>
#include <onload/nic.h>
#include <onload/tcp_helper.h>
#include <cplane/mib.h>
#include <cplane/cplane.h>

#endif /* __OO_NICS_DEPS_H__ */
