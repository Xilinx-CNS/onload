/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *
 * This file provides internal API for license validation.
 *
 * Copyright 2013:      Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#include <ci/efrm/private.h>
#include <ci/efrm/resource.h>
#include "efrm_internal.h"
#include <ci/efrm/licensing.h>
#include <ci/efrm/debug_linux.h>
#include <ci/driver/efab/hardware.h>

int efrm_license_challenge(struct efrm_resource *rs, 
                           struct efrm_license_challenge_s *s) {
  struct efrm_nic* rm_nic;

  EFRM_ASSERT(rs);
  EFRM_ASSERT(s);
  /* Top bit of challenge data must be clear. */
  EFRM_ASSERT((s->challenge[0] & 0x80) == 0);

  rm_nic = efrm_nic_from_rs(rs);
  EFRM_ASSERT(rm_nic);

  if(rm_nic->efhw_nic.devtype.arch != EFHW_ARCH_EF10)
    return -EOPNOTSUPP;

  return efhw_nic_license_challenge(&rm_nic->efhw_nic, s->feature, s->challenge,
                                    &s->expiry, s->signature);
}

EXPORT_SYMBOL(efrm_license_challenge);

int efrm_v3_license_challenge(struct efrm_resource *rs,
                              struct efrm_v3_license_challenge_s *s) {
  struct efrm_nic* rm_nic;

  EFRM_ASSERT(rs);
  EFRM_ASSERT(s);

  rm_nic = efrm_nic_from_rs(rs);
  EFRM_ASSERT(rm_nic);

  return efhw_nic_v3_license_challenge(&rm_nic->efhw_nic, s->app_id,
                                       s->challenge, &s->expiry, &s->days,
                                       s->signature, s->base_macaddr,
                                       s->vadaptor_macaddr);
}

EXPORT_SYMBOL(efrm_v3_license_challenge);

