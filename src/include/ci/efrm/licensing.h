/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * This file provides internal API for license challenge.
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

#ifndef __EFRM_LICENSING_H__
#define __EFRM_LICENSING_H__

/* **********************************************
** Warning: these values are well-known.
*/

#define EFRM_LICENSE_CHALLENGE_CHALLENGE_LEN (64)
#define EFRM_LICENSE_CHALLENGE_SIGNATURE_LEN (64)

#define EFRM_V3_LICENSE_CHALLENGE_CHALLENGE_LEN (48)
#define EFRM_V3_LICENSE_CHALLENGE_SIGNATURE_LEN (96)
#define EFRM_V3_LICENSE_CHALLENGE_MACADDR_LEN (6)

/* The validation message consists of the license challenge, the app ID,
 * the MAC address: base one and current, and the expiry time and units. */
#define EFRM_V3_LICENSE_VALIDATION_MSG_LEN   \
  (EFRM_V3_LICENSE_CHALLENGE_CHALLENGE_LEN + \
   sizeof(uint64_t) +                        \
   EFRM_V3_LICENSE_CHALLENGE_MACADDR_LEN +   \
   EFRM_V3_LICENSE_CHALLENGE_MACADDR_LEN +   \
   sizeof(uint32_t) +                        \
   sizeof(uint32_t))

/* ********************************************** */

/* struct passed into efrm_license_challenge(). */
struct efrm_license_challenge_s {
  /* IN: Single feature to challenge. Select a well known feature id. */
  uint32_t  feature;

  /* OUT: U32 repr of standard Linux time. */
  uint32_t  expiry;

  /* IN: challenge data */
  uint8_t challenge[EFRM_LICENSE_CHALLENGE_CHALLENGE_LEN];

  /* OUT: signature (on success). */
  uint8_t signature[EFRM_LICENSE_CHALLENGE_SIGNATURE_LEN];
};

/* struct passed into efrm_v3_license_challenge(). */
struct efrm_v3_license_challenge_s {
  /* IN: app ID to challenge. */
  uint64_t  app_id;

  /* OUT: U32 time representation in days or accounting units */
  uint32_t  expiry;

  /* OUT: Expiry time unit flag */
  uint32_t  days;

  /* IN: challenge data */
  uint8_t challenge[EFRM_V3_LICENSE_CHALLENGE_CHALLENGE_LEN];

  /* OUT: signature (on success). */
  uint8_t signature[EFRM_V3_LICENSE_CHALLENGE_SIGNATURE_LEN];

  /* OUT: base adress of the NIC */
  uint8_t base_macaddr[EFRM_V3_LICENSE_CHALLENGE_MACADDR_LEN];

  /* OUT: current address of the vadapter */
  uint8_t vadaptor_macaddr[EFRM_V3_LICENSE_CHALLENGE_MACADDR_LEN];
};


struct efrm_resource;

/* (licensing.c)
 * Check if the given feature is licensed in the NIC and respond to the
 * challenge. */
extern int efrm_license_challenge(struct efrm_resource *rs, 
                                  struct efrm_license_challenge_s *s);

/* (licensing.c)
 * Check if the given feature is licensed in the NIC and respond to the
 * challenge. */
extern int efrm_v3_license_challenge(struct efrm_resource *rs,
                                  struct efrm_v3_license_challenge_s *s);


#endif /* __EFRM_LICENSING_H__ */

