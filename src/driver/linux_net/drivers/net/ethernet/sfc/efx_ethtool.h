/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#ifndef EFX_ETHTOOL_H
#define EFX_ETHTOOL_H

int efx_ethtool_get_module_info(struct net_device *net_dev,
				struct ethtool_modinfo *modinfo);
int efx_ethtool_get_module_eeprom(struct net_device *net_dev,
				  struct ethtool_eeprom *ee,
				  u8 *data);

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_ETHTOOL_EEPROM_BY_PAGE)
int efx_ethtool_get_module_eeprom_by_page(struct net_device *dev,
					  const struct ethtool_module_eeprom *page,
					  struct netlink_ext_ack *extack);
#endif

#endif
