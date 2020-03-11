/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#undef EFX_USE_IRQ_SET_AFFINITY_HINT
#undef EFX_HAVE_ROUND_JIFFIES_UP
#undef EFX_NEED_PCI_CLEAR_MASTER
#define EFX_NEED_PCI_CLEAR_MASTER
#undef EFX_NEED_GETNSTIMEOFDAY
#define EFX_NEED_GETNSTIMEOFDAY
#undef EFX_NEED_NS_TO_TIMESPEC
#define EFX_NEED_NS_TO_TIMESPEC
#undef EFX_HAVE_XEN_START_INFO
#undef EFX_NEED_SET_NORMALIZED_TIMESPEC
#define EFX_NEED_SET_NORMALIZED_TIMESPEC
