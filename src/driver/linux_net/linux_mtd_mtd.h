/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2012 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

/* Prior to Linux 3.2, <linux/mtd/mtd.h> would define a DEBUG
 * function-like macro, which we really don't want.  Save and
 * restore the defined-ness of DEBUG across this #include.
 */

#ifdef DEBUG
#define EFX_MTD_DEBUG
#undef DEBUG
#endif
#include <linux/mtd/mtd.h>
#undef DEBUG
#ifdef EFX_MTD_DEBUG
#define DEBUG
#endif
