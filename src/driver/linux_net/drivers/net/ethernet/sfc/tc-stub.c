/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "tc.h"

/* These stub functions are used to allow the efx driver to link despite common
 * code that conditionally calls the corresponding functions in tc.c.
 */
int efx_init_struct_tc(struct efx_nic *efx)
{
       return 0;
}

void efx_fini_struct_tc(struct efx_nic *efx)
{
}
