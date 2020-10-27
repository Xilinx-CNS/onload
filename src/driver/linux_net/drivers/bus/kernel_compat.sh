#!/bin/bash -eu
# SPDX-License-Identifier: GPL-2.0
######################################################################
#
# Driver for Solarflare and Xilinx network controllers and boards
# Copyright 2019 Solarflare Communications Inc.
# Copyright 2019-2020 Xilinx Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation, incorporated herein by reference.
#
######################################################################

me=$(basename "$0")

######################################################################
# Symbol definition map

function generate_kompat_symbols() {
    echo "
EFX_HAVE_VIRTUAL_BUS			symbol	virtbus_drv_unregister	include/linux/virtual_bus.h
EFX_HAVE_DEV_PM_DOMAIN_ATTACH		symbol	dev_pm_domain_attach	include/linux/pm_domain.h
EFX_HAVE_OF_IRQ_H			file	include/linux/of_irq.h
EFX_NEED_IDA				nsymbol	ida_simple_get	include/linux/idr.h
" | egrep -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
}

TOPDIR=$(dirname "$0")/../..
source $TOPDIR/scripts/kernel_compat_funcs.sh
