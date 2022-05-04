# SPDX-License-Identifier: GPL-2.0
################################################################################
#
# Driver for Solarflare and Xilinx network controllers and boards
# Copyright 2019 Solarflare Communications Inc.
# Copyright 2019-2020 Xilinx Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation, incorporated herein by reference.
#
################################################################################

ifndef KERNELRELEASE
ifndef EFX_UPSTREAM
# Compat: KDIR used to be called KPATH
ifdef KPATH
  KDIR ?= $(KPATH)
endif
endif
KDIR ?= /lib/modules/$(shell uname -r)/build

export-srpm export: $(KDIR)/include/linux/net/sfc/sfc_rdma.h

$(KDIR)/include/linux/net/sfc/sfc_rdma.h: net/sfc/sfc_rdma.h
	@mkdir -p $(@D)
	cp $^ $@
endif
