# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) 2005-2019 Solarflare Communications Inc

ifeq ($(DRIVER),1)
  ifeq ($(MMAKE_LIBERAL),1)
    NOWERROR := 1
  endif

  ifndef MMAKEBUILDTREE
  include $(TOPPATH)/$(CURRENT)/Makefile
  endif

  ../../../linux/virtual_bus.ko: modules
	cp -f virtual_bus.ko $@

  all: ../../../linux/virtual_bus.ko
endif
