# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) 2005-2019 Solarflare Communications Inc

SUBDIRS := util

ifeq ($(DRIVER),1)
  ifeq ($(MMAKE_LIBERAL),1)
    NOWERROR := 1
  endif

  OBJECT_FILES_NON_STANDARD := n

  ifndef MMAKEBUILDTREE
  include $(TOPPATH)/$(CURRENT)/Makefile
  endif

  ../../../../../linux/sfc.ko: modules
	cp -f sfc.ko $@

  ../../../../../linux/sfc_driverlink.ko: modules
	cp -f sfc_driverlink.ko $@

  all: ../../../../../linux/sfc.ko ../../../../../linux/sfc_driverlink.ko
endif
