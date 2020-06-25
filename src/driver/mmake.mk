# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
# For linux_net/util
ifeq ($(LINUX),1)
SUBDIRS         += linux_net
endif

MMAKE_NO_DEPS	:= 1

ifeq ($(LINUX),1)

# DRIVER_SUBDIRS must be ordered according to inter-driver dependencies
DRIVER_SUBDIRS	:= linux_net linux_affinity linux_resource \
		linux_char linux_onload linux

endif # ifeq ($(LINUX),1)

all: passthruparams := "CI_FROM_DRIVER=1"
all:
	+@(target=all ; $(MakeSubdirs))

clean:
	@$(MakeClean)

