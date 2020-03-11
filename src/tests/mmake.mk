# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
ifeq ($(GNU),1)
SUBDIRS		:=     driver \
                   ef_vi \
                   onload \
                   orm_test_client \
		   rtt \
                   syscalls \
                   tap \
		   trade_sim \

OTHER_SUBDIRS	:=

ifeq ($(ONLOAD_ONLY),1)
SUBDIRS		:= ef_vi \
                   onload \
                   rtt \
                   trade_sim
endif

endif

DRIVER_SUBDIRS	:=

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

