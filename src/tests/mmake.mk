# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc.
ifeq ($(GNU),1)
SUBDIRS		:=     driver \
                   ef_vi \
                   onload \
                   orm_test_client \
                   syscalls \
                   tap \
		   trade_sim \
		   compat \

OTHER_SUBDIRS	:=

ifeq ($(ONLOAD_ONLY),1)
SUBDIRS		:= ef_vi \
                   onload \
                   trade_sim \

endif

# Do not attempt to build unit tests with NDEBUG. This adds visibility
# attributes to symbols in the library objects, making it an error for those
# symbols not to be present when linking.
#
# TODO it would be nice to be able to run the unit tests on all builds.
# Perhaps something could be done to resolve the link error, such as removing
# the attributes from the object files before linking.
ifndef NDEBUG
  SUBDIRS += unit
endif

endif

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

