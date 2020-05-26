##############################################################################
#
# Support for building the net driver TSO unit test as part of the L5 build system.
# See the Makefile for building it standalone.
#

# The Kbuild link should override the mmake-generated Makefile, but
# Linux <2.6.10 does not look for that.  Do nothing if included by
# Kbuild.
ifndef MMAKE_IN_KBUILD

CONFIG_FILES := tso_config.h
MMAKE_GEN_SRCS :=

ifdef DRIVER

export CONFIG_SFC := m
export CONFIG_SFC_DEBUGFS := y
export CONFIG_SFC_DUMP := y
export CONFIG_SFC_MCDI_MON := y
export CONFIG_SFC_MTD := y
export CONFIG_SFC_SRIOV := y
export CONFIG_SFC_PTP := y
export CONFIG_SFC_AOE := y
export CONFIG_SFC_PPS := y

TARGETS := tso_test_mod.o

ifdef NOWERROR
EXTRA_MAKEFLAGS += NOWERROR=1
endif
ifdef MMAKE_LIBERAL
EXTRA_MAKEFLAGS += NOWERROR=1
endif

ifdef EFX_NOT_EXPORTED
EXTRA_MAKEFLAGS += EFX_NOT_EXPORTED=1
endif

SFC_MODULES := $(subst .o,.ko, $(TARGETS))

ifneq ($(CC),)
EXTRA_MAKEFLAGS += CC=$(CC)
endif

test_o = tso_test.o
all_tests = tso_test

all : $(all_tests:=-test)

unexport NDEBUG

kbuild :
	@if ! [ -h $(CURDIR)/Kbuild ]; then                             \
		echo "  UPD     Kbuild";                                \
		ln -sf $(SRCPATH)/driver/linux_net/unittest/Makefile $(CURDIR)/Kbuild; \
	fi
	$(MMAKE_KBUILD_PRE_COMMAND)
	$(MAKE) $(EXTRA_MAKEFLAGS) $(MMAKE_KBUILD_ARGS) M=$(CURDIR) NDEBUG=$(NDEBUG) MMAKE_IN_KBUILD=1
	$(MMAKE_KBUILD_POST_COMMAND)

clean:
	@$(MakeClean)
	rm -rf *.o *.s *.ko *.mod.c *.symvers .tmp_versions .*.cmd $(CONFIG_FILES) $(all_tests)

tso_test_mod.o : kbuild

# Normal .c to .o rule
$(test_o) : %.o : %.c tso_shared.h
	@echo [normal CC] $@
	@$(CC) -Wall -g -c -o $@ $<

# Get kernel version and source directory.  If neither is specified then we
# assume the current kernel version.
ifdef KPATH
ifndef KVER
KVER := $(shell sed -r 's/^\#define UTS_RELEASE "(.*)"/\1/; t; d' $(KPATH)/include/generated/utsrelease.h $(KPATH)/include/linux/utsrelease.h $(KPATH)/include/linux/version.h 2>/dev/null)
ifeq ($(KVER),)
$(error Failed to find kernel version for $(KPATH))
endif
endif
else
ifndef KVER
KVER := $(shell uname -r)
endif
KPATH := /lib/modules/$(KVER)/build
endif # KPATH

KVERBASE := $(word 1,$(subst -, ,$(KVER)))

# if compiling against 2.6.32 then build properly, otherwise build dummy.
ifeq ($(KVERBASE),2.6.32)
# Normal final link rule
tso_test : tso_test.o tso_test_mod.o
	@set -e; if [ "`file -b tso_test.o`" == "`file -b tso_test_mod.o`" ]; then      \
		echo [normal LD] $@;    \
		$(CC) -o $@ $^;         \
	else                            \
		echo [normal CC];       \
		$(CC) -o $@ dummy.c -DMSG="user and kernel binaries are incompatible";  \
	fi
else
# Dummy rule if kernel version not supported by this test.
tso_test : dummy.c
	@echo [normal CC] $@
	@$(CC) -o $@ $^ -DMSG="kernel $(KVER) not supported"
endif

tso_test-test : tso_test
	@set -e; for nic in 3 4; do echo $< $$nic; ./$< $$nic; done

.PHONY : all clean $(all_tests:=-test)

endif # DRIVER

endif # !MMAKE_IN_KBUILD
