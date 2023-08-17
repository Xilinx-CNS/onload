# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2019-2023 Xilinx, Inc.

BUILD_PROFILE ?= extra
export TRANSPORT_CONFIG_OPT_HDR ?= ci/internal/transport_config_opt_$(BUILD_PROFILE).h
BUILD_ROOT ?= $(abspath build)

all: kernel

define helptext
Build Onload. Summary of the most commonly-used build options:

Targets:
  all     Will build userspace and driver. Currently driver only
  kernel  Build driver only
  clean   Delete build tree

Options:
  V=1               Print full build command lines
  NDEBUG=1          Create optimized build
  MMAKE_LIBERAL=1   Turn off -Werror
  HAVE_SFC=0        Build without netdriver and driverlink support to work in
                    AF_XDP mode only
  HAVE_EFCT=0       Build without EFCT support.
  HAVE_EF10CT=0     Build without EF10CT support.
  BUILD_PROFILE=x   Onload configuration, e.g. "cloud" (default: extra)
  KBUILDTOP=<path>  Where to put driver build (default: build/$$KARCH_linux-$$KVER)
  KPATH=<path>      Kernel to build for (default: /lib/modules/`uname -r`/build)
  BUILD_EFCT_TEST=1 Build the efct test driver
endef
help:
	$(info $(helptext))
	@true

clean: clean_kernel

.PHONY: all clean help

ifneq ($(MMAKETOOL_ADD_DEBUG),)
 ifeq ($(NDEBUG),)
  BUILDTOP_EXTRA_SUFFIX := _debug
 endif
endif
ifneq ($(MMAKETOOL_ADD_HOST),)
  BUILDTOP_EXTRA_PREFIX := $(shell uname -n)_
endif

##############################################################################
################################ Kernel build ################################
##############################################################################

DRIVER_SUBDIRS := src/driver/linux_char src/driver/linux_onload \
                  src/driver/linux_resource src/lib/citools src/lib/ciul \
                  src/lib/cplane src/lib/transport/ip

ifeq ($(KPATH),)
  ifeq ($(KVER),)
  KVER := $(shell uname -r)
  endif
  ifeq ($(KARCH),)
  KARCH := $(shell uname -m)
  endif
  KPATH := /lib/modules/$(KVER)/build
else
 KVERARCH := $(subst $\",,$(shell echo 'UTS_RELEASE UTS_MACHINE'|gcc -E -P -include $(KPATH)/include/generated/utsrelease.h -include $(KPATH)/include/generated/compile.h -))
 ifeq ($(KVERARCH),)
   $(error Cannot extract kernel info from KPATH "$(KPATH)" - not a built tree?)
 endif
 KVER ?= $(firstword $(KVERARCH))
 KARCH ?= $(lastword $(KVERARCH))
endif

export HAVE_EFCT ?=
export HAVE_EF10CT ?= 1

# There are three options here: native kernel aux bus support, support
# through the out of tree cns aux bus repo for older kernels, or no aux
# bus support at all, in that order of preference.
#
ifneq ($(wildcard $(dir $(KPATH))/*/include/linux/auxiliary_bus.h),)
export HAVE_KERNEL_AUX := 1
export HAVE_CNS_AUX := 0
else
export AUX_BUS_PATH ?= $(abspath ../cns-auxiliary-bus)
export HAVE_CNS_AUX := $(or $(and $(wildcard $(AUX_BUS_PATH)),1),0)
endif

export CI_HAVE_AUX_BUS := $(or $(filter 1, $(HAVE_CNS_AUX) $(HAVE_KERNEL_AUX)),0)

ifneq ($(HAVE_CNS_AUX),0)
KBUILD_EXTRA_SYMBOLS := $(AUX_BUS_PATH)/drivers/base/Module.symvers
export KBUILD_EXTRA_SYMBOLS := $(AUX_BUS_PATH)/drivers/base/Module.symvers
else
ifneq (,$(wildcard /lib/modules/$(KVER)/updates/auxiliary.symvers))
export KBUILD_EXTRA_SYMBOLS := /lib/modules/$(KVER)/updates/auxiliary.symvers
endif
endif

export HAVE_SFC ?= 1
ifeq ($(HAVE_SFC),1)
DRIVER_SUBDIRS += src/driver/linux_net/drivers/net/ethernet/sfc
endif

ifeq ($(BUILD_EFCT_TEST),1)
DRIVER_SUBDIRS += src/tests/resource/efct_test
endif

# Linux 4.6 added some object-file validation, which was also merged into
# RHEL 7.3.  Unfortunately, it assumes that all functions that don't end with
# a return or a jump are recorded in a hard-coded table inside objtool.  That
# is not of much use to an out-of-tree driver, and we have far too many such
# functions to rewrite them, so we turn off the checks.
export OBJECT_FILES_NON_STANDARD := y

ifneq ($(KERNELRELEASE),)
################## Stuff run within kbuild

obj-m := $(addsuffix /,$(DRIVER_SUBDIRS))

AUTOCOMPAT := $(obj)/src/driver/linux_resource/autocompat.h
LINUX_RESOURCE := $(src)/src/driver/linux_resource
$(AUTOCOMPAT): $(LINUX_RESOURCE)/kernel_compat.sh $(LINUX_RESOURCE)/kernel_compat_funcs.sh
	@mkdir -p $(@D)
	($< -k $(CURDIR) $(if $(filter 1,$(V)),-v,-q) > $@) || (rm -f $@ && false)

mkdirs:
	@mkdir -p $(obj)/src/lib/efhw
	@mkdir -p $(obj)/src/lib/efhw/ef10ct
	@mkdir -p $(obj)/src/lib/efrm
	@mkdir -p $(obj)/src/lib/efthrm
	@mkdir -p $(obj)/src/lib/kernel_utils

# Define the high-level dependencies between libraries:
$(obj)/src/driver/linux_resource: $(AUTOCOMPAT) mkdirs
$(obj)/src/lib/transport/ip: $(AUTOCOMPAT)
$(obj)/src/lib/ciul: $(AUTOCOMPAT)
$(obj)/src/lib/citools: $(AUTOCOMPAT)
$(obj)/src/lib/cplane: $(AUTOCOMPAT) $(obj)/src/lib/ciul
$(obj)/src/lib/kernel_utils: $(AUTOCOMPAT)
$(obj)/src/tests/resource/efct_test: $(AUTOCOMPAT)
$(obj)/src/driver/linux_char: $(AUTOCOMPAT)
$(obj)/src/driver/linux_char: $(obj)/src/lib/citools $(obj)/src/lib/ciul
$(obj)/src/driver/linux_onload: $(obj)/src/lib/citools $(obj)/src/lib/ciul \
                                $(obj)/src/lib/transport/ip \
                                $(obj)/src/lib/cplane mkdirs

else
################## Top-level makefile

ifeq ($(V),1)
Q :=
else
Q := @
endif

KBUILDTOP := $(BUILD_ROOT)/$(BUILDTOP_EXTRA_PREFIX)$(KARCH)_linux-$(KVER)$(BUILDTOP_EXTRA_SUFFIX)
override KBUILDTOP := $(abspath $(KBUILDTOP))
OUTMAKEFILES := $(foreach D,$(DRIVER_SUBDIRS), \
                  $(if $(wildcard $(D)/Kbuild),$(KBUILDTOP)/$(D)/Kbuild, \
                                               $(KBUILDTOP)/$(D)/Makefile)) \
                $(KBUILDTOP)/Makefile

# extract from the net driver's makefile the set of CONFIG_ opts it needs:
define _LF :=


endef
define _GET_NET_CONFIG_OPTS :=
print_vars:\n
	@echo $$(foreach V,$$(filter CONFIG_%,$$(.VARIABLES)),$$(V):=$$($$(V)))\n
include Makefile
endef
$(eval $(patsubst CONFIG_%,export CONFIG_%$(_LF), \
       $(shell echo -e '$(_GET_NET_CONFIG_OPTS)' | \
               MFLAGS= MAKEFLAGS= make -C src/driver/linux_net/drivers/net/ethernet/sfc -r --no-print-directory -f - print_vars)))

# CFLAGS
ONLOAD_CFLAGS += -I$$(obj) -I$$(obj)/src -I$$(src) -I$$(src)/src -I$$(src)/src/include \
                 -D__ci_driver__ "-DTRANSPORT_CONFIG_OPT_HDR=<$(TRANSPORT_CONFIG_OPT_HDR)>"
ONLOAD_CFLAGS += -DCI_HAVE_AUX_BUS=$(CI_HAVE_AUX_BUS)

ifneq ($(NDEBUG),)
ONLOAD_CFLAGS += -DNDEBUG
else
ONLOAD_CFLAGS += -g
endif
ifneq ($(HAVE_CNS_AUX),0)
ONLOAD_CFLAGS += -I$(AUX_BUS_PATH)/include
endif

ifeq ($(HAVE_EFCT),0)
else ifeq ($(CI_HAVE_AUX_BUS),0)
else ifneq ($(wildcard $(dir $(KPATH))/*/include/linux/net/xilinx/xlnx_efct.h),)
HAVE_KERNEL_EFCT := 1
else
X3_NET_PATH ?= $(abspath ../x3-net-linux)
HAVE_CNS_EFCT := $(or $(and $(wildcard $(X3_NET_PATH)/include/linux/net/xilinx/xlnx_efct.h),1),0)
endif

ifeq ($(or $(filter 1, $(HAVE_KERNEL_EFCT) $(HAVE_CNS_EFCT)),0),1)
  ONLOAD_CFLAGS += -DCI_HAVE_EFCT_AUX=1
  ifneq ($(HAVE_CNS_EFCT),0)
    ONLOAD_CFLAGS += -I$(X3_NET_PATH)/include
  endif
else
  ifneq ($(HAVE_EFCT),1)
    ONLOAD_CFLAGS += -DCI_HAVE_EFCT_AUX=0
  else
    $(error Unable to build Onload with EFCT or AUX bus support)
  endif
endif


ifeq ($(HAVE_EF10CT),0)
  ONLOAD_CFLAGS += -DCI_HAVE_EF10CT=0
else ifeq ($(CI_HAVE_AUX_BUS),0)
  ONLOAD_CFLAGS += -DCI_HAVE_EF10CT=0
else
  ONLOAD_CFLAGS += -DCI_HAVE_EF10CT=1
endif

ifneq ($(MMAKE_LIBERAL),1)
ONLOAD_CFLAGS += -Werror
endif

ONLOAD_MAKEFLAGS ?=

ifeq ($(HAVE_SFC),1)
  ONLOAD_CFLAGS += -DCI_HAVE_SFC=1
  # This code base does not support Solarflare Siena.
  ONLOAD_MAKEFLAGS += CONFIG_SFC_SIENA=
else
  ONLOAD_CFLAGS += -DCI_HAVE_SFC=0
endif


.PHONY: modules modules_install clean_kernel kernel

kernel: modules
	@mkdir -p $(KBUILDTOP)/driver/linux
	$(Q)ln -rsf $(wildcard $(patsubst %,$(KBUILDTOP)/%/*.ko,$(DRIVER_SUBDIRS))) $(KBUILDTOP)/driver/linux
	$(Q)cp src/driver/linux/*.sh $(KBUILDTOP)/driver/linux

modules modules_install: $(OUTMAKEFILES)
	$(Q)$(MAKE) -C $(KPATH) M=$(KBUILDTOP) \
		"src=\$$(patsubst $(KBUILDTOP)%,$$PWD%,\$$(obj))" \
		"SRCPATH=$$PWD/src" \
		'subdir-ccflags-y=$(subst ','\'',$(ONLOAD_CFLAGS))' \
		MMAKE_IN_KBUILD=1 MMAKE_USE_KBUILD=1 MMAKE_NO_RULES=1 \
		DRIVER=1 LINUX=1 $(patsubst modules,,$@) \
		$(ONLOAD_MAKEFLAGS)

kernel: modules

clean_kernel:
	$(RM) -r $(KBUILDTOP)/src
	$(RM) -r $(KBUILDTOP)/driver
	$(RM) -r $(KBUILDTOP)/built-in.a
	$(RM) -r $(KBUILDTOP)/modules.order
	$(RM) -r $(KBUILDTOP)/Module.symvers

# Can't figure out a way to get modpost to look in the src directory. At least
# the number of makefiles is much smaller than the number of source files
$(OUTMAKEFILES): $(KBUILDTOP)/%: %
	$(Q)mkdir -p $(@D)
	$(Q)ln -sf `realpath '--relative-to=$(@D)' '$<'` $@

endif  # ifeq ($(KERNELRELEASE),)
