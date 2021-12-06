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
  V=1              Print full build command lines
  NDEBUG=1         Create optimized build
  MMAKE_LIBERAL=1  Turn off -Werror
  BUILD_PROFILE=x  Onload configuration, e.g. "cloud" (default: extra)
  KBUILDTOP=<path> Where to put driver build (default: build/$$KARCH_linux-$$KVER)
  KPATH=<path>     Kernel to build for (default: /lib/modules/`uname -r`/build)
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
                  src/lib/cplane src/lib/transport/ip \
                  src/driver/linux_net/drivers/bus \
                  src/driver/linux_net/drivers/net/ethernet/sfc
export AUX_BUS_PATH ?= $(abspath ../cns-auxiliary-bus)
export HAVE_CNS_AUX := $(or $(and $(wildcard $(AUX_BUS_PATH)),1),0)
export X3_NET_PATH ?= $(abspath ../x3-net-linux)
export HAVE_X3_NET := $(or $(and $(wildcard $(X3_NET_PATH)),1),0)

ifeq ($(HAVE_X3_NET),1)
DRIVER_SUBDIRS += src/tests/resource/efct_test
endif

ifneq ($(HAVE_CNS_AUX),0)
KBUILD_EXTRA_SYMBOLS := $(AUX_BUS_PATH)/drivers/base/Module.symvers
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
# It's not at all clear why "unset CC" is necessary in the recipe below to
# make Debian 10 (4.19) work. Perhaps a bug in kbuild? - it's set to " gcc-8"
$(AUTOCOMPAT): $(LINUX_RESOURCE)/kernel_compat.sh $(LINUX_RESOURCE)/kernel_compat_funcs.sh
	@mkdir -p $(@D)
	(unset CC; $< -k $(CURDIR) $(if $(filter 1,$(V)),-v,-q) > $@) || (rm -f $@ && false)

mkdirs:
	@mkdir -p $(obj)/src/lib/efhw
	@mkdir -p $(obj)/src/lib/efrm
	@mkdir -p $(obj)/src/lib/efthrm

# Define the high-level dependencies between libraries:
$(obj)/src/driver/linux_resource: $(AUTOCOMPAT) mkdirs
$(obj)/src/lib/transport/ip: $(AUTOCOMPAT)
$(obj)/src/lib/citools: $(AUTOCOMPAT)
$(obj)/src/lib/cplane: $(AUTOCOMPAT)
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

ifeq ($(KPATH),)
  ifeq ($(KVER),)
  KVER := $(shell uname -r)
  endif
  ifeq ($(KARCH),)
  KARCH := $(shell uname -m)
  endif
  KPATH := /lib/modules/$(KVER)/build
else
 KVERARCH := $(subst ",,$(shell echo 'UTS_RELEASE UTS_MACHINE'|gcc -E -P -include $(KPATH)/include/generated/utsrelease.h -include $(KPATH)/include/generated/compile.h -))
 ifeq ($(KVERARCH),)
   $(error Cannot extract kernel info from KPATH "$(KPATH)" - not a built tree?)
 endif
 KVER ?= $(firstword $(KVERARCH))
 KARCH ?= $(lastword $(KVERARCH))
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
ONLOAD_CFLAGS += -DCI_HAVE_CNS_AUX=$(HAVE_CNS_AUX)
ifneq ($(NDEBUG),)
ONLOAD_CFLAGS += -DNDEBUG
else
ONLOAD_CFLAGS += -g
endif
ifneq ($(HAVE_CNS_AUX),0)
ONLOAD_CFLAGS += -DCI_AUX_HEADER='"$(AUX_BUS_PATH)/include/linux/auxiliary_bus.h"'
ONLOAD_CFLAGS += -DCI_AUX_MOD_HEADER='"$(AUX_BUS_PATH)/drivers/base/mod_devicetable_auxiliary.h"'
endif
ONLOAD_CFLAGS += -DCI_HAVE_X3_NET=$(HAVE_X3_NET)
ifneq ($(HAVE_X3_NET),0)
ONLOAD_CFLAGS += -DCI_XLNX_EFCT_HEADER='"$(X3_NET_PATH)/include/linux/net/xilinx/xlnx_efct.h"'
endif
ifneq ($(MMAKE_LIBERAL),1)
ONLOAD_CFLAGS += -Werror
endif


.PHONY: modules modules_install clean_kernel kernel

kernel: modules
	@mkdir -p $(KBUILDTOP)/driver/linux
	$(Q)ln -rsf $(KBUILDTOP)/src/driver/linux_onload/*.ko $(KBUILDTOP)/src/driver/linux_char/*.ko $(KBUILDTOP)/src/driver/linux_resource/*.ko $(KBUILDTOP)/src/driver/linux_net/drivers/bus/*.ko $(KBUILDTOP)/src/driver/linux_net/drivers/net/ethernet/sfc/*.ko $(KBUILDTOP)/driver/linux
	$(Q)cp src/driver/linux/*.sh $(KBUILDTOP)/driver/linux

modules modules_install: $(OUTMAKEFILES)
	$(Q)$(MAKE) -C $(KPATH) M=$(KBUILDTOP) \
		"src=\$$(patsubst $(KBUILDTOP)%,$$PWD%,\$$(obj))" \
		"SRCPATH=$$PWD/src" \
		'subdir-ccflags-y=$(subst ','\'',$(ONLOAD_CFLAGS))' \
		MMAKE_IN_KBUILD=1 MMAKE_USE_KBUILD=1 MMAKE_NO_RULES=1 \
		DRIVER=1 LINUX=1 $(patsubst modules,,$@)

kernel: modules

clean_kernel:
	$(RM) -r $(KBUILDTOP)

# Can't figure out a way to get modpost to look in the src directory. At least
# the number of makefiles is much smaller than the number of source files
$(OUTMAKEFILES): $(KBUILDTOP)/%: %
	$(Q)mkdir -p $(@D)
	$(Q)ln -sf `realpath '--relative-to=$(@D)' '$<'` $@

endif  # ifeq ($(KERNELRELEASE),)
