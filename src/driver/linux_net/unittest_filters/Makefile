ifdef KERNELRELEASE
# Build kernel modules

obj-m += arb_filter_test_mod.o

EXTRA_CFLAGS += -I$(src) -Wall
ifndef NOWERROR
EXTRA_CFLAGS += -Werror
endif

ifndef KPATH
ifndef KVER
KVER := $(shell uname -r)
endif
KPATH := /lib/modules/$(KVER)/build
endif # KPATH

# Turn on all debugging
EXTRA_CFLAGS += -DDEBUG -I$(src)/..

all : Module.symvers
	$(MAKE) -C $(KPATH) M=$$(pwd) V=1 modules

clean :
	rm -f *.o *.s *.ko *.mod.c *.symvers
	$(MAKE) -C $(KPATH) M=$$(pwd) clean

Module.symvers : ../Module.symvers
	cp $< $@

else # !KERNELRELEASE
# Build userland apps, and call into kbuild for modules

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

CFLAGS := -Wall -Werror -I$$(pwd)/.. -fno-strict-aliasing

all: arb_filter_test_mod.ko afta racer

clean:
	rm -f *.o afta racer filter.h driverlink_api.h
	$(MAKE) -C $(KPATH) M=$$(pwd) clean

Module.symvers: ../Module.symvers
	cp $< $@

arb_filter_test_mod.ko: Module.symvers ../filter.h ../driverlink_api.h
	$(MAKE) -C $(KPATH) M=$$(pwd)

endif
