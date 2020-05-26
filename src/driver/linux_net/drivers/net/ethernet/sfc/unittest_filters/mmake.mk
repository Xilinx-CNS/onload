MMAKE_GEN_SRCS := %.mod.c

ifdef DRIVER

TARGETS := arb_filter_test_mod.ko
DRIVER_SUBDIRS :=

all: kbuild

kbuild: Module.symvers
	@if ! [ -h $(CURDIR)/Kbuild ]; then				\
		echo "  UPD     Kbuild";				\
		ln -sf $(SRCPATH)/driver/linux_net/unittest_filters/Makefile $(CURDIR)/Kbuild; \
	fi
	$(MAKE) $(MMAKE_KBUILD_ARGS) M=$(CURDIR)

Module.symvers: ../Module.symvers
	cp $< $@

clean:
	@$(MakeClean)
	rm -rf *.ko Module.symvers .tmp_versions .*.cmd

else

TEST_APPS := afta racer
TARGETS := $(TEST_APPS)
SUBDIRS :=
DRIVERINCLUDE := $(SRCPATH)/driver/linux_net/
MMAKE_INCLUDE := -I$(DRIVERINCLUDE)
MMAKE_CFLAGS += -fno-strict-aliasing

all: $(TEST_APPS)

clean:
	@$(MakeClean)

endif
