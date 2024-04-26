# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc.

MMAKE_LIBS := \
	$(LINK_CIAPP_LIB) \
	$(LINK_CIIP_LIB) \
	$(LINK_CITOOLS_LIB) \
	$(LINK_CIUL_LIB) \
	$(LINK_CPLANE_LIB) \
	-lmnl

MMAKE_LIB_DEPS := \
	$(CIAPP_LIB_DEPEND) \
	$(CIIP_LIB_DEPEND) \
	$(CITOOLS_LIB_DEPEND) \
	$(CIUL_LIB_DEPEND) \
	$(CPLANE_LIB_DEPEND)
MMAKE_CFLAGS += -DCP_UNIT -D_GNU_SOURCE

ifeq ($(NO_CAPS),1)
MMAKE_CFLAGS += -DNO_CAPS
endif

MMAKE_CFLAGS += $(CP_INTF_VER_CFLAGS)

CPLANE_SRC_DIR := ../../../tools/cplane
CPLANE_OBJ_DIR := cplane

# Need this for SLES 15 because it puts the libmnl.h in a non-standard location:
# /usr/include/libmnl/libmnl/libmnl.h
# Need this for SLES 12 because it puts the libmnl.h in a non-standard location:
# /usr/include/libmnl-1.0.3/libmnl/libmnl.h
MMAKE_INCLUDE += $(addprefix -I,$(wildcard /usr/include/libmnl*))

# This defines SERVER_OBJS, which lists object files for the control plane
# itself.
include $(TOPPATH)/$(CURRENT)/$(CPLANE_SRC_DIR)/server_obj_build.mk
# Source-file dependencies for the unit tests.
SRCS := ../../tap/tap.c ../../../tools/onload_mibdump/dump_tables.c \
        session.c netlink.c insert.c
# Main source file for each unit test binary.
TEST_SRCS := test_route.c test_route_expire.c test_arp_expire.c \
	     test_route_stress.c test_teambond.c test_namespace.c \
	     test_service_dnat.c

OBJS := $(patsubst %.c,%.o,$(SRCS))
OBJS += $(patsubst %,$(CPLANE_OBJ_DIR)/%,$(SERVER_OBJS))

$(OBJS): $(CP_INTF_VER_HDR)

TARGETS := $(patsubst %.c,%,$(TEST_SRCS))

$(CPLANE_OBJ_DIR):
	mkdir -p $(CPLANE_OBJ_DIR)

$(CPLANE_OBJ_DIR)/%.o: $(CPLANE_SRC_DIR)/%.c | $(CPLANE_OBJ_DIR)
	$(MMakeCompileC)

%.o: %.c
	$(MMakeCompileC)

test_%: $(OBJS) test_%.o $(MMAKE_LIB_DEPS)
	@(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))

all: $(TARGETS)

targets:
	@echo $(TARGETS)

clean:
	@$(MakeClean)
	@rm -rf $(CPLANE_OBJ_DIR)

ifdef UNIT_TEST_OUTPUT
PROVE_FLAGS += --merge --timer
UNIT_TEST_OUTPUT_DIR = $(UNIT_TEST_OUTPUT)
PROVE_REDIRECT = >> $(UNIT_TEST_OUTPUT)

test: $(UNIT_TEST_OUTPUT_DIR)

$(UNIT_TEST_OUTPUT_DIR):
	mkdir -p $$(dirname $(UNIT_TEST_OUTPUT_DIR))
	touch $(UNIT_TEST_OUTPUT_DIR)
endif # UNIT_TEST_OUTPUT

HARNESS_TIME_OUT=600

.PHONY: test
test: $(TARGETS)
	/usr/bin/timeout $(HARNESS_TIME_OUT) prove -j2 --merge --exec '' \
	$(PROVE_FLAGS) $(patsubst %,./%,$(TARGETS)) $(PROVE_REDIRECT)
