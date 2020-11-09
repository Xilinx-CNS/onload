# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc.

# note: no dependency on cp_client as custom build is used below
MMAKE_LIBS := \
	$(LINK_CIAPP_LIB) \
	$(LINK_CITOOLS_LIB) \
	-lmnl

MMAKE_LIB_DEPS := \
	$(CIAPP_LIB_DEPEND) \
	$(CITOOLS_LIB_DEPEND)

MMAKE_CFLAGS += -fPIC -DCP_SYSUNIT -D_GNU_SOURCE -Dcp_server_entry=main \
                -Dcp_frc64_get=ci_frc64_get
ifdef USE_ASAN
SANITIZE_CFLAGS := -static-libasan -static-libubsan -fsanitize=address \
                   -fsanitize=undefined -fno-omit-frame-pointer -fno-common
SANITIZER_OUTPUT_PREFIX := /tmp/cplane_sysunit-
endif

MMAKE_CFLAGS += $(CP_INTF_VER_CFLAGS)

ifeq ($(NO_CAPS),1)
MMAKE_CFLAGS += -DNO_CAPS
endif

SHIM_SRCS := cp_shim.c
SHIM_OBJS := $(patsubst %.c,%.o,$(SHIM_SRCS))

# allow shim object to access cp_server's private.h
$(SHIM_OBJS): MMAKE_CFLAGS += -I$(TOPPATH)/$(CURRENT)/$(CP_SERVER_SRC_DIR)

CP_CLIENT_LIB_SRC_DIR := ../../../lib/cplane
CP_CLIENT_LIB_OBJ_DIR := cp_client_lib

# This defines CLIENT_LIB_OBJS, which lists object files for the control plane
# itself.
# FIXME: include $(TOPPATH)/$(CURRENT)/$(CP_CLIENT_SRC_DIR)/client_lib_obj_build.mk
CLIENT_LIB_OBJS := mib.o mib_fwd.o onload.o
SHIM_CLIENT_LIB_OBJS := $(patsubst %,$(CP_CLIENT_LIB_OBJ_DIR)/%,$(CLIENT_LIB_OBJS)) $(SHIM_OBJS)


CP_SERVER_SRC_DIR := ../../../tools/cplane
CP_SERVER_OBJ_DIR := cp_server

# This defines SERVER_OBJS, which lists object files for the control plane
# itself.  Also defines CLIENT_OBJS, which lists object files for the
# onload_cp_client tool.
include $(TOPPATH)/$(CURRENT)/$(CP_SERVER_SRC_DIR)/server_obj_build.mk


SHIM_SERVER_OBJS := $(patsubst %,$(CP_SERVER_OBJ_DIR)/%,$(SERVER_OBJS)) $(SHIM_CLIENT_LIB_OBJS)
SHIM_CLIENT_OBJS := $(patsubst %,$(CP_SERVER_OBJ_DIR)/%,$(CLIENT_OBJS)) $(SHIM_CLIENT_LIB_OBJS)

$(SHIM_OBJS) $(SHIM_SERVER_OBJS) $(SHIM_CLIENT_OBJS): $(CP_INTF_VER_HDR)

$(CP_SERVER_OBJ_DIR):
	mkdir -p $(CP_SERVER_OBJ_DIR)

$(CP_CLIENT_OBJ_DIR)/%.o $(CP_SERVER_OBJ_DIR)/%.o: $(CP_SERVER_SRC_DIR)/%.c | $(CP_SERVER_OBJ_DIR)
	(cflags="$(SANITIZE_CFLAGS)"; $(MMakeCompileC))


$(CP_CLIENT_LIB_OBJ_DIR):
	mkdir -p $(CP_CLIENT_LIB_OBJ_DIR)

$(CP_CLIENT_LIB_OBJ_DIR)/%.o: $(CP_CLIENT_LIB_SRC_DIR)/%.c | $(CP_CLIENT_LIB_OBJ_DIR)
	$(MMakeCompileC)


%.o: %.c
	$(MMakeCompileC)


shim_cp_server := $(patsubst %,$(AppPattern),shim_cp_server)
shim_cp_client := $(patsubst %,$(AppPattern),shim_cp_client)


$(shim_cp_server): $(SHIM_SERVER_OBJS) $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS) $(SANITIZE_CFLAGS)"; $(MMakeLinkCApp))


$(shim_cp_client): $(SHIM_CLIENT_OBJS) $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS) $(SANITIZE_CFLAGS)"; $(MMakeLinkCApp))



MIBDUMP_SRC_DIR := ../../../tools/onload_mibdump
MIBDUMP_OBJ_DIR := mibdump
# FIXME: get MIBDUMP_OBJS from one place
# include $(TOPPATH)/$(CURRENT)/$(MIBDUMP_SRC_DIR)/obj_build.mk
MIBDUMP_OBJS := mibdump.o dump_tables.o

$(MIBDUMP_OBJ_DIR):
	mkdir -p $(MIBDUMP_OBJ_DIR)

$(MIBDUMP_OBJ_DIR)/%.o: $(MIBDUMP_SRC_DIR)/%.c | $(MIBDUMP_OBJ_DIR)
	$(MMakeCompileC)

SHIM_MIBDUMP_OBJS := $(patsubst %,$(MIBDUMP_OBJ_DIR)/%,$(MIBDUMP_OBJS)) $(SHIM_CLIENT_LIB_OBJS)
$(SHIM_MIBDUMP_OBJS): $(CP_INTF_VER_HDR)

shim_mibdump := $(patsubst %,$(AppPattern),shim_mibdump)

$(shim_mibdump): $(SHIM_MIBDUMP_OBJS) $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))


SHIM_SHARED_CPLANE_LIB_OBJS := cplane_lib.o $(SHIM_CLIENT_LIB_OBJS)

shim_shared_cplane_lib = shim_cplane_lib.so
$(shim_shared_cplane_lib): $(SHIM_SHARED_CPLANE_LIB_OBJS) $(MMAKE_LIB_DEPS)
	$(CC) $(mmake_c_compile) -shared -g -Wl,-E $^ $(MMAKE_LIBS) -ldl -o $@


SCRIPTS := cplane.py test_cplane1.py
# make confuses target and source locations, so we keep the scripts in subfolder
SCRIPT_SRC_DIR := scripts


$(SCRIPTS): %: $(SCRIPT_SRC_DIR)/%
	@cp $^ $@


TARGETS := $(shim_cp_server) $(shim_cp_client) $(shim_mibdump) \
           $(shim_shared_cplane_lib) $(SCRIPTS)

all: $(TARGETS)

targets:
	@echo $(TARGETS)

clean:
	@$(MakeClean)
	@rm -fr $(MIBDUMP_OBJ_DIR) $(CP_CLIENT_LIB_OBJ_DIR) $(CP_SERVER_OBJ_DIR) \
	        $(SCRIPTS)



ifdef UNIT_TEST_OUTPUT
UNIT_TEST_OUTPUT_DIR = $(UNIT_TEST_OUTPUT)
SANITIZER_OUTPUT_PREFIX := $(UNIT_TEST_OUTPUT)/
PYTEST_JUNIT_XML_FILE = $(UNIT_TEST_OUTPUT_DIR)/testresults.xml
PYTEST_JUNIT_XML_OPT = --junit-xml $(PYTEST_JUNIT_XML_FILE)

test: $(UNIT_TEST_OUTPUT_DIR)

$(UNIT_TEST_OUTPUT_DIR):
	mkdir -p $(UNIT_TEST_OUTPUT_DIR) && \
	  chmod a+rwx $(UNIT_TEST_OUTPUT_DIR)
	rm -rf $(UNIT_TEST_OUTPUT)/*.xml
endif # UNIT_TEST_OUTPUT

ifdef UNIT_TEST_SELECT
PYTEST_SELECT_OPT := -k $(UNIT_TEST_SELECT)
endif

UNIT_TEST_ENV_VARS :=

ifdef UNIT_TEST_SEED
UNIT_TEST_ENV_VARS += UNIT_TEST_SEED=$(UNIT_TEST_SEED)
endif

ifdef CPLANE_SYS_ASSERT_NETLINK_BOND
UNIT_TEST_ENV_VARS += CPLANE_SYS_ASSERT_NETLINK_BOND=$(CPLANE_SYS_ASSERT_NETLINK_BOND)
endif

ifdef USE_ASAN
UNIT_TEST_ENV_VARS += ASAN_OPTIONS=log_path=$(SANITIZER_OUTPUT_PREFIX)asan \
                      UBSAN_OPTIONS=log_path=$(SANITIZER_OUTPUT_PREFIX)ubsan
endif

OWNER := $(shell id -un)
OWNER_GROUP := $(shell id -gn)

OUTPUT_ABSPATH := $(abspath $(UNIT_TEST_OUTPUT_DIR) )
OUTPUT_PARENT := $(subst $(UNIT_TEST_OUTPUT_DIR),,$(OUTPUT_ABSPATH))
OUTPUT_REALPATH := $(realpath $(OUTPUT_PARENT) )
OUTPUT_DF := $(shell df $(OUTPUT_REALPATH) | tail -n +2)
OUTPUT_REMOTE_PATH := $(firstword $(OUTPUT_DF))
OUTPUT_IS_NFS := $(shell if echo $(OUTPUT_REMOTE_PATH) | grep -Eq 'ukfiler'; then echo 'true' ; fi )
ifeq "$(OUTPUT_IS_NFS)" "true"
  $(info "Unit test output dir: [$(UNIT_TEST_OUTPUT_DIR)]")
  $(info "Abspath of Unit test output dir: [$(OUTPUT_ABSPATH)]")
  $(info "Parent of Unit test output dir: [$(OUTPUT_PARENT)]")
  $(info "Realpath of Unit test output dir: [$(OUTPUT_REALPATH)]")
  $(info "Remote: [$(OUTPUT_REMOTE_PATH)]")
  $(info "NFS?: [$(OUTPUT_IS_NFS)]")
  $(error Unit test output directory being on NFS does not work)
  # On NFS, root is squashed and less access to change things.
  # Creating a file on NFS as root results in a file owned by
  # nfsnobody:nfsnobody, and subsequently trying to chown it does not
  # work.
endif

HARNESS_TIME_OUT=240

.PHONY: test
test: $(TARGETS)
	touch $(PYTEST_JUNIT_XML_FILE) ; \
	chmod a+rw $(PYTEST_JUNIT_XML_FILE) ; \
	sudo /usr/bin/timeout $(HARNESS_TIME_OUT) \
	  env $(UNIT_TEST_ENV_VARS) \
	  python2 -B $(shell which py.test) -p no:cacheprovider \
	    $(PYTEST_JUNIT_XML_OPT) $(PYTEST_SELECT_OPT); \
	sudo pkill -s 0 shim_cp_server || true
