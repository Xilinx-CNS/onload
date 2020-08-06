# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
APPS := onload_cp_server onload_cp_client
#onload_cp_client

TARGETS	:= $(APPS:%=$(AppPattern))

# This defines SERVER_OBJS.
include $(TOPPATH)/$(CURRENT)/server_obj_build.mk
CLIENT_OBJS := client.o

$(SERVER_OBJS) $(CLIENT_OBJS): $(CP_INTF_VER_HDR)

# ffsll needs _GNU_SOURCE
MMAKE_CPPFLAGS += -D_GNU_SOURCE
ifeq ($(NO_CAPS),1)
MMAKE_CPPFLAGS += -DNO_CAPS
endif
ifeq ($(CP_RELEASE),1)
MMAKE_CPPFLAGS += -DCP_RELEASE
endif
ifeq ($(CP_SCALEOUT_UDP),1)
MMAKE_CPPFLAGS += -DCP_SCALEOUT_UDP
endif

onload_cp_server := $(patsubst %,$(AppPattern),onload_cp_server)
onload_cp_client := $(patsubst %,$(AppPattern),onload_cp_client)

MMAKE_LIBS	:= $(LINK_CIAPP_LIB) $(LINK_CITOOLS_LIB) $(LINK_CIUL_LIB) $(LINK_CPLANE_LIB)
MMAKE_LIB_DEPS	:= $(CIAPP_LIB_DEPEND) $(CITOOLS_LIB_DEPEND) $(CIUL_LIB_DEPEND) $(CPLANE_LIB_DEPEND)

MMAKE_CFLAGS += $(CP_INTF_VER_CFLAGS)

ifneq ($(NO_CAPS),1)
MMAKE_LIBS += -lcap
endif

$(onload_cp_server): $(SERVER_OBJS) $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))

$(onload_cp_client): $(CLIENT_OBJS) $(MMAKE_LIB_DEPS)
	(libs="$(MMAKE_LIBS)"; $(MMakeLinkCApp))

cp_wrapper_src := $(TOPPATH)/$(CURRENT)/cp_wrapper
cp_wrapper_dst := $(shell pwd)/cp_wrapper

$(cp_wrapper_dst): $(cp_wrapper_src)
	ln -sf $< $@

all: $(TARGETS) $(cp_wrapper_dst)

clean:
	rm -f *.o $(TARGETS)
