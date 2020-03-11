# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

# dynamic shared lib
DLIB_SRCS	:= onload_ext.c
DLIB_OBJS	:= $(DLIB_SRCS:%.c=%.o)

# static lib
ONLOAD_EXT_STATIC := libonload_ext.a
SLIB_SRCS	:= onload_ext_static.c
SLIB_OBJS	:= $(SLIB_SRCS:%.c=%.o)

TARGETS		:= $(ONLOAD_EXT_REALNAME)
TARGETS		+= $(ONLOAD_EXT_SONAME)
TARGETS		+= $(ONLOAD_EXT_LINKNAME)
TARGETS		+= $(ONLOAD_EXT_STATIC)

MMAKE_CFLAGS 	+= -DONLOAD_EXT_VERSION_MAJOR=$(ONLOAD_EXT_VERSION_MAJOR)
MMAKE_CFLAGS 	+= -DONLOAD_EXT_VERSION_MINOR=$(ONLOAD_EXT_VERSION_MINOR)
MMAKE_CFLAGS 	+= -DONLOAD_EXT_VERSION_MICRO=$(ONLOAD_EXT_VERSION_MICRO)


MMAKE_TYPE := DLL


all: $(TARGETS)

lib: $(TARGETS)

clean:
	@$(MakeClean)


$(ONLOAD_EXT_REALNAME): $(DLIB_OBJS)
	@(soname="$(ONLOAD_EXT_SONAME)"; $(MMakeLinkDynamicLib))

$(ONLOAD_EXT_SONAME): $(ONLOAD_EXT_REALNAME)
	ln -fs $(shell basename $^) $@

$(ONLOAD_EXT_LINKNAME): $(ONLOAD_EXT_REALNAME)
	ln -fs $(shell basename $^) $@

$(ONLOAD_EXT_STATIC): $(SLIB_OBJS)
	$(MMakeLinkStaticLib)
