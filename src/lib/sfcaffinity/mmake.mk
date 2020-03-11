# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

TARGETS		:= libsfcaffinity.so
MMAKE_TYPE	:= DLL


all: $(TARGETS)

lib: $(TARGETS)

clean:
	@$(MakeClean)


lib%.so: %.o
	@(libs="-ldl"; $(MMakeLinkPreloadLib))
