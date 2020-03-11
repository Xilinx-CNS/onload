# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
SUBDIRS	:= ip common unix
DRIVER_SUBDIRS := ip


all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

