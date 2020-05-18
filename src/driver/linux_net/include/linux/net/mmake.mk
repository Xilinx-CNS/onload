# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc

DRIVER_SUBDIRS := sfc

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)
