# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) 2005-2019 Solarflare Communications Inc

SUBDIRS := net
DRIVER_SUBDIRS := net

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)
