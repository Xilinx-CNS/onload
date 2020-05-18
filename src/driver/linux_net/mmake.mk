# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) 2005-2019 Solarflare Communications Inc

SUBDIRS := drivers
DRIVER_SUBDIRS := scripts include drivers

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)
