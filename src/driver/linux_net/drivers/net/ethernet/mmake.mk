# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) 2005-2019 Solarflare Communications Inc

SUBDIRS := sfc
DRIVER_SUBDIRS := sfc

# This code base does not support Solarflare Siena.
passthruparams := CONFIG_SFC_SIENA=

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)
