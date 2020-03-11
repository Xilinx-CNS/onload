# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
SUBDIRS	:= internal_tests

all:
	+@$(MakeSubdirs)

clean:
	@$(MakeClean)

