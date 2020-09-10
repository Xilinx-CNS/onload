# SPDX-License-Identifier: BSD-2-Clause
# (c) Copyright 2006-2016 Xilinx, Inc.

TARGETS := phy_power reset_nic set_carrier
TARGETS_RENAME := $(TARGETS:%=$(TARGETS_PREFIX)%)
AUTO_COMPAT := user_autocompat.h

# This constrained rule is needed so that the default rules do not make
# the executable directly from the .c file

all: $(TARGETS_RENAME)

$(TARGETS_RENAME) : % : %.o
	@echo [LD] $@
	$(Q)$(CC) -o $@ $<

$(TARGETS_PREFIX)%.o: %.c $(AUTO_COMPAT)
	@echo [CC] $@
	$(Q)$(CC) -I.. $(CFLAGS) -c -o $@ $<

$(AUTO_COMPAT): user_compat.sh
	@echo Running compat checks
	@./user_compat.sh > $@
	@touch $@

clean:
	rm -f *.o $(TARGETS_RENAME) $(AUTO_COMPAT)
