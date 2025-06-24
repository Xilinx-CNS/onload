# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: (c) 2025 Advanced Micro Devices, Inc.

HAVE_EFCP := $(shell echo "\#include <cplane/api.h>" | \
$(CC) -E - >/dev/null 2>&1 && echo "Y")

EFSEND_APPS := efsend efsend_timestamping efsend_warming
ifdef HAVE_EFCP
  EFSEND_APPS += efsend_cplane
else
  $(info NOTE: will skip efsend_cplane due to missing dependencies)
  $(info NOTE: install onload-devel and rerun `make` to build)
  $(info )
endif

TEST_APPS       := efforward efrss efsink \
                   efsink_packed eflatency \
                   $(EFSEND_APPS)
LDFLAGS += -lciul1
CFLAGS_COMMON := -DNDEBUG -Werror -Wall -Wundef -Wpointer-arith \
                 -Wstrict-prototypes -Wnested-externs -Wno-stringop-truncation \
                 -Wno-format-truncation -Wimplicit-fallthrough=5 \
                 -Wno-array-bounds -Wno-stringop-overflow \
                 -Wno-deprecated-declarations -fomit-frame-pointer -O2 -g
LDFLAGS_COMMON := -O2 -g -Wl,-E -Wl,-rpath -pthread

.PHONY: all clean
all: $(TEST_APPS)
clean:
	rm -f *.o *.d $(TEST_APPS)

eflatency: eflatency.o utils.o
efsink: efsink.o utils.o
efsink_packed: efsink_packed.o utils.o
efsend_cplane: LDFLAGS += -lefcp

$(EFSEND_APPS): %: %.o utils.o efsend_common.o
$(TEST_APPS): %: %.o
$(TEST_APPS):
	$(CC) $^ $(CFLAGS) $(LDFLAGS) $(LDFLAGS_COMMON) -o $@
%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS_COMMON) -c $< -o $@
