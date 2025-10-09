# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: (c) 2025 Advanced Micro Devices, Inc.

TEST_APPS       := exchange trader_onload_ds_efvi
LDFLAGS += -lonload_ext
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

trader_onload_ds_efvi: \
	LDFLAGS += -lciul1
$(TEST_APPS): %: %.o utils.o
$(TEST_APPS):
	$(CC) $^ $(CFLAGS) $(LDFLAGS) $(LDFLAGS_COMMON) -o $@
%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS_COMMON) -c $< -o $@
