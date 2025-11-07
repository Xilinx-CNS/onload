# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: (c) 2025 Advanced Micro Devices, Inc.
TARGETS	:= rx_timestamping tx_timestamping cpacket_send

ifneq ($(strip $(USEONLOADEXT)),)
CFLAGS += -DONLOADEXT_AVAILABLE
LDFLAGS += -lonload_ext
endif
CFLAGS_COMMON := -DNDEBUG -Werror -Wall -Wundef -Wpointer-arith \
                 -Wstrict-prototypes -Wnested-externs -Wno-stringop-truncation \
                 -Wno-format-truncation -Wimplicit-fallthrough=5 \
                 -Wno-array-bounds -Wno-stringop-overflow \
                 -Wno-deprecated-declarations -fomit-frame-pointer -O2 -g
LDFLAGS_COMMON := -O2 -g -Wl,-E -Wl,-rpath -pthread

.PHONY: all clean
all: $(TARGETS)
clean:
	rm -f *.o *.d $(TARGETS)

$(TARGETS): %: %.o
$(TARGETS):
	$(CC) $^ $(CFLAGS) $(LDFLAGS) $(LDFLAGS_COMMON) -o $@
%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGS_COMMON) -c $< -o $@
