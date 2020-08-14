# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2016-2020 Xilinx, Inc.

TEST_APPS := orm_test_client

TARGETS := $(TEST_APPS:%=$(AppPattern))

all: $(TARGETS)

clean:
	@$(MakeClean)

orm_test_client: orm_test_client.py
	cp $< $@
