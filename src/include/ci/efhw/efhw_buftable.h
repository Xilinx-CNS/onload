/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2019 Xilinx, Inc. */
#ifndef __CI_EFHW_EFHW_BUFTABLE_H__
#define __CI_EFHW_EFHW_BUFTABLE_H__

#include <ci/efhw/efhw_types.h>

#ifndef NDEBUG
static inline void
efhw_buffer_table_set_debug(struct efhw_buffer_table_block *block,
			     int first_entry, int n_entries)
{
	EFHW_ASSERT(first_entry >= 0);
	EFHW_ASSERT(first_entry < EFHW_BUFFER_TABLE_BLOCK_SIZE);
	EFHW_ASSERT(n_entries > 0);
	EFHW_ASSERT(n_entries <= EFHW_BUFFER_TABLE_BLOCK_SIZE);
	EFHW_ASSERT(first_entry + n_entries <=
		    EFHW_BUFFER_TABLE_BLOCK_SIZE);
}

static inline void
efhw_buffer_table_clear_debug(struct efhw_buffer_table_block *block,
			       int first_entry, int n_entries)
{
	EFHW_ASSERT(first_entry >= 0);
	EFHW_ASSERT(first_entry < EFHW_BUFFER_TABLE_BLOCK_SIZE);
	EFHW_ASSERT(n_entries > 0);
	EFHW_ASSERT(n_entries <= EFHW_BUFFER_TABLE_BLOCK_SIZE);
	EFHW_ASSERT(first_entry + n_entries <=
		    EFHW_BUFFER_TABLE_BLOCK_SIZE);
}

#endif /* NDEBUG */

#endif /* __CI_EFHW_EFHW_BUFTABLE_H__ */
