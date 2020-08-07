/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2019 Xilinx, Inc. */
/****************************************************************************
 * GCOV module for the Etherfabric drivers
 *
 * Copyright 2006-2007: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 * Author: Steve Hodgson
 *
 * Copyright (c) International Business Machines Corp., 2002-2003
 *
 * Author: Hubertus Franke <frankeh@us.ibm.com>
 *         Peter Oberparleiter <peter.oberparleiter@de.ibm.com>*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 **************************************************************************/

#ifndef GCOV_H
#define GCOV_H GCOV_H

/**************************************************************************
 *
 * Functions used by other modules wanting GCOV information. A module
 * can use these so we don't have to recompile the kernel
 *
 **************************************************************************/

extern int gcov_provider_init ( struct module* module );
extern void gcov_provider_fini ( struct module* module );

/**************************************************************************
 *
 * Type definitions pulled from include/linux/gcov.h
 *
 **************************************************************************/

#include <linux/module.h>
#include <linux/spinlock.h>
#include <asm/types.h>

#define GCC_VERSION_LOWER(major, minor) ((__GNUC__ < major) ||		\
					 (__GNUC__ == major) &&		\
					 (__GNUC_MINOR__ < minor))

#if GCC_VERSION_LOWER(3, 1)
/**
 * Profiling types for GCC prior to version 3.1
 */

typedef long gcov_type;

/* Same as gcc/libgcc2.c */
struct bb
{
	long zero_word;
	const char *filename;
	long *counts;
	long ncounts;
	struct bb *next;
	const unsigned long *addresses;
	long nwords;
	const char **functions;
	const long *line_nums;
	const char **filenames;
	char *flags;
};

#elif GCC_VERSION_LOWER(3, 3)
/*
 * Profiling types for GCC 3.1 to 3.2
 */

#if BITS_PER_LONG >= 64
typedef long gcov_type;
#else
typedef long long gcov_type;
#endif

/* Same as gcc/libgcc2.c */
struct bb
{
	long zero_word;
	const char *filename;
	gcov_type *counts;
	long ncounts;
	struct bb *next;
	const unsigned long *addresses;
	long nwords;
	const char **functions;
	const long *line_nums;
	const char **filenames;
	char *flags;
};

#elif GCC_VERSION_LOWER(3, 4)
/**
 * Profiling types for GCC 3.3
 */

typedef long long gcov_type;

/* Same as gcc/libgcc2.c */
struct bb_function_info
{
	long checksum;
	int arc_count;
	const char *name;
};

struct bb
{
	long zero_word;
	const char *filename;
	gcov_type *counts;
	long ncounts;
	struct bb *next;
	long sizeof_bb;
	struct bb_function_info *function_infos;
};

#else
/**
 * Profiling types for GCC 3.4 and above (see gcc-3.4/gcc/gcov-io.h)
 */

#define GCOV_COUNTERS		5
#define GCOV_DATA_MAGIC		((gcov_unsigned_t) 0x67636461)
#define GCOV_TAG_FUNCTION	((gcov_unsigned_t) 0x01000000)
#define GCOV_TAG_COUNTER_BASE	((gcov_unsigned_t) 0x01a10000)
#define GCOV_TAG_FOR_COUNTER(COUNT)					\
	(GCOV_TAG_COUNTER_BASE + ((gcov_unsigned_t) (COUNT) << 17))

#if BITS_PER_LONG >= 64
typedef long gcov_type;
#else
typedef long long gcov_type;
#endif

typedef unsigned int gcov_unsigned_t;
typedef unsigned int gcov_position_t;

typedef void (*gcov_merge_fn) (gcov_type *, gcov_unsigned_t);

struct gcov_fn_info
{
	gcov_unsigned_t ident;
	gcov_unsigned_t checksum;
	unsigned int n_ctrs[0];			/* Note: the number of bits
						 * set in bb->ctr_mask decides
						 * how big this array is. */
};

struct gcov_ctr_info
{
	gcov_unsigned_t num;
	gcov_type *values;
	gcov_merge_fn merge;
};

struct bb /* should be 'struct gcov_info' but we're sticking with the old name
	   * so we can reuse some of our pre-3.4 functions */
{
	gcov_unsigned_t version;
	struct bb *next;
	gcov_unsigned_t stamp;
	const char *filename;
	unsigned int n_functions;
	const struct gcov_fn_info *functions;
	unsigned int ctr_mask;
	struct gcov_ctr_info counts[0];		/* Note: the number of bits
						 * set in ctr_mask decides
						 * how big this array is. */
};
	
#endif /* GCC_VERSION */

#if GCC_VERSION_LOWER(3, 4)

extern void __bb_init_func ( struct bb *bb );
extern void __bb_fork_func ( void );

#else 

extern void __gcov_init ( struct bb *bb );
extern void __gcov_merge_add(gcov_type *counters, unsigned int n_counters);

#endif /* GCC_VERSION */

#endif /* GCOV_H */

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 *  indent-tabs-mode: 1
 * End:
 */
