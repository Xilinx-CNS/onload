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

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <asm/uaccess.h>
#include "gcov.h"

#define GCOV_CORE_HEADER	"gcov-core: "
#define GCOV_PROC_HEADER	"gcov-proc: "
#define GCOV_PROC_ROOT		"gcov"
#define GCOV_PROC_MODULE	"module"
#define PAD8(x)			(((x) + 7) & ~7)
#define PAD4(x)			(((x) + 3) & ~3)

/**************************************************************************
 *
 * Error macros
 *
 **************************************************************************/

#define GCOV_DBG_LOG		1
#define GCOV_DBG_TRACE		2

#define GCOV_ERR(...) \
	printk ( KERN_ERR __VA_ARGS__ )
#define GCOV_CORE_ERR(...) \
	GCOV_ERR ( GCOV_CORE_HEADER __VA_ARGS__ )
#define GCOV_PROC_ERR(...) \
	GCOV_ERR ( GCOV_PROC_HEADER __VA_ARGS__ )

#define GCOV_LOG(...) \
	printk ( KERN_INFO __VA_ARGS__ )
#define GCOV_CORE_LOG(...) \
	GCOV_LOG ( GCOV_CORE_HEADER __VA_ARGS__ )
#define GCOV_PROC_LOG(...) \
	GCOV_LOG ( GCOV_PROC_HEADER __VA_ARGS__ )

#define GCOV_ASSERT(x) do { if ( unlikely ( ! (x) ) ) {			\
			GCOV_ERR ( "GCOV_ASSERT ( %s ) failed at %s line %d\n",	\
				   #x, __FILE__, __LINE__ );		\
		} } while ( 0 )

#define EFX_DBG_MSG(level,...) do {					\
		if ( unlikely ( (level) <= efx_debug_level ) ) {	\
			printk ( __VA_ARGS__ );				\
		} } while ( 0 )

/**************************************************************************
 *
 * Local data types
 *
 **************************************************************************/

typedef enum {
	status_normal,	/* Normal status */
	status_ghost	/* Module associated with this node has been unloaded
			 * but data was saved. */
} node_status;

/* Data structure used to manage proc filesystem entries. */
struct gcov_ftree_node;

struct gcov_ftree_node
{
	char *fname;			 /* Hierarchy-relative name */
	struct gcov_ftree_node *sibling; /* First sibling of this node */
	struct gcov_ftree_node *files;	 /* First child of this node */
	struct gcov_ftree_node *parent;	 /* Parent of this node */
	struct proc_dir_entry *proc[4];	 /* Entries for .da, .bb, .bbg, .c */
	struct bb *bb;			 /* Associated struct bb */
	loff_t offset;			 /* Offset in vmlinux file */
	size_t da_size;			 /* Size of associated .da file */
	size_t header_size;		 /* Size of associated file header */
	struct gcov_ftree_node *next;	 /* Next leaf node */
	node_status status;		 /* Status of this node */
};

/* This structure is used to keep track of all struct bbs associated with a
 * module. */
struct gcov_context
{
	struct list_head list;
	struct module *module;
	unsigned long count;
	struct bb **bb;
};

enum gcov_cmd {
	gcov_add,
	gcov_remove
};

/**************************************************************************
 *
 * Local state
 *
 **************************************************************************/

/* Linked list for registered struct bbs. */
struct bb *bb_head;

/* Callback informed of struct bb addition and removal. */
void (*gcov_callback)(enum gcov_cmd, struct bb *bbptr) = NULL;

/* List of contexts for registered bb entries. */
static LIST_HEAD(context_list);

/* Context into which blocks are inserted during initialization. */
static struct gcov_context *current_context = NULL;

/* Protect global variables from concurrent access. */
static spinlock_t gcov_core_lock = SPIN_LOCK_UNLOCKED;

/* Root node for internal data tree. */
static struct gcov_ftree_node tree_root;

#if GCC_VERSION_LOWER(3,4)
/* Filename extension for data files. */
static const char *da_ending = "da";

/* Array of filename endings to use when creating links. */
static const char *endings[] = { "bb", "bbg", "c" };
#else
/* Filename extension for data files. */
static const char *da_ending = "gcda";

/* Array of filename endings to use when creating links. */
static const char *endings[] = { "gcno", "c" };
#endif /* GCC_VERSION_LOWER */

/* First leaf node. */
static struct gcov_ftree_node *leaf_nodes = NULL;

/* Protect global variables from concurrent access. */
static DECLARE_MUTEX_LOCKED(gcov_lock);

/**************************************************************************
 *
 * Module parameters
 *
 **************************************************************************/

/* If set to non-zero, keep gcov data for modules after unload. */
static int gcov_persist = 0;
module_param ( gcov_persist, int, 0444 );
MODULE_PARM_DESC(gcov_persist, "If set to non-zero, keep gcov data for modules "
		 "after unload");

/* If set to non-zero, create links to additional files in proc filesystem
 * entries. */
static int gcov_link = 1;
module_param ( gcov_link, int, 0444 );
MODULE_PARM_DESC(gcov_link, "If non-zero, create links to additional "
		 "files in proc filesystem entries");

/**************************************************************************
 *
 * Kernel Compatabilty
 *
 **************************************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
/*rhel4 */
#define efx_module_sections module_sections
#else
/* fc4 */
#define efx_module_sections module_sect_attrs
#define EFX_NEED_NOVERS
#endif

#ifdef EFX_NEED_NOVERS
#define EXPORT_SYMBOL_NOVERS(sym)				\
        static const char __kstrtab_##sym[]                     \
        __attribute__((section("__ksymtab_strings")))           \
        = MODULE_SYMBOL_PREFIX #sym;                            \
        static const struct kernel_symbol __ksymtab_##sym       \
        __attribute_used__                                      \
        __attribute__((section("__ksymtab"), unused))		\
        = { (unsigned long)&sym, __kstrtab_##sym }
#endif

/**************************************************************************
 *
 * Interfaces used by other modules wanting GCOV support
 *
 **************************************************************************/

/**
 * When files are compiled a .tmp_ is places in front of the file
 * In some instances we want to remove .tmp_ from the filename
 * which this function does
 */
static char* mangle_token = ".tmp_";

/**
 * Given the module pointer iterate over the ELF sections
 * and pick up the .ctor elf section
 *
 * WARNING: This function does seem very kernel version
 * specific - and is highly dependent on the kernel having
 * stored enough ELF state for us to extract the required information
 * when gcov_provider_init is called.
 *
 * Variations on this theme are expected to work from 2.6.9 onwards,
 * but for kernels earlier than that an alternative scheme will have
 * to be used. e.g. provide the path to the module as a module paramater
 * so this module can directly find the ELF .ctor section by vmapping the file
  */
static int gcov_get_ctors ( struct module * module,
			    char** start, char** end )
{
	struct efx_module_sections *sect_attrs = module->sect_attrs;
	struct module_sect_attr* sattr = &sect_attrs->attrs[0];
	int i = 0;

	*start = *end = NULL;
	
	/**
	 * Iterate over all the ELF sections. There doesn't seem to be
	 * a generic way of figuring out how many sections there are
	 * (2.6.17 has a trailing NULL, whilst 2.6.9 doesn't)
	 */
	while ( i++ < 100 ) {
		if ( *start != NULL ) {
			/* this is the section after .ctors */
			*end = (char*) sattr->address;
			return 0;
		}
		if ( strcmp ( sattr->name,".ctors" ) == 0 ) {
			*start = (char*) sattr->address;
		}
		if ( strcmp ( sattr->name,".comment" ) == 0 )
			break;
		if ( strncmp ( sattr->name,".debug", 6 ) == 0 )
			break;
		++sattr;
	}

	/* if we get here then we couldn't find the section start of finish */
	*start = *end = NULL;
	return -EINVAL;
}
	
/**
 * Called by a module at module_init time to initialise the GCOV
 * data structures 
 */
int gcov_provider_init ( struct module * module )
{
  	typedef void (*func_ptr)(void);
	int err = 0;
	func_ptr *func;
	unsigned long count, size;
	char* ctors_start, *ctors_end;

	/* we only support dynamic modules */
	GCOV_ASSERT(module);

	spin_lock(&gcov_core_lock);

	GCOV_PROC_LOG ( "Initialising provider: %s\n",
			module->name );

	/* get the ctors section */
	if ( ( err = gcov_get_ctors( module, &ctors_start, &ctors_end ) ) != 0 ) {
		GCOV_CORE_ERR ( "unable to find sector .ctor."
				"Was module compiled with -fprofile-arcs -ftest-coverage?\n" );
		goto out_unlock;
	}

	/* Create a context to associate struct bbs with this MODULE */
	count = ((unsigned long) (ctors_end - ctors_start)) /
		sizeof(func_ptr);
	size = sizeof(struct gcov_context) + count * sizeof(struct bb *);
	current_context = (struct gcov_context*) kmalloc(size,
							 GFP_KERNEL);
	if (!current_context) {
		GCOV_CORE_ERR ( "not enough memory for coverage data!\n");
		err = -ENOMEM;
		goto out_unlock;
	}
	
	current_context->module = module;
	current_context->count = 0;
	current_context->bb = (struct bb **) (current_context + 1);
	list_add(&current_context->list, &context_list);

	/* Call constructors */
	for (func = (func_ptr *) ctors_start;
	     *func && (func != (func_ptr *) ctors_end);
	     func++)
		(*func)();

 out_unlock:
	current_context = NULL;
	spin_unlock(&gcov_core_lock);
	return err;
}

/**
 * Called by a module at module_exit time to free the GCOV data
 * structures
 */
void gcov_provider_fini ( struct module* module )
{
	struct gcov_context* context;
	struct gcov_context* tmp;
	struct bb *bb;
	struct bb *prev;
	unsigned long i;

	spin_lock(&gcov_core_lock);
	/* Get associated context */
	context = NULL;
	list_for_each_entry(tmp, &context_list, list) {
		if (tmp->module == module) {
			context = tmp;
			break;
		}
	}
	if (!context)
		goto out_unlock;

	/* Remove all bb entries belonging to this module */
	prev = NULL;
	for (bb = bb_head; bb ; bb = bb->next) {
		for (i = 0; i < context->count; i++) {
			if (context->bb[i] == bb) {
				/* Detach bb from list. */
				if (prev)
					prev->next = bb->next;
				else
					bb_head = bb->next;
				/* Notify callback */
				if (gcov_callback)
					(*gcov_callback)(gcov_remove, bb);
				break;
			}
		}
		if (i == context->count)
			prev = bb;
	}
	list_del(&context->list);
	kfree(context);
out_unlock:
	spin_unlock(&gcov_core_lock);
}

EXPORT_SYMBOL_NOVERS ( gcov_provider_init );
EXPORT_SYMBOL_NOVERS ( gcov_provider_fini );

/**************************************************************************
 *
 * Functions called by the GCOV initialiser routines that we must
 * implement lest the kernel dynamic linker won't be able to resolve
 * all the symbols
 *
 **************************************************************************/

#if GCC_VERSION_LOWER(3, 4)
/* Register supplied struct BB. Called by each object code constructor. */
void __bb_init_func(struct bb *bb)
{
	if (bb->zero_word)
		return;
	/* Set up linked list */
	bb->zero_word = 1;
	bb->next = bb_head;
	bb_head = bb;
	/* Associate with module context */
	if (current_context)
		current_context->bb[current_context->count++] = bb;
	/* Notify callback */
	if (gcov_callback != NULL)
		(*gcov_callback)(gcov_add, bb);
}

/* Unused functions needed to prevent linker errors. */
void __bb_fork_func(void) {}

EXPORT_SYMBOL_NOVERS(__bb_init_func);
EXPORT_SYMBOL_NOVERS(__bb_fork_func);

#else

gcov_unsigned_t gcov_version = 0;

/* Register supplied struct BB. Called by each object code constructor. */
void __gcov_init(struct bb *bb)
{
	if (!bb->version)
		return;
	/* Check for compatible gcc version */
	if (gcov_version == 0)
		gcov_version = bb->version;
	else if (bb->version != gcov_version) {
		GCOV_CORE_ERR ( "gcc version mismatch in file '%s'!\n", bb->filename);
		return;
	}
	/* Set up linked list */
	bb->version = 0;
	bb->next = bb_head;
	bb_head = bb;

	/* Associate with module context */
	if (current_context)
		current_context->bb[current_context->count++] = bb;
	/* Notify callback */
	if (gcov_callback != NULL)
		(*gcov_callback)(gcov_add, bb);
}

/* Unused functions needed to prevent linker errors. */
void __gcov_flush(void) {}
void __gcov_merge_add(gcov_type *counters, unsigned int n_counters) {}
void __gcov_merge_single(gcov_type *counters, unsigned int n_counters) {}
void __gcov_merge_delta(gcov_type *counters, unsigned int n_counters) {}

EXPORT_SYMBOL_NOVERS(gcov_version);
EXPORT_SYMBOL_NOVERS(__gcov_init);
EXPORT_SYMBOL_NOVERS(__gcov_flush);
EXPORT_SYMBOL_NOVERS(__gcov_merge_add);
EXPORT_SYMBOL_NOVERS(__gcov_merge_single);
EXPORT_SYMBOL_NOVERS(__gcov_merge_delta);

#endif /* GCC_VERSION_LOWER */ 

/**************************************************************************
 *
 * PROC interface
 *
 **************************************************************************/

#if GCC_VERSION_LOWER(3, 3)
/*
 *  pre-gcc 3.3 functions
 */

/* Store a portable representation of VALUE in DEST using BYTES*8-1 bits.
 * Return a non-zero value if VALUE requires more than BYTES*8-1 bits
 * to store (adapted from gcc/gcov-io.h). */
static int
store_gcov_type(gcov_type value, char *dest, size_t bytes)
{
	int upper_bit = (value < 0 ? 128 : 0);
	size_t i;

	if (value < 0) {
		gcov_type oldvalue = value;
		value = -value;
		if (oldvalue != -value)
			return 1;
	}

	for (i = 0 ; i < (sizeof(value) < bytes ? sizeof(value) : bytes) ;
	     i++) {
		dest[i] = value & (i == (bytes - 1) ? 127 : 255);
		value = value / 256;
	}

	if (value && value != -1)
		return 1;

	for(; i < bytes ; i++)
		dest[i] = 0;
	dest[bytes - 1] |= upper_bit;
	return 0;
}

/* Return size of .da file associated with BB. */
static inline size_t
sizeof_da_file(struct bb *bb)
{
	return (bb->ncounts + 1) * 8;
}

/* Store data of .da file associated with NODE to userspace memory at BUF.
 * OFFSET specifies the offset inside the .da file. COUNT is the maximum
 * number of bytes to store. Return the number of bytes stored, zero for
 * EOF or a negative number in case of error. */
static ssize_t
store_da_file(struct gcov_ftree_node *node, char *buf, size_t count,
	      loff_t offset)
{
	char data[8];
	char *from;
	ssize_t stored;
	size_t len;

	stored = 0;
	while (count > 0) {
		if (offset < 8) {
			/* Number of counts */
			if (store_gcov_type(node->bb->ncounts, data, 8))
				return -EINVAL;
			from = data + offset;
			len = 8 - offset;
		} else if (offset < node->da_size) {
			/* Count data */
			if (store_gcov_type(node->bb->counts[(offset - 8) / 8],
					    data, 8))
				return -EINVAL;
			from = data + offset % 8;
			len = 8 - offset % 8;
		} else
			break;
		if (len > count)
			len = count;
		if (copy_to_user(buf, from, len))
			return -EFAULT;
		stored += len;
		count -= len;
		offset += len;
		buf += len;
	}
	return stored;
}

#elif GCC_VERSION_LOWER(3, 4)
/*
 *   gcc 3.3 specific functions
 */

/* Return size of .da file section associated with function data FUNC. */
static inline size_t
sizeof_func_info(struct bb_function_info *func)
{
	return (size_t)
	       (/* delim */ 4 + /* strlen */ 4 + PAD4(strlen(func->name) + 1) +
	        /* delim */ 4 + /* checksum */ 4 + /* arc_count */ 4 +
	        /* count values */ func->arc_count * 8);
}


/* Return size of .da file associated with BB. */
static inline size_t
sizeof_da_file(struct bb *bb)
{
	struct bb_function_info *func;
	size_t size;

	size = ( /* magic */ 4 + /* num_func */ 4 + /* num_extra */ 4);
	for (func = bb->function_infos; func->arc_count != -1; func++)
		size += sizeof_func_info(func);
	return size;
}


/* Return the number of functions associated with BB. */
static inline gcov_type
count_functions(struct bb *bb)
{
	gcov_type result;

	for (result = 0; bb->function_infos[result].arc_count != -1;
	     result++);
	return result;
}


/* Return non-zero if OFFSET is within the range START <= OFFSET < START + SIZE,
 * zero otherwise. Update REL_OFF to contain the relative offset inside the
 * range, SIZE_VAR to contain the range size and START to point to the next
 * range after this one. */
static inline int in_range(loff_t offset, size_t size, loff_t *rel_off,
			   loff_t *start, size_t *size_var)
{
	int result;

	result = (offset >= *start) && (offset < *start + size);
	*rel_off = offset - *start;
	*start += size;
	*size_var = size;
	return result;
}


/* Store data of .da file associated with NODE to userspace memory at BUF.
 * OFFSET specifies the offset inside the .da file. COUNT is the maximum
 * number of bytes to store. Return the number of bytes stored, zero for
 * EOF or a negative number in case of error. */
static ssize_t
store_da_file(struct gcov_ftree_node *node, char *buf, size_t count,
	      loff_t offset)
{
	struct bb_function_info *func;
	gcov_type *count_ptr;
	char data[8];
	char *from;
	ssize_t stored;
	size_t len;
	size_t size;
	size_t func_off;
	size_t next_off;
	loff_t rel_off;
	loff_t start;

	func_off = 0;
	func = NULL;
	count_ptr = NULL;
	stored = 0;
	while (count > 0) {
		start = 0;
		if (in_range(offset, 4, &rel_off, &start, &size)) {
			/* Magic */
			if (store_gcov_type(-123, data, 4))
				return -EINVAL;
			from = data + rel_off;
			len = size - rel_off;
		} else if (in_range(offset, 4, &rel_off, &start, &size)) {
			/* Number of functions */
			if (store_gcov_type(count_functions(node->bb),
					    data, 4))
				return -EINVAL;
			from = data + rel_off;
			len = size - rel_off;
		} else if (in_range(offset, 4, &rel_off, &start, &size)) {
			/* Size of extra data */
			store_gcov_type(0, data, 4);
			from = data + rel_off;
			len = size - rel_off;
		} else if (offset < node->da_size) {
			/* Function data */
			rel_off = offset - 12;
			/* Try to minimize search effort */
			if (!(func && (func_off <= rel_off))) {
				func = node->bb->function_infos;
				func_off = 0;
				count_ptr = node->bb->counts;
			}
			/* Find function which is hit by offset */
			for (; func->arc_count != -1; func++) {
				next_off = func_off + sizeof_func_info(func);
				if (next_off > rel_off)
					break;
				func_off = next_off;
				count_ptr += func->arc_count;
			}
			start = 0;
			if (in_range(offset - func_off - 12, 4, &rel_off,
				     &start, &size)) {
				/* String delimiter */
				store_gcov_type(-1, data, 4);
				from = data + rel_off;
				len = size - rel_off;
			} else if (in_range(offset - func_off - 12, 4, &rel_off,
				   &start, &size)) {
				/* String length */
				if (store_gcov_type(strlen(func->name),
						    data, 4))
					return -EINVAL;
				from = data + rel_off;
				len = size - rel_off;
			} else if (in_range(offset - func_off - 12,
				   strlen(func->name), &rel_off, &start,
				   &size)) {
				/* Function name */
				from = (char *) func->name + rel_off;
			len = size - rel_off;
			} else if (in_range(offset - func_off - 12,
				   PAD4(strlen(func->name) + 1) -
				   strlen(func->name), &rel_off, &start,
				   &size)) {
				/* Nil byte padding */
				memset(data, 0, size);
				from = data;
				len = size - rel_off;
			} else if (in_range(offset - func_off - 12, 4, &rel_off,
				   &start, &size)) {
				/* String delimiter */
				store_gcov_type(-1, data, size);
				from = data + rel_off;
				len = size - rel_off;
			} else if (in_range(offset - func_off - 12, 4, &rel_off,
				   &start, &size)) {
				/* Checksum */
				store_gcov_type(func->checksum, data, 4);
				from = data + rel_off;
				len = size - rel_off;
			} else if (in_range(offset - func_off - 12, 4, &rel_off,
				   &start, &size)) {
				/* Number of arcs */
				if (store_gcov_type(func->arc_count, data, 4))
					return -EINVAL;
				from = data + rel_off;
				len = size - rel_off;
			} else if (in_range(offset - func_off - 12,
				   func->arc_count * 8, &rel_off, &start,
				   &size)) {
				/* Counts */
				if (store_gcov_type(count_ptr[rel_off / 8],
						    data, 8))
					return -EINVAL;
				from = data + rel_off % 8;
				len = 8 - rel_off % 8;
			} else {
				break;
			}
		} else
			break;
		if (len > count)
			len = count;
		if (copy_to_user(buf, from, len))
			return -EFAULT;
		stored += len;
		count -= len;
		offset += len;
		buf += len;
	}
	return stored;
}

#else
/*
 *  gcc 3.4 functions
 */

/* Determine whether counter TYPE is active in BB. */
static inline int
counter_active(struct bb *bb, unsigned int type)
{
	return (1 << type) & bb->ctr_mask;
}


/* Return the number of active counter types for BB. */
static inline unsigned int
num_counter_active(struct bb *bb)
{
	unsigned int i;
	unsigned int result;

	result = 0;
	for (i=0; i < GCOV_COUNTERS; i++)
	if (counter_active(bb, i))
			result++;
	return result;
}


/* Get number of bytes used for one entry in the gcov_fn_info array pointed to
 * by BB->functions. */
static inline unsigned int
get_fn_stride(struct bb *bb)
{
	unsigned int stride;

	stride = sizeof(struct gcov_fn_info) + num_counter_active(bb) *
		 sizeof(unsigned int);
	if (__alignof__(struct gcov_fn_info) > sizeof(unsigned int)) {
		stride += __alignof__(struct gcov_fn_info) - 1;
		stride &= ~(__alignof__(struct gcov_fn_info) - 1);
	}
	return stride;
}


/* Get the address of gcov_fn_info for function FUNC of BB. */
static inline struct gcov_fn_info *
get_fn_info(struct bb *bb, unsigned int func)
{
	return (struct gcov_fn_info *)
		((char *) bb->functions + func * get_fn_stride(bb));
}


/* Return size of .gcda counter section. */
static inline size_t
sizeof_counter_data(struct bb *bb, struct gcov_fn_info *func, unsigned int type)
{
	if (counter_active(bb, type)) {
		return /* tag */ 4 + /* length */ 4 +
		       /* counters */ func->n_ctrs[type] * 8;
	} else
		return 0;
}


/* Return size of .gcda data section associated with FUNC.  */
static inline size_t
sizeof_func_data(struct bb *bb, struct gcov_fn_info *func)
{
	size_t result;
	unsigned int type;

	result = /* tag */ 4 + /* length */ 4 + /* ident */ 4+
		 /* checksum */ 4;
	for (type=0; type < GCOV_COUNTERS; type++)
		result += sizeof_counter_data(bb, func, type);
	return result;
}


/* Get size of .gcda file associated with BB. */
static inline size_t
sizeof_da_file(struct bb *bb)
{
	size_t result;
	unsigned int i;

	result = /* magic */ 4 + /* version */ 4 + /* stamp */ 4;
	for (i=0; i < bb->n_functions; i++)
		result += sizeof_func_data(bb, get_fn_info(bb, i));
	return result;
}


/* Store a 32 bit unsigned integer value in GCOV format to memory at address
 * BUF. */
static inline void
store_int32(uint32_t i, char *buf)
{
	uint32_t *p;

	p = (int *) buf;
	*p = i;
}


/* Store a 64 bit unsigned integer value in GCOV format to memory at address
 * BUF. */
static inline void
store_int64(uint64_t i, char *buf)
{
	store_int32((uint32_t) (i & 0xffff), buf);
	store_int32((uint32_t) (i >> 32), buf + 4);
}


/* Store a gcov counter in GCOV format to memory at address BUF. The counter is
 * identified by BB, FUNC, TYPE and COUNTER. */
static inline void
store_counter(struct bb *bb, unsigned int func, unsigned int type,
	      unsigned int counter, char *buf)
{
	unsigned int counter_off;
	unsigned int type_off;
	unsigned int i;

	/* Get offset into counts array */
	type_off = 0;
	for (i=0; i < type; i++)
		if (counter_active(bb, i))
			type_off++;
	/* Get offset into values array. */
	counter_off = counter;
	for (i=0; i < func; i++)
		counter_off += get_fn_info(bb, i)->n_ctrs[type];
	/* Create in temporary storage */
	store_int64(bb->counts[type_off].values[counter_off], buf);
}


/* Store a counter section in userspace memory. The counter section is
 * identified by BB, FUNC and TYPE. The destination address is BUF. Store at
 * most COUNT bytes beginning at OFFSET. Return the number of bytes stored or a
 * negative value on error. */
static inline ssize_t
store_counter_data(struct bb *bb, unsigned int func, unsigned int type,
		  char *buf, size_t count, loff_t offset)
{
	struct gcov_fn_info *func_ptr;
	char data[8];
	char *from;
	size_t len;
	ssize_t result;
	unsigned int i;

	result = 0;
	func_ptr = get_fn_info(bb, func);
	while (count > 0) {
		if (offset < 4) {
			/* Tag ID */
			store_int32((uint32_t) GCOV_TAG_FOR_COUNTER(type),
				    data);
			len = 4 - offset;
			from = data + offset;
		} else if (offset < 8) {
			/* Tag length in groups of 4 bytes */
			store_int32((uint32_t)
				    func_ptr->n_ctrs[type] * 2, data);
			len = 4 - (offset - 4);
			from = data + (offset - 4);
		} else {
			/* Actual counter data */
			i = (offset - 8) / 8;
		/* Check for EOF */
			if (i >= func_ptr->n_ctrs[type])
				break;
			store_counter(bb, func, type, i, data);
			len = 8 - (offset - 8) % 8;
			from = data + (offset - 8) % 8;
		} 
		if (len > count)
			len = count;
		if (copy_to_user(buf, from, len))
			return -EFAULT;
		count -= len;
		buf += len;
		offset += len;
		result += len;
	}
	return result;
}


/* Store a function section and associated counter sections in userspace memory.
 * The function section is identified by BB and FUNC. The destination address is
 * BUF. Store at most COUNT bytes beginning at OFFSET. Return the number of
 * bytes stored or a negative value on error. */
static inline ssize_t
store_func_data(struct bb *bb, unsigned int func, char *buf,
		size_t count, loff_t offset)
{
	struct gcov_fn_info *func_ptr;
	char data[4];
	char *from;
	size_t len;
	unsigned int i;
	loff_t off;
	size_t size;
	ssize_t result;
	ssize_t rc;

	func_ptr = get_fn_info(bb, func);
	result = 0;
	while (count > 0) {
		if (offset < 16) {
			if (offset < 4) {
				/* Tag ID */
				store_int32((uint32_t) GCOV_TAG_FUNCTION, data);
				len = 4 - offset;
				from = data + offset;
			} else if (offset < 8) {
				/* Tag length */
				store_int32(2, data);
				len = 4 - (offset - 4);
				from = data + (offset - 4);
			} else if (offset < 12) {
				/* Function ident */
				store_int32((uint32_t) func_ptr->ident, data);
				len = 4 - (offset - 8);
				from = data + (offset - 8);
			} else {
				/* Function checksum */
				store_int32((uint32_t) func_ptr->checksum,
					    data);
				len = 4 - (offset - 12);
				from = data + (offset - 12);
			}
			/* Do the actual store */
			if (len > count)
				len = count;
			if (copy_to_user(buf, from, len))
				return -EFAULT;
		} else {
			off = 16;
			len = 0;
			for (i=0; i < GCOV_COUNTERS; i++) {
				size = sizeof_counter_data(bb, func_ptr, i);
				if (offset < off + size) {
					rc = store_counter_data(bb, func, i,
								buf, count,
								offset - off);
					if (rc < 0)
						return rc;
					len = rc;
					break;
				}
				off += size;
			}
			/* Check for EOF */
			if (i == GCOV_COUNTERS)
				break;
		}
		count -= len;
		buf += len;
		offset += len;
		result += len;
	}
	return result;
}


/* Store data of .gcda file associated with NODE to userspace memory at BUF.
 * OFFSET specifies the offset inside the .da file. COUNT is the maximum
 * number of bytes to store. Return the number of bytes stored, zero for
 * EOF or a negative number in case of error. */
static ssize_t
store_da_file(struct gcov_ftree_node *node, char *buf, size_t count,
	      loff_t offset)
{
	struct bb *bb;
	char data[4];
	char *from;
	size_t len;
	unsigned int i;
	loff_t off;
	size_t size;
	ssize_t result;
	ssize_t rc;

	bb = node->bb;
	result = 0;
	while (count > 0) {
		if (offset < 12) {
			if (offset < 4) {
				/* File magic */
				store_int32((uint32_t) GCOV_DATA_MAGIC, data);
				len = 4 - offset;
				from = data + offset;
			} else if (offset < 8) {
				/* File format/GCC version */
				store_int32(gcov_version, data);
				len = 4 - (offset - 4);
				from = data + (offset - 4);
			} else {
				/* Time stamp */
				store_int32((uint32_t) bb->stamp, data);
				len = 4 - (offset - 8);
				from = data + (offset - 8);
			}
			/* Do the actual store */
			if (len > count)
				len = count;
			if (copy_to_user(buf, from, len))
				return -EFAULT;
		} else {
			off = 12;
			len = 0;
			for (i=0; i < bb->n_functions; i++) {
				size = sizeof_func_data(bb, get_fn_info(bb, i));
				if (offset < off + size) {
					rc = store_func_data(bb, i, buf, count,
							     offset - off);
					if (rc < 0)
						return rc;
					len = rc;
					break;
				}
				off += size;
			}
			/* Check for EOF */
			if (i == bb->n_functions)
				break;
		}
		count -= len;
		buf += len;
		offset += len;
		result += len;
	}
	return result;
}
#endif /* if GCC_VERSION_LOWER */

/* Return size of header which precedes .da file entry associated with BB
 * in the vmlinux file. */
static inline size_t
sizeof_vmlinux_header(struct bb *bb)
{
	return 8 + PAD8(strlen(bb->filename) + 1);
}

/* Update data related to vmlinux file. */
static void
update_vmlinux_data(void)
{
	struct gcov_ftree_node *node;
	loff_t offset;

	offset = 0;
	for (node = leaf_nodes; node; node = node->next) {
		node->offset = offset;
		node->da_size = sizeof_da_file(node->bb);
		node->header_size = sizeof_vmlinux_header(node->bb);
		offset += node->header_size + node->da_size;
	}
}

/* Read .da or vmlinux file. */
static ssize_t read_gcov(struct file *file, char *buf, size_t count,
			 loff_t *pos)
{
	struct gcov_ftree_node *node;
	struct proc_dir_entry *dir_entry;
	ssize_t rc;

	down(&gcov_lock);
	dir_entry = PDE(file->f_path.dentry->d_inode);
	rc = 0;

	node = (struct gcov_ftree_node *) dir_entry->data;
	if (node)
		rc = store_da_file(node, buf, count, *pos);

	if (rc > 0)
		*pos += rc;
	up(&gcov_lock);
	return rc;
}

static inline void
reset_bb(struct bb* bb)
{
#if GCC_VERSION_LOWER(3, 4)
	memset(bb->counts, 0, bb->ncounts * sizeof(gcov_type));
#else
	const struct gcov_ctr_info *ctr;
	unsigned int i;

	ctr = bb->counts;
	for (i=0; i < GCOV_COUNTERS; i++)
		if (counter_active(bb, i)) {
			memset(ctr->values, 0, ctr->num * sizeof(gcov_type));
			ctr++;
		}
#endif /* GCC_VERSION_LOWER */
}

/* Reset counters on write request. */
static ssize_t
write_gcov(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
	struct gcov_ftree_node *node;
	struct proc_dir_entry *dir_entry;

	down(&gcov_lock);
	dir_entry = PDE(file->f_path.dentry->d_inode);
	node = (struct gcov_ftree_node *) dir_entry->data;
	reset_bb(node->bb);
	up(&gcov_lock);
	return count;
}

/* Return a newly allocated copy of STRING. */
static inline char *
strdup(const char *string)
{
	char *result;

	result = (char *) kmalloc(strlen(string) + 1, GFP_KERNEL);
	if (result)
		strcpy(result, string);
	return result;
}

/* Allocate a new node and fill in NAME and BB. */
static struct gcov_ftree_node *
alloc_node(const char *name, struct bb *bb)
{
	struct gcov_ftree_node *node;

	node = (struct gcov_ftree_node *)
		kmalloc(sizeof(struct gcov_ftree_node), GFP_KERNEL);
	if (!node)
		return NULL;
	memset(node, 0, sizeof(struct gcov_ftree_node));
	node->fname = strdup(name);
	if (!node->fname) {
		kfree(node);
		return NULL;
	}
	node->bb = bb;
	node->status = status_normal;
	return node;
}

/* Free memory allocated for BB. */
static void
free_bb(struct bb *bb)
{
#if GCC_VERSION_LOWER(3,4)
	kfree(bb);
#else
	kfree(bb->functions);
	kfree(bb);
#endif /* GCC_VERSION_LOWER */
}

/* Free memory allocated for NODE. */
static void
free_node(struct gcov_ftree_node *node)
{
	if (node == &tree_root)
		return;
	if (node->fname)
		kfree(node->fname);
	if (node->status == status_ghost)
		free_bb(node->bb);
	kfree(node);
}

/* Remove proc filesystem entries associated with NODE. */
static void delete_from_proc(struct gcov_ftree_node *node)
{
	struct proc_dir_entry *parent;
	int i;

	parent = (node->parent) ? node->parent->proc[0] : &proc_root;

	for (i = 0; i < sizeof(node->proc) / sizeof(node->proc[0]); i++) {
		if (node->proc[i] && node->proc[i]->name)
			remove_proc_entry(node->proc[i]->name, parent);
	}
}

/* Release all resources associated with NODE. If NODE is a directory node,
 * also clean up all children. */
static void cleanup_node(struct gcov_ftree_node *node)
{
	struct gcov_ftree_node *curr;
	struct gcov_ftree_node *next;
	struct gcov_ftree_node *prev;

	next = node;
	do {
		/* Depth first traversal of all children */
		curr = next;
		while (curr->files)
			curr = curr->files;
		if (curr->sibling)
			next = curr->sibling;
		else
			next = curr->parent;
		/* Remove from tree */
		if (curr->parent) {
			if (curr->parent->files == curr)
				curr->parent->files = curr->sibling;
			else {
				for (prev = curr->parent->files;
				     prev->sibling != curr;
				     prev = prev->sibling);
				prev->sibling = curr->sibling;
			}
		}
		/* Remove from leaf node list if necessary */
		if (curr->bb) {
			if (leaf_nodes == curr)
				leaf_nodes = curr->next;
			else {
				for (prev = leaf_nodes;
				     prev && (prev->next != curr);
				     prev = prev->next);
				if (prev)
					prev->next = curr->next;
			}
		}
		/* Delete node */
		delete_from_proc(curr);
		free_node(curr);
	} while (node != curr);
}

/* Clean up NODE and containing path in case it would be left empty. */
static void
cleanup_node_and_path(struct gcov_ftree_node *node)
{
	/* sph: I'm not convinced that this is quite
	 * enough work. Since it is only used on error paths
	 * i'll leave it for now
	 */
	while (node->parent &&
	       !node->parent->files->sibling)
		node = node->parent;
	cleanup_node(node);
}

/* Create a new directory node named NAME under PARENT. Upon success return
 * zero and update RESULT to point to the newly created node. Return non-zero
 * otherwise. */
static int create_dir_node(struct gcov_ftree_node *parent, char *name,
			   struct gcov_ftree_node **result)
{
	struct gcov_ftree_node *node;

	/* Initialize new node */
	node = alloc_node(name, NULL);
	if (!node)
		return -ENOMEM;
	/* Create proc filesystem entry */
	node->proc[0] = proc_mkdir(name, parent->proc[0]);
	if (!node->proc[0]) {
		free_node(node);
		return -EIO;
	}
	/* Insert node into tree */
	node->parent = parent;
	node->sibling = parent->files;
	parent->files = node;
	*result = node;
	return 0;
}

static struct file_operations proc_gcov_operations = {
	read: read_gcov,
	write: write_gcov,
	owner: THIS_MODULE
};

/* Create a new file node named NAME under PARENT. Associate node with BB.
 * Return zero upon success, non-zero otherwise. */
static int
create_file_node(struct gcov_ftree_node *parent, char *name, struct bb *bb)
{
	struct gcov_ftree_node *node;
	char *link_target, *link_name;
	int is_source, i, mangled;

	/* Initialize new node */
	node = alloc_node(name, bb);
	if (!node)
		return -ENOMEM;

	/* some of the source files are mangled. Be careful
	 * to move the link name and target appropriately */
	mangled = (strstr(name, mangle_token) == name);
	if (mangled)
		name += strlen(mangle_token);

	/* Create proc filesystem entry */
	node->proc[0] = create_proc_entry(name, S_IWUSR | S_IRUGO,
					  parent->proc[0]);
	if (!node->proc[0]) {
		free_node(node);
		return -EIO;
	}
	node->proc[0]->data = node;
	node->proc[0]->proc_fops = &proc_gcov_operations;
	node->proc[0]->size = sizeof_da_file(bb);
	if (gcov_link) {
		link_target = (char *) kmalloc(strlen(bb->filename) +
					       strlen(da_ending) + 
					       100,
					       GFP_KERNEL);
		if (!link_target) {
			delete_from_proc(node);
			free_node(node);
			return -ENOMEM;
		}

		for (i = 0; i < sizeof(endings) / sizeof(endings[0]); i++) {
			is_source = ( strcmp ( endings[i], "c" ) == 0 );
			
			/* produce the target by replacing the ending */
			strcpy(link_target, bb->filename);
			link_target[strlen(link_target) -
				    strlen(da_ending)] = 0;
			strcat(link_target, endings[i]);
	
			/* the link name also has the new extension */
			link_name = strrchr(link_target, '/') + 1;

			if ( mangled ) {
				if ( is_source ) {
					/* the target and source need nobbling,
					 * so just nobble the target
					 */
					char *p,*q;
					for (p=link_name, q=link_name+strlen(mangle_token);
					     *q; *p++=*q++);
					*p = 0;
				}
				else {
					/* just nobble the link name */
					link_name += strlen(mangle_token);
				}
			}

			node->proc[i + 1] = proc_symlink(link_name,
							 parent->proc[0],
							 link_target);

			if (!node->proc[i + 1]) {
				kfree(link_target);
				delete_from_proc(node);
				free_node(node);
				return -EIO;
			}
		}
		kfree(link_target);
	}


	/* Insert node into tree */
	node->parent = parent;
	node->sibling = parent->files;
	parent->files = node;
	node->next = leaf_nodes;
	leaf_nodes = node;
	return 0;
}

static int create_child_node(struct gcov_ftree_node *parent,
			     char *fname,
			     struct gcov_ftree_node **node)
{
	int rc;

	/* Does this node already exist? */
	for (*node = parent->files; *node; *node = (*node)->sibling) {
		if (strcmp((*node)->fname, fname) == 0)
			return 0;
	}

	if ((rc = create_dir_node(parent,fname,node)) != 0) {
		*node = NULL;
		return rc;
	}
	return 0;
}

/* Create tree node and proc filesystem entry for BB. Create subdirectories as
 * necessary. Return zero upon success, non-zero otherwise. */
static int create_node(struct bb *bb)
{
	struct gcov_ftree_node *parent;
	struct gcov_ftree_node *node;
	char *filename;
	char *curr;
	char *next;
	int rc;

	/* Put all files under the module/<modulename> location */
	if ((rc = create_child_node(&tree_root, GCOV_PROC_MODULE, &parent)) != 0)
		goto out1;

	if (current_context) {
		if ((rc=create_child_node(parent, current_context->module->name,
					  &node)) != 0)
			goto out2;
		parent = node;
	}

	/* we will be modifying bb->filename, so copy it */
	if ((filename = kmalloc(strlen(bb->filename) + 1, GFP_KERNEL)) == NULL) {
		rc = -ENOMEM;
		goto out3;
	}
	strcpy(filename, bb->filename);

	/* Create/find the directory hierarchy */
	curr = filename+1;
	while ((next = strchr(curr, '/'))) {
		*next = 0;
		if ((rc=create_child_node(parent, curr, &node)) != 0)
			goto out4;
		
		parent = node;
		curr = next + 1;
	}
	rc = create_file_node(parent, curr, bb);
	kfree(filename);
	return rc;

 out4:
	kfree(filename);
	/* FALLTHROUGH */
 out3:
	/* FALLTHROUGH */
 out2:
	cleanup_node_and_path(parent);
	/* FALLTHROUGH */
 out1:
	return rc;
}

/* Add count data from SOURCE to DEST. */
static void
merge_bb(struct bb *dest, struct bb *source)
{
#if GCC_VERSION_LOWER(3, 4)
	long i;

	for (i = 0; i < dest->ncounts; i++)
		dest->counts[i] += source->counts[i];
#else
	unsigned int i;
	unsigned int j;

	for (i=0; i < num_counter_active(dest); i++)
		for (j=0; j < dest->counts[i].num; j++)
			dest->counts[i].values[j] +=
				source->counts[i].values[j];
#endif /* GCC_VERSION_LOWER */
}

/* Return a copy of BB which contains only data relevant to this module. */
static struct bb *
clone_bb(struct bb *bb)
{
	struct bb *result;
	size_t len;

#if GCC_VERSION_LOWER(3, 3) 
	/* Allocate memory */
	len = sizeof(struct bb) + bb->ncounts * sizeof(gcov_type) +
	      strlen(bb->filename) + 1;
	result = (struct bb *) kmalloc(len, GFP_KERNEL);
	if (!result)
		return NULL;
	memset(result, 0, len);
	/* Copy count data */
	result->counts = (gcov_type *) (result + 1);
	result->ncounts = bb->ncounts;
	memcpy(result->counts, bb->counts, result->ncounts * sizeof(gcov_type));
	/* Copy filename */
	result->filename = (const char *) &result->counts[result->ncounts];
	strcpy((char *) result->filename, bb->filename);
#elif GCC_VERSION_LOWER(3, 4)
	unsigned int i;
	char *name;

	/* Allocate memory */
	len = sizeof(struct bb) + bb->ncounts * sizeof(gcov_type) +
	      strlen(bb->filename) + 1 + sizeof(struct bb_function_info);
	for (i = 0; bb->function_infos[i].arc_count != -1; i++)
		len += sizeof(struct bb_function_info) +
		       strlen(bb->function_infos[i].name) + 1;
	result = (struct bb *) kmalloc(len, GFP_KERNEL);
	if (!result)
		return NULL;
	memset(result, 0, len);
	/* Copy count data */
	result->counts = (gcov_type *) (result + 1);
	result->ncounts = bb->ncounts;
	memcpy(result->counts, bb->counts, result->ncounts * sizeof(gcov_type));
	/* Prepare copy of function infos */
	result->function_infos = (struct bb_function_info *)
					&result->counts[result->ncounts];
	/* Copy filename */
	result->filename = (const char *) &result->function_infos[i + 1];
	strcpy((char *) result->filename, bb->filename);
	/* Copy function infos */
	name = (char *) result->filename + strlen(result->filename) + 1;
	for (i = 0; bb->function_infos[i].arc_count != -1; i++) {
		result->function_infos[i].checksum =
			bb->function_infos[i].checksum;
		result->function_infos[i].arc_count =
			bb->function_infos[i].arc_count;
		strcpy(name, bb->function_infos[i].name);
		result->function_infos[i].name = name;
		name += strlen(name) + 1;
	}
	result->function_infos[i].arc_count = -1;
	result->sizeof_bb = bb->sizeof_bb;
#else
	unsigned int active;
	unsigned int i;
	char *name;
	struct gcov_fn_info *func;

	/* Allocate memory for struct bb */
	active = num_counter_active(bb); 
	len = sizeof(struct bb) +
	      sizeof(struct gcov_ctr_info) * active +
	      strlen(bb->filename) + 1;
	for (i=0; i < active; i++)
		len += sizeof(gcov_type) * bb->counts[i].num;
	result = (struct bb *) kmalloc(len, GFP_KERNEL);
	if (!result)
		return NULL;
	memset(result, 0, len);
	/* Allocate memory for array of struct gcov_fn_info */
	len = bb->n_functions * get_fn_stride(bb);
	func = (struct gcov_fn_info *) kmalloc(len, GFP_KERNEL);
	if (!func) {
		kfree(result);
		return NULL;
	}
	/* Copy function data */
	memcpy(func, bb->functions, len);
	result->functions = func;
	/* Copy counts */
	for (i=0; i < active; i++) {
		result->counts[i].num = bb->counts[i].num;
		result->counts[i].merge = bb->counts[i].merge;
		if (i == 0) {
			result->counts[i].values =
				(gcov_type *) &result->counts[active];
		} else {
			result->counts[i].values =
				result->counts[i - 1].values +
				result->counts[i - 1].num;
		}
		memcpy(result->counts[i].values, bb->counts[i].values,
		       sizeof(gcov_type) * result->counts[i].num);
	}
	/* Copy rest */
	result->stamp = bb->stamp;
	name = (char *) (result->counts[active - 1].values +
			 result->counts[active - 1].num);
	strcpy(name, bb->filename);
	result->filename = name;
	result->n_functions = bb->n_functions;
	result->ctr_mask = bb->ctr_mask;
#endif /* GCC_VERSION_LOWER */
	return result;
}

/* Return non-zero if BB1 and BB2 are compatible, zero otherwise. */
static int
is_compatible(struct bb *bb1, struct bb *bb2)
{
#if GCC_VERSION_LOWER(3, 3)
	return (bb1->ncounts == bb2->ncounts);
#elif GCC_VERSION_LOWER(3, 4)
	int i;

	if ((bb1->ncounts != bb2->ncounts) ||
	    (bb1->sizeof_bb != bb2->sizeof_bb))
		return 0;
	for (i = 0; (bb1->function_infos[i].arc_count != -1) &&
		     (bb2->function_infos[i].arc_count != -1); i++)
		if (bb1->function_infos[i].checksum !=
		    bb2->function_infos[i].checksum)
			return 0;
	return (bb1->function_infos[i].arc_count == -1) &&
		(bb2->function_infos[i].arc_count == -1);
#else
	return (bb1->stamp == bb2->stamp);
#endif /* GCC_VERSION_LOWER */
}



/* If there is a ghosted node for BB, merge old and current data, set status
 * to normal and return zero. Return non-zero otherwise. */
static int
revive_node(struct bb *bb)
{
	struct gcov_ftree_node *node;

	/* Check for a ghosted node */
	for (node = leaf_nodes; node &&
	     (strcmp(node->bb->filename, bb->filename) != 0);
	     node=node->next);
	if (!node)
		return -ENOENT;
	/* Check for compatible data */
	if (!is_compatible(bb, node->bb)) {
		GCOV_PROC_ERR ( "discarding saved data for %s due to "
				"incompatibilities\n", bb->filename );
		cleanup_node_and_path(node);
		update_vmlinux_data();
		return -EINVAL;
	}
	/* Revive */
	merge_bb(bb, node->bb);
	kfree(node->bb);
	node->bb = bb;
	node->status = status_normal;
	return 0;
}

/* Make a copy of the struct bb associated with node and set node status to
 * ghost. Return zero on success, non-zero otherwise. */
static int
ghost_node(struct gcov_ftree_node *node)
{
	struct bb *bb;

	/* Ghost node instead of removing it */
	bb = clone_bb(node->bb);
	if (!bb) {
		GCOV_PROC_ERR ( "not enough memory to save data for %s", 
				node->bb->filename );
		return -ENOMEM;
	}
	node->bb = bb;
	node->status = status_ghost;
	return 0;
}

/* Callback used to keep track of changes in the bb list. */
static void
gcov_proc_callback(enum gcov_cmd cmd, struct bb *bb)
{
	struct gcov_ftree_node *node;
	int rc;

	down(&gcov_lock);
	switch (cmd) {
	case gcov_add:
		if (gcov_persist && (revive_node(bb) == 0))
			break;
		/* Insert node */
		rc = create_node(bb);
		if (rc) {
			GCOV_PROC_ERR ( "add failed: could not create node for %s (err=%d)\n",
					bb->filename, rc );
		}
		update_vmlinux_data();
		break;
	case gcov_remove:
		/* Find node to remove */
		for (node = leaf_nodes; node && (node->bb != bb);
		     node=node->next);
		if (!node)
			break;
		if (gcov_persist && (ghost_node(node) == 0))
			break;
		/* Remove node and empty path */
		cleanup_node_and_path(node);
		update_vmlinux_data();
		break;
	}
	up(&gcov_lock);
}



/**************************************************************************
 *
 * Module intialisation and cleanup
 *
 **************************************************************************/

/* Initialize module. */
static int __init __gcov_init_module(void)
{
	struct bb *bb;
	int rc;

	GCOV_PROC_LOG ( "proc init (persist=%d)\n",
			gcov_persist );
	/* Initialize root node and /proc/gcov entry */
	tree_root.fname = GCOV_PROC_ROOT;
	tree_root.proc[0] = proc_mkdir(tree_root.fname, NULL);
	if (!tree_root.proc[0]) {
		GCOV_PROC_ERR ( "init failed: could not "
				"create root proc filesystem entry\n" );
		return -EIO;
	}

	/* Initialize /proc/gcov tree */
	spin_lock(&gcov_core_lock);
	for (bb = bb_head; bb ; bb = bb->next) {
		rc = create_node(bb);
		if (rc) {
			GCOV_PROC_ERR ( "init failed: could not create node "
					"for %s (err=%d)\n", bb->filename, rc );
			cleanup_node(&tree_root);
			return rc;
		}
	}
	gcov_callback = gcov_proc_callback;
	update_vmlinux_data();
	spin_unlock(&gcov_core_lock);
	up(&gcov_lock);
	return 0;
}

/* Clean up module data. */
static void __exit __gcov_cleanup_module(void)
{
	down(&gcov_lock);
	gcov_callback = NULL;
	cleanup_node(&tree_root);
	GCOV_PROC_LOG ( "proc unloaded\n" );
}

module_init(__gcov_init_module);
module_exit(__gcov_cleanup_module);

MODULE_AUTHOR ( "Steve Hodgson <shodgson@solarflare.com>" );
MODULE_DESCRIPTION ( "GCOV Standalone kernel module" );
MODULE_LICENSE ( "GPL" );

/*
 * Local variables:
 *  c-basic-offset: 8
 *  c-indent-level: 8
 *  tab-width: 8
 *  indent-tabs-mode: 1
 * End:
 */
