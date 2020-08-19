/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  Andrew Rybchenko
**  \brief  Memory leaks debugging
**   \date  2004/10/05
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_TOOLS_MEMLEAK_DEBUG_H__
#define __CI_TOOLS_MEMLEAK_DEBUG_H__

#include "ci/tools/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! simple OOM provoker */
#define CI_RANDOM_ERROR() (((ci_frc32_get() >> 4)  % 4 ) == 0 )

#define CI_RANDOM_OOM_RET(ret) 			        \
do { 						        \
  if (CI_RANDOM_ERROR()) {                              \
    ci_log("%s: random oom rc=%d", __FUNCTION__,ret);	\
    return (ret);				        \
  }						        \
} while(0);

#define CI_RANDOM_OOM_JUMP(label)		            \
do { 						            \
  if (CI_RANDOM_ERROR()) {                                  \
    ci_log("%s: random oom jump=%s", __FUNCTION__, #label); \
    goto fail##label;                                       \
  }						            \
} while(0);

/*! Maximum number of allocation table bulks */
#define CI_ALLOC_TABLE_BULKS    1024
/*! Size of the bulk in allocation table */
#define CI_ALLOC_TABLE_BULK_2   7
#define CI_ALLOC_TABLE_BULK_SZ  (1 << CI_ALLOC_TABLE_BULK_2)


/*! Information about allocated memory region */
struct ci_alloc_entry {
  void       *addr;  /*!< Pointer to allocated memory */
  size_t      size;  /*!< Size of allocated memory */
  const char *file;  /*!< File name of call-site of allocator */
  unsigned    line;  /*!< Line no of call-site of allocation */
  int         type;  /*!< Type of allocation (k/v)malloc */
  int        scratch;/*<! Temp used while parsing table */
};

/*! Information about allocation table size and its content */
struct ci_alloc_info {
  unsigned int  bulk;   /*!< Number of the bulk to get */
  struct ci_alloc_entry entries[CI_ALLOC_TABLE_BULK_SZ];
};

/*! Size of input/control information in 'struct ci_alloc_info' */
#define CI_ALLOC_INFO_SIZEOF_CTRL \
  (sizeof(struct ci_alloc_info) -               \
   sizeof(((struct ci_alloc_info *)0)->entries))


#ifdef __KERNEL__

#if CI_MEMLEAK_DEBUG_ALLOC_TABLE


/*! Memory allocation table */
extern struct ci_alloc_entry *ci_alloc_table[CI_ALLOC_TABLE_BULKS];

/*! Current size of the allocation table */
extern unsigned int ci_alloc_table_sz;


/*!
 * Add address, size and call-site info in allocation table.
 *
 * \param addr      Address
 * \param size      Size of the memory block
 * \param type      Type of allocation (k/v)malloc (0/1)
 * \param file      File of allocation call-site
 * \param line      Line of allocation call-site
 */
extern void ci_alloc_table_add(void *addr, size_t size, int type,
                               const char *file, unsigned line);

/*!
 * Delete address from allocation table.
 *
 * \param addr      Target address
 * \param type      Type of allocation (k/v)malloc (0/1)
 */
extern void ci_alloc_table_del(void *addr, int type);

/*!
 * Check for memory leaks, and output a table if any are found
 */

extern void ci_alloc_memleak_test(void);

/* For populating /proc */
extern int ci_alloc_memleak_readproc (char *buf, char **start, off_t offset,
                                      int count, int *eof, void *data);

/*!
 * Memory allocation wrapper with debugging using allocation table.
 *
 * \param n     Bytes to be allocated
 *
 * \retval Pointer to allocated memory
 */
ci_inline void* ci_alloc_memleak_debug(size_t n, const char *file, unsigned ln)
{
  void *addr = __ci_alloc(n);
  ci_alloc_table_add(addr, n, 0, file, ln);
  return addr;
}

ci_inline void* ci_atomic_alloc_memleak_debug(size_t n, const char *file, unsigned ln)
{
  void *addr = __ci_atomic_alloc(n);
  ci_alloc_table_add(addr, n, 0, file, ln);
  return addr;
}

ci_inline void * ci_alloc_fn_memleak_debug(size_t n)
{
  void *addr = __ci_alloc(n);
  ci_alloc_table_add(addr, n, 0, "via-func-ptr", 100);
  return addr;
}

/*!
 * Memory deallocation wrapper with debugging using allocation table.
 *
 * \param p     Pointer to allocated memory to be freed
 */
ci_inline void ci_free_memleak_debug(void* p) {
  ci_alloc_table_del(p, 0);
  __ci_free(p);
}


/*!
 * Memory allocation wrapper with debugging using allocation table.
 *
 * \param n     Bytes to be allocated
 *
 * \retval Pointer to allocated memory
 */
ci_inline void* ci_vmalloc_memleak_debug(size_t n, const char *file, unsigned ln)
{
  void *addr = __ci_vmalloc(n);

  ci_alloc_table_add(addr, n, 1, file, ln);
  return addr;
}

ci_inline void* ci_vmalloc_fn_memleak_debug(size_t n)
{
  void *addr = __ci_vmalloc(n);

  ci_alloc_table_add(addr, n, 1, "via-func-ptr", 100);
  return addr;
}


/*!
 * Memory deallocation wrapper with debugging using allocation table.
 *
 * \param p     Pointer to allocated memory to be freed
 */
ci_inline void ci_vfree_memleak_debug(void* p) {
  ci_alloc_table_del(p, 1);
  __ci_vfree(p);
}


#endif /* CI_MEMLEAK_DEBUG_ALLOC_TABLE */

#endif /* __ci_driver__ */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !__CI_TOOLS_MEMLEAK_DEBUG_H__ */

/*! \cidoxg_end */
