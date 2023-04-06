/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2023 Advanced Micro Devices, Inc. */
/*
 ****************************************************************************
 *
 * A library to allocate hugepages in the kernelspace
 * (which is not encouraged and not straightforward).
 *
 * How it works: the userspace donates a memfd file to the kernel module via
 * ioctl(). Then the library calls ftruncate(), fallocate(), mmap(),
 * pin_user_pages() and munmap() to get an instance of a 2 MiB hugepage,
 * which we can give to NIC after dma_map_single(). For older kernels without
 * the memfd support, the library calls hugetlb_file_setup() directly.
 *
 * Ideally, the userspace should do the allocation itself, i.e. ftruncate(),
 * fallocate(), mmap(), and then make an ioctl() with the virtual address.
 * In this case, we become aligned with the kernel API, and the library
 * degenerates into a single pin_user_pages() call. This may require
 * significant workflow refactoring in Onload.
 *
 ****************************************************************************
 */

#ifndef __OO_HUGETLB_H__
#define __OO_HUGETLB_H__

#include <onload/common.h>
#include <onload/atomics.h>

#define OO_HUGEPAGE_SIZE (2 * 1024 * 1024)

struct oo_hugetlb_allocator {
	struct file *filp;
	off_t offset;
	atomic_t refcnt;
};

struct oo_hugetlb_page {
	struct file *filp;
	struct page *page;
};

/* Create/destroy the memory allocator. */

/*
 * oo_hugetlb_allocator_create - Create a hugepage allocator.
 *
 * Parameters:
 *   fd:             A donated memfd file descriptor to use for hugepage
 *                   allocation or -1 on systems without memfd_create().
 *
 * Return:
 *   On success, get a file reference identified by the file descriptor
 *   or open a pseudo file with hugetlb_file_setup(), and return a valid
 *   pointer to use later for allocation.
 *
 *   On failure, return a negative error number:
 *     ENOSYS: Unable to find or call hugetlb_file_setup() in absence of memfd.
 *     ENOMEM: Kernel memory allocation failure.
 *     EINVAL: User error, e.g. a wrong file descriptor.
 *     Those, returned by hugetlb_file_setup().
 *
 * Notes:
 *   EINVAL should be treated as a fatal error indicating a software defect.
 */
extern struct oo_hugetlb_allocator *oo_hugetlb_allocator_create(int fd);

extern struct oo_hugetlb_allocator *
oo_hugetlb_allocator_get(struct oo_hugetlb_allocator *);

extern void oo_hugetlb_allocator_put(struct oo_hugetlb_allocator *);

static inline void
oo_hugetlb_page_reset(struct oo_hugetlb_page *page)
{
	page->filp = NULL;
	page->page = NULL;
}

/* Allocate/free one hugepage. */

extern int
oo_hugetlb_page_alloc_raw(struct oo_hugetlb_allocator *,
		struct file **, struct page **);

/*
 * oo_hugetlb_page_alloc - Allocate one hugepage OO_HUGEPAGE_SIZE bytes.
 *
 * Return:
 *   0 on success or a negative error number otherwise. Additionally,
 *   reset an instance of oo_hugetlb_page so that oo_hugetlb_page_valid()
 *   returns False, if allocation fails.
 *
 * Notes:
 *   The hugepage allocator does not implement locking. The user must
 *   serialise accesses to the allocator to prevent race conditions.
 *
 *   The hugepage instance is not tied to the allocator lifespan,
 *   i.e. the users can legally destroy the allocator while the
 *   hugepage is still in use.
 *
 *   Allocation happens on behalf of the userspace process and is not
 *   suitable for the GFP_ATOMIC contexts.
 */
static inline int
oo_hugetlb_page_alloc(struct oo_hugetlb_allocator *alloc,
		struct oo_hugetlb_page *page)
{
	return oo_hugetlb_page_alloc_raw(alloc, &page->filp, &page->page);
}

extern void oo_hugetlb_page_free_raw(struct file *, struct page *);

static inline void oo_hugetlb_page_free(struct oo_hugetlb_page *page)
{
	oo_hugetlb_page_free_raw(page->filp, page->page);
	oo_hugetlb_page_reset(page);
}

/* Misc. */

/*
 * oo_hugetlb_pages_prealloc - Preallocate number of hugepages
 * to support EF_PREALLOC_PACKETS.
 *
 * Return:
 *   0 on success, or an error number returned by vfs_truncate()
 *   or vfs_fallocate().
 */
extern int
oo_hugetlb_pages_prealloc(struct oo_hugetlb_allocator *, int);

static inline bool
oo_hugetlb_page_valid(struct oo_hugetlb_page *page)
{
	return page->filp && page->page;
}

#endif /* __OO_HUGETLB_H__ */
