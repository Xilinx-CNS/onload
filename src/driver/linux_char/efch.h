/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
#ifndef __EFCH_H__
#define __EFCH_H__

#include <ci/efrm/resource.h>
#include <ci/driver/internal.h>
#include <ci/efch/resource_id.h>


/*--------------------------------------------------------------------
 *
 * configuration
 *
 *--------------------------------------------------------------------*/

/* Enable this to keep a circular list of all ci_resource_table_t structures,
   so that efab_priv_dump can display all privs (otherwise it can still
   display the one it is passed). Update this comment if you use
   priv_list for anything else... */
/* As far as I know, it is not used currently. */
#define CI_CFG_PRIVATE_T_DEBUG_LIST     0

/* How big the inline resource table should be.  This should reflect the
** number of resources an FD is typically using. 
*/
#define CI_DEFAULT_RESOURCE_TABLE_SIZE	5



/*--------------------------------------------------------------------
 *
 * efch_resource_ops
 *
 *--------------------------------------------------------------------*/

struct ci_private_char_s;
struct ci_resource_alloc_s;
struct ci_resource_op_s;
union ci_filter_add_u;
struct ci_resource_table_s;
struct efch_resource_s;
typedef struct ci_resource_table_s ci_resource_table_t;
struct efch_resource_s;
struct efch_capabilities_in;
struct efch_capabilities_out;


/**
 * Operations supported by a char resource (efrm_resource_char_t).
 * Note that some operations act on resources while others act on
 * resource managers.
 */
typedef struct efch_resource_ops_s {
  /** Allocates a new resource and ties it to a resource manager */
  int  (*rm_alloc)(struct ci_resource_alloc_s *args_results,
		   ci_resource_table_t* rt, struct efch_resource_s* rs,
                   int intf_ver_id);

  /** Frees a resource */
  void (*rm_free)(struct efch_resource_s *);

  /**
   * Memory-map a resource.  If [*bytes] is zero then the implementation
   * should return without doing anything (and without error).  The
   * implementation should subtract the number of bytes actually mapped
   * from [*bytes].  ie. It is not an error if [*bytes] is larger than the
   * area the resource has to be mmap()ed.  Clearly the implementation
   * should not attempt to map more than [*bytes]!
   *
   * [map_num], [offset] and [vma] should be passed through to
   * ci_mmap_pages() etc. unmodified.
   */
  int  (*rm_mmap)(struct efrm_resource*, unsigned long* bytes,
                  struct vm_area_struct* vma, int index);

  /** No-page handler.  Returns page number or (unsigned) -1 if fails.
   *  The only current implementation is Linux.
   */
  struct page* (*rm_nopage)(struct efrm_resource*, struct vm_area_struct* vma,
                            unsigned long offset, unsigned long map_size);

  /** dump resource info (optionally within context with priv_opt), and write
   line_prefix at the start of each line. */
  void (*rm_dump)(struct efrm_resource*, ci_resource_table_t *rt, 
		  const char *line_prefix);

  /** handle resource ops for this resource type */
  int (*rm_rsops)(struct efch_resource_s* rs, ci_resource_table_t* rt,
		  struct ci_resource_op_s* op, int* copy_out);

  /** Return the size of the memory mapping of the given type. */
  int (*rm_mmap_bytes)(struct efrm_resource*, int map_type_index);

} efch_resource_ops;


struct efch_filter_list {
  spinlock_t lock;
  ci_dllist  filters;
  int        next_id;
  int        wrapped;
};


struct efch_memreg;


/* Flags to enable us to determine which sniff filters we have installed */
#define EFCH_RX_SNIFF 0x01
#define EFCH_TX_SNIFF 0x02
/* TX sniff enable bit */
#define EFCH_TX_SNIFF_ENABLE 0x01
typedef struct efch_resource_s {
  struct efrm_resource  *rs_base;
  efch_resource_ops     *rs_ops;
  union {
    struct {
      struct efch_filter_list fl;
      unsigned sniff_flags;
    } vi;
    struct {
      struct efch_filter_list fl;
      unsigned sniff_flags;
    } vi_set;
    struct efch_memreg *memreg;
  };
} efch_resource_t;




/*--------------------------------------------------------------------
 *
 * ci_resource_table_t - holds a resource table from user of 
 * the resource driver
 *
 *--------------------------------------------------------------------*/

struct ci_resource_table_s {
#if CI_CFG_PRIVATE_T_DEBUG_LIST
  struct list_head      priv_list;      
#endif

  unsigned		access;		/*!< capabilities */
# define		CI_CAP_BAR	0x01    /* raw access to apertures */
# define		CI_CAP_PHYS	0x02    /* can use physical addresses*/
# define		CI_CAP_DRV	0x04    /* can use ci_driver safely */

  efch_resource_t*   resource_table_static[CI_DEFAULT_RESOURCE_TABLE_SIZE];

  /* highwater is next index to allocate; table is only ever added to */
  volatile uint32_t resource_table_highwater;
  volatile uint32_t resource_table_size;
  efch_resource_t**volatile resource_table;
} /* ci_resource_table_t */ ;

void ci_resource_table_ctor( ci_resource_table_t *p, unsigned access);
void ci_resource_table_dtor( ci_resource_table_t *p);



/*! Comment? */
extern int efch_resource_alloc(ci_resource_table_t* rt,
                               struct ci_resource_alloc_s*);

extern void efch_resource_free(efch_resource_t *);

/*! Comment? */
extern int efch_resource_op(ci_resource_table_t* rt,
                            struct ci_resource_op_s*, int* copy_out);

extern int efch_filter_add(ci_resource_table_t* rt,
                           union ci_filter_add_u* filter_add,
                           int* copy_out);

extern int efch_vi_prime(struct ci_private_char_s* priv,
                         efch_resource_id_t, unsigned current_ptr);

extern unsigned efch_vi_poll(struct ci_private_char_s* priv,
                             struct file* filp, poll_table* wait);

/*! retrieve the resource referred to by the given resource ID in the (per-FD)
 *  private state provided
 */
extern int efch_resource_id_lookup(efch_resource_id_t id, 
				   ci_resource_table_t *rt,
				   efch_resource_t **out);

/*--------------------------------------------------------------------
 * licensing
 */

struct ci_license_challenge_op_s;

/* (efch_license.c)
 * Check if the given feature is licensed in the NIC and respond to the
 * challenge. */
extern int efch_license_challenge(ci_resource_table_t* rt,
                                  struct ci_license_challenge_op_s* op, 
                                  int* copy_out);

extern int efch_vi_filter_add(efch_resource_t* rs,
                              union ci_filter_add_u* filter_add,
                              int* copy_out);

extern int efch_capabilities_op(struct efch_capabilities_in* cap_in,
                                struct efch_capabilities_out* cap_out);

struct ci_v3_license_challenge_op_s;

/* (efch_license.c)
 * Check if the given feature is licensed in the NIC and respond to the
 * challenge. */
extern int efch_v3_license_challenge(ci_resource_table_t* rt,
                                     struct ci_v3_license_challenge_op_s* op,
                                     int* copy_out);

#endif /* __EFCH_H__ */
