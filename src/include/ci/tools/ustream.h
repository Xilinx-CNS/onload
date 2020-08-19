/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  cgg
**  \brief  Efficient stream fifo (based on circular buffer).
**   \date  2003/06/30
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_USTREAM_H__
#define __CI_TOOLS_USTREAM_H__

/*
** This datastructure uses a circular buffer to implement a FIFO of variably
** sized items each a whole number of bytes.  Iff necessary, the oldest
** entries in the FIFO are discarded when new entries are added.
**
** We use the power-of-2 fifos that look like this:
**
**   struct ustream_struct {
**     unsigned               fifo_mask;
**     unsigned               fifo_rd_i;
**     unsigned               fifo_wr_i;
**   };
**
**   struct ustream_data_struct {
**     struct ustream_struct  hdr;
**     ci_ustream_element_t   fifo[1 << ln_size];
**   };
**
** Note that capacity is [(1<<n)-1], and that [fifo_mask] is one less than
** the buffer size.
**
** Unlike fifo2s we use fifo_rd_i and fifo_wr_i as continuously varying
** quantities which need to be modded to the buffer size before being used
** as an index.
*/


typedef ci_uint32 ci_ustream_element_t;
/* Note: the num(ber) of elements, capacity, space left and buffer	*/
/*       size in the following are all in units of ci_ustream_element_t */
/*       (i.e. typically they are numbers of 4-byte quantities)         */

typedef ci_uint16 ci_ustream_elementsize_t;
/* Note: this is also used as the unit in which the length of an	*/
/*       allocation is stored - so its size may limit the maximum size  */
/*       of an allocation (to 32767 ci_ustream_element_ts by default)	*/

typedef ci_uint8 ci_ustream_elementtype_t;
/* Note: the "type" of an entry is expressed in one of these quantities */
/*       its size limits the number of types that can be supported      */

typedef ci_uint8 ci_ustream_elementinfo_t;
/* Note: this is the type and size of a spare field in the word		*/
/*       allocated before every entry that pads the entry up to a	*/
/*       ci_ustream_element_t					        */

typedef unsigned ci_ustream_index_t;

/* This can be shared between accessors in different address spaces */
typedef struct ci_ustream_struct
{   unsigned           fifo_mask;
    ci_int32           fifo_rd_i;
    ci_int32           fifo_wr_i;
} ci_ustream_t;

/* This header appears before each item.  It should be kept small to
 * avoid overheads in the profile code.  The code below currently
 * assumes that it is the same size as an element. */
typedef struct			 
{   ci_ustream_elementsize_t len;
    ci_ustream_elementtype_t type;
    ci_ustream_elementinfo_t info;
} ci_ustream_elementhdr_t;

#define ci_ustream_valid(_u)    (NULL != (_u) && (_u)->fifo_mask > 0 &&  \
                                CI_IS_POW2((_u)->fifo_mask+1u))

#define ci_ustream_init(_u, size)                               \
  do{ ci_assert(CI_IS_POW2(size));                              \
      (_u)->fifo_rd_i = (_u)->fifo_wr_i = 0u;                   \
      (_u)->fifo_mask = (size/sizeof(ci_ustream_element_t))-1;  \
  }while(0)

#define ci_ustream_empty(_u)            \
  (_u)->fifo_rd_i = (_u)->fifo_wr_i

/* in C, unsigned-unsigned = unsigned */
#define _ci_ustream_ix_num(_u, rd)   ((signed)((_u)->fifo_wr_i - (rd)))
#define _ci_ustream_num(_u)          _ci_ustream_ix_num(_u, (_u)->fifo_rd_i)
#define _ci_ustream_buf_size(_u)     ((_u)->fifo_mask + 1u)
#define _ci_ustream_is_empty(_u)     (_ci_ustream_num(_u)<=0)
#define _ci_ustream_is_full(_u)      (_ci_ustream_num(_u)>=_ci_ustream_buf_size(_u))
#define _ci_ustream_capacity(_u)     ((_u)->fifo_mask)
#define _ci_ustream_ix_space(_u, rd) (signed)(_ci_ustream_capacity(_u) - \
				     _ci_ustream_ix_num(_u, rd))
#define _ci_ustream_space(_u)        _ci_ustream_ix_space(_u, (_u)->fifo_rd_i)

#define ci_ustream_start(_u)         ((ci_ustream_element_t *)\
                                     ((ci_ustream_t *)(_u)+1))
#define _ci_ustream_end(_u)          (ci_ustream_start(_u)+_ci_ustream_buf_size(_u))
#define ci_ustream_pos(_u, ix)       (ci_ustream_start(_u) + \
                                     ((ix)&((_u)->fifo_mask)))

#define _ci_ustream_ix_peek(_u, ix)  (*ci_ustream_pos(_u, ix))
#define _ci_ustream_peek(_u)         _ci_ustream_ix_peek(_u, (_u)->fifo_rd_i)
#define ci_ustream_reader_fresh(_u, ix) ((signed)((ix)-((_u)->fifo_rd_i)) >= 0)


#define _ci_ustream_hdr(ptr)         ((ci_ustream_elementhdr_t *)(ptr)-1)

#define ci_ustream_hdr_len(ptr)     (_ci_ustream_hdr(ptr)->len)
#define ci_ustream_hdr_type(ptr)    (_ci_ustream_hdr(ptr)->type)
#define ci_ustream_hdr_info(ptr)    (_ci_ustream_hdr(ptr)->info)

#define ci_ustream_hdr_set_len(ptr, _len)   \
    (_ci_ustream_hdr(ptr)->len = _len)
#define ci_ustream_hdr_set_type(ptr, _type) \
    (_ci_ustream_hdr(ptr)->type = _type)
#define ci_ustream_hdr_set_info(ptr, _info) \
    (_ci_ustream_hdr(ptr)->info = _info)


/* Atomic operation required internally, in what follows */

/* This costs ~ 100 cycles if you turn it off */
#define CI_COMPILER_INCN_ATOMIC 1

/* If increment is implemented atomically something simple will do what we
   want...
   otherwise there is the possibility that simultaneous write-back may causes
   the new value not to have been incremented by a competing value
*/
ci_inline unsigned _ci_ustream_add_ret(volatile ci_int32 *lv_n, unsigned inc)
{
#if CI_COMPILER_INCN_ATOMIC
    return (*lv_n += inc)-inc;
#else
    unsigned incattempt;
    do {
      incattempt = *lv_n;
    } while(ci_cas32_fail(lv_n, incattempt, incattempt+inc));
    return incattempt;
#endif
}




/* This fifo is used as follows:

   ci_ustream_init(ustream, 1 << ln_capacity);

   ci_ustream_element_t *new;
   ci_ustream_alloc(&new, ustream, size_in_elements);
   if (NULL != new)
        ... fill in new value quickly, before it gets read!

   ci_ustream_element_t *old;
   int size_in_elements;
   ci_ustream_get(&old, ustream, &size_in_elements);
   if (NULL != old)
        ... do something with the value quickly before it gets overwritten
*/	


ci_inline void _ci_ustream_frag_readq(ci_ustream_t *_u,
                                      ci_ustream_index_t *lv_ix,
                                      void **lv_old, ci_uint32 *lv_n)
{   ci_ustream_index_t _read;

    do {
        _read = *lv_ix;
        if (!ci_ustream_reader_fresh(_u, _read)) {
            _read = (_u)->fifo_rd_i; /* try to keep up */
        }
        if (_ci_ustream_ix_num(_u, _read) <= 1) {
            *(lv_old) = NULL; /* empty */
            *(lv_ix) = _read;
            return;
        }
        else {
            ci_ustream_elementhdr_t *_hdr = ((ci_ustream_elementhdr_t *)	
                                             ci_ustream_pos(_u, _read));
            ci_ustream_elementsize_t _items = _hdr->len;

            /* The header is assumed to be contiguous above and the
             * index is increased by 1 for the header below, so the
             * header must be the same size as an element. */
            ci_assert_equal(sizeof(ci_ustream_elementhdr_t),
                            sizeof(ci_ustream_element_t));

            *(lv_old) = (void *)ci_ustream_pos(_u, _read+1);
            *(lv_ix) = _read + 1 + _items;
            *(lv_n) = _items; 
        }
    } while(!ci_ustream_reader_fresh(_u, _read));
}



ci_inline void _ci_ustream_frag_nqalloc(void **lv_new, ci_ustream_t *_u,
                                        ci_uint32 _n)	
{								   
    ci_ustream_elementsize_t _items = (ci_ustream_elementsize_t)(_n); /* truncate if needed */	
    ci_ustream_index_t index = _ci_ustream_add_ret(&(_u)->fifo_wr_i, 1+_items);
    ci_ustream_element_t *_new = ci_ustream_pos(_u, index);
    ci_ustream_elementhdr_t *_hdr = (ci_ustream_elementhdr_t *)_new;	

    
    /* The header is assumed to be contiguous above and the index is
     * increased by 1 for the header above and below, so the header
     * must be the same size as an element. */
    ci_assert_equal(sizeof(ci_ustream_elementhdr_t),
                    sizeof(ci_ustream_element_t));
    ci_assert_equal(_items, _n); /* Make sure no truncation */

    while (CI_UNLIKELY(_ci_ustream_space(_u) <= 0))
        /* not enough space after write */
    {   /* free some space at the bottom.. */
        ci_ustream_index_t rd_i = (_u)->fifo_rd_i;
        ci_ustream_element_t *_skip = ci_ustream_pos(_u, rd_i);
        ci_ustream_elementhdr_t *_skiphdr= (ci_ustream_elementhdr_t *)_skip;

        /* The only reason for this to fail is for someone else to do
         * the same assignment. */
        ci_cas32_fail(&(_u)->fifo_rd_i, rd_i, rd_i+1+_skiphdr->len);
    }
    _hdr->len = _items;  /* should fit now! */				     
    _hdr->type = 0xff;
    *(lv_new) = (void *)(_new+1); /* NB: bad if fragmented at _hdr+1 */      
}



/* some allocations will straddle the end of the buffer and be fragmented */
#define ci_ustream_fragment(_u, _ptr, _n) \
    ((signed)(_n) >= _ci_ustream_end(_u)-((ci_ustream_element_t *)(_ptr)))




ci_inline void ci_ustream_nqalloc(void **lv_new, ci_ustream_t *_u, ci_uint32 n)
{
    void *fragment;
    ci_uint32 _fitems = (n);
    ci_assert((n) > 0 && (n) < (1 << 8*sizeof(ci_ustream_elementsize_t)));
    do {
        _ci_ustream_frag_nqalloc(&fragment, _u, _fitems);
    } while (CI_UNLIKELY(fragment != NULL &&
		       ci_ustream_fragment(_u, fragment, _fitems)));
    /* ignore fragmented allocations */
    *(lv_new) = fragment;
}



/* return next index to be used */
#define ci_ustream_current(_u) ((_u)->fifo_wr_i)




/* return first index available */
#define ci_ustream_oldest(_u) ((_u)->fifo_rd_i)




/* return entry at given index and update index */
#define ci_ustream_readq(_u, lv_ix, lv_old, lv_n) \
do {									      \
    void *fragment;							      \
    ci_uint32 _fitems = 0;						      \
    do {								      \
	_ci_ustream_frag_readq(_u, lv_ix, &fragment, &_fitems);		      \
    } while (CI_UNLIKELY(fragment != NULL &&                                  \
                         ci_ustream_fragment(_u, fragment, _fitems)));        \
    /* ignore fragmented allocations */					      \
    *(lv_n) = _fitems;    						      \
    *(lv_old) = fragment;						      \
} while(0)




#endif /* __CI_TOOLS_USTREAM_H__ */
