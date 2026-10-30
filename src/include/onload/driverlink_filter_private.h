/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  "Private" interface for the driverlink filter module
**           Filtering support for the Net -> char data traffic
**   \date  2004/08/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_DRIVERLINK__FILTER__PRIVATE_H__
#define __CI_DRIVER_EFAB_DRIVERLINK__FILTER__PRIVATE_H__

/* This file is the private part of driverlink_filter.h; it is included
 * only from driverlink_filter.c. */
#ifndef __ci_driver__
#error "This is a driver module."
#endif


#if CI_CFG_HANDLE_ICMP
/*! Defines one entry in the master filter table */
typedef struct efx_dlfilt_entry_s {
  int       thr_id;     /*!< TCP helper res. ID from char driver 
			* (-1 if unknown) */
  ci_addr_t raddr;
  ci_addr_t laddr;
  ci_uint16 rport_be16;
  ci_uint16 lport_be16;
  ci_uint32 state;
#define EFAB_DLFILT_INUSE      0x00000000U
#define EFAB_DLFILT_TOMBSTONE  0x40000000U
                            /* 0x80000000U invalid */
#define EFAB_DLFILT_EMPTY      0xC0000000U
#define EFAB_DLFILT_STATE_MASK 0xC0000000U
#define EFAB_DLFILT_STATE_SHIFT 30
  ci_uint8  ip_protocol;
} efx_dlfilt_entry_t;


/* MUST BE a power of 2, <= 0x40000000  & accomodate the number 
 * of NIC hardware filters */
#define EFAB_DLFILT_ENTRY_COUNT_MAX 0x40000000U
#define EFAB_DLFILT_ENTRY_COUNT_DEFAULT 0x4000U

typedef struct efx_dlfilt_table_s {
  ci_uint32 size_mask;
  CI_DECLARE_FLEX_ARRAY(efx_dlfilt_entry_t, arr);
} efx_dlfilt_table_t;

#define DLFILT_TAGGED_TABLE_TAG_GET(table) ((uintptr_t)(table) & 1UL)
#define DLFILT_TAGGED_TABLE_TAG_SET(table) ((void *)((uintptr_t)(table) | 1UL))
#define DLFILT_TAGGED_TABLE_TAG_UNSET(table) ((void *)((uintptr_t)(table) & ~1UL))

static inline efx_dlfilt_table_t*
dlfilt_table_untag_if_used(efx_dlfilter_cb_t* fcb)
{
  efx_dlfilt_table_t* table = CI_READ_ONCE(fcb->tagged_table);

  if(unlikely( DLFILT_TAGGED_TABLE_TAG_GET(table) ))
    return NULL;
  return table;
}
#endif


#endif /* __CI_DRIVER_EFAB_DRIVERLINK__FILTER__PRIVATE_H__ */
/*! \cidoxg_end */
