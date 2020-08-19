/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2019 Xilinx, Inc. */

#ifndef __CI_EFCH_RESOURCE_ID_H__
#define __CI_EFCH_RESOURCE_ID_H__

#include <ci/compat.h>


#define EFRM_RESOURCE_MAX_PER_FD_BITS    9
#define EFRM_RESOURCE_MAX_PER_FD         (1u << EFRM_RESOURCE_MAX_PER_FD_BITS)


/***********************************************************************
 * Identify resources within the context of a file descriptor at user 
 * level.
 ***********************************************************************/

typedef struct efch_resource_id_s {
  ci_uint32 index;
} efch_resource_id_t;

#define EFCH_RESOURCE_ID_FMT  "[rid:%08x]"

ci_inline unsigned 
EFCH_RESOURCE_ID_PRI_ARG(efch_resource_id_t h) {
  return (h.index);
}

ci_inline efch_resource_id_t efch_make_resource_id(unsigned index) {
  efch_resource_id_t id;
  id.index = index;
  return id;
}

ci_inline efch_resource_id_t efch_resource_id_none(void) {
  efch_resource_id_t id;
  id.index = ~(ci_uint32)0;
  return id;
}

ci_inline ci_boolean_t efch_resource_id_is_none(efch_resource_id_t id) {
  return (id.index == ~(ci_uint32)0) ? CI_TRUE : CI_FALSE;
}


ci_inline int 
efch_resource_id_has_value(efch_resource_id_t id, unsigned value) {
  return id.index == value;
}

ci_inline int efch_resource_id_equality(efch_resource_id_t x, 
			      efch_resource_id_t y) {
  return x.index == y.index;
}
				      

#endif /* __CI_EFCH_RESOURCE_ID_H__ */
