/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  David Riddoch <driddoch@solarflare.com>
**  \brief  Registered memory.
**   \date  2012/02/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <etherfabric/pd.h>
#include <etherfabric/pio.h>
#include <etherfabric/capabilities.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"


#define PIO_BUF_MAP_SIZE     PAGE_SIZE

#define EF10_VI_WINDOW_STEP  8192


#if EF_VI_CONFIG_PIO

int ef_pio_alloc(ef_pio* pio, ef_driver_handle pio_dh, ef_pd* pd,
                 unsigned len_hint, ef_driver_handle pd_dh)
{
  ci_resource_alloc_t ra;
  int rc;
  unsigned long pio_buffer_size;

  rc = ef_pd_capabilities_get(pio_dh, pd, pd_dh, EF_VI_CAP_PIO_BUFFER_SIZE,
                              &pio_buffer_size);
  if( rc < 0 ) {
    if( rc != -ENOTTY ) {
      LOGVV(ef_log("%s: ef_pd_capabilities_get() failed", __FUNCTION__));
      return rc;
    }
    /* Old driver, so must be a 7000-series. */
    pio_buffer_size = 2048;
  }

  memset(pio, 0, sizeof(*pio));
  pio->pio_len = len_hint < pio_buffer_size ? len_hint : pio_buffer_size;
  pio->pio_buffer = calloc(sizeof(uint8_t), pio->pio_len);
  if( ! pio->pio_buffer ) {
    LOGVV(ef_log("%s: calloc of pio_buffer failed", __FUNCTION__));
    return -ENOMEM;
  }

  memset(&ra, 0, sizeof(ra));
  ef_vi_set_intf_ver(ra.intf_ver, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_PIO;
  ra.u.pio.in_pd_fd = pd_dh;
  ra.u.pio.in_pd_id = efch_make_resource_id(pd->pd_resource_id);

  rc = ci_resource_alloc(pio_dh, &ra);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: ci_resource_alloc failed %d", __FUNCTION__, rc));
    goto err;
  }

  pio->pio_resource_id = ra.out_id.index;
  return 0;

 err:
  free(pio->pio_buffer);
  return rc;
}

#endif


int ef_pio_free(ef_pio* pio, ef_driver_handle dh)
{
  free(pio->pio_buffer);
  EF_VI_DEBUG(memset(pio, 0, sizeof(*pio)));
  return 0;
}


int ef_pio_link_vi(ef_pio* pio, ef_driver_handle pio_dh, ef_vi* vi,
                   ef_driver_handle vi_dh)
{
  void* p;
  ci_resource_op_t op;
  int rc;

  op.op = CI_RSOP_PIO_LINK_VI;
  op.id = efch_make_resource_id(pio->pio_resource_id);
  op.u.pio_link_vi.in_vi_fd = vi_dh;
  op.u.pio_link_vi.in_vi_id = efch_make_resource_id(vi->vi_resource_id);

  rc = ci_resource_op(pio_dh, &op);
  if( rc < 0 ) {
    LOGV(ef_log("%s: ci_resource_op failed %d", __FUNCTION__, rc));
    return rc;
  }

  if( pio->pio_io == NULL ) {
    int bar_off = vi->vi_i * EF10_VI_WINDOW_STEP + 4096;
    rc = ci_resource_mmap(vi_dh, vi->vi_resource_id, EFCH_VI_MMAP_PIO,
                          PIO_BUF_MAP_SIZE, &p);
    if( rc < 0 ) {
      LOGVV(ef_log("%s: ci_resource_mmap (pio) %d", __FUNCTION__, rc));
      return rc;
    }
    pio->pio_io = (uint8_t*) p + (bar_off & (PAGE_SIZE - 1));
  }

  vi->linked_pio = pio;
  return 0;
}


int ef_pio_unlink_vi(ef_pio* pio, ef_driver_handle pio_dh, ef_vi* vi,
                     ef_driver_handle vi_dh)
{
  ci_resource_op_t op;
  int rc;

  op.op = CI_RSOP_PIO_UNLINK_VI;
  op.id = efch_make_resource_id(pio->pio_resource_id);
  op.u.pio_unlink_vi.in_vi_fd = vi_dh;
  op.u.pio_unlink_vi.in_vi_id = efch_make_resource_id(vi->vi_resource_id);

  rc = ci_resource_op(pio_dh, &op);
  if( rc < 0 ) {
    LOGV(ef_log("%s: ci_resource_op failed %d", __FUNCTION__, rc));
  }
  else {
    rc = ci_resource_munmap(vi_dh, pio->pio_io, PIO_BUF_MAP_SIZE);
    if( rc < 0 )
      LOGV(ef_log("%s: ci_resource_munmap failed %d", __FUNCTION__, rc));
  }
  return rc;
}


int ef_vi_get_pio_size(ef_vi* vi)
{
  ef_pio* pio = vi->linked_pio;
  return pio->pio_len;
}
