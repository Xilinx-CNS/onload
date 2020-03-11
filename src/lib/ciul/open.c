/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_ef */
#include <etherfabric/base.h>
#include "ef_vi_internal.h"
#include "logging.h"
#include <fcntl.h>
#include <unistd.h>


int ef_driver_open(ef_driver_handle* pfd)
{
  int rc;
  rc = open("/dev/sfc_char", O_RDWR);
  if( rc >= 0 ) {
    *pfd = rc;
    return 0;
  }
  return -errno;
}


int ef_driver_close(ef_driver_handle dh)
{
  return close(dh);
}

/*! \cidoxg_end */
