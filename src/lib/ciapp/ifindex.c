/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  An interface to translate between ifindex and interface name.
**   \date  2008/12/18
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */
#include <ci/app.h>
#include <ci/app/ifindex.h>
#include <net/if.h>

int ci_net_interface_ifindex_to_name(int ifindex, char* name_buf,
                                     int name_buf_len)
{
  struct ifreq ifr;
  int s, rc;

  s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if( s < 0 )  return -errno;

  ifr.ifr_ifindex = ifindex;
  rc = ioctl(s, SIOCGIFINDEX, &ifr);
  close(s);
  if( rc < 0 )
    return -errno;

  if( strlen(ifr.ifr_name) + 1 > name_buf_len )
    return E2BIG;
  strcpy(name_buf, ifr.ifr_name);
  return 0;
}


int ci_net_interface_name_to_ifindex(const char* name)
{
  struct ifreq ifr;
  char dummy;
  int s, rc;

  /* Accept integer that is already an ifindex, or an interface name. */
  if( sscanf(name, "%d%c", &rc, &dummy) == 1 )
    return rc;

  if( strlen(name) + 1 > IFNAMSIZ )
    return -E2BIG;
  strcpy(ifr.ifr_name, name);

  s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if( s < 0 )  return -errno;

  rc = ioctl(s, SIOCGIFINDEX, &ifr);
  close(s);
  if( rc == 0 )
    return ifr.ifr_ifindex;
  else
    return -errno;
}
