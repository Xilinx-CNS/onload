/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef __DRIVER_ACCESS_H__
#define __DRIVER_ACCESS_H__

#if defined(__KERNEL__)
# error __KERNEL__ not allowed here.
#endif

#include <netinet/in.h>

#include <ci/efch/op_types.h>
#include <ci/efch/mmap_id.h>
#include <ci/efrm/resource_id.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

struct ci_resource_alloc_s;
struct ci_resource_op_s;


/*! \i_efab_unix */
ci_inline int
ci_resource_alloc(int fp, struct ci_resource_alloc_s* io)
{
  if( ioctl(fp, CI_RESOURCE_ALLOC, io) < 0 )  return -errno;
  return 0;
}

/*! \i_efab_unix */
ci_inline int
ci_resource_mmap(int fp, unsigned res_id, unsigned map_id, unsigned bytes,
                 void** p_out)
{
  *p_out = mmap((void*) 0, bytes, PROT_READ | PROT_WRITE,
                MAP_SHARED, fp,
                EFAB_MMAP_OFFSET_MAKE(efch_make_resource_id(res_id), map_id));
  return *p_out != MAP_FAILED ? 0 : -errno;
}


/*! \i_efab_unix */
ci_inline int
ci_resource_munmap(int fp, void* ptr, int bytes)
{
  if( munmap(ptr, bytes) < 0 )  return -errno;
  return 0;
}


/*! \i_efab_unix */
ci_inline int
ci_resource_op(int fp, struct ci_resource_op_s* io)
{
  int r;
  if( (r = ioctl(fp, CI_RESOURCE_OP, io)) < 0 )  return -errno;
  return r;
}


/*! \i_efab_unix */
ci_inline int
ci_filter_add(int fp, ci_filter_add_t* filter_add)
{
  int r;
  if( (r = ioctl(fp, CI_FILTER_ADD, filter_add)) < 0 )  return -errno;
  return r;
}


/*! \i_efab_unix */
ci_inline int
ci_resource_prime(int fp, struct ci_resource_prime_op_s* io)
{
  int r;
  if( (r = ioctl(fp, CI_RESOURCE_PRIME, io)) < 0 )  return -errno;
  return r;
}


/*! \i_efab_unix */
ci_inline int
ci_capabilities_op(int fp, struct ci_capabilities_op_s* io)
{
  int r;
  if( (r = ioctl(fp, CI_CAPABILITIES_OP, io)) < 0 )  return -errno;
  return r;
}

#endif  /* _CI_DRIVER_UNIX_INTF_H_ */
/*! \cidoxg_end */
