/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg, djr
**  \brief  Filter for "net driver" packets inspected via driverlink.
**   \date  2004/08/23
**    \cop  (c) Level 5 Networks Limited, Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab */

#ifndef __CI_DRIVER_EFAB_DRIVERLINK__FILTER_H__
#define __CI_DRIVER_EFAB_DRIVERLINK__FILTER_H__


struct ci_ether_hdr_s;
struct efx_dlfilt_cb_s;


typedef int (*efx_dlfilter_is_onloaded_t)(void* ctx, struct net* netns,
                                          ci_ifid_t ifindex);

/*! Construct a driverlink filter object - stored in the per-nic struct.
 * \param ctx - context passed to callbacks
 * \param is_onloaded - callback used to identify SFC interfaces
 *                      must be safe in soft IRQ context
 * \Return     ptr to object or NULL if failed
 */
extern struct efx_dlfilt_cb_s*
efx_dlfilter_ctor(void* ctx, efx_dlfilter_is_onloaded_t is_onloaded);

/*! Clean-up object created through efx_dlfilter_ctor() */
extern void efx_dlfilter_dtor(struct efx_dlfilt_cb_s*);

/*! Data-passing entry point. */
extern int
efx_dlfilter_handler(struct net* netns, int ifindex, struct efx_dlfilt_cb_s*,
                     const struct ci_ether_hdr_s*, const void* ip_hdr, int len);


extern void efx_dlfilter_dump(struct efx_dlfilt_cb_s*);


/* Add a filter.  Caller is responsible for protecting this and
 * efx_dlfilter_remove() from concurrency.
 */
extern void
efx_dlfilter_add(struct efx_dlfilt_cb_s*, unsigned protocol, ci_addr_t laddr,
                 ci_uint16 lport,  ci_addr_t raddr, ci_uint16 rport,
                 int thr_id, unsigned* handle_out);

/* Remove a filter.  Caller is responsible for protecting this and
 * efx_dlfilter_add() from concurrency.
 */
extern void
efx_dlfilter_remove(struct efx_dlfilt_cb_s*, unsigned handle);

#define EFX_DLFILTER_HANDLE_BAD  ((unsigned) -1)


extern void
efx_dlfilter_count_stats(struct efx_dlfilt_cb_s* fcb,
                         int *n_empty, int *n_tomp, int *n_used);

#endif /* __CI_DRIVER_EFAB_DRIVERLINK__FILTER_H__ */
/*! \cidoxg_end */
