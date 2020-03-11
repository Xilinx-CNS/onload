/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE >
** \author  stg
**  \brief  Linux specific char driver IP control proto ("IPP") rx code. 
**          IPP includes ICMP, IGMP and, optionally, UDP broadcasts
**   \date  2004/06/23
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_driver_linux */

#include <ci/internal/ip.h>
#include <onload/linux_ip_protocols.h>
#include <onload/debug.h>
#include <onload/tcp_helper_fns.h>

#define VERB(x)


/*--------------------------------------------------------------------
 *!
 * This function is intended to safely decode a TCP helper resource
 * handle that we passed to the NET driver back into a locked netif
 *
 * Given a TCP helper resource handle, this function attempts to
 * return a locked netif. If it succeeds its up to the callee to drop
 * the netif lock by calling efab_tcp_helper_netif_unlock, and drop a
 * reference by calling efab_thr_release().  This function can fail
 * because the handle is no longer valid OR its not possible to get
 * the netif lock at this time
 *
 * \param nic           nic object the handle relates to
 * \param tcp_id        TCP helper resource id
 *
 * \returns pointer to locked TCP helper resource or NULL
 *
 *--------------------------------------------------------------------*/

static tcp_helper_resource_t *
efab_ipp_get_locked_thr_from_tcp_handle(unsigned tcp_id)
{
  tcp_helper_resource_t * thr = NULL;
  int rc;

  /* ask resource manager to decode to a resource */
  rc = efab_thr_table_lookup(NULL, NULL, tcp_id,
                             EFAB_THR_TABLE_LOOKUP_NO_CHECK_USER, &thr);
  if (rc < 0) {
    OO_DEBUG_IPP( ci_log("%s: Invalid TCP helper resource handle %u", 
                         __FUNCTION__, tcp_id) );
  }
  else {
    /* so we have found the resource in the table and have incremented
    ** its reference count  - now lets try and lock the associated netif 
    */
    if ( !efab_tcp_helper_netif_try_lock(thr, 1) ) {
      OO_DEBUG_IPP( ci_log("%s: Failed to lock TCP helper", __FUNCTION__) );
      efab_thr_release(thr);
      thr = NULL;
    }
  }
  return thr;
}



/* Function called from the ARP keventd tasklet in response to 
 * a data message from the net driver
 *
 * NOTE: the current implementation discards data when it
 * cannot get a lock.  As the mechanism is for protocols that
 * do not guarantee data delivery this is considered acceptible.
 */
int efab_handle_ipp_pkt_task(int thr_id, ci_ifid_t ifindex,
                             const void* in_data, int len)
{
  tcp_helper_resource_t* thr;
  const ci_ipx_hdr_t* in_ipx;
  efab_ipp_addr addr;

  /* NOTE: the efab_ipp_icmp_validate fills the addr struct with
   * references to the in_ip param - make sure that in_ip remains
   * accessible while addr is in use */
  in_ipx = in_data;

  /* Have a full IP,ICMP hdr - so [data_only] arg is 0 */
  if( !efab_ipp_icmp_parse( in_ipx, len, &addr, 0))
    goto exit_handler;
  addr.ifindex = ifindex;

  if( (thr = efab_ipp_get_locked_thr_from_tcp_handle(thr_id))) {
    ci_sock_cmn* s;

    s = efab_ipp_icmp_for_thr( thr, &addr );
    if( s )  efab_ipp_icmp_qpkt( thr, s, &addr );
    efab_tcp_helper_netif_unlock( thr, 1 );
    efab_thr_release(thr);
  }

exit_handler:
  return 0;
}

/*! \cidoxg_end */
