/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
**  \brief Kernel-private endpoints routines
**   \date Started at Jul, 29 2004
**    \cop (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include <onload/debug.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/tcp_helper_fns.h>
#include <onload/oof_interface.h>
#include <onload/oof_onload.h>
#include <onload/drv/dump_to_user.h>
#include <onload/tcp-ceph.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/slice_ext.h>
#include "tcp_filters_internal.h"
#include "oof_impl.h"


/************************************************************************** \
*
\**************************************************************************/

/* See description in include/driver/efab/tcp_helper_endpoint.h */
void
tcp_helper_endpoint_ctor(tcp_helper_endpoint_t *ep,
                         tcp_helper_resource_t * thr,
                         int id)
{
  int i;

  OO_DEBUG_VERB(ci_log("%s: ID=%d", __FUNCTION__, id));

  CI_ZERO(ep);
  ep->thr = thr;
  ep->id = OO_SP_FROM_INT(&thr->netif, id);

  ci_dllink_self_link(&ep->ep_with_pinned_pages);
  ci_dllist_init(&ep->pinned_pages);
  ep->n_pinned_pages = 0;

  ci_waitable_ctor(&ep->waitq);

  ep->os_port_keeper = NULL;
  ep->os_socket = NULL;
  ep->wakeup_next = 0;
  ep->fasync_queue = NULL;
  ep->ep_aflags = 0;
  ep->alien_ref = NULL;
  spin_lock_init(&ep->lock);
  oo_os_sock_poll_ctor(&ep->os_sock_poll);
  init_waitqueue_func_entry(&ep->os_sock_poll.wait, efab_os_sock_callback);

  for( i = 0; i < CI_CFG_N_READY_LISTS; i++ )
    ci_dllink_self_link(&ep->epoll[i].os_ready_link);

  oof_socket_ctor(&ep->oofilter);

#if CI_CFG_TCP_OFFLOAD_RECYCLER
  for( i = 0; i < CI_CFG_MAX_INTERFACES; ++i )
    ep->plugin_stream_id[i] = INVALID_PLUGIN_HANDLE;
#endif
}

/*--------------------------------------------------------------------*/

static void
clear_plugin_state(tcp_helper_endpoint_t * ep)
{
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  ci_netif* ni = &ep->thr->netif;
  int intf_i;

  ci_assert( ! in_atomic() );
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    struct efrm_pd *pd = efrm_vi_get_pd(tcp_helper_vi(ep->thr, intf_i));
    if( ep->plugin_stream_id[intf_i] == INVALID_PLUGIN_HANDLE )
      continue;
    efrm_ext_destroy_rsrc(efrm_pd_to_resource(pd),
                          ni->nic_hw[intf_i].plugin_handle,
                          XSN_CEPH_RSRC_CLASS_STREAM,
                          ep->plugin_stream_id[intf_i]);
    ep->plugin_stream_id[intf_i] = INVALID_PLUGIN_HANDLE;
  }
#endif
}

#if CI_CFG_UL_INTERRUPT_HELPER
/* FIXME Sasha
 * ci_tcp_sock_set_stack_filter() and ci_tcp_sock_clear_stack_filter()
 * should be called from UL only in this mode.  There is no easy way to
 * do it now, so scalable filters are deliberately broken.*/
#define BREAK_SCALABLE_FILTERS
#endif

/* See description in include/onload/tcp_helper_endpoint.h */
void
tcp_helper_endpoint_dtor(tcp_helper_endpoint_t * ep)
{
  unsigned long lock_flags;
#ifndef BREAK_SCALABLE_FILTERS
  ci_sock_cmn* s = SP_TO_SOCK(&ep->thr->netif, ep->id);
#endif

  /* We need to release zero, one or two file references after dropping a
   * spinlock. */
  struct file* files_to_drop[2];
  int num_files_to_drop = 0;
  int i;

  /* the endpoint structure stays in the array in the THRM even after
     it is freed - therefore ensure properly cleaned up */
  OO_DEBUG_VERB(ci_log(FEP_FMT, FEP_PRI_ARGS(ep)));

  clear_plugin_state(ep);
#ifndef BREAK_SCALABLE_FILTERS
  if( s->s_flags & CI_SOCK_FLAG_STACK_FILTER )
    ci_tcp_sock_clear_stack_filter(&ep->thr->netif,
                                   SP_TO_TCP(&ep->thr->netif, ep->id));
#endif
  oof_socket_del(oo_filter_ns_to_manager(ep->thr->filter_ns), &ep->oofilter);
  oof_socket_mcast_del_all(oo_filter_ns_to_manager(ep->thr->filter_ns),
                           &ep->oofilter);
  oof_socket_dtor(&ep->oofilter);

  spin_lock_irqsave(&ep->lock, lock_flags);
  if( ep->os_socket != NULL ) {
    if( ID_TO_WAITABLE_OBJ(&ep->thr->netif, ep->id)->waitable.state !=
        CI_TCP_STATE_ACTIVE_WILD ) {
      OO_DEBUG_ERR(ci_log(FEP_FMT "ERROR: O/S socket still referenced",
                          FEP_PRI_ARGS(ep)));
    }
    files_to_drop[num_files_to_drop++] = ep->os_socket;
    ep->os_socket = NULL;
  }
  if( ep->os_port_keeper != NULL ) {
    files_to_drop[num_files_to_drop++] = ep->os_port_keeper;
    ep->os_port_keeper = NULL;
  }
  spin_unlock_irqrestore(&ep->lock, lock_flags);

  for( i = 0; i < num_files_to_drop; ++i )
    fput(files_to_drop[i]);

  if( ep->alien_ref != NULL ) {
    OO_DEBUG_ERR(ci_log(FEP_FMT "ERROR: alien socket still referenced",
                        FEP_PRI_ARGS(ep)));
    fput(ep->alien_ref->_filp);
    ep->alien_ref = NULL;
  }

  ci_waitable_dtor(&ep->waitq);

  ci_assert(ep->n_pinned_pages == 0);

  ep->id = OO_SP_NULL;
}


#if CI_CFG_ENDPOINT_MOVE
static int
tcp_helper_endpoint_reuseaddr_cleanup(ci_netif* ni, ci_sock_cmn* s)
{
  int i;

  if( (~s->b.state & CI_TCP_STATE_TCP) || s->b.state == CI_TCP_LISTEN )
    return 0;

  for( i = 0; i < (int)ni->state->n_ep_bufs; ++i ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, i);
    
    if( wo->waitable.state != CI_TCP_TIME_WAIT )
      continue;

    if( ! CI_IPX_ADDR_EQ(sock_ipx_raddr(s), sock_ipx_raddr(&wo->sock)) ||
        sock_rport_be16(s) != sock_rport_be16(&wo->sock) ||
        ! CI_IPX_ADDR_EQ(sock_ipx_laddr(s), sock_ipx_laddr(&wo->sock)) ||
        sock_lport_be16(s) != sock_lport_be16(&wo->sock) )
      continue;

    /* We've found something to drop! */
    ci_tcp_drop(ni, SOCK_TO_TCP(&wo->sock), 0);
    return 1;
  }

  return 0;
}
#endif

/*--------------------------------------------------------------------
 *!
 * Called by TCP/IP stack to setup all the filters needed for a
 * TCP/UDP endpoint. This includes
 *    - hardware IP filters
 *    - filters in the software connection hash table
 *    - filters for NET to CHAR driver comms to support fragments
 *
 * \param ep              endpoint kernel data structure
 * \param phys_port       L5 physical port index to support SO_BINDTODEVICE
 *                        (ignored unless raddr/rport = 0/0)
 * \param from_tcp_id     block id of listening socket to "borrow" filter from
 *                        (-1 if not required)
 *
 * \return                standard error codes
 *
 * Examples supported:
 *    laddr/lport   raddr/rport    extra        Comment
 *      ------       --------     ------        -------
 *      lIP/lp        rIP/rp     from_tcp_id<0  Fully specified
 *      lIP/lp        0/0        from_tcp_id<0  listen on local IP address
 *      0/lp          0/0        phys_port=-1   listen on IPADDR_ANY
 *      0/lp          0/0        phys_port=n    listen on BINDTODEVICE
 *      lIP/lp        rIP/rp     from_tcp_id=n  TCP connection passively opened
 *                                              (use filter from this TCP ep)
 *      aIP/ap        rIP/rp     s_flags & TPROXY
 *                               && phys_port=n TCP connection using transparent
 *                                              shared filter
 *
 *
 *--------------------------------------------------------------------*/


/* Function flushes pending endpoint CLEAR FILTER operation, which is
 * normally scheduled to be done asnychronously by tcp_helper_do_non_atomic()
 * in workqueue context.
 * Flushing is required before setting new filter. */
static int
tcp_helper_flush_clear_filters(tcp_helper_endpoint_t* ep)
{
#if ! CI_CFG_UL_INTERRUPT_HELPER
  /* Avoid racing with tcp_helper_do_non_atomic(). */
  unsigned ep_aflags;
  ci_assert( ci_netif_is_locked(&ep->thr->netif) );
again:
  if( (ep_aflags = ep->ep_aflags) & OO_THR_EP_AFLAG_NON_ATOMIC ) {
    if( in_atomic() )
      /* Cannot do much here in interrupt context, we are
       * on listen_try_promote() path with newly allocated endpoint.
       * After returning fail, operation will eventually be resumed on
       * retransmission. */
      return -EAGAIN;
    /* do not expect this endpoint to be going to be freed */
    ci_assert(!(ep_aflags & OO_THR_EP_AFLAG_NEED_FREE));
    if( (ep_aflags = ep->ep_aflags) & OO_THR_EP_AFLAG_CLEAR_FILTERS ) {
      /* let us try to steal the flag, so we can do the operation ourselves */
      if( ci_cas32_fail(&ep->ep_aflags, ep_aflags,
                        ep_aflags & ~ OO_THR_EP_AFLAG_CLEAR_FILTERS) )
        goto again;
      /* we have stolen the flag, clearing the filters */
      tcp_helper_endpoint_clear_filters(ep, 0);
      return 0;
    }
    /* Looks we clashed with the tcp_helper_do_non_atomic() while it is running,
     * let us wait till it finishes */
    flush_work(&ep->thr->non_atomic_work);
    ci_assert(!(ep->ep_aflags & OO_THR_EP_AFLAG_NON_ATOMIC));
  }
#endif
  return 0;
}


static int
ci_tcp_use_mac_filter(ci_netif* ni, ci_sock_cmn* s, ci_ifid_t ifindex,
                      oo_sp from_tcp_id)
{
  int use_mac_filter = 0;
  int mode;

  if( NI_OPTS(ni).scalable_filter_enable != CITP_SCALABLE_FILTERS_ENABLE )
    return 0;

  mode = NI_OPTS(ni).scalable_filter_mode;
  if( mode & (CITP_SCALABLE_MODE_TPROXY_ACTIVE | CITP_SCALABLE_MODE_ACTIVE) ) {
    /* TPROXY sockets don't get associated with a hw filter, so don't need
     * oof management.
     */
    use_mac_filter |= (s->s_flags & CI_SOCK_FLAGS_SCALABLE);
  }

  if( ! use_mac_filter && (mode & CITP_SCALABLE_MODE_PASSIVE) ) {
    /* Passively opened sockets accepted from a listener using a MAC filter
     * also use the MAC filter.
     */
    use_mac_filter |= OO_SP_NOT_NULL(from_tcp_id) &&
             (SP_TO_SOCK(ni, from_tcp_id)->s_flags & CI_SOCK_FLAG_STACK_FILTER);

#ifndef BREAK_SCALABLE_FILTERS
    if( (use_mac_filter == 0) && (s->b.state == CI_TCP_LISTEN) &&
        ci_tcp_use_mac_filter_listen(ni, s, ifindex) )
      use_mac_filter = 1;
#endif
  }

  if( use_mac_filter ) {
    /* Only TCP sockets support use of MAC filters at the moment */
    ci_assert_flags(s->b.state, CI_TCP_STATE_TCP);
  }

  return use_mac_filter;
}


int
tcp_helper_endpoint_set_filters(tcp_helper_endpoint_t* ep,
                                ci_ifid_t bindto_ifindex, oo_sp from_tcp_id)
{
  struct file* os_sock_ref;
  ci_netif* ni = &ep->thr->netif;
  ci_sock_cmn* s = SP_TO_SOCK(ni, ep->id);
  tcp_helper_endpoint_t* listen_ep = NULL;
  ci_addr_t laddr, raddr;
  int protocol, lport, rport;
  int rc;
  unsigned long lock_flags;
  int use_mac_filter, af_space;
#if CI_CFG_TCP_OFFLOAD_RECYCLER
  bool enable_recycler = s->s_flags & CI_SOCK_FLAG_TCP_OFFLOAD &&
                         ! CI_IPX_ADDR_IS_ANY(sock_raddr(s));
#endif

  OO_DEBUG_TCPH(ci_log("%s: [%d:%d] bindto_ifindex=%d from_tcp_id=%d",
                       __FUNCTION__, ep->thr->id,
                       OO_SP_FMT(ep->id), bindto_ifindex, from_tcp_id));

  /* Make sure the endpoint is not subject to pending async filter operations.
   *
   * In some circumstances we might be racing with non-atomic work handler.
   * When clear filter operation occurs in atomic context a hw filter clear
   * gets scheduled in workqueue context.
   * Before proceeding with setting the filter a pending filter clear
   * operation needs to be flushed. */
  rc = tcp_helper_flush_clear_filters(ep);
  if(CI_UNLIKELY( rc < 0 ))
    return rc;

  /* The lock is needed for assertions with CI_NETIF_FLAG_IN_DL_CONTEXT
   * flag only. */
  ci_assert( ci_netif_is_locked(&ep->thr->netif) );

#if CI_CFG_FD_CACHING
  /* The special cases that allow active-wild sharers to be cacheable depend on
   * not entering this function, which takes a port-keeper reference to the OS
   * socket on the underlying active-wild. */
  ci_assert(! ci_tcp_is_cacheable_active_wild_sharer(s));
#endif

  af_space = sock_af_space(s);
  laddr = sock_laddr(s);
  raddr = sock_raddr(s);
  lport = sock_lport_be16(s);
  rport = sock_rport_be16(s);
  protocol = sock_protocol(s);

  use_mac_filter = ci_tcp_use_mac_filter(ni, s, bindto_ifindex, from_tcp_id);

  /* Grab reference to the O/S socket.  This will be consumed by
   * oof_socket_add() if it succeeds.  [from_tcp_id] identifies a listening
   * TCP socket, and is used when we're setting filters for a passively
   * opened TCP connection.
   */
  spin_lock_irqsave(&ep->lock, lock_flags);
  if( OO_SP_NOT_NULL(from_tcp_id) &&
      ! ( use_mac_filter &&
          NI_OPTS(ni).scalable_listen ==
          CITP_SCALABLE_LISTEN_ACCELERATED_ONLY ) ) {

    listen_ep = ci_trs_get_valid_ep(ep->thr, from_tcp_id);
    os_sock_ref = listen_ep->os_socket;
  }
  else {
    os_sock_ref = ep->os_socket;
  }
  if( os_sock_ref != NULL )
    get_file(os_sock_ref);
  spin_unlock_irqrestore(&ep->lock, lock_flags);

  /* Loopback sockets do not need filters */
  if( (s->b.state & CI_TCP_STATE_TCP) && s->b.state != CI_TCP_LISTEN &&
      OO_SP_NOT_NULL(SOCK_TO_TCP(s)->local_peer) ) {
    rc = 0;
    goto set_os_port_keeper_and_out;
  }

  if( oof_socket_is_armed(&ep->oofilter) ) {
    /* We already have a filter.  The only legitimate way to get here is
     * UDP connect() including disconnect.
     * However, the user can call OO_IOC_EP_FILTER_SET for any endpoint,
     * and we should not crash (at least in NDEBUG build). */
    ci_assert(ep->os_port_keeper);
    ci_assert( ! in_atomic() );
    ci_assert( ~ep->thr->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT );
    ci_assert_equal(protocol, IPPROTO_UDP);

    /* Closing a listening socket without being able to get the stack
     * lock will free the OS socket but not much else, so we need to
     * cope with os_sock_ref == NULL.  We don't expect this to also
     * result in the filter already existing (so shouldn't get here in
     * that situation) but need to be robust to misbehaving UL.
     */
    if( os_sock_ref != NULL ) {
      fput(os_sock_ref);
      os_sock_ref = NULL;
    }
    else {
      OO_DEBUG_ERR(ci_log(
        "ERROR: %s is changing the socket [%d:%d] filter to "
        "%s " IPX_PORT_FMT " -> " IPX_PORT_FMT ", "
        "the filter already exists and there is no backing socket.  "
        "Something went awry.",
        __func__, ep->thr->id, OO_SP_FMT(ep->id),
        protocol == IPPROTO_UDP ? "UDP" : "TCP",
        IPX_ARG(AF_IP(laddr)), lport, IPX_ARG(AF_IP(raddr)), rport));
      ci_assert(0);
    }
    if( protocol == IPPROTO_UDP && !CI_IPX_ADDR_IS_ANY(raddr) &&
        CI_IPX_ADDR_IS_ANY(ep->oofilter.sf_raddr) ) {
      return oof_udp_connect(oo_filter_ns_to_manager(ep->thr->filter_ns),
                             &ep->oofilter, af_space, laddr, raddr, rport);
    }
    if( protocol != IPPROTO_UDP ) {
      /* UDP re-connect is OK, but we do not expect anything else.
       * We've already crashed in DEBUG, but let's complain in NDEBUG. */
      OO_DEBUG_ERR(ci_log(
        "ERROR: %s is changing the socket [%d:%d] filter to "
        "%s " IPX_PORT_FMT" -> " IPX_PORT_FMT ", "
        "but some filter is already installed.  Something went awry.",
        __func__, ep->thr->id, OO_SP_FMT(ep->id),
        protocol == IPPROTO_UDP ? "UDP" : "TCP",
        IPX_ARG(AF_IP(laddr)), lport, IPX_ARG(AF_IP(raddr)), rport));
      /* Filter is cleared so that endpoint comes back to consistent state:
       * tcp sockets after failed set filter operations have no filter.
       * However, as we are afraid that endpoint is compromised we
       * return error to prevent its use. */
      tcp_helper_endpoint_clear_filters
        (ep,
         (ni->flags & CI_NETIF_FLAG_IN_DL_CONTEXT) ?
            EP_CLEAR_FILTERS_FLAG_SUPRESS_HW : 0);
      return -EALREADY;
    }
    oof_socket_del(oo_filter_ns_to_manager(ep->thr->filter_ns), &ep->oofilter);
  }

  /* Assuming that sockets that already use MAC filter do not enter here.
   * We would have no information on how to clear the MAC filter. */
  ci_assert((s->s_flags & CI_SOCK_FLAG_STACK_FILTER) == 0);

#ifndef BREAK_SCALABLE_FILTERS
  if( use_mac_filter )
    rc = ci_tcp_sock_set_stack_filter(ni, SP_TO_SOCK(ni, ep->id));
  else
#endif
  if( OO_SP_NOT_NULL(from_tcp_id) )
    rc = oof_socket_share(oo_filter_ns_to_manager(ep->thr->filter_ns),
                          &ep->oofilter, &listen_ep->oofilter,
                          af_space, laddr, raddr, lport, rport);
  else {
    int flags;
    ci_assert( ! in_atomic() );
    ci_assert( ~ep->thr->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT );

    flags =
#if CI_CFG_ENDPOINT_MOVE
        (ep->thr->thc != NULL && (s->s_flags & CI_SOCK_FLAG_REUSEPORT) != 0) ?
            OOF_SOCKET_ADD_FLAG_CLUSTERED :
#endif
            0;

#if CI_CFG_TCP_OFFLOAD_RECYCLER
    if( enable_recycler )
      flags |= CI_Q_ID_TCP_RECYCLER << OOF_SOCKET_ADD_FLAG_SUBVI_SHIFT;
#endif

    /* We need to add the socket here, even if it doesn't want unicast filters.
     * This ensures that the filter code knows when and how the socket is
     * bound, so can appropriately install multicast filters.
     */
    if( (s->b.state == CI_TCP_STATE_UDP) &&
        UDP_GET_FLAG(SP_TO_UDP(ni, ep->id), CI_UDPF_NO_UCAST_FILTER) ) {
      ci_assert(protocol == IPPROTO_UDP);
      flags |= OOF_SOCKET_ADD_FLAG_NO_UCAST;
    }

    rc = oof_socket_add(oo_filter_ns_to_manager(ep->thr->filter_ns),
                        &ep->oofilter, flags, protocol,
                        af_space, laddr, lport, raddr, rport, NULL);
#if CI_CFG_ENDPOINT_MOVE
    if( rc != 0 && rc != -EFILTERSSOME &&
        (s->s_flags & CI_SOCK_FLAG_REUSEADDR) &&
        tcp_helper_endpoint_reuseaddr_cleanup(&ep->thr->netif, s) ) {
      rc = oof_socket_add(oo_filter_ns_to_manager(ep->thr->filter_ns),
                          &ep->oofilter, flags, protocol,
                          af_space, laddr, lport, raddr, rport, NULL);
    }
#endif
    if( rc == 0 || rc == -EFILTERSSOME )
      s->s_flags |= CI_SOCK_FLAG_FILTER;
  }

 set_os_port_keeper_and_out:
  if( os_sock_ref != NULL && (rc == 0 || rc == -EFILTERSSOME) )
    os_sock_ref = oo_file_xchg(&ep->os_port_keeper, os_sock_ref);
  if( os_sock_ref != NULL )
    fput(os_sock_ref);

#if CI_CFG_TCP_OFFLOAD_RECYCLER
  if( rc == 0 && enable_recycler ) {
    int intf_i;
    ci_assert( ! in_atomic() );
    OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
      struct efrm_pd *pd = efrm_vi_get_pd(tcp_helper_vi(ep->thr, intf_i));
      struct efrm_resource* rs = efrm_pd_to_resource(pd);
      struct xsn_ceph_create_stream create;
      ci_netif_state_nic_t* nsn = &ni->state->nic[intf_i];

      if( ni->nic_hw[intf_i].plugin_handle == INVALID_PLUGIN_HANDLE )
        continue;
      create = (struct xsn_ceph_create_stream){
        .tcp.in_app_id = cpu_to_le32(ni->nic_hw[intf_i].plugin_app_id),
        .tcp.in_user_mark = cpu_to_le32(ep->id),
        .tcp.in_synchronised = false,   /* passive-open not supported */
        .in_data_buf_capacity = NI_OPTS(ni).ceph_data_buf_bytes,
      };
      rc = efrm_ext_msg(rs, ni->nic_hw[intf_i].plugin_handle,
                        XSN_CEPH_CREATE_STREAM, &create, sizeof(create));
      if( rc ) {
        OO_DEBUG_ERR(ci_log("ERROR: Can't create Ceph stream state (%d)", rc));
        /* Current policy is to continue unaccelerated. We may add alternative
         * options later. */
        continue;
      }
      ep->plugin_stream_id[intf_i] = le32_to_cpu(create.tcp.out_conn_id);
      /* In reality, all streams are bound to have the same address space: */
      ci_assert(nsn->plugin_addr_space == 0 ||
                nsn->plugin_addr_space == create.out_addr_spc_id);
      nsn->plugin_addr_space = create.out_addr_spc_id;
    }
  }
#endif
  return rc;
}


/*--------------------------------------------------------------------
 *!
 * Clear all filters for an endpoint
 *
 * \param ep              endpoint kernel data structure
 * \param flags           see EP_CLEAR_FILTERS_FLAG_*
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

int
tcp_helper_endpoint_clear_filters(tcp_helper_endpoint_t* ep,
                                  int flags)
{
  struct file* os_sock_ref;
  ci_sock_cmn* s = SP_TO_SOCK(&ep->thr->netif, ep->id);
  int rc = 0;

  OO_DEBUG_TCPH(
    ci_log("%s: [%d:%d] %s%s%s", __FUNCTION__, ep->thr->id, OO_SP_FMT(ep->id),
           in_atomic() ? "ATOMIC":"",
           flags & EP_CLEAR_FILTERS_FLAG_SUPRESS_HW ? " SUPRESS_HW":"",
           flags & EP_CLEAR_FILTERS_FLAG_NEED_UPDATE ? " NEED_UPDATE":"")
  );

  /* Sockets have either FILTER or MAC_FILTER with exception of
   * scalable SO_REUSEPORT listen sockets, which can have both */
  ci_assert_impl(! (s->b.state == CI_TCP_LISTEN &&
                    (s->s_flags & CI_SOCK_FLAG_REUSEPORT) != 0),
                 (s->s_flags & CI_SOCK_FLAG_FILTER) == 0 ||
                 (s->s_flags & CI_SOCK_FLAG_STACK_FILTER) == 0);

#if CI_CFG_FD_CACHING
  if( (flags & EP_CLEAR_FILTERS_FLAG_NEED_UPDATE) &&
      !(s->s_flags & CI_SOCK_FLAGS_SCALABLE) )
    tcp_helper_endpoint_update_filter_details(ep);
#endif

  if( in_atomic() ) {
    ci_assert_flags(flags, EP_CLEAR_FILTERS_FLAG_SUPRESS_HW);
  }

  if( (s->s_flags & (CI_SOCK_FLAGS_SCALABLE | CI_SOCK_FLAG_STACK_FILTER)) != 0 ) {
#ifndef BREAK_SCALABLE_FILTERS
    if( (s->s_flags & CI_SOCK_FLAG_STACK_FILTER) != 0 )
      ci_tcp_sock_clear_stack_filter(&ep->thr->netif,
                                     SP_TO_TCP(&ep->thr->netif,ep->id));
#endif

    if( (s->s_flags & CI_SOCK_FLAG_FILTER) == 0 ) {
      os_sock_ref = oo_file_xchg(&ep->os_port_keeper, NULL);
      if( os_sock_ref != NULL )
        fput(os_sock_ref);
      goto bail_out;
    }
    /* scalable rss listen socket can have both MAC_FILTER flag
     * (for SW filter) as well as FILTER flag for dummy cluster oof
     * filter. */
  }
#if ! CI_CFG_UL_INTERRUPT_HELPER
  if( flags & EP_CLEAR_FILTERS_FLAG_SUPRESS_HW ) {
    /* Remove software filters immediately to ensure packets are not
     * delivered to this endpoint.  Defer oof_socket_del() if needed
     * to non-atomic context.
     */
    if( oof_socket_del_sw(oo_filter_ns_to_manager(ep->thr->filter_ns),
                          &ep->oofilter) ) {
      tcp_helper_endpoint_queue_non_atomic(ep, OO_THR_EP_AFLAG_CLEAR_FILTERS);
      /* If we have been called from atomic context, we sill might actually
       * have a hw filter. However in such a case there is a non-atomic work
       * pending on endpoint to sort that out - we fall through to clearing
       * socket filter flags */
      rc = -EAGAIN;
    }
    else {
      os_sock_ref = oo_file_xchg(&ep->os_port_keeper, NULL);
      if( os_sock_ref != NULL )
        fput(os_sock_ref);
    }
  }
  else
#endif
  {
    clear_plugin_state(ep);
    oof_socket_del(oo_filter_ns_to_manager(ep->thr->filter_ns), &ep->oofilter);
    oof_socket_mcast_del_all(oo_filter_ns_to_manager(ep->thr->filter_ns),
                             &ep->oofilter);
    os_sock_ref = oo_file_xchg(&ep->os_port_keeper, NULL);
    if( os_sock_ref != NULL )
      fput(os_sock_ref);
  }

bail_out:
  SP_TO_SOCK(&ep->thr->netif, ep->id)->s_flags &=
                              ~(CI_SOCK_FLAG_FILTER | CI_SOCK_FLAG_STACK_FILTER);

  return rc;
}

/******************* Move Filters from one ep to another ****************/
/* We support full move in 3 cases:
 * - closed TCP socket: no filters;
 * - closed UDP socket: no filters;
 * - accepted TCP socket:
 *   ep_from has shared filter,
 *   ep_to gets full filter and os socket ref
 *
 * We also support move without filters (drop_filter = true) in one case:
 * - clustered dummy tcp socket that is connecting to loopback address.
 *   hw and sw filter is left behind to be cleared in '_post' phase function.
 *   That is in fact we move os_port_keeper only.
 */

/* Move filters from one endpoint to another: called BEFORE the real move.
 * This function MUST NOT clear software filters from ep_from,
 * because there might be handled packets for it in the stack rx queue.
 */
int
tcp_helper_endpoint_move_filters_pre(tcp_helper_endpoint_t* ep_from,
                                     tcp_helper_endpoint_t* ep_to,
                                     int drop_filter)
{
  struct file* os_sock_ref;
  int rc;
  ci_sock_cmn* s = SP_TO_SOCK(&ep_from->thr->netif, ep_from->id);

  ci_assert(!in_atomic());

  if( ep_to->os_port_keeper != NULL ) {
    ci_log("%s: non-null target port keeper", __func__);
    ci_assert(0);
    return -EINVAL;
  }

  if( ! drop_filter && s->b.state != CI_TCP_CLOSED &&
      ep_from->oofilter.sf_local_port != NULL ) {
    if( (s->s_flags & CI_SOCK_FLAG_REUSEPORT) != 0 &&
        (NI_OPTS(&ep_from->thr->netif).cluster_ignore == 0 ||
         NI_OPTS(&ep_to->thr->netif).cluster_ignore == 0) ) {
      LOG_E(ci_log("%s: ERROR: reuseport being set and socket not closed",
                   __func__));
      return -EINVAL;
    }
    rc = tcp_helper_endpoint_set_filters(ep_to, CI_IFID_BAD, OO_SP_NULL);
    if( rc != 0 )
      return rc;
  }
  else {
    /* Before further operations we need to ensure no clear filter operations
     * is pending, typically tcp_helper_endpoint_set_filters() would do that
     * but we do not call it here */
    rc = tcp_helper_flush_clear_filters(ep_to);
    if(CI_UNLIKELY( rc < 0 ))
      return rc;
  }

  os_sock_ref = oo_file_xchg(&ep_from->os_port_keeper, NULL);
  if( os_sock_ref != NULL ) {
    struct file* old_ref;
    old_ref = oo_file_xchg(&ep_to->os_port_keeper, os_sock_ref);
    ci_assert_equal(old_ref, NULL);
    if( old_ref != NULL )
      fput(old_ref);
  }

  /* It should remove hw filters ONLY.
   * For now, we do not have hw filters in ep_from, so comment this out.
   * See also failure path in efab_file_move_to_alien_stack().
   tcp_helper_endpoint_clear_filters(ep_from, 0); */

  return 0;
}

/* Move filters from one endpoint to another: called AFTER the real move.
 * All ep_from filters should be cleared;
 * ep_to should have properly-installed filters.
 */
void
tcp_helper_endpoint_move_filters_post(tcp_helper_endpoint_t* ep_from,
                                      tcp_helper_endpoint_t* ep_to)
{
  tcp_helper_endpoint_clear_filters(ep_from, 0);
}

/* Move filters from one endpoint to another: undo the actions from pre().
 * All ep_to filters should be cleared;
 * ep_from should have properly-installed filters.
 */
void
tcp_helper_endpoint_move_filters_undo(tcp_helper_endpoint_t* ep_from,
                                      tcp_helper_endpoint_t* ep_to)
{
  struct file* os_sock_ref;

  os_sock_ref = oo_file_xchg(&ep_to->os_port_keeper, NULL);
  if( os_sock_ref != NULL ) {
    struct file* old_ref;
    old_ref = oo_file_xchg(&ep_from->os_port_keeper, os_sock_ref);
    ci_assert_equal(old_ref, NULL);
    if( old_ref != NULL )
      fput(old_ref);
  }

  tcp_helper_endpoint_clear_filters(ep_to, 0);
}

void
tcp_helper_endpoint_update_filter_details(tcp_helper_endpoint_t* ep)
{
  ci_netif* ni = &ep->thr->netif;
  ci_sock_cmn* s = SP_TO_SOCK(ni, ep->id);
  struct oof_manager* om = oo_filter_ns_to_manager(ep->thr->filter_ns);

  if( !(s->s_flags & (CI_SOCK_FLAG_STACK_FILTER | CI_SOCK_FLAGS_SCALABLE)) )
    oof_socket_update_sharer_details(om, &ep->oofilter,
                                     sock_ipx_raddr(s), sock_rport_be16(s));
}

static void oof_socket_dump_fn(void* arg, oo_dump_log_fn_t log, void* log_arg)
{
/* FIXME SCJ OOF */
  oof_onload_socket_dump(&efab_tcp_driver, arg, log, log_arg);
}


static void oof_manager_dump_fn(void* arg, oo_dump_log_fn_t log, void* log_arg)
{
/* FIXME SCJ OOF */
  oof_onload_manager_dump(&efab_tcp_driver, log, log_arg);
}


int
tcp_helper_endpoint_filter_dump(tcp_helper_resource_t* thr, oo_sp sockp,
                                void* user_buf, int user_buf_len)
{
  if( OO_SP_NOT_NULL(sockp) ) {
    tcp_helper_endpoint_t* ep = ci_trs_get_valid_ep(thr, sockp);
    return oo_dump_to_user(oof_socket_dump_fn, &ep->oofilter,
                           user_buf, user_buf_len);
  }
  else {
    return oo_dump_to_user(oof_manager_dump_fn, NULL, user_buf, user_buf_len);
  }
}


/*--------------------------------------------------------------------
 *!
 * Shutdown endpoint socket
 * NB it is called for a listening socket only
 *
 * \param thr             TCP helper resource
 * \param ep_id           ID of endpoint
 * \param how             How to shutdown the socket
 *
 * \return                standard error codes
 *
 *--------------------------------------------------------------------*/

int
tcp_helper_endpoint_shutdown(tcp_helper_resource_t* thr, oo_sp ep_id,
                             int how, ci_uint32 old_state)
{
  tcp_helper_endpoint_t * ep = ci_trs_get_valid_ep(thr, ep_id);
  int rc, supress_hw_ops = thr->netif.flags & CI_NETIF_FLAG_IN_DL_CONTEXT;

  ci_assert_equal(old_state, CI_TCP_LISTEN);
#if CI_CFG_FD_CACHING
  /* This must be done before we remove filters, as the information must be
   * correct for sockets sharing our filter when we do the un-share fixup.
   */
  ci_tcp_listen_update_cached(&thr->netif,
                              SP_TO_TCP_LISTEN(&thr->netif, ep->id));
#endif

  /* Calling shutdown on the socket unbinds it in most situations.
   * Since we must never have a filter configured for an unbound
   * socket, we clear the filters here. */
  tcp_helper_endpoint_clear_filters(
                ep, supress_hw_ops ? EP_CLEAR_FILTERS_FLAG_SUPRESS_HW : 0);
  /* Filter flags should have been cleared by
   * tcp_helper_endpoint_clear_filters.
   */
  ci_assert_nflags(SP_TO_SOCK(&thr->netif, ep_id)->s_flags,
                   (CI_SOCK_FLAG_FILTER | CI_SOCK_FLAG_STACK_FILTER));

  rc = efab_tcp_helper_shutdown_os_sock(ep, how);

#if ! CI_CFG_UL_INTERRUPT_HELPER
  ci_assert(ci_netif_is_locked(&thr->netif));
  ci_tcp_listen_shutdown_queues(&thr->netif,
                                SP_TO_TCP_LISTEN(&thr->netif, ep->id));
#endif
  return rc;
}
