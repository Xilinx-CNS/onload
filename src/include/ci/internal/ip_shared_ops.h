/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Control of access to the shared state.
**   \date  2005/01/12
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_internal  */
#ifndef __CI_INTERNAL_IP_SHARED_OPS_H__
#define __CI_INTERNAL_IP_SHARED_OPS_H__

/*
** READ ME FIRST please.
**
** This header contains the definition of the API for accessing the state
** of the Etherfabric TCP/IP stack (not including types, see
** ip_shared_types.h).
**
** The only stuff that may appear here is function declarations, macros and
** inline function definitions.
**
** NO TYPE DEFINITIONS IN THIS FILE PLEASE.
*/



/**********************************************************************
****************************** Netif lock *****************************
**********************************************************************/

#define ci_netif_is_locked(ni)        ef_eplock_is_locked(&(ni)->state->lock)

/* Todo: remove this, ON-12116 */
extern void ci_netif_unlock(ci_netif*) CI_HF;


#if OO_DO_STACK_POLL

#if ! CI_CFG_UL_INTERRUPT_HELPER
extern int oo_want_proactive_packet_allocation(ci_netif* ni);
#endif
extern ci_uint64
ci_netif_unlock_slow_common(ci_netif*, ci_uint64 lock_val,
                            ci_uint64 flags_to_handle) CI_HF;


/* Threshhold for proactive socket allocation is half of the shmbuf chunk
 * capability: 2^21 / 2^10 / 2 = 1024.  It can't guarantee that one driverlink
 * poll does not exhaust all the spare socket buffers, but probably gives
 * a good chance that a listener can accept all incoming connections and
 * create new sockets.
 *
 * Driverlink budget is usually 64, but with RX event merging one poll can
 * accept some hundreds of packets.
 */
#define __OO_SOCK_ALLOC_PROACTIVE_THRESH 1024
#ifdef __KERNEL__
#define OO_SOCK_ALLOC_PROACTIVE_THRESH \
  (OO_SHARED_BUFFER_CHUNK_SIZE / CI_CFG_EP_BUF_SIZE / 2)
#if OO_SOCK_ALLOC_PROACTIVE_THRESH != __OO_SOCK_ALLOC_PROACTIVE_THRESH
#error Please fix __OO_SOCK_ALLOC_PROACTIVE_THRESH value
#endif
#else
#define OO_SOCK_ALLOC_PROACTIVE_THRESH __OO_SOCK_ALLOC_PROACTIVE_THRESH
#endif
static inline int
oo_want_proactive_socket_allocation(ci_netif* ni)
{
  return ni->state->free_eps_num < OO_SOCK_ALLOC_PROACTIVE_THRESH;
}

/*! Blocking calls that grab the stack lock return 0 on success.  When
 * called at userlevel, this is the only possible outcome.  In the kernel,
 * they return -EINTR if interrupted by a signal.
 */
#if ! defined(__KERNEL__) || ! CI_CFG_UL_INTERRUPT_HELPER
#define ci_netif_lock(ni)        ef_eplock_lock(ni)
#endif

#ifdef __KERNEL__
#define ci_netif_lock_maybe_wedged(ni) ef_eplock_lock_maybe_wedged(ni)
#endif
#define ci_netif_lock_id(ni,id)  ef_eplock_lock(ni)
#define ci_netif_trylock(ni)     ef_eplock_trylock(&(ni)->state->lock)

#define ci_netif_lock_fdi(epi)   ci_netif_lock_id((epi)->sock.netif,    \
                                                  SC_SP((epi)->sock.s))
#define ci_netif_unlock_fdi(epi) ci_netif_unlock((epi)->sock.netif)

/* ci_netif_lock_count()
**
** Just like ci_netif_lock(), but increments the specified ci_netif_stats
** member on contention.
*/
#if CI_CFG_STATS_NETIF
ci_inline int __ci_netif_lock_count(ci_netif* ni, ci_uint32* stat) {
  if( ! ci_netif_trylock(ni) ) {
    int rc = ci_netif_lock(ni);
    if( rc )  return rc;
    ++*stat;
  }
  return 0;
}

# define ci_netif_lock_count(ni, stat_name)                     \
  __ci_netif_lock_count((ni), &(ni)->state->stats.stat_name)
#else
# define ci_netif_lock_count(ni, stat)  ci_netif_lock(ni)
#endif

#endif /* OO_DO_STACK_POLL */


/**********************************************************************
****************** Shared state consistency assertion *****************
**********************************************************************/

#define ci_ss_assert2(ni, e, x, y)                      \
  ci_ss_assertfl2((ni), e, x, y, __FILE__, __LINE__)

#if defined(__KERNEL__) && ! defined(NDEBUG)

/* Module parameter */
extern int no_shared_state_panic;

# define ci_ss_assertfl2(ni, e, x, y, file, line)  do {                 \
    if(CI_UNLIKELY( ! (e) )) {                                          \
      (ni)->error_flags |= CI_NETIF_ERROR_ASSERT;                       \
      (ni)->state->error_flags |= CI_NETIF_ERROR_ASSERT;                \
      LOG_SSA(ci_log("ci_ss_assert(%s)\nwhere [%s=%"CI_PRIx64"] "       \
                     "[%s=%"CI_PRIx64"]\nat %s:%d\nfrom %s:%d", #e      \
                     , #x, (ci_uint64)(ci_uintptr_t)(x)                 \
                     , #y, (ci_uint64)(ci_uintptr_t)(y),                \
                     __FILE__, __LINE__, (file), (line)));              \
      if( no_shared_state_panic == 0 )       \
          ci_fail(("Panic!"));                                          \
    }                                                                   \
  } while(0)
#else
# define ci_ss_assertfl2(netif, e, x, y, file, line)    \
        _ci_assert2(e, x, y, (file), (line))
#endif


#define ci_ss_assert_eq(ni, x, y)    ci_ss_assert2((ni), (x)==(y), x, y)
#define ci_ss_assert_neq(ni, x, y)   ci_ss_assert2((ni), (x)!=(y), x, y)
#define ci_ss_assert_le(ni, x, y)    ci_ss_assert2((ni), (x)<=(y), x, y)
#define ci_ss_assert_lt(ni, x, y)    ci_ss_assert2((ni), (x)< (y), x, y)
#define ci_ss_assert_ge(ni, x, y)    ci_ss_assert2((ni), (x)>=(y), x, y)
#define ci_ss_assert_gt(ni, x, y)    ci_ss_assert2((ni), (x)> (y), x, y)
#define ci_ss_assert_or(ni, x, y)    ci_ss_assert2((ni), (x)||(y), x, y)

#define ci_ss_assert_impl(ni, x, y)  ci_ss_assert2((ni), !(x) || (y), x, y)
#define ci_ss_assert_equiv(ni, x, y) ci_ss_assert2((ni), !(x)== !(y), x, y)



#define ci_ss_assert(ni, x)  ci_ss_assertfl(ni, x, __FILE__, __LINE__)

#if defined(__KERNEL__) && ! defined(NDEBUG)
# define ci_ss_assertfl(ni, x, file, line)  do {                        \
    if(CI_UNLIKELY( ! (x) )) {                                          \
      (ni)->error_flags |= CI_NETIF_ERROR_ASSERT;                       \
      (ni)->state->error_flags |= CI_NETIF_ERROR_ASSERT;                \
      LOG_SSA(ci_log("ci_ss_assert(%s)\nat %s:%d\nfrom %s:%d", #x,      \
                     __FILE__, __LINE__, (file), (line)));              \
      if( no_shared_state_panic == 0 )       \
          ci_fail(("Panic!"));                                          \
    }                                                                   \
  } while(0)
#else
# define ci_ss_assertfl(netif, x, file, line)  _ci_assert(x, file, line)
#endif



/**********************************************************************
*********************** Netif address conversion **********************
**********************************************************************/

/*
** The shared state consists of a contiguous region (the region accessible
** via netif->state) and various discontiguous regions including the socket
** buffers and packet buffers.
**
** The contiguous region and the socket buffers form a unified virtual
** address space, addressed by a "netif address".
**
** CI_NETIF_PTR(ni, na) converts a netif address [na] to a pointer.  This
** function does not attempt to validate the address: If necessary it
** should already have been cleaned/validated by the caller.  This call is
** safe provided [na] is valid.
**
** oo_ptr_to_statep() converts a pointer to a netif address, but can
** only be applied to a pointer that lies within the contiguous region.
*/


/* Get from a pointer to an [oo_p].  This must only be used for a pointer
** that lies within the contiguous region of the netif state.
*/
ci_inline oo_p oo_ptr_to_statep(const ci_netif* ni, void* ptr) {
  oo_p sp;
#ifdef __KERNEL__
  OO_P_INIT(sp, ni, (ci_uint32) oo_shmbuf_ptr2off(&ni->shmbuf, ptr));
#else
  OO_P_INIT(sp, ni, (ci_uint32) ((char*) ptr - (char*) ni->state));
#endif
  return sp;
}


/* The driver has a trusted version of ep_ofs. */
#if CI_CFG_NETIF_HARDEN
# define ci_netif_ep_ofs(ni)  ((ni)->ep_ofs)
#else
# define ci_netif_ep_ofs(ni)  ((ni)->state->ep_ofs)
#endif


/* Both in the kernel and at UL, the logical stack address space is mapped as
 * a single contiguous region beginning at the base address of the shared
 * state. */
ci_inline char* oo_state_off_to_ptr(ci_netif* ni, unsigned off)
{
#ifndef __KERNEL__
  return (char*) ni->state + off;;
#else
  return oo_shmbuf_off2ptr(&ni->shmbuf, off);
#endif
}


# define __CI_NETIF_PTR(ni, oop)  oo_state_off_to_ptr((ni), OO_P_OFF(oop))


#if CI_CFG_DETAILED_CHECKS
  extern char* CI_NETIF_PTR(ci_netif*, oo_p);
#else
# define CI_NETIF_PTR(ni, oop)   __CI_NETIF_PTR((ni), (oop))
#endif


/**********************************************************************
**************** Socket / citp_waitable buffers access ****************
**********************************************************************/

/* EP_BUF_SIZE must be an exact divisor of CI_PAGE_SIZE to ensure we don't
** straddle page boundaries.  We'd like to compute the number of EPs that
** fit in a page at compile-time, but that ain't easy.  So it is hard coded
** here, and checked in ci_netif_sanity_checks() to ensure it is sensible.
*/
#define EP_BUF_SIZE        CI_CFG_EP_BUF_SIZE
#define EP_BUF_PER_PAGE    (CI_PAGE_SIZE / EP_BUF_SIZE)

/* Aux buffers are sub-buffers of EP buffers.  Header at beginning,
 * and 7 aux buffer per 1024 bytes. */
#define AUX_PER_BUF ((CI_CFG_EP_BUF_SIZE - CI_AUX_HEADER_SIZE) /  \
                     CI_AUX_MEM_SIZE)


/* TRUSTED_SOCK_ID(ni, id)
**
** Munge a socket id so that it is guaranteed to be valid when in a
** hardened build.  Generates an ss-fault if not valid.
*/
#if CI_CFG_NETIF_HARDEN
ci_inline unsigned __TRUSTED_SOCK_ID(ci_netif* ni, unsigned id,
                                  const char* f, int l) {
  ci_ss_assertfl(ni, id < ni->ep_tbl_n, f, l);
  return id % ni->ep_tbl_n;
}
#else
ci_inline unsigned __TRUSTED_SOCK_ID(ci_netif* ni, unsigned id,
                                     const char* f, int l) {
  ci_ss_assertfl(ni, id < ni->state->n_ep_bufs, f, l);
  return id;
}
#endif


#define TRUSTED_SOCK_ID(ni, id)                         \
  __TRUSTED_SOCK_ID((ni), (id), __FILE__, __LINE__)

#define TRUSTED_SOCK_ID_FROM_P(ni, sockp)       \
  TRUSTED_SOCK_ID((ni), OO_SP_TO_INT(sockp))


ci_inline unsigned oo_sockid_to_state_off(ci_netif* ni, unsigned sock_id)
{ return ci_netif_ep_ofs(ni) + sock_id * EP_BUF_SIZE; }

/* Convert pointer to oo_p.
 * When in-kernel, it works for for the main state area only;
 * it should not be used for socket buffer area in kernel mode.
 */
ci_inline oo_p oo_state_ptr_to_statep(const ci_netif* ni, const void* ptr)
{
  uintptr_t off = (uintptr_t)ptr - (uintptr_t)ni->state;
  oo_p sp;
#ifdef __KERNEL__
  ci_assert_lt(off, ci_netif_ep_ofs(ni));
#endif
  OO_P_INIT(sp, ni, off);
  return sp;
}

/* oo_sockp_to_statep(ni, oo_sp)
**
** Convert an [oo_sp] to an [oo_p].  The result is guaranteed valid
** provided the socket id is valid.
*/
ci_inline oo_p oo_sockp_to_statep(ci_netif* ni, oo_sp sockp) {
  oo_p sp;
  OO_P_INIT(sp, ni, oo_sockid_to_state_off(ni, OO_SP_TO_INT(sockp)));
  return sp;
}



/* oo_sockp_to_ptr(ni, sockp)
**
** Convert a socket id to a pointer.  Safe if [sockp] is valid.
*/
ci_inline char* oo_sockp_to_ptr(ci_netif* ni, oo_sp sockp)
{ return CI_NETIF_PTR(ni, oo_sockp_to_statep(ni, sockp)); }


/* oo_sockp_to_ptr_safe(ni, sockp)
**
** Convert a socket id to a pointer.  This operation is safe even if
** [sockp] is invalid (in which case some arbitrary buffer is returned).
*/
# define TRUSTED_SOCK_P(ni, sockp)                                      \
  OO_SP_FROM_INT((ni), TRUSTED_SOCK_ID((ni), OO_SP_TO_INT(sockp)))
# define oo_sockp_to_ptr_safe(ni, sockp)                \
  oo_sockp_to_ptr((ni), TRUSTED_SOCK_P((ni), (sockp)))


/* SP_TO_foo(ni, oo_sp)
**
** Convert an [oo_sp] to the requested typed buffer.  These operations are
** safe.  It is up to the caller to be sure that the socket is of the
** appropriate type.
*/
#define SP_TO_foo(ni, sp, foo)     ((foo*) oo_sockp_to_ptr_safe((ni), (sp)))
#define SP_TO_WAITABLE_OBJ(ni, sp) SP_TO_foo((ni), (sp), citp_waitable_obj)
#define SP_TO_WAITABLE(ni, sp)	   SP_TO_foo((ni), (sp), citp_waitable)
#define SP_TO_SOCK(ni, sp)	   SP_TO_foo((ni), (sp), ci_sock_cmn)
#define SP_TO_SOCK_CMN(ni, sp)	   SP_TO_foo((ni), (sp), ci_sock_cmn)
#define SP_TO_UDP(ni, sp)	   SP_TO_foo((ni), (sp), ci_udp_state)
#define SP_TO_TCP(ni, sp)	   SP_TO_foo((ni), (sp), ci_tcp_state)
#define SP_TO_TCP_LISTEN(ni, sp)   SP_TO_foo((ni), (sp), ci_tcp_socket_listen)
#define SP_TO_PIPE(ni, sp)         SP_TO_foo((ni), (sp), struct oo_pipe)
#define SP_TO_ACTIVE_WILD(ni, sp)  SP_TO_foo((ni), (sp), ci_active_wild)

#define ID_TO_foo(ni, id, foo)     SP_TO_##foo((ni), OO_SP_FROM_INT((ni),(id)))
#define ID_TO_WAITABLE_OBJ(ni, id) ID_TO_foo((ni), (id), WAITABLE_OBJ)
#define ID_TO_WAITABLE(ni, id)     ID_TO_foo((ni), (id), WAITABLE)
#define ID_TO_SOCK(ni, id)         ID_TO_foo((ni), (id), SOCK)
#define ID_TO_SOCK_CMN(ni, id)     ID_TO_foo((ni), (id), SOCK_CMN)
#define ID_TO_UDP(ni, id)          ID_TO_foo((ni), (id), UDP)
#define ID_TO_TCP(ni, id)          ID_TO_foo((ni), (id), TCP)
#define ID_TO_TCP_LISTEN(ni, id)   ID_TO_foo((ni), (id), TCP_LISTEN)


/*********************************************************************
************************ Packet buffer access ************************
*********************************************************************/

#ifdef __KERNEL__
# define pkt_sets_n(ni) (ni)->pkt_sets_n
# define pkt_sets_max(ni) (ni)->pkt_sets_max
# define ep_tbl_n(ni) (ni)->ep_tbl_n
#else
# define pkt_sets_n(ni) (ni)->packets->sets_n
# define pkt_sets_max(ni) (ni)->packets->sets_max
# define ep_tbl_n(ni) (ni)->state->n_ep_bufs
#endif

/* VALID_PKT_ID(ni, id)
**
** Converts a packet id that may be out of range into one that definitely
** is valid and safe to use.  This is relatively expensive, so don't use in
** fast-path code.
*/
ci_inline oo_pkt_p VALID_PKT_ID(ci_netif* ni, oo_pkt_p pp) {
  OO_PP_INIT(ni, pp,
             OO_PP_ID(pp) % (pkt_sets_n(ni) << CI_CFG_PKTS_PER_SET_S));
  return pp;
}





/* TRUSTED_PKT_ID(ni, id)
**
** Munge a packet id so that it is guaranteed to be valid when in a trusted
** build.  Generates an ss-fault if not valid.
*/
#if CI_CFG_NETIF_HARDEN
ci_inline oo_pkt_p __TRUSTED_PKT_ID(ci_netif* ni, oo_pkt_p pp,
                                    const char* f, int l) {
  unsigned id = OO_PP_ID(pp);
  ci_ss_assertfl(ni, id < ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S, f, l);
  OO_PP_INIT(ni, pp, id % (ni->pkt_sets_n << CI_CFG_PKTS_PER_SET_S));
  return pp;
}
#else
ci_inline oo_pkt_p __TRUSTED_PKT_ID(ci_netif* ni, oo_pkt_p pp,
                                    const char* f, int l) {
  ci_ss_assertfl(ni, (unsigned) OO_PP_ID(pp) < ni->packets->n_pkts_allocated,
                 f, l);
  return pp;
}
#endif

#define TRUSTED_PKT_ID(ni, id)                          \
  __TRUSTED_PKT_ID((ni), (id), __FILE__, __LINE__)

#define PKT_ID2SET(id) ((id) >> CI_CFG_PKTS_PER_SET_S)
#define PKT_SET_ID(pkt) PKT_ID2SET(OO_PKT_P(pkt))

/* __PKT_BUF(ni, id)
**
** Convert packet id to buffer.  Internal use only please, no checks.
** You'd better be sure [id] is valid, and that the packet is mapped (on
** platforms that require it).
*/
#ifdef __KERNEL__
/* Note that, to avoid us having kernel-only args (or unused args in 
 * user mode), ef_iobufset_ptr() doesn't exist in the kernel */
# define __PKT_BUF(ni, id)                                      \
  oo_iobufset_ptr((ni)->pkt_bufs[PKT_ID2SET(id)],               \
                  ((id) & PKTS_PER_SET_M) * CI_CFG_PKT_BUF_SIZE)
#else
# define __PKT_BUF(ni, id)                                      \
  ((ni)->pkt_bufs[PKT_ID2SET(id)] +                             \
            ((id) & PKTS_PER_SET_M) * CI_CFG_PKT_BUF_SIZE)
#endif

/* __PKT(ni, pp)
**
** Converts an [oo_pkt_p] to a packet without any checks.  Maps it into the
** current address space if necessary.
*/
#if defined(__KERNEL__)

  /* Buffer will already be mmaped, or faulted in on demand. */
# define __PKT(ni, pp)  ((ci_ip_pkt_fmt*) __PKT_BUF((ni),OO_PP_ID(pp)))

#else

# define PKT_BUFSET_U_MMAPPED(ni, setid)  ((ni)->pkt_bufs[setid] != NULL)

extern ci_ip_pkt_fmt* __ci_netif_pkt(ci_netif* ni, unsigned id) CI_HF;

ci_inline ci_ip_pkt_fmt* __PKT(ci_netif* ni, unsigned id) {
  if(CI_LIKELY( PKT_BUFSET_U_MMAPPED((ni), (id) >> CI_CFG_PKTS_PER_SET_S) ))
    return (ci_ip_pkt_fmt*) __PKT_BUF((ni), (id));
  else
    return __ci_netif_pkt(ni, id);
}

#endif


/* PKT() converts a packet id to a pointer to the packet.  In debug
** builds it checks the id is valid.  Netif must be locked.
**
** PKT_CHK() does some additional checks on fields on the packet, so use
** this when the packet should be in a valid state.  Netif must be locked.
*/
#define PKT(ni, id)      __PKT((ni), TRUSTED_PKT_ID((ni), (id)))


/* Validate packet.  Requires netif lock. */
extern void __ci_assert_valid_pkt(ci_netif*, ci_ip_pkt_fmt*,
                                  const char* file, int line) CI_HF;
/* Validate packet.  Netif lock optional. */
extern void ci_assert_valid_pkt(ci_netif*, ci_ip_pkt_fmt*,
                                ci_boolean_t ni_locked,
                                const char* file, int line) CI_HF;


ci_inline ci_ip_pkt_fmt* __ci_pkt_chk(ci_netif* ni, oo_pkt_p pp, int ni_locked,
                                      const char* file, int line) {
#if CI_CFG_DETAILED_CHECKS
  (void) __TRUSTED_PKT_ID(ni, pp, file, line);
  ci_assert_valid_pkt(ni, __PKT(ni, pp), ni_locked, file, line);
#endif
  return __PKT(ni, __TRUSTED_PKT_ID(ni, pp, file, line));
}

#define PKT_CHK(ni, id)                                 \
  __ci_pkt_chk((ni), (id), CI_TRUE, __FILE__, __LINE__)
#define PKT_CHK_NNL(ni, id)                                     \
  __ci_pkt_chk((ni), (id), CI_FALSE, __FILE__, __LINE__)
#define PKT_CHK_NML(ni, id, ni_locked)                    \
  __ci_pkt_chk((ni), (id), (ni_locked), __FILE__, __LINE__)


ci_inline ef_addr pkt_dma_addr_bufset(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                                         int intf_i, oo_pktbuf_set* set)
{
  unsigned id = OO_PKT_ID(pkt);
  unsigned idx = id & PKTS_PER_SET_M;
  int perintf = PKTS_PER_SET >> set->page_order;
  ef_addr* dma_base = ni->dma_addrs + set->dma_addr_base;
  return dma_base[perintf * intf_i + (idx >> set->page_order)] +
         CI_CFG_PKT_BUF_SIZE * (id & ((1 << set->page_order) - 1));
}


/* Returns the address of the given packet as it should be given to the
 * hardware, i.e. for the rxq and txq */
ci_inline ef_addr pkt_dma_addr(ci_netif* ni, ci_ip_pkt_fmt* pkt, int intf_i)
{
  return pkt_dma_addr_bufset(ni, pkt, intf_i,
                             &ni->packets->set[PKT_SET_ID(pkt)]);
}


/*********************************************************************
********************* Ethernet header access *************************
*********************************************************************/

ci_inline struct oo_eth_hdr* oo_ether_hdr(const ci_ip_pkt_fmt* pkt)
{
  return (void*) (pkt->dma_start + pkt->pkt_start_off);
}

ci_inline const struct oo_eth_hdr* oo_ether_hdr_const(const ci_ip_pkt_fmt* pkt)
{
  return (void*) (pkt->dma_start + pkt->pkt_start_off);
}

ci_inline uint8_t* oo_ether_dhost(ci_ip_pkt_fmt* pkt)
{
  return oo_ether_hdr(pkt)->ether_dhost;
}

ci_inline uint8_t* oo_ether_shost(ci_ip_pkt_fmt* pkt)
{
  return oo_ether_hdr(pkt)->ether_shost;
}

/* Length of headers ahead of L3 header.  Includes encap if any. */
ci_inline int oo_pre_l3_len(const ci_ip_pkt_fmt* pkt)
{
  return pkt->pkt_eth_payload_off - pkt->pkt_start_off;
}


/*********************************************************************
************************ IP header access ****************************
*********************************************************************/

ci_inline void* oo_l3_hdr(const ci_ip_pkt_fmt* pkt)
{
  return (void*)(pkt->dma_start + pkt->pkt_eth_payload_off);
}

ci_inline ci_ip4_hdr* oo_ip_hdr(ci_ip_pkt_fmt* pkt)
{
  return oo_l3_hdr(pkt);
}

ci_inline const ci_ip4_hdr* oo_ip_hdr_const(const ci_ip_pkt_fmt* pkt)
{
  return oo_l3_hdr((ci_ip_pkt_fmt*) pkt);
}

ci_inline void* oo_ip_data(ci_ip_pkt_fmt* pkt)
{
  return ci_ip_data(oo_ip_hdr(pkt));
}

#if CI_CFG_IPV6
ci_inline ci_ip6_hdr* oo_ip6_hdr(ci_ip_pkt_fmt* pkt)
{
  return oo_l3_hdr(pkt);
}

ci_inline void* oo_ip6_data(ci_ip_pkt_fmt* pkt)
{
  return ci_ip6_data(oo_ip6_hdr(pkt));
}
#endif

ci_inline ci_ipx_hdr_t* oo_ipx_hdr(const ci_ip_pkt_fmt* pkt)
{
  return (ci_ipx_hdr_t*)oo_l3_hdr(pkt);
}

#define oo_ipx_data(af, pkt) ipx_hdr_data(af, oo_ipx_hdr(pkt))

ci_inline uint16_t oo_pkt_ether_type(ci_ip_pkt_fmt* pkt)
{
  const uint16_t* p = oo_l3_hdr(pkt);
  return p[-1];
}

#if CI_CFG_IPV6
ci_inline int oo_pkt_af(const ci_ip_pkt_fmt* pkt)
{
  return (pkt->flags & CI_PKT_FLAG_IS_IP6) ? AF_INET6 : AF_INET;
}

ci_inline void oo_pkt_af_set(ci_ip_pkt_fmt* pkt, int af)
{
  if( IS_AF_INET6(af) )
    pkt->flags |= CI_PKT_FLAG_IS_IP6;
  else
    pkt->flags &=~ CI_PKT_FLAG_IS_IP6;
}
#else
#define oo_pkt_af(pkt) AF_INET
#define oo_pkt_af_set(pkt, af)
#endif


/**********************************************************************
 * Transmit packet layout.
 *
 * When we initialise the layer-3 (and above) parts of a packet we don't
 * yet know what the layer-2 encapsulation will be, so we have to leave
 * space for the worst case.  So we place the IP header at a fixed offset,
 * and the start of the Ethernet header varies.
 */

ci_inline void oo_tx_pkt_layout_init(ci_ip_pkt_fmt* pkt)
{
  ci_assert_equal(pkt->pkt_start_off, PKT_START_OFF_BAD);
  ci_assert_equal(pkt->pkt_eth_payload_off, PKT_START_OFF_BAD);
  pkt->pkt_start_off = 0;
  pkt->pkt_eth_payload_off = ETH_HLEN;
  pkt->pkt_outer_l3_off = ETH_HLEN;
}

ci_inline void oo_tx_pkt_layout_update(ci_ip_pkt_fmt* pkt, int ether_offset)
{
  /* ether_offset==0 means VLAN tag is present.  ==4 means no VLAN. */
  int eth_hdr_len = (ETH_HLEN + ETH_VLAN_HLEN) - ether_offset;
  int16_t new_start_off = pkt->pkt_outer_l3_off - eth_hdr_len;
  int16_t delta = new_start_off - pkt->pkt_start_off;

  /* Sanity check the consistency of the values.  We only support two options,
   * ethernet header with VLAN or ethernet header without VLAN.  The
   * ethernet header (with or without VLAN) occurs directly before the
   * outer l3 header.  The only change we can make in this function is to
   * add or remove a VLAN.
   */
  ci_assert(ether_offset == 0 || ether_offset == ETH_VLAN_HLEN);
  ci_assert_equal(pkt->pkt_eth_payload_off, ETH_HLEN);
  ci_assert(pkt->pkt_start_off == pkt->pkt_outer_l3_off - ETH_HLEN ||
            pkt->pkt_start_off == pkt->pkt_outer_l3_off -
                                  (ETH_HLEN + ETH_VLAN_HLEN));
  ci_assert(delta == 0 || delta == ETH_VLAN_HLEN || delta == -ETH_VLAN_HLEN);

  pkt->pkt_start_off = new_start_off;
  pkt->buf_len -= delta;
  pkt->pay_len -= delta;
}

ci_inline struct oo_eth_hdr* oo_tx_ether_hdr(ci_ip_pkt_fmt* pkt)
{
  return oo_ether_hdr(pkt);
}

ci_inline int oo_tx_ether_hdr_size(const ci_ip_pkt_fmt* pkt)
{
  return pkt->pkt_outer_l3_off - pkt->pkt_start_off;
}

/* Length of headers ahead of L3 header.  Includes encap if any. */
ci_inline int oo_tx_pre_l3_len(const ci_ip_pkt_fmt* pkt)
{
  return pkt->pkt_eth_payload_off - pkt->pkt_start_off;
}

ci_inline int oo_tx_l3_len(const ci_ip_pkt_fmt* pkt)
{
  return pkt->pay_len - (pkt->pkt_eth_payload_off - pkt->pkt_start_off);
}

ci_inline uint16_t oo_tx_ether_type_get(const ci_ip_pkt_fmt* pkt)
{
  const uint16_t* p = (const void*) (pkt->dma_start + pkt->pkt_outer_l3_off);
  return p[-1];
}

ci_inline void oo_tx_ether_type_set(ci_ip_pkt_fmt* pkt, uint16_t ether_type)
{
  uint16_t* p = (void*) (pkt->dma_start + pkt->pkt_outer_l3_off);
  p[-1] = ether_type;
}

ci_inline void* oo_tx_outer_l3_hdr(ci_ip_pkt_fmt* pkt)
{
  return pkt->dma_start + pkt->pkt_outer_l3_off;
}

ci_inline void* oo_tx_l3_hdr(ci_ip_pkt_fmt* pkt)
{
  ci_assert_equal(pkt->pkt_eth_payload_off, ETH_HLEN);
  return pkt->dma_start + ETH_HLEN;
}

ci_inline ci_ip4_hdr* oo_tx_ip_hdr(ci_ip_pkt_fmt* pkt)
{
  return oo_tx_l3_hdr(pkt);
}

ci_inline void* oo_tx_ip_data(ci_ip_pkt_fmt* pkt)
{
  return oo_tx_ip_hdr(pkt) + 1;
}

#if CI_CFG_IPV6
ci_inline ci_ip6_hdr* oo_tx_ip6_hdr(ci_ip_pkt_fmt* pkt)
{
  return oo_tx_l3_hdr(pkt);
}

ci_inline void* oo_tx_ip6_data(ci_ip_pkt_fmt* pkt)
{
  return oo_tx_ip6_hdr(pkt) + 1;
}
#endif

#if CI_CFG_IPV6
#define oo_tx_ipx_hdr(af, pkt) ((af == AF_INET6) ? \
  (ci_ipx_hdr_t*)oo_tx_ip6_hdr(pkt) : (ci_ipx_hdr_t*)oo_tx_ip_hdr(pkt))
#define oo_tx_ipx_data(af, pkt) ((af == AF_INET6) ? \
  oo_tx_ip6_data(pkt) : oo_tx_ip_data(pkt))
#else
ci_inline ci_ipx_hdr_t* oo_tx_ipx_hdr(int af, ci_ip_pkt_fmt* pkt)
  { (void) af; return (ci_ipx_hdr_t*)oo_tx_ip_hdr(pkt); }
ci_inline void* oo_tx_ipx_data(int af, ci_ip_pkt_fmt* pkt)
  { (void) af; return oo_tx_ip_data(pkt); }
#endif

ci_inline struct ci_pkt_zc_header* oo_tx_zc_header(ci_ip_pkt_fmt* pkt)
{
  ci_assert_flags(pkt->flags, CI_PKT_FLAG_INDIRECT);
  return (struct ci_pkt_zc_header*)oo_offbuf_end(&pkt->buf);
}

ci_inline int oo_tx_zc_left(ci_ip_pkt_fmt* pkt)
{
  struct ci_pkt_zc_header* zc = oo_tx_zc_header(pkt);
  int used = CI_MEMBER_OFFSET(ci_ip_pkt_fmt, buf) + pkt->buf.end + zc->end;
  return CI_CFG_PKT_BUF_SIZE - used;
}


/*********************************************************************
**************** access to cached IP header fields *******************
*********************************************************************/

ci_inline void *ci_ip_cache_ether_hdr(const ci_ip_cached_hdrs *ipcache)
{
  return (void *)(ipcache->ether_header + ipcache->ether_offset);
}
ci_inline int ci_ip_cache_ether_hdr_len(const ci_ip_cached_hdrs *ipcache)
{
  return ETH_HLEN + ETH_VLAN_HLEN - ipcache->ether_offset;
}
ci_inline void *ci_ip_cache_ether_dhost(const ci_ip_cached_hdrs *ipcache)
{
  return (void *)(ipcache->ether_header + ipcache->ether_offset);
}
ci_inline void *ci_ip_cache_ether_shost(const ci_ip_cached_hdrs *ipcache)
{
  return (void *)(ipcache->ether_header + ipcache->ether_offset + ETH_ALEN);
}

#endif  /* __CI_INTERNAL_IP_SHARED_OPS_H__ */
/*! \cidoxg_end */
