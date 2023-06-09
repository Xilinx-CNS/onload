/* TX timestamp to CMSG  including support functions */

/* Special return codes from ci_udp_recvmsg_socklocked_slowpath() */
#define SLOWPATH_RET_IOVLEN_INITED (1<<30)
#define SLOWPATH_RET_ZERO (SLOWPATH_RET_IOVLEN_INITED + 1)

#define LOCAL_MSG_TRUNC	MSG_TRUNC

struct oo_copy_state {
  int pkt_left;
  int pkt_off;
  int bytes_copied;
  int bytes_to_copy;
  const char *from;
  const ci_ip_pkt_fmt* pkt;
};

ci_inline int do_copy(void* to, const void* from, int n_bytes)
{
#ifdef __KERNEL__
  return copy_to_user(to, from, n_bytes) != 0;
#else
  memcpy(to, from, n_bytes);
  return 0;
#endif
}


ci_inline int
__oo_copy_frag_to_iovec_no_adv(ci_netif* ni, 
                               ci_iovec_ptr* piov, 
                               struct oo_copy_state *ocs)
{
  int n;

  n = CI_MIN((size_t)ocs->pkt_left, CI_IOVEC_LEN(&piov->io));
  n = CI_MIN(n, ocs->bytes_to_copy);
  if(CI_UNLIKELY( do_copy(CI_IOVEC_BASE(&piov->io),
                          ocs->from + ocs->pkt_off, n) != 0 ))
    return -EFAULT;
  
  ocs->bytes_copied += n;
  ocs->pkt_off += n;
  if( n == ocs->bytes_to_copy )
    return 0;
  
  ocs->bytes_to_copy -= n;
  if( n == ocs->pkt_left ) {
    /* Caller guarantees that packet contains at least [bytes_to_copy]. */
    ci_assert(OO_PP_NOT_NULL(ocs->pkt->frag_next));
    ci_iovec_ptr_advance(piov, n);
    ocs->pkt = PKT_CHK_NNL(ni, ocs->pkt->frag_next);
    ocs->pkt_off = 0;
    /* We're unlikely to hit end-of-pkt-buf and end-of-iovec at the same
     * time, and if we do, just go round the loop again.
     */
    return 1;
  }
  
  ci_assert_equal(n, CI_IOVEC_LEN(&piov->io));
  if( piov->iovlen == 0 )
    return 0;
  piov->io = *piov->iov++;
  --piov->iovlen;

  return 1;
}


#ifndef __KERNEL__
#if CI_CFG_TIMESTAMPING
/* Very similar to oo_copy_pkt_to_iovec_no_adv() but doesn't use pkt->buf */
static int 
ci_udp_timestamp_q_pkt_to_iovec(ci_netif* ni, const ci_ip_pkt_fmt* pkt,
                                ci_iovec_ptr* piov)
{
  int rc;
  struct oo_copy_state ocs;
  ocs.bytes_copied = 0;
  /* We have to copy all chunks of jumbo frame, so pkt->buf_len is wrong
   * here. */
  ocs.bytes_to_copy = CI_BSWAP_BE16(oo_ip_hdr_const(pkt)->ip_tot_len_be16) +
    oo_tx_pre_l3_len(pkt);
  ocs.pkt_off = 0;
  ocs.pkt = pkt;
  while( 1 ) {
    /* Don't use pkt->buf so we don't interfere with the data path.  We
     * need different offsets to include the delivery of the headers
     */
    ocs.pkt_left = ocs.pkt->buf_len - ocs.pkt_off;
    ocs.from = (char *)oo_ether_hdr_const(ocs.pkt);
    rc = __oo_copy_frag_to_iovec_no_adv(ni, piov, &ocs);
    if( rc == 0 )
      return ocs.bytes_copied;
    else if( rc == 1 )
      continue;
    else if( rc < 0 )
      return rc;
    else
      ci_assert(0);
  }
}


static inline int ci_ip_tx_timestamping_to_cmsg(int proto, ci_netif* ni,
                                                  ci_ip_pkt_fmt* pkt,
                                                  ci_sock_cmn* s,
                                                  struct cmsg_state* cmsg_state,
                                                  ci_iovec_ptr* piov)
{
  int rc = 0;

  struct {
    struct oo_sock_extended_err ee;
    union {
      struct sockaddr_in        offender;
#if CI_CFG_IPV6
      struct sockaddr_in6       offender6;
#endif
    };
  } __attribute__((packed, aligned(sizeof(ci_uint32)))) errhdr;

  int do_data = ( cmsg_state->msg->msg_iovlen > 0 );
  if( do_data )
    ci_iovec_ptr_init_nz(piov, cmsg_state->msg->msg_iov, cmsg_state->msg->msg_iovlen);

  if( s->timestamping_flags & ONLOAD_SOF_TIMESTAMPING_ONLOAD ) {
    struct onload_timestamp ts = {pkt->hw_stamp.tv_sec,
                                  pkt->hw_stamp.tv_nsec};
    ci_put_cmsg(cmsg_state, SOL_SOCKET, ONLOAD_SCM_TIMESTAMPING,
                sizeof(ts), &ts);
  }
  else {
    struct timespec ts[3];
    memset(ts, 0, sizeof(ts));

    if( s->timestamping_flags & ONLOAD_SOF_TIMESTAMPING_RAW_HARDWARE ) {
      ts[2].tv_sec = pkt->hw_stamp.tv_sec;
      ts[2].tv_nsec = pkt->hw_stamp.tv_nsec;
    }
    if( (s->timestamping_flags & ONLOAD_SOF_TIMESTAMPING_SYS_HARDWARE) &&
        (pkt->hw_stamp.tv_nsec & CI_IP_PKT_HW_STAMP_FLAG_IN_SYNC) ) {
      ts[1].tv_sec = pkt->hw_stamp.tv_sec;
      ts[1].tv_nsec = pkt->hw_stamp.tv_nsec;
    }
    ci_put_cmsg(cmsg_state, SOL_SOCKET, ONLOAD_SCM_TIMESTAMPING,
                sizeof(ts), &ts);
  }

  if( s->timestamping_flags & ONLOAD_SOF_TIMESTAMPING_OPT_TSONLY ) {
    rc = SLOWPATH_RET_ZERO;
  }
  else if( do_data ) {
    rc = ci_udp_timestamp_q_pkt_to_iovec(ni, pkt, piov);
    if( rc < pkt->buf_len )
      *cmsg_state->p_msg_flags |= LOCAL_MSG_TRUNC;
  }
  else {
    *cmsg_state->p_msg_flags |= LOCAL_MSG_TRUNC;
    rc = SLOWPATH_RET_ZERO;
  }

  memset(&errhdr, 0, sizeof(errhdr));
  errhdr.ee.ee_errno = ENOMSG;
  errhdr.ee.ee_origin = SO_EE_ORIGIN_TIMESTAMPING;
  errhdr.ee.ee_info = 0;
  errhdr.ee.ee_data = pkt->ts_key;

  if( s->timestamping_flags & ONLOAD_SOF_TIMESTAMPING_OPT_CMSG ) {
    ci_addr_t saddr = ipx_hdr_saddr(oo_pkt_af(pkt), oo_ipx_hdr(pkt));
#if CI_CFG_IPV6
    if( IS_AF_INET6(s->domain) )
      ci_make_sockaddr_in6_from_ip6(&errhdr.offender6, 0,
                                    (ci_uint32*)saddr.ip6);
    else
#endif
      ci_make_sockaddr_from_ip4(&errhdr.offender, 0, saddr.ip4);
  }

#if CI_CFG_IPV6
  if( IS_AF_INET6(s->domain) )
    ci_put_cmsg(cmsg_state, SOL_IPV6, IPV6_RECVERR,
                sizeof(errhdr.ee) + sizeof(errhdr.offender6), &errhdr);
  else
#endif
    ci_put_cmsg(cmsg_state, SOL_IP, IP_RECVERR,
                sizeof(errhdr.ee) + sizeof(errhdr.offender), &errhdr);

  return rc;
}
#endif
#endif
