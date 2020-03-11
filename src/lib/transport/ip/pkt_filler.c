/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
** <L5_PRIVATE L5_SOURCE>
**   Copyright: (c) Solarflare Communications Inc.
**      Author: djr
**     Started: 2009/01/14
** Description: Fill packet buffers.
** </L5_PRIVATE>
\**************************************************************************/

/*! \cidoxg_lib_transport_ip */
#include "ip_internal.h"
#include <onload/pkt_filler.h>


void oo_pkt_filler_free_unused_pkts(ci_netif* ni, int* p_netif_locked,
                                    struct oo_pkt_filler* pf)
{
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p next;

  if( pf->alloc_pkt == NULL )
    return;

  next = OO_PKT_P(pf->alloc_pkt);
  pf->alloc_pkt = NULL;

  do {
    pkt = PKT_CHK_NML(ni, next, *p_netif_locked);
    next = pkt->next;
    if( ! (pkt->flags & CI_PKT_FLAG_NONB_POOL) ) {
      if( *p_netif_locked || (*p_netif_locked = ci_netif_trylock(ni)) ) {
        ci_netif_pkt_release_1ref(ni, pkt);
        --ni->state->n_async_pkts;
        continue;
      }
      /* Couldn't get the lock without blocking, so just free it to the
       * nonblocking pool.  (We mustn't block here, as there may be a
       * signal pending).  Next time it is used it should get recycled back
       * into the normal pool again.
       */
    }
    pkt->refcount = 0;
    __ci_netif_pkt_clean(pkt);
    ci_netif_pkt_free_nonb_list(ni, OO_PKT_P(pkt), pkt);
  } while( OO_PP_NOT_NULL(next) );
}


ci_inline int oo_pkt_fill_copy(void* to, const void* from, int n_bytes
                               CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
#ifdef __KERNEL__
  if( addr_spc != CI_ADDR_SPC_KERNEL )
    return copy_from_user(to, from, n_bytes);
#endif
  memcpy(to, from, n_bytes);
  return 0;
}


int oo_pkt_fill(ci_netif* ni, ci_sock_cmn* s, int* p_netif_locked,
                int can_block,
                struct oo_pkt_filler* pf, ci_iovec_ptr* piov,
                int bytes_to_copy  CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  ci_ip_pkt_fmt* next_pkt;
  int n;
  int rc;

  ci_assert_ge((int) (pf->buf_end - pf->buf_start), 0);
  ci_assert(pf->buf_start >= PKT_START(pf->last_pkt));
  ci_assert(pf->buf_start <= pf->buf_end);
  /* ?? FIXME -- should depend on buffer size */
  ci_assert(pf->buf_end <= CI_PTR_ALIGN_FWD(PKT_START(pf->last_pkt),
                                            CI_CFG_PKT_BUF_SIZE));

  while( 1 ) {
    n = (int) (pf->buf_end - pf->buf_start);
    n = CI_MIN(n, CI_IOVEC_LEN(&piov->io));
    n = CI_MIN(n, bytes_to_copy);
    if(CI_UNLIKELY( oo_pkt_fill_copy(pf->buf_start, CI_IOVEC_BASE(&piov->io),
                                     n CI_KERNEL_ARG(addr_spc)) != 0 ))
      return -EFAULT;

    pf->buf_start += n;
    pf->pkt->pay_len += n;
    ci_iovec_ptr_advance(piov, n);

    if( n == bytes_to_copy )
      break;

    bytes_to_copy -= n;

    if( pf->buf_start == pf->buf_end ) {
      /* If [bytes_to_copy > 0] then there *must* be more to copy out of
       * [piov].  This is important so we don't allocate a new packet
       * buffer and put nothing in it.
       */
      ci_assert(CI_IOVEC_LEN(&piov->io) > 0 || piov->iovlen > 0);

      pf->last_pkt->buf_len =
        pf->buf_start - PKT_START(pf->last_pkt);

      next_pkt = oo_pkt_filler_next_pkt(ni, pf, *p_netif_locked);
      if( next_pkt == NULL ) {
        ci_assert(p_netif_locked);
        rc = ci_netif_pkt_alloc_block(ni, s, p_netif_locked, can_block,
                                      &next_pkt);
        if( rc != 0 )
          return rc;

      }
      oo_tx_pkt_layout_init(next_pkt);
      ++pf->pkt->n_buffers;

      pf->last_pkt->frag_next = OO_PKT_P(next_pkt);
      pf->last_pkt = next_pkt;
      pf->buf_start = PKT_START(next_pkt);
      /* ?? FIXME -- should depend on buffer size */
      pf->buf_end = CI_PTR_ALIGN_FWD(pf->buf_start, CI_CFG_PKT_BUF_SIZE);
      continue;
    }

    ci_assert_equal(CI_IOVEC_LEN(&piov->io), 0);
    if( piov->iovlen == 0 )
      break;
    piov->io = *piov->iov++;
    --piov->iovlen;
  }

  pf->last_pkt->buf_len = pf->buf_start - PKT_START(pf->last_pkt);
  return 0;
}
