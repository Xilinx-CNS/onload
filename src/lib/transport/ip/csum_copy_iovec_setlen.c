/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
 /**************************************************************************\
 *//*! \file
 ** <L5_PRIVATE L5_SOURCE>
 ** \author  cjr/ctk
 **  \brief  Copy from iovec with Internet checksum.
 **   \date  2004/01/06
 **    \cop  (c) Level 5 Networks Limited.
 ** </L5_PRIVATE>
 *//*
 \**************************************************************************/

 /*! \cidoxg_lib_citools */

#include "ip_internal.h"


ci_inline int do_copy_from_user(void* to, const void* from, int n_bytes
                      CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
#ifdef __KERNEL__
  if( addr_spc != CI_ADDR_SPC_KERNEL )
    return copy_from_user(to, from, n_bytes);
#endif
  memcpy(to, from, n_bytes);
  return 0;
}


int __ci_copy_iovec_to_pkt(ci_netif* ni, ci_ip_pkt_fmt* pkt,
                           ci_iovec_ptr* piov
                           CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  int n, total;
  char* dest;

  ci_assert(! ci_iovec_ptr_is_empty_proper(piov));
  ci_assert_gt(oo_offbuf_left(&pkt->buf), 0);

  dest = oo_offbuf_ptr(&pkt->buf);

  ci_assert_equal(pkt->n_buffers, 1);

  total = 0;
  while( 1 ) {
    n = oo_offbuf_left(&pkt->buf);
    n = CI_MIN(n, (int)CI_IOVEC_LEN(&piov->io));
    if(CI_UNLIKELY( do_copy_from_user(dest, CI_IOVEC_BASE(&piov->io), n
                                      CI_KERNEL_ARG(addr_spc)) ))
      return -EFAULT;

    /* TODO this isn't correct unless (n_buffers == 1) - it needs this
     * code to be updated to increment buf_len on current and
     * pay_len on first pkt in frag_next chain
     */
    pkt->buf_len += n;
    pkt->pay_len += n;

    total += n;
    ci_iovec_ptr_advance(piov, n);
    oo_offbuf_advance(&pkt->buf, n);

    /* We've either exhaused the source data (piov), the segment, or the
    ** space in the packet.  For latency critical apps, exhausting the
    ** source data is most likely, so we check for that first.
    */
    if( CI_IOVEC_LEN(&piov->io) == 0 ) {
      if( piov->iovlen == 0 )  goto done;
      --piov->iovlen;
      piov->io = *piov->iov++;
    }

    if( oo_offbuf_left(&pkt->buf) == 0 )  goto done;

    dest += n;
  }

done:
  return total;
}


ci_inline int do_copy_to_user(void* to, const void* from, int n_bytes
                      CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
#ifdef __KERNEL__
  if( addr_spc != CI_ADDR_SPC_KERNEL )
    return copy_to_user(to, from, n_bytes);
#endif
  memcpy(to, from, n_bytes);
  return 0;
}

ssize_t
__ci_ip_copy_pkt_to_user(ci_netif* ni, ci_iovec* iov, ci_ip_pkt_fmt* pkt,
                         int peek_off CI_KERNEL_ARG(ci_addr_spc_t addr_spc))
{
  size_t len;

  len = oo_offbuf_left(&pkt->buf) - peek_off;
  len = CI_MIN(len, CI_IOVEC_LEN(iov));

  if( do_copy_to_user(CI_IOVEC_BASE(iov), oo_offbuf_ptr(&pkt->buf) + peek_off,
                      len CI_KERNEL_ARG(addr_spc)) ) {
    ci_log("%s: faulted", __FUNCTION__);
    return -EFAULT;
  }

  CI_IOVEC_BASE(iov) = (char *)CI_IOVEC_BASE(iov) + len;
  CI_IOVEC_LEN(iov) -= len;

  return len;
}


#ifdef __KERNEL__
size_t
__ci_ip_copy_pkt_from_piov(
  ci_netif                        *ni,
  ci_ip_pkt_fmt                   *pkt,
  ci_iovec_ptr                    *piov,
  ci_addr_spc_t                   addr_spc)
{
  if( addr_spc == CI_ADDR_SPC_KERNEL || addr_spc == CI_ADDR_SPC_CURRENT)
    return ci_copy_iovec_to_pkt(ni, pkt, piov, addr_spc);

  /* ?? We want to know about this for now. */
  ci_log("%s: addr_spc=%d", __FUNCTION__, addr_spc);
  return 0;
}
                   
#else  /* ! __KERNEL__ */

size_t
__ci_ip_copy_pkt_from_piov(
  ci_netif                        *ni,
  ci_ip_pkt_fmt                   *pkt,
  ci_iovec_ptr                    *piov)
{
  /* ?? TODO: We should inline this in ip.h. */
  return ci_copy_iovec_to_pkt(ni, pkt, piov);
}

#endif  /* __KERNEL__ */
/*! \cidoxg_end */
