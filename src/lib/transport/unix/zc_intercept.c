/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  kjm
**  \brief  Intercept of zero-copy API calls
**   \date  2011/06/07
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#include "internal.h"
#include <onload/ul/tcp_helper.h>

#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#include <onload/extensions.h>
#include <onload/extensions_zc.h>


/* Helper for the zc functions which accept 'any' fd to refer to the stack
 * containing that fd. Outputs the found stack in ni, or returns <0.
 * On success, caller must call citp_fdinfo_release_ref(fdi, 0) */
static int fd_to_stack(int fd, ci_netif** pni, citp_fdinfo** pfdi)
{
  int rc;
  citp_sock_fdi* epi;
  citp_fdinfo* fdi = citp_fdtable_lookup(fd);
  if( ! fdi )  /* Not an Onload socket */
    return -ESOCKTNOSUPPORT;

  switch( citp_fdinfo_get_type(fdi) ) {
  case CITP_UDP_SOCKET:
  case CITP_TCP_SOCKET:
    epi = fdi_to_sock_fdi(fdi);
    *pfdi = fdi;
    *pni = epi->sock.netif;
    return 0;
  case CITP_EPOLL_FD:
    rc = -ENOTSOCK;
    break;
  case CITP_PIPE_FD:
    rc = -ENOTSOCK;
    break;
  case CITP_PASSTHROUGH_FD:
    rc = -ESOCKTNOSUPPORT;
    break;
  default:
    LOG_U(log("%s: unknown fdinfo type %d", __FUNCTION__,
              citp_fdinfo_get_type(fdi)));
    rc = -EINVAL;
  }
  citp_fdinfo_release_ref(fdi, 0);
  return rc;
}


static bool txqs_have_reached(ci_netif* ni, const uint32_t* dest)
{
  int i;
  OO_STACK_FOR_EACH_INTF_I(ni, i) {
    int32_t diff = dest[i] - ni->state->nic[i].tx_dmaq_done_seq;
    if( diff > 0 )
      return false;
  }
  return true;
}


int onload_zc_await_stack_sync(int fd)
{
  int rc, i;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  ci_netif* ni;
  uint32_t added[CI_CFG_MAX_INTERFACES];

  Log_CALL(ci_log("%s(%d)", __FUNCTION__, fd));
  citp_enter_lib(&lib_context);

  rc = fd_to_stack(fd, &ni, &fdi);
  if( rc == 0 ) {
    int tries = 0;
    ci_netif_lock(ni);
    OO_STACK_FOR_EACH_INTF_I(ni, i)
      added[i] = ni->state->nic[i].tx_dmaq_insert_seq;
    while( ! txqs_have_reached(ni, added) ) {
      if( ++tries > 100 ) {
        /* This hack exists for the purpose of coping with NIC reset. The
         * tx_dmaq_* checking works fine in the presence of a reset, except
         * that the code to fix it all up in the tcp_helper requires the stack
         * lock. We therefore release the lock every so often for a bit. */
        tries = 0;
        ci_netif_unlock(ni);
        usleep(1);
        ci_netif_lock(ni);
      }
      ci_netif_poll(ni);
    }
    ci_netif_unlock(ni);
    citp_fdinfo_release_ref(fdi, 0);
  }

  citp_exit_lib(&lib_context, TRUE);
  Log_CALL_RESULT(rc);
  return rc;
}



int onload_zc_alloc_buffers(int fd, struct onload_zc_iovec* iovecs,
                            int iovecs_len, 
                            enum onload_zc_buffer_type_flags flags)
{
  int rc = 0, i;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  citp_sock_fdi* epi;
  ci_netif* ni;
  ci_ip_pkt_fmt *pkt;
  unsigned max_len;
  ci_tcp_state* ts = NULL;

  Log_CALL(ci_log("%s(%d, %p, %d, %x)", __FUNCTION__, fd, iovecs,
                  iovecs_len, flags));

  citp_enter_lib(&lib_context);

  rc = fd_to_stack(fd, &ni, &fdi);
  if( rc == 0 ) {
    epi = fdi_to_sock_fdi(fdi);
    ni = epi->sock.netif;
    ci_netif_lock(ni);
    if( epi->sock.s->b.state & CI_TCP_STATE_TCP_CONN )
      ts = SOCK_TO_TCP(epi->sock.s);

    for( i = 0; i < iovecs_len; ++i ) {
      max_len = CI_CFG_PKT_BUF_SIZE;
      pkt = ci_netif_pkt_tx_tcp_alloc(ni, ts);
      if( pkt == NULL ) {
        while( --i >= 0 )
          ci_netif_pkt_release(ni, zc_handle_to_pktbuf(iovecs[i].buf));
        rc = -ENOMEM;
        goto out;
      }
      /* Make sure this is clear as it affects behaviour when freeing */
      pkt->rx_flags &=~ CI_PKT_RX_FLAG_KEEP;
      pkt->user_refcount = CI_ZC_USER_REFCOUNT_ONE;
      iovecs[i].buf = zc_pktbuf_to_handle(pkt);
      if( flags & ONLOAD_ZC_BUFFER_HDR_TCP ) {
        if( ts != NULL ) {
          oo_tx_pkt_layout_init(pkt);
          iovecs[i].iov_base = ((char *)oo_tx_ip_hdr(pkt)) +
            ts->outgoing_hdrs_len;
          max_len = tcp_eff_mss(ts);
        }
        else {
          /* Best guess.  We can fix it up later.  Magic 12 leaves
           * space for time stamp option (common case)
           */
          oo_tx_pkt_layout_init(pkt);
          iovecs[i].iov_base =
            (uint8_t*) oo_tx_ip_data(pkt) + sizeof(ci_tcp_hdr) + 12;
        }
      }
      else if( flags & ONLOAD_ZC_BUFFER_HDR_UDP ) {
        oo_tx_pkt_layout_init(pkt);
        iovecs[i].iov_base =
          (uint8_t*) oo_tx_ip_data(pkt) + sizeof(ci_udp_hdr);
      }
      else
        iovecs[i].iov_base = PKT_START(pkt);
      iovecs[i].iov_len = CI_CFG_PKT_BUF_SIZE -
        ((char *)iovecs[i].iov_base - (char *)pkt);
      if( iovecs[i].iov_len > max_len )
        iovecs[i].iov_len = max_len;
    }
    ni->state->n_async_pkts += iovecs_len;
 out:
    ci_netif_unlock(ni);
    citp_fdinfo_release_ref(fdi, 0);
  } 

  citp_exit_lib(&lib_context, TRUE);
  Log_CALL_RESULT(rc);
  return rc;
}


int onload_zc_release_buffers(int fd, onload_zc_handle* bufs, int bufs_len)
{
  int rc = 0, i, rx_pkt, released;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  ci_netif* ni;
  ci_ip_pkt_fmt* pkt;

  Log_CALL(ci_log("%s(%d, %p, %d)", __FUNCTION__, fd, bufs, bufs_len));

  citp_enter_lib(&lib_context);

  rc = fd_to_stack(fd, &ni, &fdi);
  if( rc == 0 ) {
    ci_netif_lock(ni);
    for( i = 0; i < bufs_len; ++i ) {
      ci_assert_nequal(bufs[i], ONLOAD_ZC_HANDLE_NONZC);
      pkt = zc_handle_to_pktbuf(bufs[i]);
      if( pkt->stack_id != ni->state->stack_id ) {
        LOG_U(log("%s: attempt to free buffer from stack %d to stack %d",
                  __FUNCTION__, pkt->stack_id, ni->state->stack_id));
        rc = -EINVAL;
        break;
      }
    }
    if( rc == 0 ) {
      for( i = 0; i < bufs_len; ++i ) {
        pkt = zc_handle_to_pktbuf(bufs[i]);
        pkt->pio_addr = -1;  /* Got reused by user_refcount */
        /* If we are releasing a packet without the RX_FLAG then the user
          * allocated and then freed the packet (without using it).
          * We detect this to decrement n_asyn_pkts.
          * RX packets (kept via ONLOAD_ZC_KEEP) are counted differently
          * so don't decrement here.  (But may release)
          */
        rx_pkt = pkt->flags & CI_PKT_FLAG_RX;
        released = ci_netif_pkt_release_check_keep(ni, pkt);
        if ( ! rx_pkt ) {
          ci_assert(released == 1);
          (void) released;
          --ni->state->n_async_pkts;
        }
      }
    }
    ci_netif_unlock(ni);
    citp_fdinfo_release_ref(fdi, 0);
  } 

  citp_exit_lib(&lib_context, TRUE);
  Log_CALL_RESULT(rc);

  return rc;
}


int onload_zc_query_rx_memregs(int fd, struct onload_zc_iovec* iov,
                               int* iovecs_len, int flags)
{
  int rc = 0;
  unsigned i;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  ci_netif* ni;

  Log_CALL(ci_log("%s(%d, %p, %p, %d)",
                  __FUNCTION__, fd, iov, iovecs_len, flags));

  citp_enter_lib(&lib_context);

  rc = fd_to_stack(fd, &ni, &fdi);
  if( rc == 0 ) {
    int sets_n = 0;
    if( *iovecs_len < ni->packets->sets_max )
      rc = -ENOSPC;
    *iovecs_len = ni->packets->sets_max;

    if( rc == 0 ) {
      ci_netif_lock(ni);
      /* Allocate the complete range of memory right now, because the user is
       * probably going to query where it actually is in physical memory. It
       * is a future possibility to add a flag which causes this part not to
       * happen, if such a thing is found to be useful. */
      while( ni->packets->sets_n < ni->packets->sets_max ) {
        rc = ci_tcp_helper_more_bufs(ni);
        if( rc != 0 )
          break;
      }
      CHECK_FREEPKTS(ni);
      sets_n = ni->packets->sets_n;
      ci_netif_unlock(ni);
    }

    if( rc == 0 ) {
      /* We could be more generous here by collapsing contiguous regions in
       * to a single returned iov, but users aren't interested in that kind
       * of efficiency. If it ever gets done, note that typical allocation
       * patterns cause sets to get mapped top-down.
       * NB: the array indices here are those in
       * onload_zc_iovec::rx_memreg_idx, so if the fill strategy changes in
       * any way here then the callback call sites in udp_recv and tcp_recv
       * need to change too. */
      for( i = 0; i < sets_n; ++i ) {
        iov[i].iov_len = PKTS_PER_SET * CI_CFG_PKT_BUF_SIZE;
        iov[i].iov_flags = 0;
        iov[i].buf = NULL;
        iov[i].addr_space = EF_ADDRSPACE_LOCAL;
        iov[i].iov_base = PKT(ni, i << CI_CFG_PKTS_PER_SET_S);
        if( ! iov[i].iov_base ) {
          /* Mapping in to the current address space failed */
          rc = -EFAULT;
          break;
        }
      }
    }

    citp_fdinfo_release_ref(fdi, 0);
  }

  citp_exit_lib(&lib_context, TRUE);
  Log_CALL_RESULT(rc);

  return rc;
}


int onload_zc_recv(int fd, struct onload_zc_recv_args* args)
{
  int rc;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;

  Log_CALL(ci_log("%s(%d, %p(flags=%x))", __FUNCTION__, fd, args, args->flags));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    rc = citp_fdinfo_get_ops(fdi)->zc_recv(fdi, args);
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, TRUE);
  } else {
    citp_exit_lib_if(&lib_context, TRUE);
    rc = -ESOCKTNOSUPPORT;
  }

  Log_CALL_RESULT(rc);
  return rc;
}



int onload_zc_send(struct onload_zc_mmsg* msgs, int mlen, int flags)
{
  int done = 0, last_fd = -1, i;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi = NULL;

  Log_CALL(ci_log("%s(%p, %d, %x)", __FUNCTION__, msgs, mlen, flags));

  citp_enter_lib(&lib_context);

  for( i = 0; i < mlen; ++i ) {
    if( msgs[i].fd != last_fd ) {
      if( fdi != NULL )
        citp_fdinfo_release_ref(fdi, 0);
      fdi = citp_fdtable_lookup(msgs[i].fd);
      if( fdi == NULL ) {
        msgs[i].rc = -ESOCKTNOSUPPORT;
        ++done;
        goto out;
      }
      last_fd = msgs[i].fd;
    }

    CI_TRY_EQ( citp_fdinfo_get_ops(fdi)->zc_send(fdi, &msgs[i], flags), 1);
    /* If we got an error, return the number of msgs that have had
     * rc set and exit.  fd_op should have updated msgs.rc appropriately
     */
    ++done;
    if( msgs[i].rc < 0 )
      goto out;
  }

 out:

  if( fdi != NULL )
    citp_fdinfo_release_ref(fdi, 0);

  citp_exit_lib(&lib_context, TRUE);

  ci_assert_gt(done, 0);
  ci_assert_le(done, mlen);

  Log_CALL_RESULT(done);
  return done;
}


int onload_set_recv_filter(int fd, onload_zc_recv_filter_callback filter,
                           void* cb_arg, int flags)
{
  int rc;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;

  Log_CALL(ci_log("%s(%d, %p, %p, %x)", __FUNCTION__, fd, filter,
                  cb_arg, flags));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    rc = citp_fdinfo_get_ops(fdi)->zc_recv_filter(fdi, filter, cb_arg, flags);
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  } else {
    citp_exit_lib_if(&lib_context, TRUE);
    rc = -ESOCKTNOSUPPORT;
  }

  Log_CALL_RESULT(rc);
  return rc;
}


static bool is_page_aligned(uint64_t v)
{
  return (v & (CI_PAGE_SIZE - 1)) == 0;
}

/* Is the caller allowed to use remote address spaces on this netif?
 *
 * If not, return an error code. */
static int verify_addrspace_override(ci_netif* ni)
{
  int nic_i;
  int has_ef100 = 0;

  /* Only EF100 hardware supports address space overrides. Fail if the
   * machine only contains older NICs. */
  OO_STACK_FOR_EACH_INTF_I(ni, nic_i) {
    if( ci_netif_vi(ni, nic_i)->nic_type.arch == EF_VI_ARCH_EF100 )
      has_ef100 = 1;
  }

  if( !has_ef100 )
    return -EINVAL;

  /* Address space override is only allowed in physical addressing
   * mode (for now) */
  if( (NI_OPTS(ni).packet_buffer_mode & CITP_PKTBUF_MODE_PHYS) == 0 )
    return -EPERM;

  return 0;
}


static bool have_af_xdp(ci_netif* ni)
{
  int nic_i;

  OO_STACK_FOR_EACH_INTF_I(ni, nic_i)
    if( ci_netif_vi(ni, nic_i)->nic_type.arch == EF_VI_ARCH_AF_XDP )
      return true;

  return false;
}


int onload_zc_register_buffers(int fd, ef_addrspace addr_space,
                               uint64_t base_ptr, uint64_t len, int flags,
                               onload_zc_handle* handle)
{
  int rc;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  ci_netif* ni;

  Log_CALL(ci_log("%s(%d, %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %d, %p)",
                  __FUNCTION__, fd, addr_space, base_ptr, len, flags, handle));

  citp_enter_lib(&lib_context);

  if( flags )
    rc = -EINVAL;
  else if( addr_space == EF_ADDRSPACE_LOCAL &&
           (base_ptr == 0 || ! is_page_aligned(base_ptr)) )
    rc = -EINVAL;
  else if( len == 0 || ! is_page_aligned(len) )
    rc = -EINVAL;
  else if( len >> EF_VI_NIC_PAGE_SHIFT > INT_MAX )
    rc = -E2BIG;
  else if( (rc = fd_to_stack(fd, &ni, &fdi)) == 0 ) {
    int num_pages = len >> EF_VI_NIC_PAGE_SHIFT;
    struct ci_zc_usermem* um = malloc(sizeof(struct ci_zc_usermem) +
                                      sizeof(um->hw_addrs[0]) * num_pages *
                                      oo_stack_intf_max(ni));
    if( ! um )
      rc = -ENOMEM;
    else if( addr_space != EF_ADDRSPACE_LOCAL &&
             (rc = verify_addrspace_override(ni)) < 0 ) {
      /* error code already set appropriately */
    }
    else if( have_af_xdp(ni) ) {
      /* Because AF_XDP doesn't support checksum offload, the code necessary
       * to compute checksums on the host is gnarly and thus non-existant. */
      rc = -ENOTSUP;
    }
    else {
      um->addr_space = addr_space;
      um->base = base_ptr;
      um->size = len;

      if( addr_space == EF_ADDRSPACE_LOCAL )
        rc = ci_tcp_helper_zc_register_buffers(ni, (void*)(uintptr_t)base_ptr,
                                               num_pages, um->hw_addrs,
                                               &um->kernel_id);

      if( rc == 0 )
        *handle = zc_usermem_to_handle(um);
    }
    if( rc )
      free(um);

    citp_fdinfo_release_ref(fdi, 0);
  }

  citp_exit_lib(&lib_context, TRUE);
  Log_CALL_RESULT(rc);
  return rc;
}


int onload_zc_unregister_buffers(int fd, onload_zc_handle handle, int flags)
{
  int rc;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;
  ci_netif* ni;

  Log_CALL(ci_log("%s(%d, %p, %d)", __FUNCTION__, fd, handle, flags));

  citp_enter_lib(&lib_context);

  if( handle == ONLOAD_ZC_HANDLE_NONZC || ! zc_is_usermem(handle) )
    rc = -EINVAL;
  else if( flags )
    rc = -EINVAL;
  else if( (rc = fd_to_stack(fd, &ni, &fdi)) == 0 ) {
    struct ci_zc_usermem* um = zc_handle_to_usermem(handle);

    if( um->addr_space == EF_ADDRSPACE_LOCAL )
      rc = ci_tcp_helper_zc_unregister_buffers(ni, um->kernel_id);

    if( rc == 0 )
      free(um);

    citp_fdinfo_release_ref(fdi, 0);
  }

  citp_exit_lib(&lib_context, TRUE);
  Log_CALL_RESULT(rc);
  return rc;
}


int onload_recvmsg_kernel(int fd, struct msghdr *msg, int flags)
{
  int rc;
  citp_lib_context_t lib_context;
  citp_fdinfo* fdi;

  Log_CALL(ci_log("%s(%d, %p, %x)", __FUNCTION__, fd, msg, flags));

  if( (fdi = citp_fdtable_lookup_fast(&lib_context, fd)) ) {
    rc = citp_fdinfo_get_ops(fdi)->recvmsg_kernel(fdi, msg, flags);
    citp_fdinfo_release_ref_fast(fdi);
    citp_exit_lib(&lib_context, rc >= 0);
  } else {
    citp_exit_lib_if(&lib_context, TRUE);
    rc = -ESOCKTNOSUPPORT;
  }

  Log_CALL_RESULT(rc);
  return rc; 
}


int onload_zc_buffer_incref(int fd, onload_zc_handle buf)
{
  int rc = 0;
  ci_ip_pkt_fmt* pkt = zc_handle_to_pktbuf(buf);

  Log_CALL(ci_log("%s(%d, %p)", __FUNCTION__, fd, buf));

  __sync_add_and_fetch(&pkt->user_refcount, 1);

  Log_CALL_RESULT(rc);
  return rc;
}


int onload_zc_buffer_decref(int fd, onload_zc_handle buf)
{
  int rc = 0;
  ci_ip_pkt_fmt* pkt = zc_handle_to_pktbuf(buf);

  Log_CALL(ci_log("%s(%d, %p)", __FUNCTION__, fd, buf));

  /* We can avoid the atomic in the common case that we're removing the last
   * ref, because anybody else trying to increment it again would be
   * inherently racing */
  if( pkt->user_refcount == CI_ZC_USER_REFCOUNT_ONE ||
      __sync_sub_and_fetch(&pkt->user_refcount, 1) <
          CI_ZC_USER_REFCOUNT_ONE ) {
    rc = onload_zc_release_buffers(fd, &buf, 1);
    if( rc < 0 )
      pkt->user_refcount = CI_ZC_USER_REFCOUNT_ONE;
  }

  Log_CALL_RESULT(rc);
  return rc;
}
