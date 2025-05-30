/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2019 Xilinx, Inc. */

#include "internal.h"
#include "ul_poll.h"
#include "ul_select.h"


/****************************************************************************
 ************************************ SELECT ********************************
 ****************************************************************************/

#ifdef __GLIBC__
# define CI_NFDBITS        __NFDBITS
# define CI_FDS_BITS(f)    __FDS_BITS(f)
  typedef __fd_mask        ci_fd_mask;
#else
# error Need help here please.
#endif


#define merge_fdsets(n_words, out, in1, in2)            \
do {                                                    \
  int i;                                                \
  for (i = 0; i < (n_words); i++) {                     \
    CI_FDS_BITS(out)[i] = CI_FDS_BITS(in1)[i] |         \
                          CI_FDS_BITS(in2)[i];          \
  }                                                     \
} while(0)


static void select_zero(fd_set* rds, fd_set* wrs, fd_set* exs, int n_words)
{
  if( rds )  memset(rds, 0, n_words * sizeof(ci_fd_mask));
  if( wrs )  memset(wrs, 0, n_words * sizeof(ci_fd_mask));
  if( exs )  memset(exs, 0, n_words * sizeof(ci_fd_mask));
}

static struct timeval nonblock_tv = {0,0};

#ifdef NDEBUG

# define log_select(msg, nfds, rds, wrs, exs, timeout)  \
         do{}while(0)

# define do_sys_select(why, nfds, rds, wrs, exs)       \
         ci_sys_select((nfds), (rds), (wrs), (exs), &nonblock_tv)

#else

static int ci_format_select_set(char* s, int len_s, int nfds, const fd_set* fds)
{
  int i, rc, n = 0, first = 1;

  if( len_s < 3 ) {
    s[0] = '\0';
    return 0;
  }
  if( fds == 0 ) {
    s[0] = '[';
    s[1] = ']';
    s[2] = '\0';
    return 2;
  }

  s[0] = '[';
  s[1] = '\0';
  n = 1;

  for( i = 0; i < nfds && len_s - n > 1; ++i )
    if( FD_ISSET(i, fds) ) {
      rc = snprintf(s + n, len_s - n, first ? "%d":",%d", i);
      if( rc < 0 || rc >= len_s - n || len_s - n - rc < 2 ) {
	s[n++] = '-';
	s[n] = '\0';
	return n;
      }
      n += rc;
      first = 0;
    }

  if( len_s - n > 1 ) {
    s[n++] = ']';
    s[n] = '\0';
  }
  return n;
}


static int ci_format_select(char* s, int len_s, int nfds,
                            const fd_set* rds, const fd_set* wrs,
                            const fd_set* exs, int timeout)
{
  int n = 0, rc;

  rc = snprintf(s + n, len_s - n, "(%d, ", nfds);
  if( rc < 0 || rc >= len_s - n )  return n;
  n += rc;

  n += ci_format_select_set(s + n, len_s - n, nfds, rds);
  if( len_s - n < 3 )  return n;

  n += snprintf(s + n, 3, ", ");

  n += ci_format_select_set(s + n, len_s - n, nfds, wrs);
  if( len_s - n < 3 )  return n;

  n += snprintf(s + n, 3, ", ");

  n += ci_format_select_set(s + n, len_s - n, nfds, exs);
  if( len_s - n < 3 )  return n;

  rc = snprintf(s + n, len_s - n, ", %d)", timeout);
  if( rc < 0 || rc >= len_s - n )  return n;
  n += rc;

  return n;
}

static inline void log_select(const char* msg, int nfds,
                              fd_set* rds, fd_set* wrs, fd_set* exs,
                              int timeout)
{
  char s[1024];
  ci_format_select(s, sizeof(s), nfds, rds, wrs, exs, timeout);
  ci_log("select[%s]%s", msg, s);
}


static inline int do_sys_select(const char* why, int nfds,
                                fd_set* rds, fd_set* wrs, fd_set* exs)
{
  char s[1024];
  char r[256], w[256], e[256];
  int rc;
  Log_SEL(ci_format_select(s, sizeof(s), nfds, rds, wrs, exs, 0));
  rc = ci_sys_select(nfds, rds, wrs, exs, &nonblock_tv);
  Log_SEL(if( rc > 0 ) {
            ci_format_select_set(r, sizeof(r), nfds, rds);
            ci_format_select_set(w, sizeof(w), nfds, wrs);
            ci_format_select_set(e, sizeof(e), nfds, exs);
            ci_log("select[%s]%s => %d (%s %s %s)", why, s, rc, r, w, e);
          }
          else {
            ci_log("select[%s]%s => %d", why, s, rc);
          }
          );
  return rc;
}
#endif

#define ci_count_trailing_zeros(x) __builtin_ctzll(x)

/*
 * get next fd bit.
 * /

static inline ci_fd_mask ci_bitmap_next_set(ci_fd_mask *ai, ci_fd_mask i, int nwords)
{
  ci_fd_mask i0 = i / CI_NFDBITS;
  ci_fd_mask i1 = i % CI_NFDBITS;
  ci_fd_mask t;

  if (i0 < nwords) {
    t = (ai[i0] >> i1) << i1;

    if (t) {
      return ci_count_trailing_zeros(t) + i0 * CI_NFDBITS;
    }

    for (i0++; i0 < nwords; i0++) {
      t = ai[i0];
      if (t) {
        return ci_count_trailing_zeros(t) + i0 * CI_NFDBITS;
      }
    }
  }

  return ~0;
}

/*
** Performs a select for user level entries in the fdset
** Input fdsets are {rd,wr,ex}in
** Kernel fds are returned in {rd,rw,ex}k - assumed clear on entry
** Ul status is returned in {rd,rw,ex}out - assumed clear on entry
*/
ci_inline int citp_ul_select(struct oo_ul_select_state*__restrict__ s)
{
  int r, w, e, fd, n = 0;
  int n_words, i, fd_min = -1;

#if CI_CFG_SPIN_STATS
  s->stat_incremented = 0;
#endif
  ci_assert(s->nfds_inited >= 0);
  ci_assert(s->nfds_inited <= citp_fdtable.inited_count);

  if( citp_fdtable_not_mt_safe() )
    CITP_FDTABLE_LOCK_RD();

  s->is_kernel_fd = 0;
  n_words = (s->nfds_inited + CI_NFDBITS - 1) / CI_NFDBITS;
  ci_fd_mask union_fds[n_words];
  ci_fd_mask *rdm = (ci_fd_mask*)s->rdi;
  ci_fd_mask *wrm = (ci_fd_mask*)s->wri;
  ci_fd_mask *exm = (ci_fd_mask*)s->exi;
  ci_fd_mask rdvalue, wrvalue, exvalue;

  for( i = 0; i < n_words; i++ ) {
    rdvalue = rdm ? rdm[i] : 0;
    wrvalue = wrm ? wrm[i] : 0;
    exvalue = exm ? exm[i] : 0;

    union_fds[i] = rdvalue | wrvalue | exvalue;
    if (union_fds[i] != 0 && fd_min == -1) {
      fd_min = i * CI_NFDBITS + ci_count_trailing_zeros(union_fds[i]);
    }
  }

  for( fd = fd_min; fd < s->nfds_inited && fd != ~0;
       fd = ci_bitmap_next_set( union_fds, fd + 1, n_words ) ) {
    r = FD_ISSET(fd, s->rdi);
    w = FD_ISSET(fd, s->wri);
    e = FD_ISSET(fd, s->exi);

    if( r | w | e ) {
      citp_fdinfo_p fdip = citp_fdtable.table[fd].fdip;
      if( fdip_is_normal(fdip) ) {
	citp_fdinfo* fdi = fdip_to_fdi(fdip);

        /* If SO_BUSY_POLL behaviour requested need to check if there is
         * a spinning socket in the set, and remove flag to enable spinning
         * if it is found */
        if( ( s->ul_select_spin & (1 << ONLOAD_SPIN_SO_BUSY_POLL) ) &&
            citp_fdinfo_get_ops(fdip_to_fdi(fdip))->
                                        is_spinning(fdip_to_fdi(fdip)) ) {
          s->ul_select_spin &= ~(1 << ONLOAD_SPIN_SO_BUSY_POLL);
        }

	if( citp_fdinfo_get_ops(fdi)->select(fdi, &n, r, w, e, s) ) {
	  s->is_ul_fd = 1;
	  continue;
	}
      }

      if( r )  FD_SET(fd, s->rdk);
      if( w )  FD_SET(fd, s->wrk);
      if( e )  FD_SET(fd, s->exk);
      s->is_kernel_fd = 1;
    }
  }

  if( citp_fdtable_not_mt_safe() )
    CITP_FDTABLE_UNLOCK_RD();

  for( ; fd < s->nfds_split; ++fd ) {
    r = FD_ISSET(fd, s->rdi);
    w = FD_ISSET(fd, s->wri);
    e = FD_ISSET(fd, s->exi);
    if( r | w | e ) {
      if( r )  FD_SET(fd, s->rdk);
      if( w )  FD_SET(fd, s->wrk);
      if( e )  FD_SET(fd, s->exk);
      s->is_kernel_fd = 1;
    }
  }

  /* If we'd like to spin for spinning socket only, and we've failed to
   * find any - remove spinning flags. */
  if( s->ul_select_spin & (1 << ONLOAD_SPIN_SO_BUSY_POLL) )
    s->ul_select_spin = 0;

  return n;
}

/* Generic select/pselect implementation. */
int citp_ul_do_select(int nfds, fd_set* rds, fd_set* wrs, fd_set* exs,
                      ci_uint64 timeout_ms, ci_uint64 *used_ms,
                      citp_lib_context_t *lib_context,
                      const sigset_t *sigmask)
{
  /* Sorry, but we're relying somewhat on how GLIBC arranges its fd_set.
  ** Will need some work to run on anything other than GLIBC.
  */
  struct oo_ul_select_state s;
  int n_words;           // number of words to store the fdsets
  int n_words_bs;        // number of words before the split
  int n_bytes_bs;        // number of bytes before the split
  int n_bytes_as;        // number of bytes after the split
  int n;                 // number of ul fds that are ready
  int split;             // true if a split is occuring
  int polled_kfds = 0;
  struct timeval non_blocking;
  ci_uint64 poll_start_frc = 0;
  ci_uint64 poll_fast_frc = 0;
  int sigmask_set = 0;
  sigset_t sigsaved;

  Log_FL(CI_UL_LOG_CALL | CI_UL_LOG_SEL,
         log_select("enter", nfds, rds, wrs, exs, timeout_ms));

  /* Cope with some apps just passing a really big number in [nfds]
  ** Split between ul/kern and kern only handling at nfds_split
  */
  /* Round to a word address */
  n_words    = (nfds                      + CI_NFDBITS - 1) / CI_NFDBITS;
  n_words_bs = (citp_fdtable.inited_count + CI_NFDBITS - 1) / CI_NFDBITS;
  split      = n_words_bs < n_words;
  if( split ) {
    s.nfds_inited = citp_fdtable.inited_count;
    s.nfds_split = n_words_bs * CI_NFDBITS;
  }
  else {
    n_words_bs = n_words;
    s.nfds_inited = CI_MIN(nfds, citp_fdtable.inited_count);
    s.nfds_split = nfds;
  }
  n_bytes_bs = n_words_bs * sizeof(ci_fd_mask);
  n_bytes_as = (n_words - n_words_bs) * sizeof(ci_fd_mask);
  s.is_ul_fd = 0;
  s.ul_select_spin = 
    oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_SELECT);
  if( s.ul_select_spin ) {
    s.ul_select_spin |=
      oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_SO_BUSY_POLL);
  }

  {
    ci_fd_mask *bits = alloca(n_words * 7 * sizeof (ci_fd_mask));

    /* If any input sets are NULL, we point them at a set of zeros.  (This is
    ** just to avoid some conditionals).
    */
    if (!rds | !wrs | !exs) {
      /* Create a zero set
       * cast to a char* to avoid strict aliasing warning */
      char* zero_set = (char*) (bits + 0 * n_words);
      memset(bits, 0, n_words_bs * sizeof(ci_fd_mask));
      s.rdi = rds ? rds : (fd_set*)zero_set;
      s.wri = wrs ? wrs : (fd_set*)zero_set;
      s.exi = exs ? exs : (fd_set*)zero_set;
    } else {
      s.rdi = rds;
      s.wri = wrs;
      s.exi = exs;
    }
   
    /* {rd,wr,ex}u - ul output
     * {rd,wr,ex}k - kernel fdset inputs with zeroed ul fds */
    s.rdk = NULL;
    s.wrk = NULL;
    s.exk = NULL;
    s.rdu = (fd_set*) (bits + 4*n_words);
    s.wru = (fd_set*) (bits + 4*n_words + 1*n_words_bs);
    s.exu = (fd_set*) (bits + 4*n_words + 2*n_words_bs);
   
    ci_frc64(&poll_start_frc);
    s.now_frc = poll_start_frc;
   
  poll_again:
    /* zero {rd,wr,ex}u */
    memset(s.rdu , 0, n_bytes_bs*3);
    /* zero {rd,wr,ex}k before the split */
    if( rds ) {
      s.rdk = (fd_set*) (bits + 1*n_words);
      memset(s.rdk, 0, n_bytes_bs);
    }
    if( wrs ) {
      s.wrk = (fd_set*) (bits + 2*n_words);
      memset(s.wrk, 0, n_bytes_bs);
    }
    if( exs ) {
      s.exk = (fd_set*) (bits + 3*n_words);
      memset(s.exk, 0, n_bytes_bs);
    }
   
    /* Poll the user level state and create input fds for the kernel */
    n = citp_ul_select(&s);
   
    /* [is_kernel_fd] currently tells us whether there are any kernel fds
    ** below the split.  Let's make it tell us whether there are any kernel
    ** fds at all (including any above the split).
    */
    s.is_kernel_fd |= split;
   
    errno = lib_context->saved_errno;
    if( n ) {
      /* We have userlevel (and/or kernel) sockets ready.  So just need to do
      ** a non-blocking poll of kernel sockets and we're done.
      */
      if( CITP_OPTS.ul_select_fast || ! s.is_kernel_fd || polled_kfds )
        goto copy_ul_only_and_out;
      else
        goto poll_kernel_merge_and_out;
    }

    /* We spin for a while if we've got any U/L sockets. */
    if( timeout_ms != 0 ) {
      if( s.is_ul_fd && 
          KEEP_POLLING(s.ul_select_spin, s.now_frc, poll_start_frc) ) {

        if( s.now_frc - poll_start_frc >= timeout_ms * citp.cpu_khz ) {
          /* Timeout while spinning */
          select_zero(rds, wrs, exs, n_words);
          n = 0;
          *used_ms = timeout_ms;
          Log_SEL(log_select("spin_timeout", nfds, rds, wrs, exs,
                             timeout_ms));
          goto out;
        }
   
        if( sigmask != NULL && !sigmask_set ) {
          int rc;
          rc = citp_ul_pwait_spin_pre(lib_context, sigmask, &sigsaved);
          if( rc != 0 ) {
            citp_exit_lib(lib_context, CI_FALSE);
            return -1;
          }
          sigmask_set = 1;
        }

        if( s.now_frc - poll_fast_frc > citp.select_fast_cycles ) {
          if( s.is_kernel_fd ) {
            /* We need to keep an eye on the kernel fds when polling, else smp
            ** configs can really suffer.  We don't need to citp_exit_lib()
            ** before the syscall, as we're not blocking.
            */
            /* copy the input fdsets after the split into {rd,wr,ex}k */
            if( split ) {
              if( rds )
                memcpy((char*)s.rdk+n_bytes_bs, (char*)rds+n_bytes_bs, n_bytes_as);
              if( wrs )
                memcpy((char*)s.wrk+n_bytes_bs, (char*)wrs+n_bytes_bs, n_bytes_as);
              if( exs )
                memcpy((char*)s.exk+n_bytes_bs, (char*)exs+n_bytes_bs, n_bytes_as);
            }
            lib_context->thread->select_nonblock_fast_frc = s.now_frc;
            n = do_sys_select("poll_k", nfds, s.rdk, s.wrk, s.exk);
            if( n ) {
              if( n < 0 ) {
                /* Do not touch fdsets, as Linux does not do it in case of
                 * error.
                 */
                goto out;
              }
              goto copy_k_only_and_out;
            }
          }
          polled_kfds = 1;
          if( CITP_OPTS.ul_select_fast_usec )
            poll_fast_frc = s.now_frc;
          if(CI_UNLIKELY( lib_context->thread->sig.c.aflags &
                          OO_SIGNAL_FLAG_HAVE_PENDING )) {
            errno = EINTR;
            n = -1;
            goto out;
          }
        }
        goto poll_again;
      }

      /* no UL fd or spin off */
      n = CI_SOCKET_HANDOVER;
      goto out;
    }

    /* We are non-blocking now. */

    /* Prioritise ul fds over kernel fds and keep semantics of only
     * kernel fds in poll set same as not using onload
     */
    if( ! s.is_kernel_fd ||
        s.now_frc - lib_context->thread->select_nonblock_fast_frc <
            citp.select_nonblock_fast_cycles ) {
      select_zero(rds, wrs, exs, n_words);
      Log_SEL(log_select("ul_only_nonb_0", nfds, rds, wrs, exs, timeout_ms));
      n = 0;
      goto out;
    }
    /* No userlevel fds are ready, and we're non-blocking, but we do have to
     * check the kernel fds.
     */
    if( ! s.is_ul_fd ) {
      /* No userlevel fds, so avoid cost merging. */
      n = CI_SOCKET_HANDOVER;
      goto out;
    }
    if( split ) {
      if( rds )
        memcpy((char*) s.rdk + n_bytes_bs, (char*) rds + n_bytes_bs, n_bytes_as);
      if( wrs )
        memcpy((char*) s.wrk + n_bytes_bs, (char*) wrs + n_bytes_bs, n_bytes_as);
      if( exs )
        memcpy((char*) s.exk + n_bytes_bs, (char*) exs + n_bytes_bs, n_bytes_as);
    }
    lib_context->thread->select_nonblock_fast_frc = s.now_frc;
    if( (n = do_sys_select("nonb_k", nfds, s.rdk, s.wrk, s.exk)) > 0 )
      goto copy_k_only_and_out;
    if( n == 0 )
      select_zero(rds, wrs, exs, n_words);
    ci_assert_equal(sigmask_set, 0);
    citp_exit_lib(lib_context, n >= 0);
    return n;
   
   
  poll_kernel_merge_and_out:
    {
      int rc;
      /* copy the input fdsets after the split into {rd,wr,ex}k */
      if( split ) {
        if( rds )
          memcpy((char*)s.rdk + n_bytes_bs, (char*)rds + n_bytes_bs, n_bytes_as);
        if( wrs )
          memcpy((char*)s.wrk + n_bytes_bs, (char*)wrs + n_bytes_bs, n_bytes_as);
        if( exs )
          memcpy((char*)s.exk + n_bytes_bs, (char*)exs + n_bytes_bs, n_bytes_as);
      }
      non_blocking.tv_sec = non_blocking.tv_usec = 0;
      lib_context->thread->select_nonblock_fast_frc = s.now_frc;
      rc = do_sys_select("ul_rdy", nfds, s.rdk, s.wrk, s.exk);
      if(CI_UNLIKELY( rc < 0 )) {
        n = rc;
        goto out;
      }
      if( rc != 0 ) {
        n += rc;
        if( rds ) {
          merge_fdsets(n_words_bs, rds, s.rdu, s.rdk);
          if (split)
            memcpy((char *)rds+n_bytes_bs, (char *)s.rdk+n_bytes_bs, n_bytes_as);
        }
        if( wrs ) {
          merge_fdsets(n_words_bs, wrs, s.wru, s.wrk);
          if (split)
            memcpy((char *)wrs+n_bytes_bs, (char *)s.wrk+n_bytes_bs, n_bytes_as);
        }
        if( exs ) {
          merge_fdsets(n_words_bs, exs, s.exu, s.exk);
          if (split)
            memcpy((char *)exs+n_bytes_bs, (char *)s.exk+n_bytes_bs, n_bytes_as);
        }
        Log_SEL(log_select("merge_out", nfds, rds, wrs, exs, timeout_ms));
        goto out;
      }
      else
        goto copy_ul_only_and_out;
    }
   
   
  copy_ul_only_and_out:
    if( rds ) {
      memcpy(rds, s.rdu, n_bytes_bs);
      if (split) memset((char *)rds+n_bytes_bs, 0, n_bytes_as);
    }
    if( wrs ) {
      memcpy(wrs, s.wru, n_bytes_bs);
      if (split) memset((char *)wrs+n_bytes_bs, 0, n_bytes_as);
    }
    if( exs ) {
      memcpy(exs, s.exu, n_bytes_bs);
      if (split) memset((char *)exs+n_bytes_bs, 0, n_bytes_as);
    }
    Log_SEL(log_select("ul_out", nfds, rds, wrs, exs, timeout_ms));
  } /* End of block that declares [bits]. */

 out:
  /* Calculate new timeout */
  *used_ms = (s.now_frc - poll_start_frc) / citp.cpu_khz;

  /* Exit library, and protect signals if necessary */
  if( sigmask_set ) {
    citp_ul_pwait_spin_done(lib_context, &sigsaved, &n);
    if( n < 0 )
      return n;
  }
  else
    citp_exit_lib(lib_context, n >= 0);

  if( n == CI_SOCKET_HANDOVER )
    Log_SEL(log_select("pass_through", nfds, rds, wrs, exs, timeout_ms));

  return n;


 copy_k_only_and_out:
  if( rds )  memcpy(rds, s.rdk, n_words * sizeof(ci_fd_mask));
  if( wrs )  memcpy(wrs, s.wrk, n_words * sizeof(ci_fd_mask));
  if( exs )  memcpy(exs, s.exk, n_words * sizeof(ci_fd_mask));
  Log_SEL(log_select("k_out", nfds, rds, wrs, exs, timeout_ms));
  goto out;
}


/****************************************************************************
 ************************************* POLL *********************************
 ****************************************************************************/

/* Return the number of non-kernel fds,
   or negative if there are too mnay kernel fds.
*/
static int citp_ul_poll(int nfds, struct oo_ul_poll_state*__restrict__ ps)
{
  int i;

  ps->n_ul_ready = 0;
  ps->n_ul_fds = 0;
  ps->nkfds = 0;

  if( citp_fdtable_not_mt_safe() )
    CITP_FDTABLE_LOCK_RD();

  for( i = 0; i < nfds; ++i ) {
    unsigned fd = ps->pfds[i].fd;

    if( fd < citp_fdtable.inited_count ) {
      citp_fdinfo_p fdip = citp_fdtable.table[fd].fdip;
      if( fdip_is_normal(fdip) ) {
        ++ps->n_ul_fds;

        /* If SO_BUSY_POLL behaviour requested need to check if there is
         * a spinning socket in the set, and remove flag to enable spinning
         * if it is found */
        if( ( ps->ul_poll_spin & (1 << ONLOAD_SPIN_SO_BUSY_POLL) ) &&
            citp_fdinfo_get_ops(fdip_to_fdi(fdip))->
                                        is_spinning(fdip_to_fdi(fdip)) ) {
          ps->ul_poll_spin &= ~(1 << ONLOAD_SPIN_SO_BUSY_POLL);
        }

        if( citp_fdinfo_get_ops(fdip_to_fdi(fdip))->poll(fdip_to_fdi(fdip),
                                                         &ps->pfds[i], ps) ) {
          if( ps->pfds[i].revents != 0 )
            ++ps->n_ul_ready;
          continue;
        }
      }
    }

    if( (int) fd < 0 ) {
      ps->pfds[i].revents = 0;
      continue;
    }

    if( ps->nkfds == OO_POLL_KFDS_LOCAL && ps->kfds == ps->kfds_local ) {
      ps->kfds = ci_alloc(sizeof(*ps->kfds) * (nfds - i + ps->nkfds));
      ps->kfd_map = ci_alloc(sizeof(*ps->kfd_map) * (nfds - i + ps->nkfds));
      if( ps->kfds == NULL || ps->kfd_map == NULL ) {
        ps->n_ul_ready = -1;
        goto unlock_out;
      }
      memcpy(ps->kfds, ps->kfds_local, sizeof(ps->kfds_local));
      memcpy(ps->kfd_map, ps->kfd_map_local, sizeof(ps->kfd_map_local));
    }
    ps->kfd_map[ps->nkfds] = i;
    /* ?? Could delay these two lines until we are about to do sys_poll. */
    ps->kfds[ps->nkfds].fd = fd;
    ps->kfds[ps->nkfds].events = ps->pfds[i].events;
    ps->pfds[i].revents = 0;
    ++ps->nkfds;
  }

  /* If we'd like to spin for spinning socket only, and we've failed to
   * find any - remove spinning flags. */
  if( ps->ul_poll_spin & (1 << ONLOAD_SPIN_SO_BUSY_POLL) )
    ps->ul_poll_spin = 0;

 unlock_out:
  if( citp_fdtable_not_mt_safe() )
    CITP_FDTABLE_UNLOCK_RD();
  FDTABLE_ASSERT_VALID();
  return ps->n_ul_ready;
}


static void citp_ul_poll_merge_kfds(struct oo_ul_poll_state*__restrict__ ps)
{
  int i;
  for( i = 0; i < ps->nkfds; ++i )
    ps->pfds[ps->kfd_map[i]].revents = ps->kfds[i].revents;
}


/* Generic poll/ppoll implementation. */
int citp_ul_do_poll(struct pollfd*__restrict__ fds, nfds_t nfds,
                    ci_uint64 timeout_ms, ci_uint64 *used_ms,
                    citp_lib_context_t *lib_context,
                    const sigset_t *sigmask)
{
  struct oo_ul_poll_state ps;
  int rc, i, n = 0, polled_kfds = 0;
  ci_uint64 poll_start_frc;
  ci_uint64 poll_fast_frc = 0;
  int sigmask_set = 0;
  sigset_t sigsaved;

  ci_frc64(&poll_start_frc);
  ps.this_poll_frc = poll_start_frc;
  ps.pfds = fds;
  ps.ul_poll_spin = oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_POLL);
  if( ps.ul_poll_spin ) {
    ps.ul_poll_spin |=
      oo_per_thread_get()->spinstate & (1 << ONLOAD_SPIN_SO_BUSY_POLL);
  }
  ps.kfds = ps.kfds_local;
  ps.kfd_map = ps.kfd_map_local;

 poll_again:
  n = citp_ul_poll(nfds, &ps);
  if(CI_UNLIKELY( n < 0 ))
    goto out_block;

  if( n ) {
    /* We have userlevel sockets ready.  So just need to do a non-blocking
     * poll of kernel sockets (at most) and we're done.
     */
    if( CITP_OPTS.ul_poll_fast || ps.nkfds == 0 || polled_kfds ) {
      for( i = 0; i < ps.nkfds; ++i )
        fds[ps.kfd_map[i]].revents = 0;
      goto out;
    }
    goto poll_kfds_and_return;
  }

  /* Prioritise ul fds over kernel fds and keep semantics of only
   * kernel fds in poll set same as not using onload
   */
  if( ps.n_ul_fds != 0 && timeout_ms == 0 &&
      ps.this_poll_frc - lib_context->thread->poll_nonblock_fast_frc < 
      citp.poll_nonblock_fast_cycles)
    goto out;

  if( ps.n_ul_fds != 0 ) {
    /* We have some userlevel fds. */
    if( timeout_ms ) {
      /* Blocking.  Shall we spin? */
      if( KEEP_POLLING(ps.ul_poll_spin, ps.this_poll_frc, poll_start_frc) ) {
        /* Timeout while spinning? */
        if( timeout_ms > 0 && (ps.this_poll_frc - poll_start_frc >=
                               timeout_ms * citp.cpu_khz) ) {
          for( i = 0; i < ps.nkfds; ++i )
            fds[ps.kfd_map[i]].revents = 0;
          *used_ms = timeout_ms;
          goto out;
        }

        if( sigmask != NULL && !sigmask_set ) {
          int rc;
          rc = citp_ul_pwait_spin_pre(lib_context, sigmask, &sigsaved);
          if( rc != 0 ) {
            n = -1;
            goto out;
          }
          sigmask_set = 1;
        }

        if( ps.this_poll_frc - poll_fast_frc > citp.poll_fast_cycles ) {
          /* Spend most of our time while spinning only looking at
           * user-level state.  First time around we'll look at kernel
           * state, but after that only 1 in n usecs.  This minimises
           * latency for user-level traffic.
           */
          if( ps.nkfds ) {
            /* We need to keep an eye on the kernel fds when polling.  We
             * don't need to citp_exit_lib() here because we're not blocking.
             */
            lib_context->thread->poll_nonblock_fast_frc = ps.this_poll_frc;
            rc = ci_sys_poll(ps.kfds, ps.nkfds, 0);
            if( rc ) {
              citp_ul_poll_merge_kfds(&ps);
              goto out;
            }
          }
          polled_kfds = 1;
          if( CITP_OPTS.ul_poll_fast_usec )
            poll_fast_frc = ps.this_poll_frc;
          if(CI_UNLIKELY( lib_context->thread->sig.c.aflags &
                          OO_SIGNAL_FLAG_HAVE_PENDING )) {
            errno = EINTR;
            n = -1;
            goto out;
          }
        }
        goto poll_again;
      }
      /* We've not found any events yet, and we'd like to block.  We may or
       * may not have looked at kernel fds.
       */
      if( ! polled_kfds ) {
        /* Poll the kernel fds separately to avoid polling onload sockets
         * in the kernel (which will enable interrupts).
         */
        lib_context->thread->poll_nonblock_fast_frc = ps.this_poll_frc;
        if( (n = ci_sys_poll(ps.kfds, ps.nkfds, 0)) ) {
          citp_ul_poll_merge_kfds(&ps);
          goto out;
        }
      }
      goto out_block;
    }
    else if( ps.nkfds == 0 ) {
      /* Non-blocking and no kernel fds. */
      goto out;
    }
    else {
      /* Non-blocking.  Just need to poll kernel fds before returning.
       * This is likely more efficient than pass-through, esp. if many UL
       * sockets.
       */
      goto poll_kfds_and_return;
    }
  }
  /* We only have kernel fds, or we want to block; so pass through. */

 out_block:
  *used_ms = (ps.this_poll_frc - poll_start_frc) / citp.cpu_khz;

  /* If the caller will block, no need to poll kfds - exit. */
  if( (timeout_ms != *used_ms) || (*used_ms == 0 && sigmask != NULL) )
    goto out;

 poll_kfds_and_return:
  /* Poll the kernel descriptors, and merge results into output. */
  lib_context->thread->poll_nonblock_fast_frc = ps.this_poll_frc;
  rc = ci_sys_poll(ps.kfds, ps.nkfds, 0);
  if( rc > 0 ) {
    citp_ul_poll_merge_kfds(&ps);
    n += rc;
  }
  else if(CI_UNLIKELY( rc < 0 )) {
    /* Ensure [revents == 0] for all entries if returning error. */
    for( i = 0; i < nfds; ++i )
      fds[i].revents = 0;
    n = rc;
  }
  else {
    /* kfd revents fields are already zeroed by citp_ul_poll(). */
  }

out:
  /* Free ps.kfd* arrays if they were allocated */
  if( ps.kfd_map != ps.kfd_map_local ) {
    ci_assert_nequal(ps.kfds, ps.kfds_local);
    ci_free(ps.kfd_map);
    ci_free(ps.kfds);
  }
  else {
    ci_assert_equal(ps.kfds, ps.kfds_local);
  }

  /* Exit library, and protect signals if necessary */
  if( sigmask_set ) {
    citp_ul_pwait_spin_done(lib_context, &sigsaved, &n);
    if( n < 0 )
      return n;
  }
  else
    citp_exit_lib(lib_context, n >= 0);

  return n;
}

