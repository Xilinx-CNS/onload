/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Onload extension API stub library -- static version.
**   \date  2011/06/14
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#define _GNU_SOURCE
#include <onload/extensions.h>
#include <onload/extensions_zc.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>


static int disabled;


static void onload_ext_check_ver(void)
{
  unsigned* onload_lib_ext_version;

  static int done;
  if( done )
    return;
  done = 1;

  onload_lib_ext_version = dlsym(RTLD_DEFAULT, "onload_lib_ext_version");
  if( onload_lib_ext_version == NULL )
    return;
  if( ONLOAD_EXT_VERSION_MAJOR == onload_lib_ext_version[0] &&
      ONLOAD_EXT_VERSION_MINOR <= onload_lib_ext_version[1] )
    /* Onload is compatible with the extensions lib. */
    return;

  /* Extensions lib has different major version, or supports new features
   * that this version of Onload doesn't know about.  We don't know for
   * certain that the app is using the new features, be we can't detect
   * that either.
   */
  fprintf(stderr,"ERROR: Onload extension library has incompatible version\n");
  fprintf(stderr,"ERROR: libonload=%d.%d.%d libonload_ext=%d.%d.%d\n",
          onload_lib_ext_version[0], onload_lib_ext_version[1],
          onload_lib_ext_version[2], ONLOAD_EXT_VERSION_MAJOR,
          ONLOAD_EXT_VERSION_MINOR, ONLOAD_EXT_VERSION_MICRO);
  fprintf(stderr,"ERROR: Onload extensions DISABLED\n");
  disabled = 1;
}


#define wrap(ret, fn_name, dec_args, call_args, ret_null)               \
ret fn_name dec_args                                                    \
{                                                                       \
  static ret (*p##fn_name)dec_args;                                     \
  if( p##fn_name == NULL ) {                                            \
    onload_ext_check_ver();                                             \
    if( disabled || (p##fn_name = dlsym(RTLD_NEXT, #fn_name)) == NULL ) \
      p##fn_name = (void*)(uintptr_t) 1;                                \
  }                                                                     \
  if( (void*) p##fn_name != (void*)(uintptr_t) 1 )                      \
    return p##fn_name call_args;                                        \
  else                                                                  \
    return ret_null;                                                    \
}

#define wrap_with_errno(ret, fn_name, dec_args, call_args, ret_null,    \
                        errno_null)                                     \
ret fn_name dec_args                                                    \
{                                                                       \
  static ret (*p##fn_name)dec_args;                                     \
  if( p##fn_name == NULL ) {                                            \
    onload_ext_check_ver();                                             \
    if( disabled || (p##fn_name = dlsym(RTLD_NEXT, #fn_name)) == NULL ) \
      p##fn_name = (void*)(uintptr_t) 1;                                \
  }                                                                     \
  if( (void*) p##fn_name != (void*)(uintptr_t) 1 )                      \
    return p##fn_name call_args;                                        \
  else {                                                                \
    errno = errno_null;                                                 \
    return ret_null;                                                    \
  }                                                                     \
}

#define wrap_with_fn(ret, fn_name, dec_args, call_args, fn_null)        \
ret fn_name dec_args                                                    \
{                                                                       \
  static ret (*p##fn_name)dec_args;                                     \
  if( p##fn_name == NULL ) {                                            \
    onload_ext_check_ver();                                             \
    if( disabled || (p##fn_name = dlsym(RTLD_NEXT, #fn_name)) == NULL ) \
      p##fn_name = (void*)(uintptr_t) 1;                                \
  }                                                                     \
  if( (void*) p##fn_name != (void*)(uintptr_t) 1 )                      \
    return p##fn_name call_args;                                        \
  else {                                                                \
    return fn_null call_args;                                           \
  }                                                                     \
}


wrap(int, onload_set_stackname, (enum onload_stackname_who who, 
                                 enum onload_stackname_scope context, 
                                 const char* stackname),
     (who, context, stackname), 0)

wrap(int, onload_stackname_save, (void),
     (), 0)

wrap(int, onload_stackname_restore, (void),
     (), 0)

wrap(int, onload_stack_opt_set_int, (const char* opt, int64_t val),
     (opt, val), 0)

wrap(int, onload_stack_opt_get_int, (const char* opt, int64_t* val),
     (opt, val), -ENOSYS)

wrap(int, onload_stack_opt_set_str, (const char* opt, const char* val),
     (opt, val), 0)

wrap(int, onload_stack_opt_get_str,
     (const char* opt, char* val_out, size_t* val_out_len),
     (opt, val_out, val_out_len), -ENOSYS)

wrap(int, onload_stack_opt_reset, (void),
     (), 0)

wrap(int, onload_is_present, (void),
     (), 0)

wrap(int, onload_fd_stat, (int fd, struct onload_stat* stat),
     (fd, stat), 0)

wrap(int, onload_zc_await_stack_sync, (int fd),
     (fd), 0)

wrap(int, onload_zc_alloc_buffers, (int fd, struct onload_zc_iovec* iovecs,
                                    int iovecs_len, 
                                    enum onload_zc_buffer_type_flags flags),
     (fd, iovecs, iovecs_len, flags), -ENOSYS)

wrap(int, onload_zc_release_buffers, (int fd, onload_zc_handle* bufs, 
                                      int bufs_len),
     (fd, bufs, bufs_len), -ENOSYS)

wrap(int, onload_zc_register_buffers, (int fd, uint64_t addr_space,
                                       uint64_t base_ptr, uint64_t len,
                                       int flags, onload_zc_handle* handle),
     (fd, addr_space, base_ptr, len, flags, handle), -ENOSYS)
wrap(int, onload_zc_unregister_buffers, (int fd, onload_zc_handle handle,
                                         int flags),
     (fd, handle, flags), -ENOSYS)

wrap(int, onload_zc_query_rx_memregs, (int fd, struct onload_zc_iovec* iov,
                                       int* iovecs_len, int flags),
     (fd, iov, iovecs_len, flags), -ENOSYS)

wrap(int, onload_zc_buffer_incref, (int fd, onload_zc_handle buf),
     (fd, buf), -ENOSYS)

wrap(int, onload_zc_buffer_decref, (int fd, onload_zc_handle buf),
     (fd, buf), -ENOSYS)

wrap(int, onload_zc_recv, (int fd, struct onload_zc_recv_args* args),
     (fd, args), -ENOSYS)

wrap(int, onload_zc_send, (struct onload_zc_mmsg* msgs, int mlen, int flags),
     (msgs, mlen, flags), -ENOSYS)

wrap(int, onload_set_recv_filter, (int fd, onload_zc_recv_filter_callback filter,
                                   void* cb_arg, int flags),
     (fd, filter, cb_arg, flags), -ENOSYS)

wrap(int, onload_zc_hlrx_alloc, (int fd, int flags,
                                 struct onload_zc_hlrx** hlrx_out),
     (fd, flags, hlrx_out), -ENOSYS)

wrap(int, onload_zc_hlrx_free, (struct onload_zc_hlrx* hlrx),
     (hlrx), -ENOSYS)

wrap(ssize_t, onload_zc_hlrx_recv_copy, (struct onload_zc_hlrx* hlrx,
                                         struct msghdr* msg, int flags),
     (hlrx, msg, flags), -ENOSYS)

wrap(ssize_t, onload_zc_hlrx_recv_zc, (struct onload_zc_hlrx* hlrx,
                               struct onload_zc_msg* msg, size_t max_bytes,
                               int flags),
     (hlrx, msg, max_bytes, flags), -ENOSYS)


wrap(int, onload_msg_template_alloc, (int fd, const struct iovec* initial_msg,
                                      int mlen, onload_template_handle* handle,
                                      unsigned flags),
     (fd, initial_msg, mlen, handle, flags), -ENOSYS)


wrap(int, onload_msg_template_update,
     (int fd, onload_template_handle handle,
      const struct onload_template_msg_update_iovec* updates, int ulen,
      unsigned flags),
     (fd, handle, updates, ulen, flags), -ENOSYS)

wrap(int, onload_msg_template_abort, (int fd, onload_template_handle handle),
     (fd, handle), -ENOSYS)

wrap(int, onload_recvmsg_kernel, (int fd, struct msghdr* msg, int flags),
     (fd, msg, flags), -ENOSYS)

wrap(int, onload_thread_set_spin, (enum onload_spin_type type, int spin),
     (type, spin), 0)

wrap(int, onload_thread_get_spin, (unsigned* state), (state), -ENOSYS)

wrap(int, onload_move_fd, (int fd), (fd), 0)

wrap( int, onload_fd_check_feature, (int fd, enum onload_fd_feature feature),
     (fd, feature), -ENOSYS)

wrap( int, onload_ordered_epoll_wait, (int epfd, struct epoll_event *events,
                                  struct onload_ordered_epoll_event *oo_events,
                                  int maxevents, int timeout),
    (epfd, events, oo_events, maxevents, timeout), -ENOSYS)

wrap(int, onload_timestamping_request, (int fd, unsigned flags),
     (fd, flags), -ENOSYS)

wrap(enum onload_delegated_send_rc,  onload_delegated_send_prepare,
     (int fd, int size, unsigned flags, struct onload_delegated_send* out),
     (fd, size, flags, out), ONLOAD_DELEGATED_SEND_RC_BAD_SOCKET)

wrap_with_errno(int,  onload_delegated_send_complete,
                (int fd, const struct iovec* iov, int iovlen, int flags),
                (fd, iov, iovlen, flags), -1, ENOSYS)

wrap_with_errno(int, onload_delegated_send_cancel, (int fd), (fd), -1, ENOSYS)

wrap_with_errno(int, oo_raw_send,
                (int fd, int hwport, const struct iovec* iov, int iovlen),
                (fd, hwport, iov, iovlen), -1, ENOSYS)

wrap_with_errno(int, onload_get_tcp_info,
                (int fd, struct onload_tcp_info* info, int* len),
                (fd, info, len), -1, EINVAL)

wrap_with_fn(int, onload_socket_nonaccel,
             (int domain, int type, int protocol),
             (domain, type, protocol), socket)

wrap_with_fn(int, onload_socket_unicast_nonaccel,
             (int domain, int type, int protocol),
             (domain, type, protocol), socket)

