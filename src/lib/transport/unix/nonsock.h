/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __UNIX_NONSOCK_H__
#define __UNIX_NONSOCK_H__
#include <ci/internal/transport_config_opt.h>
#include "internal.h"

/*************************************************************************
 ***************** Common non-socket handlers code ***********************
 *************************************************************************/

extern
int citp_passthrough_fcntl(citp_fdinfo *fdi, int cmd, long arg);
extern
int citp_passthrough_select(citp_fdinfo* fdinfo, int* n, int rd, int wr, int ex,
                            struct oo_ul_select_state*);
extern
int citp_passthrough_poll(citp_fdinfo* fdinfo, struct pollfd* pfd,
                          struct oo_ul_poll_state* ps);
extern
int citp_nonsock_bind(citp_fdinfo* fdinfo,
                      const struct sockaddr* sa, socklen_t sa_len);
extern
int citp_nonsock_listen(citp_fdinfo* fdinfo, int backlog);
extern
int citp_nonsock_accept(citp_fdinfo* fdinfo,
                        struct sockaddr* sa, socklen_t* p_sa_len, int flags,
                        citp_lib_context_t* lib_context);
extern
int citp_nonsock_connect(citp_fdinfo* fdinfo,
                         const struct sockaddr* sa, socklen_t sa_len,
                         citp_lib_context_t* lib_context);
extern
int citp_nonsock_shutdown(citp_fdinfo* fdinfo, int how);
extern
int citp_nonsock_getsockname(citp_fdinfo* fdinfo,
                             struct sockaddr* sa, socklen_t* p_sa_len);
extern
int citp_nonsock_getpeername(citp_fdinfo* fdinfo,
                             struct sockaddr* sa, socklen_t* p_sa_len);
extern
int citp_nonsock_getsockopt(citp_fdinfo* fdinfo, int level,
                            int optname, void* optval, socklen_t* optlen);
extern
int citp_nonsock_setsockopt(citp_fdinfo* fdinfo, int level, int optname,
                            const void* optval, socklen_t optlen);
extern
int citp_nonsock_recv(citp_fdinfo* fdinfo, struct msghdr* msg,
                          int flags);
extern
int citp_nonsock_send(citp_fdinfo* fdinfo, const struct msghdr* msg,
                          int flags);
extern
int citp_nonsock_recvmmsg(citp_fdinfo* fdinfo, struct mmsghdr* msg,
                          unsigned vlen, int flags,
                          ci_recvmmsg_timespec* timeout);
extern
int citp_nonsock_sendmmsg(citp_fdinfo* fdinfo, struct mmsghdr* msg,
                          unsigned vlen, int flags);
extern
int citp_nonsock_zc_send(citp_fdinfo* fdi, struct onload_zc_mmsg* msg,
                         int flags);
extern
int citp_nonsock_zc_recv(citp_fdinfo* fdi,
                         struct onload_zc_recv_args* args);
extern
int citp_nonsock_recvmsg_kernel(citp_fdinfo* fdi, struct msghdr *msg,
                                int flags);
extern
int citp_nonsock_zc_recv_filter(citp_fdinfo* fdi,
                                onload_zc_recv_filter_callback filter,
                                void* cb_arg, int flags);
extern
int citp_nonsock_tmpl_alloc(citp_fdinfo* fdi, const struct iovec* initial_msg,
                            int mlen, struct oo_msg_template** omt_pp,
                            unsigned flags);
extern int
citp_nonsock_tmpl_update(citp_fdinfo* fdi, struct oo_msg_template* omt,
                         const struct onload_template_msg_update_iovec* updates,
                         int ulen, unsigned flags);
extern
int citp_nonsock_tmpl_abort(citp_fdinfo* fdi, struct oo_msg_template* omt);

#if CI_CFG_TIMESTAMPING
extern
int citp_nonsock_ordered_data(citp_fdinfo* fdi, struct timespec* limit,
                              struct timespec* first_out, int* bytes_out);
#endif
extern
int citp_nonsock_is_spinning(citp_fdinfo* fdi);

#if CI_CFG_FD_CACHING
extern
int citp_nonsock_cache(citp_fdinfo* fdi);
#endif

#endif
