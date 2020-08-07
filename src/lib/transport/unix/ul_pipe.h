/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2011-2019 Xilinx, Inc. */
#ifndef __ONLOAD_PIPE_H__
#define __ONLOAD_PIPE_H__

#include "internal.h"

typedef struct {
  citp_fdinfo        fdinfo;
  struct oo_pipe*    pipe;
  ci_netif*          ni;
} citp_pipe_fdi;

#define fdi_to_pipe_fdi(_fdi) CI_CONTAINER(citp_pipe_fdi, fdinfo, (_fdi))

extern int citp_pipe_create(int fds[2], int flags);

extern int citp_splice_pipe_pipe(citp_pipe_fdi* in_pipe_fdi,
                                 citp_pipe_fdi* out_pipe_fdi, size_t rlen,
                                 int flags);
extern int citp_pipe_splice_write(citp_fdinfo* fdi, int alien_fd,
                                  loff_t* alien_off,
                                  size_t len, int flags,
                                  citp_lib_context_t* lib_context);
extern int citp_pipe_splice_read(citp_fdinfo* fdi, int alien_fd,
                                 loff_t* alien_off,
                                 size_t len, int flags,
                                 citp_lib_context_t* lib_context);

#endif  /* ul_pipe.h */
