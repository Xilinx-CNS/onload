/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */
#include <sys/epoll.h>
#include <errno.h>

#include "private.h"

struct cp_epoll_state* cp_epoll_register(struct cp_session* s, int fd,
                                         cp_epoll_callback* callback,
                                         unsigned private_bytes)
{
  struct cp_epoll_state* state = malloc(sizeof(*state) + private_bytes);
  if( state == NULL ) {
    errno = ENOMEM;
    return NULL;
  }
  state->fd = fd;
  state->callback = callback;
  if( private_bytes > 0 )
    state->private = state + 1;
  else
    state->private = NULL;

  struct epoll_event event;
  event.events = EPOLLIN;
  event.data.ptr = state;
  int rc = epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &event);
  if( rc < 0 ) {
    free(state);
    return NULL;
  }
  return state;
}

int cp_epoll_unregister(struct cp_session* s, struct cp_epoll_state* state)
{
  struct epoll_event event;
  if( ! state )
    return 0;
  event.events = EPOLLIN;
  int rc = epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, state->fd, &event);
  if( rc == 0 )
    free(state);
  return rc;
}
