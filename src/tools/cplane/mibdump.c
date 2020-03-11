/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <sys/socket.h>
#include <sys/un.h>

#include "private.h"
#include <cplane/mibdump_sock.h>


void cp_mibdump_sock_init(struct cp_session* s)
{
  struct sockaddr_un addr;
  int rc;

  s->mibdump_sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  if( s->mibdump_sock < 0 )
    init_failed("Failed to create mibdump socket: %s", strerror(errno));

  cp_init_mibdump_addr(&addr, s->mib->dim->server_pid);
  rc = bind(s->mibdump_sock, &addr, sizeof(addr));
  if( rc < 0 )
    init_failed("Failed to bind mibdump socket to @%s: %s",
                addr.sun_path + 1, strerror(errno));

  s->cp_print_fd = STDOUT_FILENO;
}


void cp_mibdump_sock_handle(struct cp_session* s,
                            struct cp_epoll_state* state)
{
  /* We do not expect more than 4-bytes datagram */
  char buf[sizeof(ci_uint32)];
  /* The only control message we expect is SCM_RIGHTS. */
  char cbuf[CMSG_SPACE(sizeof(int))];
  struct iovec io;
  struct msghdr msg;
  struct sockaddr_un addr;

  memset(&msg, 0, sizeof(msg));
  io.iov_base = buf;
  io.iov_len = sizeof(buf);
  msg.msg_iov= &io;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);
  msg.msg_name = &addr;
  msg.msg_namelen = sizeof(addr);

  if( recvmsg(s->mibdump_sock, &msg, 0) < 0 ) {
    /* false wakeups are not expected, but allowed
     * TODO: Increment a counter */
    return;
  }

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  ci_assert_nequal(cmsg, NULL);
  if( cmsg == NULL )
    return;

  int fd = *((int*)CMSG_DATA(cmsg));

  /* Make the fd non-blocking; caller should ensure that non-blocking write
   * is OK.  We do not want to add this all to the main epoll loop, so we
   * just call cp_print() and ignore any failures. */
  int opt = 1;
  ioctl(fd, FIONBIO, &opt);
  s->cp_print_fd = fd;

  cp_session_print_state(s, *(int*)buf);

  s->cp_print_fd = STDOUT_FILENO;
  close(fd);

  memset(buf, 0, sizeof(buf));
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  if( sendmsg(s->mibdump_sock, &msg, 0) < 0 ) {
    /* client have gone.
     * TODO: Increment a counter */
    ;
  }
  return;
}
