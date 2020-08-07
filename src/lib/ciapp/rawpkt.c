/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author
**  \brief
**   \date
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>
#include <ci/app/socket.h>
#include <ci/app/rawpkt.h>


#include <sys/poll.h>
#include <sys/sendfile.h>

static ssize_t (*rp_read)(int fd, void* buf, size_t count) = read;
static ssize_t (*rp_write)(int fd, const void* buf, size_t count) = write;

static ssize_t default_read(ci_rawpkt_t* rp, void* buf, size_t count)
{ return rp_read(rp->rd, buf, count); }

static ssize_t default_write(ci_rawpkt_t* rp, const void* buf, size_t count)
{ return rp_write(rp->wr, buf, count); }

static ssize_t default_sendfile(ci_rawpkt_t* rp, int fd_in, off_t *offset, size_t count)
{ return sendfile(rp->wr, fd_in, offset, count); }


static char* my_tok(char* s, char delim)
{
  if( !s )  return 0;
  while( *s && *s != delim )  ++s;
  if( *s == '\0' )  return 0;
  *s = '\0';
  return s + 1;
}

/**********************************************************************/

static int tap_ctor(ci_rawpkt_t* rp, char* arg)
{
  const char* dev = "/dev/tap0";
  rp->padding = 2;
  rp->rd = rp->wr = open(dev, O_RDWR);
  if( rp->rd < 0 ) {
    ci_log("ci_rawpkt_ctor: failed to open '%s' (%d)", dev, errno);
    return -errno;
  }
  return 0;
}

/**********************************************************************/

static int rw_ctor(ci_rawpkt_t* rp, char* arg)
{
  const char *rf, *wf;

  if( !arg ) {
    ci_log("ci_rawpkt_ctor: expected \"rw:rdfile[,wrfile]\"");
    return -EFAULT;
  }

  rf = arg;
  wf = my_tok(arg, ',');

  if( !wf ) {
    rp->wr = rp->rd = open(rf, O_RDWR);
    if( rp->rd < 0 ) {
      ci_log("ci_rawpkt_ctor: failed to open '%s' (%d)", rf, errno);
      return -errno;
    }
  }
  else {
    rp->rd = open(rf, O_RDONLY);
    if( rp->rd < 0 )  return -errno;
    rp->wr = open(wf, O_WRONLY);
    if( rp->wr < 0 ) {
      ci_log("ci_rawpkt_ctor: failed to open '%s' (%d)", wf, errno);
      close(rp->rd);
      return -errno;
    }
  }

  return 0;
}

/**********************************************************************/

static ssize_t udp_read(ci_rawpkt_t* rp, void* buf, size_t count)
{
  ssize_t rc = rp_read(rp->rd, buf, count);
  if( rc < 0 && errno == ECONNREFUSED )
    errno = EAGAIN;
  return rc;
}


static ssize_t udp_write(ci_rawpkt_t* rp, const void* buf, size_t count)
{
  ssize_t rc = rp_write(rp->wr, buf, count);
  if( rc < 0 && errno == ECONNREFUSED ) {
    errno = 0;
    rc = count;
  }
  return rc;
}


static int udp_ctor(ci_rawpkt_t* rp, char* arg)
{
  const char *lport_s, *raddr_s;
  struct sockaddr_in sa;

  lport_s = arg;
  raddr_s = arg = my_tok(arg, ',');

  if( !lport_s || !raddr_s ) {
    ci_log("ci_rawpkt_ctor: expected \"udp:lport,rhost:rport\"");
    return -EFAULT;
  }

  rp->read = udp_read;
  rp->write = udp_write;

  rp->rd = rp->wr = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if( rp->rd < 0 ) {
    ci_log("ci_rawpkt_ctor: socket (%d)", errno);
    return -errno;
  }
  sa.sin_family = AF_INET;
  sa.sin_port = CI_BSWAP_BE16(atoi(lport_s));
  sa.sin_addr.s_addr = CI_BSWAPC_BE32(INADDR_ANY);
  if( bind(rp->rd, (struct sockaddr*) &sa, sizeof(sa)) < 0 ) {
    ci_log("ci_rawpkt_ctor[UDP]: bind (%d)", errno);
    close(rp->rd);
    return -errno;
  }
  if( ci_hostport_to_sockaddr_in(raddr_s, &sa) < 0 ) {
    ci_log("ci_rawpkt_ctor: ci_hostport_to_sockaddr_in (%d)",
	   ci_hostport_to_sockaddr_in(raddr_s, &sa));
    close(rp->rd);
    return -errno;
  }
  if( connect(rp->rd, (struct sockaddr*) &sa, sizeof(sa)) < 0 ) {
    ci_log("ci_rawpkt_ctor: connect (%d)", errno);
    close(rp->rd);
    return -errno;
  }
  return 0;
}

/**********************************************************************/

static int null_ctor(ci_rawpkt_t* rp, char* arg)
{
  rp->rd = rp->wr = open("/dev/null", O_RDWR);
  if( rp->rd < 0 )  return -errno;
  return 0;
}

/**********************************************************************/

#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>


static ssize_t pkt_write(ci_rawpkt_t* rp, const void* buf, size_t count)
{
  memcpy(((ci_ether_hdr*) buf)->ether_shost, rp->mac, 6);
  return rp_write(rp->wr, buf, count);
}


static int pkt_ctor(ci_rawpkt_t* rp, char* arg, ci_boolean_t raw_mode)
{
  struct sockaddr_ll sa;
  struct ifreq ifr;
  int rc, ifindex;
  const char* interface = "eth0";
  int protocol = ETH_P_ALL;

  while( arg && arg[0] ) {
    if( arg[0] >= '0' && arg[0] <= '9' ) {
      const char* tmp = arg;
      arg = my_tok(arg, ',');
      sscanf(tmp, "%i", &protocol);
    }
    else {
      interface = arg;
      arg = my_tok(arg, ',');
    }
  }

  if ( !raw_mode )
    rp->write = pkt_write;

  /* Open up a packet socket. */
  rp->rd = rp->wr = cis_socket(PF_PACKET, SOCK_RAW, CI_BSWAPC_BE16(ETH_P_ALL));
  if( rp->rd < 0 ) {
    ci_log("ci_rawpkt_ctor: Failed to open packet socket.");
    ci_log("ci_rawpkt_ctor: You probably need to be root.");
    return -errno;
  }

  CI_TEST(strlen(interface) < IFNAMSIZ);
  strcpy(ifr.ifr_name, interface);

  /* Check that the interface exists. */
  rc = ioctl(rp->rd, SIOCGIFFLAGS, &ifr);

  if (rc && (errno == ENODEV)) {
    ci_log("ci_rawpkt_ctor: Could not find interface '%s'", interface);
    close(rp->rd);
    return -ENODEV;
  }

  CI_TRY(rc);

  /* Check that the interface is open. */
  if (!(ifr.ifr_flags & IFF_UP)) {
    ci_log("ci_rawpkt_ctor: Interface '%s' is not up", interface);
    close(rp->rd);
    return -ENODEV;
  }

  /* Get the index for the interface. */
  CI_TRY(ioctl(rp->rd, SIOCGIFINDEX, &ifr));
  ifindex = ifr.ifr_ifindex;

  /* Get mac address. */
  CI_TRY(ioctl(rp->rd, SIOCGIFHWADDR, &ifr));
  memcpy(rp->mac, &ifr.ifr_hwaddr.sa_data, 6);

  /* Bind to the interface.  We will only receive packets from that
  ** interface (and for the given protocol if specified), and packets sent
  ** will go to that interface.
  */
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = CI_BSWAP_BE16(protocol);
  sa.sll_ifindex = ifindex;
  rc = bind(rp->wr, (struct sockaddr*) &sa, sizeof(sa));
  if( rc < 0 ) {
    ci_log("ci_rawpkt_ctor[PKT]: bind (%d)", errno);
    close(rp->rd);
    return -errno;
  }

  return 0;
}

/**********************************************************************/
/**********************************************************************/
/**********************************************************************/

int  ci_rawpkt_ctor(ci_rawpkt_t* rp, char *s)
{
  char *n;
  int rc;

  ci_assert(rp);

  if( s == NULL ) {
    s = getenv("CI_RAWPKT");
    if( s == NULL ) {
      ci_log("ci_rawpkt_ctor: CI_RAWPKT environment variable is not set.");
      return -ENOMSG;
    }
  }

  rp->read = default_read;
  rp->write = default_write;
  rp->sendfile = default_sendfile;

  rp->padding = 0;

  s = strdup(s);
  if( s == 0 )  return -ENOMEM;

  n = my_tok(s, ':');

  if( !strcmp(s, "tap") )        rc = tap_ctor(rp, n);
  else if( !strcmp(s, "rw") )    rc = rw_ctor(rp, n);
  else if( !strcmp(s, "udp") )   rc = udp_ctor(rp, n);
  else if( !strcmp(s, "null") )  rc = null_ctor(rp, n);
  else if( !strcmp(s, "pkt") )   rc = pkt_ctor(rp, n, CI_FALSE);
  else if( !strcmp(s, "rawpkt") ) rc = pkt_ctor(rp, n, CI_TRUE);
  else {
    ci_log("ci_rawpkt_ctor: Unknown type '%s'", s);
    rc = -EDOM;
  }

  free(s);
  return rc;
}


void ci_rawpkt_dtor(ci_rawpkt_t* rp)
{
  ci_assert(rp);

  if( rp->rd != rp->wr )  close(rp->rd);
  close(rp->wr);
  rp->rd = rp->wr = -1;
}


int  ci_rawpkt_set_block_mode(ci_rawpkt_t* rp, int blocking)
{
  if( rp->rd != rp->wr ) {
    int rc = ci_setfdblocking(rp->rd, blocking);
    if( rc < 0 )  return rc;
  }
  return ci_setfdblocking(rp->wr, blocking);
}

#define MAX_PKT 10000

int  ci_rawpkt_send(ci_rawpkt_t* rp, const volatile void* packet, int len)
{
  char pkt[MAX_PKT];
  int n;

  ci_assert(rp);
  ci_assert_le(rp->padding, 100);
  ci_assert(packet);
  ci_assert_lt(len, MAX_PKT);

  if( rp->padding ) {
    /* I'd have liked to use writev() here, but it doesn't seem to work... */
    memset(pkt, 0, rp->padding);
    memcpy(pkt + rp->padding, (void*) packet, len);
    packet = pkt;
    len += rp->padding;
  }

  if( (n = rp->write(rp, (const void*) packet, len)) != len ) {
    ci_log("ci_rawpkt_send: write(%d) returned %d (errno=%d)", len, n, errno);
    return n < 0 ? -errno : -EIO;
  }

  return 0;
}


int  ci_rawpkt_sendfile(ci_rawpkt_t* rp, int fd_in, off_t *offset, int len)
{
  int n;
  ci_assert(rp);
  ci_assert_gt(len, 0);
  ci_assert_nequal(offset, NULL);

  if( (n = rp->sendfile(rp, fd_in, offset, len)) != len ) {
    ci_log("%s: sendfile(%d) returned %d (errno=%d)",
	   __FUNCTION__, len, n, errno);
    return n < 0 ? -errno : -EIO;
  }

  return 0;
}


int  ci_rawpkt_recv(ci_rawpkt_t* rp, volatile void* packet, int len)
{
  char pkt[MAX_PKT];
  char* buf;
  int n;

  ci_assert(rp);
  ci_assert_le(rp->padding, 100);
  ci_assert(packet);
  ci_assert_lt(len, MAX_PKT);

  if( rp->padding )  buf = pkt;
  else               buf = (char*) packet;

  do {
    n = rp->read(rp, buf, MAX_PKT);
    if( n == 0 )  return -EIO;
    if( n < 0 ) {
      if( errno != EAGAIN )
	ci_log("ci_rawpkt_recv: read %d (errno=%d)", n, errno);
      return -errno;
    }
  }
  while( n <= rp->padding );

  if( rp->padding ) {
    n -= rp->padding;
    memcpy((void*) packet, pkt + rp->padding, n);
  }

  return n;
}


int ci_rawpkt_clrbuff(ci_rawpkt_t* rp)
{
  char temp_data;

  while (recv(rp->rd, &temp_data, 1, MSG_DONTWAIT) > 0);

  return 0;
}


int ci_rawpkt_wait(ci_rawpkt_t* rp, int what_in, int* what_out,
		   const struct timeval* timeout)
{
  struct pollfd p[2];
  int rc, to_ms;

  ci_assert(rp);
  ci_assert(what_in & (CI_RAWPKT_WAIT_RECV | CI_RAWPKT_WAIT_SEND));

  p[0].fd = rp->wr;
  p[0].events = (what_in & CI_RAWPKT_WAIT_SEND) ? POLLOUT : 0;
  if( rp->rd == rp->wr ) {
    p[0].events |= (what_in & CI_RAWPKT_WAIT_RECV) ? POLLIN  : 0;
  }
  else {
    p[1].fd = rp->rd;
    p[1].events = (what_in & CI_RAWPKT_WAIT_RECV) ? POLLIN  : 0;
  }

  to_ms = -1;
  if( timeout )  to_ms = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;

  rc = poll(p, rp->rd == rp->wr ? 1 : 2, to_ms);
  if( rc < 0 )  ci_sys_fail("ci_rawpkt_wait: poll()", rc);
  if( rc == 0 )  return -(errno = ETIMEDOUT);

  if( what_out ) {
    *what_out  = (p[0].revents & POLLIN)  ? CI_RAWPKT_WAIT_RECV : 0;
    *what_out |= (p[0].revents & POLLOUT) ? CI_RAWPKT_WAIT_SEND : 0;
    if( rp->rd != rp->wr )
      *what_out |= (p[1].revents & POLLIN)  ? CI_RAWPKT_WAIT_RECV : 0;
  }

  return 0;
}


void ci_rawpkt_override_io(
		   ssize_t (*read)(int fd, void* buf, size_t count),
		   ssize_t (*write)(int fd, const void* buf, size_t count))
{
  ci_assert(read);
  ci_assert(write);
  rp_read = read;
  rp_write = write;
}

/*! \cidoxg_end */
