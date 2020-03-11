/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <onload/extensions.h>
#include <onload/extensions_zc.h>

#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/ioctl.h>

#define RECVBUF     1500
#define MCAST_IP    "239.100.10.1"
#define HOST_PORT   65456
#define MCAST_PORT  65456
#define SLEEP_TIME  1000000

typedef struct app_state
{
  int i;
  int cb_counter;
  int sock_fd;
  char iface[IFNAMSIZ];
  char host_ip[INET_ADDRSTRLEN];
  char remote_ip[INET_ADDRSTRLEN];
  int host_port;
  int remote_port;
  struct msghdr msg;
  int verbose;
} app_state_t;


/***************************************************************************/
/* Usage and debug information section */

static void usage(void)
{
  int rc = 0;
  fprintf(stderr, "usage:\n");
  fprintf(stderr, "zc_udp_recv [options] <interface>\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "options\n");
  fprintf(stderr, "  -m   <multicast-address>. If unspecified defaults to %s\n", MCAST_IP);
  fprintf(stderr, "  -l   <local-port>. If unspecified defaults to %d\n", HOST_PORT);
  fprintf(stderr, "  -p   <multicast-port>. If unspecified defaults to %d\n", MCAST_PORT);
  fprintf(stderr, "  -v   verbose. Enables additional logging outptu if set\n");
  fprintf(stderr, "\n");
}

void printout_sock_addr_in( struct sockaddr_in* s, char* str )
{
  char ip4[INET_ADDRSTRLEN];
  int family = s->sin_family;
  int port = ntohs(s->sin_port);

  memset((char *)&ip4,0,INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(s->sin_addr), ip4, INET_ADDRSTRLEN);
  printf("%s family: %d\n", str, family);
  printf("%s address: %s\n", str, ip4);
  printf("%s port: %d\n", str, port);
  return;
}

void printout_mreq(struct ip_mreq* m)
{
  char ip4[INET_ADDRSTRLEN];

  memset((char *)&ip4,0,INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(m->imr_interface), ip4, INET_ADDRSTRLEN);
  printf("interface address: %s\n", ip4);
  memset((char *)&ip4,0,INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(m->imr_multiaddr), ip4, INET_ADDRSTRLEN);
  printf("multicast address: %s\n", ip4);
  return;
}

void dump_app_state(app_state_t* as)
{
  printf("\n");
  printf("i=%d\ncb_counter=%d\nsock_fd=%d\niface=%s\n",
         as->i, as->cb_counter, as->sock_fd, as->iface);
  printf("host_ip=%s\nremote_ip=%s\nhost_port=%d\nremote_port=%d\nverbose=%d\n",
         as->host_ip, as->remote_ip, as->host_port, as->remote_port, as->verbose);
  return;
}

/***************************************************************************/
/* options parsing and state setup section */
int parse_opts(int argc, char* argv[], app_state_t* as)
{
  int fd, rc = 0;
  char const* opt_str = "hl:m:p:v";
  char c;
  struct ifreq ifr;

  /* Init and set default option values */
  memset(as,0,sizeof(as));
  sprintf(as->remote_ip,MCAST_IP);
  as->host_port = MCAST_PORT;
  as->remote_port = MCAST_PORT;
  as->verbose = 0;

  while( (c = getopt(argc, argv, opt_str)) != -1 )
    switch( c ) {
      case 'h':
        usage();
        exit(0);
	break;
      case 'l':
	as->host_port = atoi(optarg);
	break;
      case 'm':
        sprintf(as->remote_ip, optarg);
	break;
      case 'p':
	as->remote_port = atoi(optarg);
	break;
      case 'v':
	as->verbose = 1;
	break;
      default:
	printf("unsupported argument\n");
	exit(-1);
    }

  argc -= optind;
  argv += optind;
  if( argc < 1)
    usage();
  sprintf(as->iface, argv[0]);
  ip_from_ifname(as->iface, as->host_ip);
  ++argv; --argc;

  return rc;
}

int ip_from_ifname(char* ifname, char* ifip)
{
  int fd, rc = 0;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
  rc = ioctl(fd, SIOCGIFADDR, &ifr);
  close(fd);
  sprintf(ifip, "%s",
          inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
  return rc;
}

void udp_zcreceive_init(app_state_t* state)
{
  int sock;
  struct sockaddr_in localAddr;
  struct sockaddr_in groupAddr;
  int rc;

  /* check if onloaded. if not, exit with errors: */
  if(onload_is_present()){
    printf("onloaded\n");
  }else{
    printf("not onloaded - cannot do zero-copy.\n");
    printf("Please run under Onload.\n");
    exit(-1);
  }

  /* init local address */
  memset((char *)&localAddr, 0, sizeof(localAddr));
  inet_pton(AF_INET, state->host_ip, &(localAddr.sin_addr));
  localAddr.sin_family = AF_INET;
  localAddr.sin_port = htons(state->host_port);

  /* init group address */
  memset((char *)&groupAddr,0,sizeof(groupAddr));
  inet_pton(AF_INET, state->remote_ip, &(groupAddr.sin_addr));
  groupAddr.sin_family = AF_INET;
  groupAddr.sin_port = htons(state->remote_port);

  /* ensure join correct multicast group */
  struct ip_mreq mreq;
  mreq.imr_multiaddr = groupAddr.sin_addr;
  mreq.imr_interface = localAddr.sin_addr;

  /* init socket */
  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  state->sock_fd = sock;

  if( state->verbose ) {
    /* have a look at structure contents */
    printout_sock_addr_in(&localAddr,"RECEIVE: The local");
    printout_sock_addr_in(&groupAddr,"RECEIVE: The group");
    printout_mreq(&mreq);
  }

  /*
   * specify default interface to receive messages on,
   * bind to local interface
   */
  rc = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
  if( rc < 0 ){
    printf("failed to add IP MEMBERSHIP with rc=%d\n",rc);
    exit(rc);
  }

  /*
   * bind restricts you to listen for traffic to a/the specified address/port
   */
  bind(sock,(struct sockaddr *)&groupAddr,sizeof(groupAddr));
  setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF,
             (char *)&(localAddr.sin_addr),
             sizeof(localAddr.sin_addr));


  return;
}

/***************************************************************************/
/* zc-specific handling - callback function and packet handling */

enum onload_zc_callback_rc demo_zc_recv_callback(
                struct onload_zc_recv_args *zc_args,
                int flags)
{
  int i;
  char buf[1700];
  memset(buf,0,1700);
  app_state_t* state = zc_args->user_ptr;
  struct timeval tv_tod;
  long long int sec_diff;
  long long int usec_diff;

  for(i=0; i<zc_args->msg.msghdr.msg_iovlen; i++){
    gettimeofday (&tv_tod, 0);
    printf("callback counter:msg counter set to %d:%d\n",state->cb_counter,i);
    printf("----------------------------------------------\n");
    printf("gettimeofday: %lld.%lld\n",
           (long long)tv_tod.tv_sec, (long long)tv_tod.tv_usec);
    printf("zc callback iov %d: base address %p, payload length %zd\n", i,
           zc_args->msg.iov[i].iov_base,
           zc_args->msg.iov[i].iov_len);
    state->cb_counter++;
    /* do work on packet */
    printf("Payload data: %s\n",(char *)((int**)zc_args->msg.iov[i].iov_base));
    printf("=====================\n\n");
  }
  return ONLOAD_ZC_CONTINUE;
}

void zc_receive_packet(app_state_t *state)
{
  struct msghdr msg;
  struct sockaddr_in host_addr;
  struct iovec iov;
  char buf[2048];
  char ctrl[1024];
  int rc;

  struct onload_zc_recv_args zc_args;
  memset( &zc_args, 0, sizeof(&zc_args) );
  memset( &msg, 0, sizeof(msg) );
  memset( &host_addr, 0, sizeof(host_addr) );

  inet_pton(AF_INET,state->host_ip, &(host_addr.sin_addr) );
  host_addr.sin_family = AF_INET;
  host_addr.sin_port = htons(state->host_port);

  /* recvmsg header structure */
  iov.iov_base = buf;
  iov.iov_len = 2048;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_name = &host_addr;
  msg.msg_namelen = sizeof(struct sockaddr_in);
  msg.msg_control = ctrl;
  msg.msg_controllen = 1024;
  msg.msg_flags = 0;

  /* do zc receive, as opposed to normal receive */
  zc_args.cb = &demo_zc_recv_callback;
  zc_args.msg.msghdr = msg;
  zc_args.user_ptr = state;
  zc_args.flags = ONLOAD_MSG_RECV_OS_INLINE;

  rc = onload_zc_recv(state->sock_fd, &zc_args);
  state->i++;

  return;
}

/***************************************************************************/

int main(int argc, char* argv[])
{
  app_state_t as;
  int rc;

  rc = parse_opts(argc, argv, &as);

  if( as.verbose ) {
    dump_app_state(&as);
  }

  udp_zcreceive_init(&as);

  while(1) {
    zc_receive_packet(&as);
  }

  return 0;
}



