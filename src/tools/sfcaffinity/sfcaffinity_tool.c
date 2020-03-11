/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/app.h>
#include <ci/net/ipv4.h>
#include <ci/affinity/ul_drv_intf.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>


#define MAX_IPS  1024


static const char*const me = "sfcaffinity_tool";

static struct ifreq ip_list[MAX_IPS];
static int          ip_list_n;
static int          the_affinity_fd;
static int          log_level;
static int          quiet;


#define ip_list_name(i)  (ip_list[i].ifr_name)
#define ip_list_sin(i)   ((struct sockaddr_in*) &ip_list[i].ifr_addr)
#define ip_list_ip(i)    (ip_list_sin(i)->sin_addr.s_addr)


static void err(const char* fmt, ...)
  __attribute__((format(printf,1,2)));


static void err(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
}


static int get_affinity_fd(void)
{
  const char*const dev = "/dev/sfc_affinity";
  if( the_affinity_fd <= 0 ) {
    the_affinity_fd = open(dev, O_RDWR);
    if( the_affinity_fd < 0 ) {
      err("%s: ERROR: Failed to open %s\n", me, dev);
      err("%s:        errno=%d %s\n", me, errno, strerror(errno));
    }
  }
  return the_affinity_fd;
}


static void close_affinity_fd(void)
{
  if( the_affinity_fd > 0 ) {
    close(the_affinity_fd);
    the_affinity_fd = 0;
  }
}


static const char* my_basename(const char* path)
{
  const char* p = path + strlen(path);
  while( p > path && p[-1] != '/' )  --p;
  return p;
}


static void interface_get_basename(const char* intf_name, char* base_name)
{
  const char* sep;
  int n;
  if( (sep = strchr((char*) intf_name, '.')) ||
      (sep = strchr((char*) intf_name, ':')) ) {
    strncpy(base_name, intf_name, n = (sep - intf_name));
    base_name[n] = '\0';
  }
  else
    strcpy(base_name, intf_name);
}


static int interface_to_ifindex(const char* intf_name)
{
  struct ifreq ifr;
  int rc, sock;
  interface_get_basename(intf_name, ifr.ifr_name);
  CI_TRY(sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP));
  rc = ioctl(sock, SIOCGIFINDEX, &ifr);
  close(sock);
  if( rc == 0 )
    return ifr.ifr_ifindex;
  else
    return rc;
}


static int interface_is(const char* intf_name, const char* driver_name)
{
  /* Return true if this interface is directly implemented by the named
   * driver.  i.e. Will return false for IP aliases and VLANs.
   */
  char link_path[80];
  char link_val[80];
  int n;
  sprintf(link_path, "/sys/class/net/%s/device/driver", intf_name);
  if( (n = readlink(link_path, link_val, sizeof(link_val) - 1)) < 0 )
    return 0;
  link_val[n] = '\0';
  return ! strcmp(my_basename(link_val), driver_name);
}


static int interface_driver_is(const char* intf_name, const char* driver_name)
{
  /* Return true if the net driver that underlies this device is the one
   * named.  i.e. If the interface is an IP alias or VLAN interface, then
   * we look at the underlying interface.
   */
  char intf_base_name[IF_NAMESIZE];
  interface_get_basename(intf_name, intf_base_name);
  return interface_is(intf_base_name, driver_name);
}


static void refresh_ip_list(void)
{
  struct ifconf ifc;
  int sock;

  CI_TRY(sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP));
  ifc.ifc_len = sizeof(ip_list);
  ifc.ifc_req = ip_list;
  CI_TRY(ioctl(sock, SIOCGIFCONF, &ifc));
  ip_list_n = ifc.ifc_len / sizeof(ip_list[0]);
  close(sock);
}


static int ip_to_ifindex(unsigned ip)
{
  int i;
  for( i = 0; i < ip_list_n; ++i )
    if( ip == ip_list_ip(i) )
      return interface_to_ifindex(ip_list_name(i));
  return -1;
}


static int str_to_proto(const char* p)
{
  if( ! strcasecmp(p, "tcp") )
    return IPPROTO_TCP;
  else if( ! strcasecmp(p, "udp") )
    return IPPROTO_UDP;
  else
    return -1;
}


static const char* proto_to_str(int proto)
{
  switch( proto ) {
  case IPPROTO_TCP:
    return "tcp";
  case IPPROTO_UDP:
    return "udp";
  default:
    assert(0);
    return "<proto_to_str:bad>";
  }
}


static int is_proto(const char* p)
{
  return str_to_proto(p) >= 0;
}


static const char* ip_str(unsigned ip)
{
  static char bufs[2][16];
  static int bufs_i;
  struct in_addr in;
  int i = bufs_i++ & 1;
  in.s_addr = ip;
  strcpy(bufs[i], inet_ntoa(in));
  return bufs[i];
}


static int set_affinity(int ifindex, int protocol,
                        unsigned laddr, unsigned lport,
                        unsigned raddr, unsigned rport, int rxq, int cpu)
{
  struct sfc_aff_set sas;
  int rc, affinity_fd;

  if( (affinity_fd = get_affinity_fd()) < 0 )
    return 0;

  if( log_level )
    printf("> %s %s:%d %s:%d ifindex %d rxq %d cpu %d\n",
           proto_to_str(protocol), ip_str(laddr), ntohs(lport),
           ip_str(raddr), ntohs(rport), ifindex, rxq, cpu);

  sas.cpu = cpu;
  sas.rxq = rxq;
  sas.ifindex = ifindex;
  sas.protocol = protocol;
  sas.daddr = laddr;
  sas.dport = lport;
  sas.saddr = raddr;
  sas.sport = rport;
  sas.err_out = sfc_aff_no_error;
  rc = ioctl(affinity_fd, SFC_AFF_SET, &sas);
  if( sas.err_out != sfc_aff_no_error || rc != 0 ) {
    err("%s: ERROR: Failed to set affinity\n", me);
    err("%s:        %s %s:%d %s:%d ifindex %d rxq %d cpu %d\n",
        me, proto_to_str(protocol), ip_str(laddr), ntohs(lport), ip_str(raddr),
        ntohs(rport), ifindex, rxq, cpu);
    err("%s:        errno=%d %s\n", me, errno, strerror(errno));
    if( sas.err_out != sfc_aff_no_error )
      err("%s:        err=%d %s\n",
          me, (int) sas.err_out, sfc_aff_err_msg(sas.err_out));
    return 0;
  }
  return 1;
}


static int clear_affinity(int ifindex, int protocol,
                          unsigned laddr, unsigned lport,
                          unsigned raddr, unsigned rport)
{
  struct sfc_aff_clear sac;
  int rc, affinity_fd;

  if( (affinity_fd = get_affinity_fd()) < 0 )
    return 0;

  if( log_level )
    printf("> %s %s:%d %s:%d ifindex %d clear\n", proto_to_str(protocol),
           ip_str(laddr), ntohs(lport), ip_str(raddr), ntohs(rport), ifindex);

  sac.ifindex = ifindex;
  sac.protocol = protocol;
  sac.daddr = laddr;
  sac.dport = lport;
  sac.saddr = raddr;
  sac.sport = rport;
  sac.err_out = sfc_aff_no_error;
  rc = ioctl(affinity_fd, SFC_AFF_CLEAR, &sac);
  if( sac.err_out != sfc_aff_no_error || rc != 0 ) {
    err("%s: ERROR: Failed to clear affinity\n", me);
    err("%s:        %s %s:%d %s:%d ifindex %d\n", me, proto_to_str(protocol),
        ip_str(laddr), ntohs(lport), ip_str(raddr), ntohs(rport), ifindex);
    err("%s:        errno=%d %s\n", me, errno, strerror(errno));
    if( sac.err_out != sfc_aff_no_error )
      err("%s:        err=%d %s\n",
          me, (int) sac.err_out, sfc_aff_err_msg(sac.err_out));
    return 0;
  }
  return 1;
}


static int do_set_affinity(const char* protos, struct sockaddr_in la,
                           struct sockaddr_in ra, int rxq, int cpu)
{
  int proto = str_to_proto(protos);
  int i, ifindex;

  refresh_ip_list();

  if( la.sin_addr.s_addr == 0 ) {
    for( i = 0; i < ip_list_n; ++i )
      if( interface_driver_is(ip_list_name(i), "sfc") )
        set_affinity(interface_to_ifindex(ip_list_name(i)), proto,
                     ip_list_ip(i), la.sin_port,
                     ra.sin_addr.s_addr, ra.sin_port, rxq, cpu);
    return 1;
  }
  else if( CI_IP_IS_MULTICAST(la.sin_addr.s_addr) ) {
    for( i = 0; i < ip_list_n; ++i )
      if( interface_is(ip_list_name(i), "sfc") )
        set_affinity(interface_to_ifindex(ip_list_name(i)), proto,
                     la.sin_addr.s_addr, la.sin_port,
                     ra.sin_addr.s_addr, ra.sin_port, rxq, cpu);
    return 1;
  }
  else {
    ifindex = ip_to_ifindex(la.sin_addr.s_addr);
    if( ifindex < 0 ) {
      err("%s: ERROR: Can't find interface for IP %s\n",
          me, inet_ntoa(la.sin_addr));
      return 0;
    }
    set_affinity(ifindex, proto,
                 la.sin_addr.s_addr, la.sin_port,
                 ra.sin_addr.s_addr, ra.sin_port, rxq, cpu);
    return 1;
  }
}


static int do_clear_affinity(const char* protos, struct sockaddr_in la,
                             struct sockaddr_in ra)
{
  int proto = str_to_proto(protos);
  int i, ifindex;

  refresh_ip_list();

  if( la.sin_addr.s_addr == 0 ) {
    for( i = 0; i < ip_list_n; ++i )
      if( interface_driver_is(ip_list_name(i), "sfc") )
        clear_affinity(interface_to_ifindex(ip_list_name(i)), proto,
                       ip_list_ip(i), la.sin_port,
                       ra.sin_addr.s_addr, ra.sin_port);
    return 1;
  }
  else if( CI_IP_IS_MULTICAST(la.sin_addr.s_addr) ) {
    for( i = 0; i < ip_list_n; ++i )
      if( interface_is(ip_list_name(i), "sfc") )
        clear_affinity(interface_to_ifindex(ip_list_name(i)), proto,
                       la.sin_addr.s_addr, la.sin_port,
                       ra.sin_addr.s_addr, ra.sin_port);
    return 1;
  }
  else {
    ifindex = ip_to_ifindex(la.sin_addr.s_addr);
    if( ifindex < 0 ) {
      err("%s: ERROR: Can't find interface for IP %s\n",
          me, inet_ntoa(la.sin_addr));
      return 0;
    }
    clear_affinity(ifindex, proto,
                   la.sin_addr.s_addr, la.sin_port,
                   ra.sin_addr.s_addr, ra.sin_port);
    return 1;
  }
}


static void command_synopsys(FILE* s)
{
  fprintf(s, "add filter:\n");
  fprintf(s, "  <protocol> <[localhost:]port> [remotehost:port] cpu <cpu>\n");
  fprintf(s, "  <protocol> <[localhost:]port> [remotehost:port] rxq <rxq>\n");
  fprintf(s, "clear filter(s):\n");
  fprintf(s, "  <protocol> <[localhost:]port> [remotehost:port] clear\n");
  fprintf(s, "  clear all\n");
  fprintf(s, "\nprotocols:\n");
  fprintf(s, "  tcp\n");
  fprintf(s, "  udp\n");
}


static int parse_line(const char* line)
{
  char las[81], ras[81], protos[21], action[21];
  struct sockaddr_in la, ra;
  int rxq, cpu, rc, n;
  char dummy;

  while( *line && isspace(*line) )  ++line;

  if( *line == '#' || *line == '\0' ) {
    rc = 1;
  }
  else if( sscanf(line, "%20s %80s %80s rxq %d %c",
                  protos, las, ras, &rxq, &dummy) == 4 &&
           is_proto(protos) &&
           ci_hostport_to_sockaddr_in(las, &la) == 0 &&
           ci_hostport_to_sockaddr_in(ras, &ra) == 0 ) {
    rc = do_set_affinity(protos, la, ra, rxq, -1);
  }
  else if( sscanf(line, "%20s %80s rxq %d %c",
                  protos, las, &rxq, &dummy) == 3 &&
           is_proto(protos) &&
           ci_hostport_to_sockaddr_in(las, &la) == 0 ) {
    memset(&ra, 0, sizeof(ra));
    rc = do_set_affinity(protos, la, ra, rxq, -1);
  }
  else if( sscanf(line, "%20s %80s %80s cpu %d %c",
             protos, las, ras, &cpu, &dummy) == 4 &&
           is_proto(protos) &&
           ci_hostport_to_sockaddr_in(las, &la) == 0 &&
           ci_hostport_to_sockaddr_in(ras, &ra) == 0 ) {
    rc = do_set_affinity(protos, la, ra, -1, cpu);
  }
  else if( sscanf(line, "%20s %80s cpu %d %c",
                  protos, las, &cpu, &dummy) == 3 &&
           is_proto(protos) &&
           ci_hostport_to_sockaddr_in(las, &la) == 0 ) {
    memset(&ra, 0, sizeof(ra));
    rc = do_set_affinity(protos, la, ra, -1, cpu);
  }
  else if( sscanf(line, "%20s %80s %80s %20s %c",
                  protos, las, ras, action, &dummy) == 4 &&
           is_proto(protos) &&
           ci_hostport_to_sockaddr_in(las, &la) == 0 &&
           ci_hostport_to_sockaddr_in(ras, &ra) == 0 &&
           ! strcmp(action, "clear") ) {
    rc = do_clear_affinity(protos, la, ra);
  }
  else if( sscanf(line, "%20s %80s %20s %c",
                  protos, las, action, &dummy) == 3 &&
           is_proto(protos) &&
           ci_hostport_to_sockaddr_in(las, &la) == 0 &&
           ! strcmp(action, "clear") ) {
    memset(&ra, 0, sizeof(ra));
    rc = do_clear_affinity(protos, la, ra);
  }
  else if( sscanf(line, "clear %20s %c", action, &dummy) == 1 &&
           ! strcmp(action, "all") ) {
    close_affinity_fd();
    rc = 1;
  }
  else if( sscanf(line, "%20s %c", action, &dummy) == 1 &&
           (! strcasecmp(action, "help") || ! strcmp(line, "?\n")) ) {
    command_synopsys(stdout);
    rc = 1;
  }
  else {
    n = strlen(line);
    err("%s: ERROR: Bad command: %s%s", me,
        line, line[n - 1] == '\n' ? "":"\n");
    rc = 0;
  }

  return rc;
}


static int parse_input(FILE* fp)
{
  char line[256];
  while( fgets(line, sizeof(line), fp) )
    parse_line(line);
  return 0;
}


static void usage(FILE* f, int exit_code)
{
  fprintf(f, "usage:\n");
  fprintf(f, "  %s [options]\n", me);
  fprintf(f, "\n");
  fprintf(f, "options:\n");
  fprintf(f, "  -c <filter-command> - run a filter command\n");
  fprintf(f, "  --exit-on-eof       - exit when standard input closes\n");
  fprintf(f, "\n");
  fprintf(f, "Filter commands are also accepted from standard input.\n");
  fprintf(f, "\n");
  command_synopsys(f);
  exit(exit_code);
}


int main(int argc, char* argv[])
{
  int exit_on_eof = 0;

  --argc;  ++argv;
  while( argc > 0 ) {
    if( 0 )
      ;
    else if( ! strcmp(argv[0], "--help") ) {
      usage(stdout, 0);
    }
    else if( ! strcmp(argv[0], "-c") ) {
      if( argc < 2 )  usage(stderr, 1);
      --argc;  ++argv;
      parse_line(argv[0]);
    }
    else if( ! strcmp(argv[0], "--verbose") || ! strcmp(argv[0], "-v") ) {
      log_level = 1;
    }
    else if( ! strcmp(argv[0], "--quiet") || ! strcmp(argv[0], "-q") ) {
      quiet = 1;
    }
    else if( ! strcmp(argv[0], "--exit-on-eof") ) {
      exit_on_eof = 1;
    }
    else if( argv[0][0] == '-' ) {
      usage(stderr, 1);
    }
    else
      break;
    --argc;  ++argv;
  }

  if( argc != 0 )
    usage(stderr, 1);

  if( isatty(STDIN_FILENO) && ! quiet )
    err("sfcaffinity_tool: Waiting for input...\n");
  parse_input(stdin);
  if( exit_on_eof ) {
    if( ! quiet )
      err("sfcaffinity_tool: Removing filters\n");
  }
  else {
    if( ! quiet )
      err("sfcaffinity_tool: Press ctrl-c to exit (this will remove your"
          " filters)\n");
    while( 1 )
      ci_sleep(1000000);
  }
  return 0;
}
