/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h> /* RHEL6 needs this before linux/rtnetlink.h */
#include <linux/rtnetlink.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#include <ci/compat.h>
#include <ci/tools/sysdep.h>
#include <ci/tools/log.h>
#include <ci/tools/debug.h>
#include <ci/tools/utils.h>
#include <ci/net/ipv4.h>
#include <ci/net/ethernet.h>

#include "private.h" /* for cplane_ioctl */
#include "mibdump.h"
#include <cplane/cplane.h>
#include <cplane/create.h>
#include <cplane/mmap.h>
#include <cplane/ioctl.h>


/* CP_ANYUNIT is defined in private.h, so this check needs to come after the
 * inclusion. */
#ifndef CP_ANYUNIT
# include <onload/driveraccess.h>
#else
extern int oo_fd_open(int * fd_out);
#endif


/* libcplane uses ci_sys_ioctl to ensure we do not enter Onload twice.
 * We do not want to pull all lib/transport/unix into this client,
 * so let's define this:
 */
int (* ci_sys_ioctl)(int, long unsigned int, ...) = cplane_ioctl;

static void print_fwd_data(struct cp_mibs* mib, struct cp_fwd_data* data)
{
  ci_log(CP_FWD_DATA_BASE_FMT, CP_FWD_DATA_BASE_ARG(mib, &data->base));
  ci_log("\thwports %x "CICP_FWD_DATA_FLAG_FMT, data->hwports,
         CICP_FWD_DATA_FLAG_ARG(data->flags));
  ci_log("\tfrom "CI_MAC_PRINTF_FORMAT" to "CI_MAC_PRINTF_FORMAT,
         CI_MAC_PRINTF_ARGS(&data->src_mac),
         CI_MAC_PRINTF_ARGS(&data->dst_mac));
  /* TODO: Print bonding info */
}


static void usage(void);

static int ci_addr_sh_from_str(const char* src, ci_addr_sh_t* addr_sh)
{
  unsigned char addr_buf[sizeof(struct in6_addr)];
  if( inet_pton(AF_INET, src, addr_buf) == 1 ) {
    struct in_addr* sin_addr = (struct in_addr*)addr_buf;
    *addr_sh = CI_ADDR_SH_FROM_IP4(sin_addr->s_addr);
    return AF_INET;
  }
  else if( inet_pton(AF_INET6, src, addr_buf) == 1 ) {
    struct in6_addr* sin6_addr = (struct in6_addr*)addr_buf;
    *addr_sh = CI_ADDR_SH_FROM_IP6(sin6_addr->s6_addr);
    return AF_INET6;
  }
  return AF_UNSPEC;
}

static int fwd_resolve( struct oo_cplane_handle* cp, int argc, char** argv)
{
  struct cp_mibs* mib = &cp->mib[0];
  struct cp_fwd_key key;
  struct cp_fwd_data data;
  cicp_verinfo_t verinfo;
  int sin_family;
  int rc;

  memset(&key, 0, sizeof(key));
  oo_cp_verinfo_init(&verinfo);

  sin_family = ci_addr_sh_from_str(argv[0], &key.dst);
  if( sin_family == AF_UNSPEC ) {
    ci_log("Failed to parse destination address %s", argv[0]);
    usage();
    return 1;
  }
  key.ifindex = 0;
  key.iif_ifindex = 0;
  key.src = sin_family == AF_INET ? ip4_addr_sh_any: addr_sh_any;
  key.tos = 0;
  key.flag = CP_FWD_KEY_REQ_WAIT;
  argc--;
  argv++;

  while( argc > 0 ) {
    if( strcmp(argv[0], "nowait") == 0 ) {
      key.flag &=~ CP_FWD_KEY_REQ_WAIT;
      argc--; argv++;
    }
    else if( strcmp(argv[0], "transparent") == 0 ) {
      key.flag |= CP_FWD_KEY_TRANSPARENT;
      argc--; argv++;
    }
    else {
      if( argc == 1 ) {
        ci_log("No value for parameter %s", argv[0]);
        usage();
        return 1;
      }

      if( strcmp(argv[0], "from") == 0 ) {
        if( ci_addr_sh_from_str(argv[1], &key.src) == AF_UNSPEC ) {
          ci_log("Failed to parse source address %s", argv[1]);
          usage();
          return 1;
        }
      }
      else if( strcmp(argv[0], "via") == 0 ) {
        key.ifindex = mib->llap[cp_llap_by_ifname(mib, argv[1])].ifindex;
      }
      else if( strcmp(argv[0], "iif") == 0 ) {
        key.iif_ifindex = mib->llap[cp_llap_by_ifname(mib, argv[1])].ifindex;
      }
      else if( strcmp(argv[0], "tos") == 0 ) {
        key.tos = atoi(argv[1]);
      }
      else if( strcmp(argv[0], "verinfo") == 0 ) {
        if( sscanf(argv[1], "%x-%x", &verinfo.id, &verinfo.version) != 2 ) {
          ci_log("Failed to parse verinfo");
          return 1;
        }
      }
      else {
        ci_log("Unknown parameter %s", argv[0]);
        usage();
        return 1;
      }
      argc -= 2;
      argv += 2;
    }
  }

  rc = oo_cp_route_resolve(cp, &verinfo, &key, &data);
  if( rc < 0 ) {
    ci_log("Failed to resolve the route: %s", strerror(-rc));
    return 1;
  }

  print_fwd_data(mib, &data);
  if( rc == 1 )
    ci_log("Valid verinfo");
  else
    ci_log("\tverinfo: %x-%x", verinfo.id, verinfo.version);
  return 0;
}

static int arp_confirm(struct oo_cplane_handle* cp, int argc, char** argv)
{
  cicp_verinfo_t verinfo;
  if( argc < 1 ||
      sscanf(argv[0], "%x-%x", &verinfo.id, &verinfo.version) != 2 ) {
    ci_log("Failed to parse verinfo");
    usage();
    return 1;
  }

  oo_cp_arp_confirm(cp, &verinfo, 0 /* fwd_table_id: unused at UL */);
  return 0;
}

struct cp_func {
  const char* name;
  int (*fn)(struct oo_cplane_handle* cp, int argc, char** argv);
  const char* usage;
};
struct cp_func func[] =
{
  { "resolve", fwd_resolve,
      "<destination> [from <source>] [via <interface>] [tos <tos>] "
      "[verinfo <id>-<ver>] [nowait] [transparent] - resolve a route" },
  { "confirm", arp_confirm, "<id>-<ver> - confirm ARP entry" },
};
#define FUNC_NR (sizeof(func)/sizeof(func[0]))

static void usage(void)
{
  int i;

  ci_log("Available commands:");
  for(i = 0; i < FUNC_NR; i++ )
    ci_log("%s %s", func[i].name, func[i].usage);
}

int main(int argc, char** argv)
{
  int fd;
  struct oo_cplane_handle cp;
  int i;

  CI_TRY(oo_fd_open(&fd));
  CI_TRY(oo_cp_create(fd, &cp, CP_SYNC_LIGHT, 0));
  /* TODO: Handle errors */

  if( argc <= 1 ) {
    usage();
    exit(1);
  }

  /* Run the command */
  for(i = 0; i < FUNC_NR; i++ ) {
    if( strcmp(argv[1], func[i].name) == 0 ) {
      return func[i].fn(&cp, argc - 2, argv + 2);
    }
  }

  ci_log("%s: Unknown command %s", argv[0], argv[1]);
  usage();
  return 1;
} 
