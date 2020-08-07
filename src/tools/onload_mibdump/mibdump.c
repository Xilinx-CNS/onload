/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bits/sockaddr.h>
#include <linux/rtnetlink.h>

#include <ci/compat.h>
#include <ci/tools/log.h>
#include <ci/tools/namespace.h>
#include <ci/app/testapp.h>
#include <ci/compat.h>
#include <cplane/cplane.h>
#include <cplane/create.h>
#include <cplane/mibdump_sock.h>
#include <onload/version.h>
#if defined CP_UNIT || defined CP_SYSUNIT
extern int oo_fd_open(int * fd_out);
extern int cplane_ioctl(int, long unsigned int, ...);
#else
# include <onload/driveraccess.h>
# define cplane_ioctl ioctl
#endif


#include "../cplane/mibdump.h"
#include "dump_tables.h"

#ifdef __CI_INTERNAL_TRANSPORT_CONFIG_OPT_H__
#error "don't include ci/internal/transport_config_opt.h from binary-only code"
#endif


/* libcplane uses ci_sys_ioctl to ensure we do not enter Onload twice.
 * We do not want to pull all lib/transport/unix into this client,
 * so let's define this:
 */
int (* ci_sys_ioctl)(int, long unsigned int, ...) = cplane_ioctl;

static int /*bool*/ cfg_all = 0;
static char* cfg_ns_file = NULL;

static ci_cfg_desc cfg_opts[] = {
  { 'a', "all", CI_CFG_FLAG, &cfg_all,
    "Dump all visible control planes" },
  { 'n', "namespace",  CI_CFG_STR, &cfg_ns_file,
    "Dump the control plane for the specified namespace" },
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

#define CP_SERVER_PIDS_FILE "/proc/driver/onload/cp_server_pids"

struct usage_info {
  unsigned total;
  unsigned used;
};

static ci_uint32 khz;


static void hwport_print(struct oo_cplane_handle* cp, int fd, int unused)
{
  cp_dump_hwport_table(&cp->mib[0]);
}

static void hwport_get_usage(struct oo_cplane_handle* cp,
                             struct usage_info* usage)
{
  struct cp_mibs* mib = &cp->mib[0];
  ci_hwport_id_t hwport;
  for( hwport = 0; hwport < mib->dim->hwport_max; hwport++ ) {
    if( ! cicp_hwport_row_is_free(&mib->hwport[hwport]) ) {
      usage->used++;
    }
  }
  usage->total = mib->dim->hwport_max;
}


static void llap_print(struct oo_cplane_handle* cp, int fd, int unused)
{
  cp_dump_llap_table(&cp->mib[0]);
}

static void llap_get_usage(struct oo_cplane_handle* cp,
                           struct usage_info* usage)
{
  struct cp_mibs* mib = &cp->mib[0];
  cicp_rowid_t id;

  usage->total = mib->dim->llap_max;

  for( id = 0; id < mib->dim->llap_max; id++ ) {
    if( cicp_llap_row_is_free(&mib->llap[id]) )
      break;
  }
  usage->used = id;
}


static void ipif_print(struct oo_cplane_handle* cp, int fd, int unused)
{
  cp_dump_ipif_table(&cp->mib[0]);
}

static void ipif_get_usage(struct oo_cplane_handle* cp,
                           struct usage_info* usage)
{
  struct cp_mibs* mib = &cp->mib[0];
  cicp_rowid_t id;

  usage->total = mib->dim->ipif_max;

  for( id = 0; id < mib->dim->ipif_max; id++ ) {
    if( cicp_ipif_row_is_free(&mib->ipif[id]) )
      break;
  }
  usage->used = id;
}

static void ip6if_print(struct oo_cplane_handle *cp, int fd, int unused)
{
  cp_dump_ip6if_table(&cp->mib[0]);
}

static void services_print(struct oo_cplane_handle *cp, int fd, int unused)
{
  cp_dump_services(&cp->mib[0]);
}

static void ip6if_get_usage(struct oo_cplane_handle *cp,
                            struct usage_info *usage)
{
  const struct cp_mibs* mib = &cp->mib[0];
  cicp_rowid_t id;

  usage->total = mib->dim->ip6if_max;

  for( id = 0; id < mib->dim->ip6if_max; id++ ) {
    if( cicp_ip6if_row_is_free(&mib->ip6if[id]) )
      break;
  }
  usage->used = id;
}

static void fwd_get_usage(struct oo_cplane_handle* cp,
                          struct usage_info* usage)
{
  struct cp_mibs* mib = &cp->mib[0];
  cicp_mac_rowid_t id;

  usage->total = mib->fwd_table.mask + 1;

  for( id = 0; id <= mib->fwd_table.mask; id++ ) {
    if( cp_get_fwd_by_id(&mib->fwd_table, id)->flags &
        CICP_FWD_FLAG_OCCUPIED )
      usage->used++;
  }
}


#define PROCFS_STATS_PATH "/proc/driver/onload/cp_stats"

static FILE *stats_file;
static char stats_buffer[200];

static void stats_open(void)
{
  stats_file = fopen(PROCFS_STATS_PATH, "r");

  if( !stats_file ) {
    fprintf(stderr, "%s: %s\n", PROCFS_STATS_PATH, strerror(errno));
    exit(-1);
  }
}

static int stats_read(void)
{
  if( fgets(stats_buffer, sizeof stats_buffer, stats_file) )
    return 1;
  else
    return 0;
}

static void stats_close(void)
{
  fclose(stats_file);
}

static void stats_print(struct oo_cplane_handle* cp, int fd, int unused)
{
  printf("Control Plane statistics:\n\n");

  stats_open();

  while( stats_read() )
    printf("%s", stats_buffer);

  stats_close();
}

static void request_internal_dump(struct oo_cplane_handle* cp, int fd, int arg)
{
  int rc;
  ci_uint32 kind = arg;
  printf("Requesting dump of internal state...\n");

  int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
  if( sock < 0 )
    printf("Failed to open a socket: %s (errno=%d)\n", strerror(errno), errno);

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  if( bind(sock, &addr, sizeof(addr.sun_family)) < 0 ) {
    printf("Failed to auto-bind AF_UNIX socket: %s (errno=%d)\n",
           strerror(errno), errno);
    return;
  }


  struct iovec io;
  struct msghdr msg;
  char cbuf[CMSG_SPACE(sizeof(fd))];
  struct cmsghdr* cmsg;

  io.iov_base = &kind;
  io.iov_len = sizeof(kind);
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  msg.msg_controllen = cmsg->cmsg_len;
  msg.msg_name = &addr;
  msg.msg_namelen = sizeof(addr);
  msg.msg_flags = 0;

  cp_init_mibdump_addr(&addr, cp->mib->dim->server_pid);
  int* p_fd = (void *)CMSG_DATA(cmsg);
  *p_fd = STDOUT_FILENO;

  fflush(stdout);
  rc = sendmsg(sock, &msg, MSG_DONTWAIT);
  if( rc < 0 ) {
    printf("Failed to send a request to the cp_server: %s (errno=%d)\n",
           strerror(errno), errno);
    return;
  }

  rc = recvmsg(sock, &msg, 0);
  if( rc < 0 ) {
    printf("Failed to get an answer from the cplane server: %s (errno=%d)\n",
           strerror(errno), errno);
    return;
  }

  if( kind != 0 )
    printf("Error: %d", kind);
  else
    printf("Succeeded.\n");
}

static void table_usage_print(struct oo_cplane_handle*, int fd, int unused);

static struct {
  const char* name;
  void (*table_print)(struct oo_cplane_handle*, int fd, int arg);
  void (*get_usage)(struct oo_cplane_handle*, struct usage_info*);
  int arg;
  const char* description;
} tables[] = {
  { "usage", table_usage_print, NULL, 0,
    "amount of used and free space in each table" },

  { "version", NULL/* we always print versions */, NULL, 0,
    "MIB table versions" },

  { "hwport", hwport_print, hwport_get_usage, 0,
    "mapping from hwports to interfaces" },

  { "llap", llap_print, llap_get_usage, 0,
    "status of all known interfaces" },

  { "ipif", ipif_print, ipif_get_usage, 0,
    "local IP address configuration" },

  { "ip6if", ip6if_print, ip6if_get_usage, 0,
    "local IPv6 address configuration" },

  { "services", services_print, NULL, 0,
    "Kubernetes services configuration" },

  { "fwd", request_internal_dump, fwd_get_usage,
    1 << CP_SERVER_PRINT_STATE_FWD, "routing state" },

  { "stats",stats_print, NULL, 0,
    "statistics" },

  { "internal", request_internal_dump, NULL, 0,
    "all the internal state" },

  { "int_base", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_BASE,
    "base of the internal state" },

  { "int_route", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_ROUTE,
    "routes from the internal state" },

  { "int_route6", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_ROUTE6,
    "IPv6 fwd private of the internal state" },

  { "int_dst", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_DST,
    "destination prefixes from the internal state" },

  { "int_src", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_SRC,
    "source prefixes from the internal state" },

  { "int_dst6", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_DST6,
    "IPv6 destination prefixes from the internal state" },

  { "int_src6", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_SRC6,
    "IPv6 source prefixes from the internal state" },

  { "int_llap", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_LLAP,
    "llap private of the internal state" },

  { "int_team", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_TEAM,
    "team table of the internal state" },

  { "int_mac", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_MAC,
    "mac IP table of the internal state" },

  { "int_mac6", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_MAC6,
    "mac IPv6 table of the internal state" },

  { "int_fwd", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_FWD,
    "deprecated: equivalent to \"fwd\"" },

  { "int_laddr", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_LADDR,
    "local addresses of accelerated interfaces" },

  { "int_stats", request_internal_dump, NULL, 1 << CP_SERVER_PRINT_STATE_STAT,
    "stats of the internal state" },

  { "int_stat_doc", request_internal_dump, NULL,
    1 << CP_SERVER_PRINT_STATE_STAT_DOC,
    "documentation for internal statistic counters" },

  { NULL, NULL, NULL }
};

static void table_usage_print(struct oo_cplane_handle* cp, int fd, int unused)
{
  int i;
  struct usage_info usage;

  printf("Table space usage:\n\n");

  for( i = 0; tables[i].name; i++ ) {
    if( tables[i].get_usage ) {
      const char *alert = "";

      usage.used = usage.total = 0;
      tables[i].get_usage(cp, &usage);

      if( usage.used == usage.total )
        alert = "FULL";
      else {
        float fill = usage.used / (float)usage.total;
        if( fill > 0.9 )
          alert = "NEARLY FULL";
      }

      printf("%s:\t%d/%d\t%s\n", tables[i].name, usage.used, usage.total, alert);
    }
  }
}


static void dump_current_namespace(uint32_t which)
{
  int i;
  int fd, rc;
  struct oo_cplane_handle cp;
  
  rc = oo_fd_open(&fd);
  if( rc ) {
    fprintf(stderr, "Can't access Onload driver: %s\n", strerror(-rc));
    exit(-1);
  }

  rc = oo_cp_create(fd, &cp, CP_SYNC_LIGHT, 0);
  if( rc ) {
    fprintf(stderr, "Can't access Onload control plane: %s\n", strerror(-rc));
    exit(-1);
  }

  cplane_ioctl(fd, OO_IOC_GET_CPU_KHZ, &khz);

  printf("%s %s\n", cp.mib[0].sku->value, ONLOAD_VERSION);

  printf("Table version number: %d\n", *(cp.mib[0].version));
  printf("LLAP version number: %d\n", *(cp.mib[0].llap_version));
  printf("Dump version number: %d\n", *(cp.mib[0].dump_version));
  printf("Idle version number: %d\n", *(cp.mib[0].idle_version));
  printf("OOF version number: %d\n", *(cp.mib[0].oof_version));

  for( i = 0; tables[i].name; i++ ) {
    if( which & (1 << i) ) {
      if( tables[i].table_print ) {
        printf("\n");
        tables[i].table_print(&cp, fd, tables[i].arg);
      }
    }
  }

  close(fd);
}


static void dump_named_namespace(const char *filename, uint32_t which)
{
  if( ci_switch_net_namespace(filename) < 0 ) {
    fprintf(stderr, "Couldn't switch to %s: %s\n",
            filename, strerror(errno));
  }
  else {
    dump_current_namespace(which);
  }
}


static void usage(const char* msg)
{
  int i;

  ci_app_usage_default_noexit(msg);

  ci_log("Available tables are:");
  ci_log(" ");

  for( i = 0; tables[i].name; i++ ) {
    ci_log("  '%s' - %s", tables[i].name, tables[i].description);
    ci_log(" ");
  }

  ci_log("Or use 'all' to dump all tables.");
  exit(1);
}

int main(int argc, char** argv)
{
  int i, j;
  uint32_t which = 0;

  ci_app_standard_opts = 0;
  ci_app_usage = usage;
  ci_app_getopt("[table...]", &argc, argv, cfg_opts, N_CFG_OPTS);

  for( i = 1; i < argc; i++ ) {
    const char* table = argv[i];

    if( !strcmp(table, "all") ) {
      which = ~0;
      continue;
    }

    for( j = 0; tables[j].name; j++ ) {
      if( !strcmp(table, tables[j].name) ) {
        which |= 1 << j;
        break;
      }
    }

    if( !tables[j].name ) {
      ci_log("Unknown table '%s'", table);
      ci_log(" ");
    }
  }

  if( which == 0 ) {
    ci_app_usage("No tables specified.");
  }

  if( cfg_all ) {
    FILE *proc_file;
    char buffer[100];

    proc_file = fopen(CP_SERVER_PIDS_FILE, "r");
    if( !proc_file ) {
      perror(CP_SERVER_PIDS_FILE);
      exit(-1);
    }

    while( fgets(buffer, sizeof(buffer), proc_file) != NULL ) {
      int pid;
      sscanf(buffer, "%d", &pid);
      snprintf(buffer, sizeof(buffer),
               "/proc/%d/ns/net", pid);
      printf("Control plane state for server %d:\n\n", pid);
      dump_named_namespace(buffer, which);
      printf("\n");
    }

    fclose(proc_file);
  }
  else if( cfg_ns_file != NULL ) {
    printf("Control plane state for %s:\n\n", cfg_ns_file);
    dump_named_namespace(cfg_ns_file, which);
  }
  else {
    dump_current_namespace(which);
  }

  return 0;
}
