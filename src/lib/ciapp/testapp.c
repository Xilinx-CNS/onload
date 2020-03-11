/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Support for test apps.
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>


int         ci_app_standard_opts = 1; /* true */
const char* ci_appname;
char*       ci_cmdline;
unsigned    ci_app_cpu_khz;


#define LOG_PREFIX_BUF_SIZE  20
static char               log_prefix_buf[LOG_PREFIX_BUF_SIZE];
static const ci_cfg_desc* cfg_opts;
static int                n_cfg_opts;
static const char*        usage_str;


int         ci_cfg_quiet;
int         ci_cfg_verbose;
int         ci_cfg_iter     = 1;
int	    ci_cfg_port;
unsigned    ci_cfg_protocol;
int         ci_cfg_nic_index;
const char *ci_cfg_nic_name = "0";
ci_uint8    ci_cfg_shost[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
ci_uint8    ci_cfg_dhost[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
static int         ci_cfg_log_unique;
static unsigned    ci_cfg_log_nth;
static int         ci_cfg_log_on_fail;
static int         ci_cfg_log_on_exit;
static int         ci_cfg_log_pid;
static int         ci_cfg_log_tid;
static int         ci_cfg_log_time;
static int         ci_cfg_log_delta;
static int	   ci_cfg_log_host;
static int         ci_cfg_hang_on_fail;
static int         ci_cfg_segv_on_fail;
static int         ci_cfg_exit_on_fail;
static int         ci_cfg_stop_on_fail;
static int         ci_cfg_abort_on_fail;
static const char* ci_cfg_log_file;
static const char* ci_cfg_dump_format;

static void parse_eth_addr(const char* val, const ci_cfg_desc* cfg);

static ci_cfg_desc std_opts[] = {
  { '?', "help",     CI_CFG_USAGE, 0,               "this message"        },
  { 'q', "quiet",    CI_CFG_FLAG, &ci_cfg_quiet,    "quiet"               },
  { 'v', "verbose",  CI_CFG_FLAG, &ci_cfg_verbose,  "verbose"             },
  { 'i', "iter",     CI_CFG_INT,  &ci_cfg_iter,     "iterations"          },
  { 'p', "port",     CI_CFG_UINT, &ci_cfg_port,     "listen on this port" },
  {   0, "protocol", CI_CFG_UINT, &ci_cfg_protocol, "protocol number"     },
  
  {   0, "nic",      CI_CFG_STR,  (void*)&ci_cfg_nic_name,
      "nic name"           },
  
  {   0, "ulog",     CI_CFG_FLAG, &ci_cfg_log_unique,
    "squash duplicate log messages" },

  {   0, "nlog",     CI_CFG_UINT, &ci_cfg_log_nth,
      "only print every nth log message" },

  {   0, "flog",     CI_CFG_STR, (void*)&ci_cfg_log_file,
      "dump log messages to given file" },

  {   0, "faillog",  CI_CFG_FLAG, &ci_cfg_log_on_fail,
      "buffer log messages and dump on fail" },

  {   0, "exitlog",  CI_CFG_FLAG, &ci_cfg_log_on_exit,
      "buffer log messages and dump on exit or fail" },

  {   0, "logpid",   CI_CFG_FLAG, &ci_cfg_log_pid,
      "prepend process ID to log messages" },

  {   0, "logtid",   CI_CFG_FLAG, &ci_cfg_log_tid,
      "prepend thread ID to log messages" },

  {   0, "logtime",  CI_CFG_FLAG, &ci_cfg_log_time,
      "prepend timestamp to log messages" },

  {   0, "logdelta", CI_CFG_FLAG, &ci_cfg_log_delta,
      "prepend time deltas to log messages" },

  {   0, "loghost",  CI_CFG_FLAG, &ci_cfg_log_host,
      "set the log prefix to the hostname" },

  {   0, "exit",     CI_CFG_FLAG, &ci_cfg_exit_on_fail,
      "exit on failure" },

  {   0, "hang",     CI_CFG_FLAG, &ci_cfg_hang_on_fail,
      "hang on failure" },

  {   0, "segv",     CI_CFG_FLAG, &ci_cfg_segv_on_fail,
      "cause segmentation fault on failure" },

  {   0, "stop",     CI_CFG_FLAG, &ci_cfg_stop_on_fail,
      "send process SIGSTOP on failure" },

  {   0, "abort",    CI_CFG_FLAG, &ci_cfg_abort_on_fail,
      "abort process on failure" },

  {   0, "shost",    CI_CFG_FN,    ci_cfg_shost,
      "ethernet source address", parse_eth_addr },

  {   0, "dhost",    CI_CFG_FN,    ci_cfg_dhost,
      "ethernet destination address", parse_eth_addr},

  {   0, "dumpfmt",  CI_CFG_STR, (void*) &ci_cfg_dump_format,
      "specify format for hexdump (octets or dwords)" },
};
#define N_STD_OPTS  (sizeof(std_opts) / sizeof(std_opts[0]))


static int parse_cfg_opt(int argc, char** argv, const char* context);
static void parse_cfg_string(char* s);
static void bad_cla(const char* context, const char* cla, const char* msg);


/**********************************************************************
 ** ci_app_startup()
 */

void ci_app_startup(int argc, char* argv[])
{
  int rc;

  if( ci_appname )  return;

  if( getenv("EFAB_NIC") )
    ci_cfg_nic_name = getenv("EFAB_NIC");
  ci_cfg_nic_index = atoi(ci_cfg_nic_name);
  
  if( ci_app_cpu_khz == 0 ) {
    rc = ci_get_cpu_khz(&ci_app_cpu_khz);
    if( rc < 0 )  ci_log("ci_get_cpu_khz: %d", rc);
  }

  if( argc > 0 ) {
    int i, n = 0;
    char* p;
    for( i = 0; i < argc; ++i )
      n += strlen(argv[i]) + 1;
    ci_cmdline = malloc(n);
    if( ci_cmdline ) {
      p = ci_cmdline;
      for( i = 0; i < argc; ++i )
        p += sprintf(p, "%s%s", i == 0 ? "":" ", argv[i]);
      CI_TEST(p == ci_cmdline + n - 1);
    }

    if( argc >= 1 && argv && argv[0] ) {
      ci_appname = argv[0] + strlen(argv[0]);
      while( ci_appname > argv[0] &&
	     ci_appname[-1] != '/' && ci_appname[-1] != '\\' )
	--ci_appname;
    }
    else
      ci_appname = "";

    if( strlen(ci_appname) < (LOG_PREFIX_BUF_SIZE - 5) ) {
      strcpy(log_prefix_buf, ci_appname);
      strcat(log_prefix_buf, ": ");
      ci_set_log_prefix(log_prefix_buf);
    }
  }
}


/**********************************************************************
 ** ci_app_getopt()
 */

ci_inline void chomp_arg(int* argc, char* argv[], int n)
{
  ci_assert(*argc >= n);
  (*argc) -= n;
  memmove(argv, argv + n, (*argc) * sizeof(argv[0]));
}

void ci_app_getopt(const char* usage, int* argc, char* argv[],
		   const ci_cfg_desc* opts, int n_opts)
{
  char* s;

  ci_assert(opts || n_opts == 0);

  ci_app_startup(argc ? *argc : 0, argv);

  cfg_opts = opts;  n_cfg_opts = n_opts;
  usage_str = usage;

  /* look in the environment first */
  if( (s = getenv("CI_OPTS")) )  parse_cfg_string(s);

  if( argc ) {
    --(*argc);  ++argv;

    while( *argc > 0 ) {
      /* end of options? */
      if( argv[0][0] != '-' )       break;
      if( !strcmp("--", argv[0]) )  break;

      chomp_arg(argc, argv, parse_cfg_opt(*argc, argv, "command line"));
    }

    ++(*argc);
  }

  if( ci_cfg_hang_on_fail  )  ci_fail_stop_fn = ci_fail_hang;
  if( ci_cfg_segv_on_fail  )  ci_fail_stop_fn = ci_fail_bomb;
  if( ci_cfg_exit_on_fail  )  ci_fail_stop_fn = ci_fail_exit;
  if( ci_cfg_stop_on_fail  )  ci_fail_stop_fn = ci_fail_stop;
  if( ci_cfg_abort_on_fail )  ci_fail_stop_fn = ci_fail_abort;

  if( ci_cfg_log_file ) {
    ci_log_file_fd = open(ci_cfg_log_file, O_WRONLY | O_CREAT | O_TRUNC,
			  S_IREAD | S_IWRITE);
    if( ci_log_file_fd >= 0 )  ci_log_fn = ci_log_file;
  }
  if( ci_cfg_log_unique )    ci_log_uniquify();
  if( ci_cfg_log_nth ) {
    ci_log_nth_n = ci_cfg_log_nth;
    ci_log_nth();
  }
  if( ci_cfg_log_on_fail )  ci_log_buffer_till_fail();
  if( ci_cfg_log_on_exit )  ci_log_buffer_till_exit();
  if( ci_cfg_log_pid )    ci_log_options |= CI_LOG_PID;
  if( ci_cfg_log_tid )    ci_log_options |= CI_LOG_TID;
  if( ci_cfg_log_time )   ci_log_options |= CI_LOG_TIME;
  if( ci_cfg_log_delta )  ci_log_options |= CI_LOG_DELTA;
  if( ci_cfg_log_host ) {
    char hostname[80];
    char logpf[100];
    gethostname(hostname, 80);
    sprintf(logpf, "[%s] ", hostname);
    ci_set_log_prefix(strdup(logpf));
  }
  if( ci_cfg_dump_format ) {
    if( !strcmp(ci_cfg_dump_format, "octets") )
      ci_hex_dump_formatter = ci_hex_dump_format_octets;
    else if( !strcmp(ci_cfg_dump_format, "dwords") )
      ci_hex_dump_formatter = ci_hex_dump_format_dwords;
  }
}


/**********************************************************************
 ** ci_app_usage()
 */

void ci_app_opt_usage(const ci_cfg_desc* opts, int n_opts)
{
  const ci_cfg_desc* a;

  if( !opts ) { 
     if(!ci_app_standard_opts) return;

     opts = std_opts; n_opts = N_STD_OPTS; 
  }

  for( a = opts; a != opts + n_opts; ++a ) {
    ci_assert(a->long_name || a->short_name);
    if( a->long_name && a->short_name )
      ci_log("  -%c --%-20s -- %s", a->short_name, a->long_name,
	     (a->usage ? a->usage : ""));
    else if( a->long_name )
      ci_log("     --%-20s -- %s", a->long_name, (a->usage ? a->usage : ""));
    else
      ci_log("  -%c   %-20s -- %s", a->short_name, "",
	     (a->usage ? a->usage : ""));
  }
}


void ci_app_usage_standard_default(void)
{
  if(ci_app_standard_opts) {
     ci_log(" ");
     ci_log("standard options:");
     ci_app_opt_usage(std_opts, N_STD_OPTS);
  }
}


void ci_app_usage_default_noexit(const char* msg)
{
  if( msg ) {
    ci_log(" ");
    ci_log("%s", msg);
  }

  ci_log(" ");
  ci_log("usage:");
  ci_log("  %s [options] %s", ci_appname, (usage_str ? usage_str : ""));

  if( cfg_opts && n_cfg_opts ) {
    ci_log(" ");
    ci_log("options:");
    ci_app_opt_usage(cfg_opts, n_cfg_opts);
  }
  ci_app_usage_standard_default();

  ci_log(" ");
  ci_log("Options can also be given with the environment variable CI_OPTS");
  ci_log(" ");
}


void ci_app_usage_default(const char* msg)
{
  ci_app_usage_default_noexit(msg);
  exit(-1);
}


void (*ci_app_usage)(const char* msg) = ci_app_usage_default;


/**********************************************************************/
/**********************************************************************/
/**********************************************************************/

static const ci_cfg_desc* find_cfg_desc(
  const char*        opt,
  const ci_cfg_desc* opts,
  int                n_opts,
  const char**       pval)
{
  const ci_cfg_desc* a;
  int len;

  *pval = 0;

  for( a = opts; a != opts + n_opts; ++a ) {
    ci_assert(a->short_name || a->long_name);

    if( opt[1] == '-' ) {  /* its in long format */
      if( !a->long_name )  continue;

      len = strlen(a->long_name);
      if( !strncmp(opt + 2, a->long_name, len) ) {
	if( opt[2 + len] == '=' ) {
	  *pval = opt + 2 + len + 1;
	  return a;
	}
	else if( opt[2 + len] == 0 ) {
	  *pval = opt + 2 + len;
	  return a;
	}
      }
      continue;
    }
    else {  /* its in short format */
      if( opt[1] == a->short_name ) {
	*pval = opt + 2;
	return a;
      }
      continue;
    }
  }
  return 0;
}


static int parse_cfg_opt(int argc, char** argv, const char* context)
{
  const ci_cfg_desc* a;
  const char* val = NULL;
  int result = 1;

  /* is it "-" ? */
  if( argv[0][1] == 0 )  bad_cla(context, argv[0], "- is not allowed");

  /* find the config descriptor */
  a = 0;
  if( cfg_opts )  a = find_cfg_desc(argv[0], cfg_opts, n_cfg_opts, &val);
  if( (!a) && ci_app_standard_opts) {
     a = find_cfg_desc(argv[0], std_opts, N_STD_OPTS, &val);
  }
  if( !a )    bad_cla(context, argv[0], "unknown option");

  /* the option value (if required) may be part of this arg or the next */
  if( !val || *val == 0 ) {
    if( a->type == CI_CFG_FLAG || a->type == CI_CFG_USAGE || argc == 1 ) {
      val = 0;
    } else {
      val = argv[1];
      result = 2;
    }
  }

  switch( a->type ) {
  case CI_CFG_FLAG:
    if( val ) {
      if( sscanf(val, "%d", (int*) a->value) != 1 )
	bad_cla(context, argv[0], "expected integer or nothing");
    }
    else
      ++(*(int*) a->value);
    break;
  case CI_CFG_INT:
    if( !val || sscanf(val, "%i", (int*) a->value) != 1 )
      bad_cla(context, argv[0], "expected integer");
    break;
  case CI_CFG_UINT:
    if( !val || sscanf(val, "%i", (int*) a->value) != 1 )
      bad_cla(context, argv[0], "expected unsigned integer");
    break;
  case CI_CFG_INT64:
    if( !val || sscanf(val, "%lli", (long long int*) a->value) != 1 )
      bad_cla(context, argv[0], "expected 64bit integer");
    break;
  case CI_CFG_UINT64:
    if( !val || sscanf(val, "%lli", (long long int*) a->value) != 1 )
      bad_cla(context, argv[0], "expected unsigned 64bit integer");
    break;
  case CI_CFG_STR:
    *(const char**) a->value = val ? val : "";
    break;
  case CI_CFG_USAGE:
    ci_app_usage(0);
    break;
  case CI_CFG_FN:
    ci_assert(a->fn);
    a->fn(val, a);
    break;
  case CI_CFG_IRANGE:
    {
      int *v;
      v = (int*) a->value;
      if( sscanf(val, " %i - %i", v, v + 1) != 2 ) {
	if( sscanf(val, " %i", v) == 1 )
	  v[1] = v[0];
	else
	  bad_cla(context, argv[0], "expected integer or range");
      }
    }
    break;
  default:
    ci_log("ci_app: unknown config option type %u", a->type);
    break;
  }

  return result;
}


static void parse_cfg_string(char* s)
{
  char* p;
  int argc;
  char** argv;

  argc = 0;
  p = s;
  for( ; ; ) {
    p += strspn(p, " ");
    if( *p == 0 )
      break;
    argc += 1;
    p += strcspn(p, " ");
  }

  argv = malloc(argc * sizeof(char*));
  argc = 0;
  p = s;
  for( ; ; ) {
    p += strspn(p, " ");
    if( *p == 0 )
      break;
    argv[argc++] = p;
    p += strcspn(p, " ");
    *p = 0;
  }

  while( argc > 0 )
    chomp_arg(&argc, argv, parse_cfg_opt(argc, argv, "CI_OPTS"));

  free(argv);
}


static void bad_cla(const char* context, const char* cla, const char* msg)
{
  ci_log("ERROR: bad %s option: %s", context, cla);
  if( msg )  ci_log("ERROR: %s", msg);
  ci_app_usage(0);
  exit(-1); /* we can't guarantee that the user's "usage" function does this */
}


static void parse_eth_addr(const char* val, const ci_cfg_desc* cfg)
{
  if( !val )  bad_cla("", cfg->long_name, "expected ethernet MAC address");

  if( ci_parse_eth_addr(cfg->value, val, 0) < 0 )
    bad_cla("", cfg->long_name, "bad ethernet MAC address");
}

/*! \cidoxg_end */
