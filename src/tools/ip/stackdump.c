/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Map in shared state of U/L stack, dump info, and do stuff.
**   \date  2005/01/19
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_tests_ef */
#include <stdlib.h>
#include <ci/internal/ip.h>
#include "libstack.h"
#include <ci/app.h>
#include <onload/extensions.h>


/* Pointer dynamically allocated table of stack, freed in atexit_fn().    */
static int* s_stack_idx_col;

/* Counter for number of stacks in the s_sock_idx_col.    */
static unsigned s_stack_idx_count;

/* Pointer dynamically allocated table of stacks created from s_stack_idx_col
   with only stacks that do exist, freed after use().    */
static int* s_present_stack_idx_col;

/* Counter for number of stacks in the s_present_sock_idx_col.    */
static unsigned s_present_stack_idx_count;

/* Pointer dynamically allocated table of stack, freed in atexit_fn().    */
static int* s_sock_idx_col;


static ci_cfg_desc cfg_opts[] = {
  { 'l', "lock",      CI_CFG_FLAG, &cfg_lock,    "hold netif locks"         },
  { 'n', "nolock",    CI_CFG_FLAG, &cfg_nolock,  "don't grab stack lock"    },
  { 'b', "blocklock", CI_CFG_FLAG, &cfg_blocklock,"block for locks"         },
  {   0, "nosocklock",CI_CFG_FLAG, &cfg_nosklock,"don't grab socket locks"  },
  { 'd', "dump",      CI_CFG_FLAG, &cfg_dump,    "dump packet contents"     },
  {   0, "usec",      CI_CFG_UINT, &cfg_usec,    "set watch_bw interval"    },
  {   0, "msec",      CI_CFG_UINT, &cfg_watch_msec,"set other interval"     },
  {   0, "samples",   CI_CFG_UINT, &cfg_samples, "number of samples"        },
  { 't', "notable",   CI_CFG_FLAG, &cfg_notable, "toggle table mode"},
  { 'z', "zombie",    CI_CFG_FLAG, &cfg_zombie,  "force dump of orphan stacks"},
  {   0, "nopids",    CI_CFG_FLAG, &cfg_nopids,  "disable dumping of PIDs"},
  {   0, "filter",    CI_CFG_STR,  &cfg_filter,
                                   "dump only sockets matching pcap filter" },
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))

static void do_stack_ops(int argc, char* argv[])
{
  const stack_op_t* op;
  char dummy;

  if( argc == 0 ) {
    op = get_stack_op("dump");
    if( op->flags & FL_ID )
      for_each_stack_id(op->id_fn, NULL);
    else
      for_each_stack(op->fn, op->flags & FL_ONCE); 
  }

  for( ; argc; --argc, ++argv ) {
    op = get_stack_op(argv[0]);
    if( op == NULL ) {
      ci_log("unknown command: %s", argv[0]);
      continue;
    }

    if( argc <= op->n_args ) {
        ci_log("Missing argument to '%s' (found %d, expected %d: %s)",
               op->name, argc - 1, op->n_args, op->args);
        ci_app_usage(0);
    }

    if( op->flags & FL_ARG_U ) {
      if( sscanf(argv[1], " %" CI_PRIu64 " %c", &arg_u[0], &dummy) != 1 ) {
        ci_log("Bad argument to '%s' (expected unsigned)", op->name);
        ci_app_usage(0);
      }
      --argc;
      ++argv;
    }
    else if( op->flags & FL_ARG_X ) {
      if( sscanf(argv[1], " %" CI_PRIx64 " %c", &arg_u[0], &dummy) != 1 ) {
        ci_log("Bad argument to '%s' (expected hex)", op->name);
        ci_app_usage(0);
      }
      --argc;
      ++argv;
    }
    else if( op->flags & FL_ARG_S ) {
      arg_s[0] = argv[1];
      --argc;
      ++argv;
    }
    else if( op->flags & FL_ARG_SV ) {
      arg_s[0] = argv[1];
      arg_s[1] = argv[2];
      /* type need to be checked later */
      --argc;  ++argv;
      --argc;  ++argv;
    }

    if( op->flags & FL_ID )
      for_each_stack_id(op->id_fn, NULL);
    else
      for_each_stack(op->fn, op->flags & FL_ONCE);
  }
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static void do_socket_ops(int argc, char* argv[])
{
  char* argv_dump[] = { "dump", 0 };
  const socket_op_t* op;
  char dummy;

  if( argc == 0 ) {
    argc = 1;
    argv = argv_dump;
  }

  for( ; argc; --argc, ++argv ) {
    if( ! strcmp("bw", argv[0]) ) {
      if( argc > 1 )  ci_app_usage("args after 'bw' not permitted");
      sockets_bw();
      return;
    }
    if( ! strcmp("watch_bw", argv[0]) ) {
      if( argc > 1 )  ci_app_usage("args after 'bw' not permitted");
      sockets_watch_bw();
      return;
    }
    if( ! strcmp("watch", argv[0]) ) {
      if( argc > 1 )  ci_app_usage("args after 'watch' not permitted");
      sockets_watch();
      return;
    }

    op = get_socket_op(argv[0]);

    if( ! op ) {
      ci_log("unknown command: %s", argv[0]);
      ci_app_usage(0);
    }

    if( argc <= op->n_args ) {
        ci_log("Missing argument to '%s' (found %d, expected %d: %s)",
               op->name, argc - 1, op->n_args, op->args);
        ci_app_usage(0);
    }

    if( op->flags & FL_ARG_U ) {
      if( sscanf(argv[1], " %" CI_PRIu64 " %c", &arg_u[0], &dummy) != 1 ) {
	ci_log("Expected <int> for command %s", op->name);
	ci_app_usage(0);
      }
      --argc;
      ++argv;
    }

    for_each_socket(op);
  }
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static void enum_stack_op_log(const stack_op_t *op, void *arg)
{ ci_log("  %s\t%s\t%s", op->name, op->args ? op->args : "", op->help);
}

static void enum_socket_op_log(const socket_op_t *op, void *arg)
{ ci_log("  %s\t%s\t%s", op->name, op->args ? op->args : "", op->help);
}

static void usage(const char* msg)
{
  if( msg ) {
    ci_log(" ");
    ci_log("%s", msg);
  }

  ci_log(" ");
  ci_log("usage:");
  ci_log("  %s [options] [stacks] <commands>...", ci_appname);
  ci_log("  %s [options] <sockets>... <commands>...", ci_appname);

  ci_log(" ");
  ci_log("misc commands:");
  ci_log("  doc");
  ci_log("  threads   Show thread information of onload processes");
  ci_log("  env       Show onload related environment of processes");
  ci_log("  processes Show list of onloaded processes");
  ci_log("  stacks    Show list of stacks, names, PIDs (default if no args)");

  ci_log(" ");
  ci_log("stack commands:");
  for_each_stack_op(&enum_stack_op_log, NULL);

  ci_log(" ");
  ci_log("socket commands:");
  for_each_socket_op(&enum_socket_op_log, NULL);

  ci_log(" ");
  ci_log("socket spec:");
  ci_log("  <stack>:<socket>");
  ci_log("  <stack>:*");
  ci_log("  *:*");

  ci_log(" ");
  ci_log("options:");
  ci_app_opt_usage(cfg_opts, N_CFG_OPTS);
  ci_log(" ");
  exit(-1);
}


static void atexit_fn(void)
{
  free(s_stack_idx_col);
  free(s_sock_idx_col);
  libstack_end();
}


static void cant_do_both(void)
{
  ci_app_usage("Please specify either stacks or sockets, not both.");
}


static int compare (const void *arg1, const void *arg2)
{
  return strcmp (*(const char**)arg1, *(const char**)arg2);
}

static int is_min_str (const char *min_str)
{
  return (min_str && min_str[0] && strcmp (min_str, "MIN"));
}

static int is_max_str (const char *max_str)
{
  return (max_str && max_str[0] && strcmp (max_str, "MAX"));
}

static void print_docs(int argc, char* argv[])
{
#undef CI_CFG_OPT
#undef CI_CFG_STR_OPT
#define IFDOC(env)  if( strlen(env) )

  static struct {
        const char *item_env;
        const char *item_name;
        unsigned    item_deflt;
        char*       item_deflt_str;
        const char *item_doc;
        const char *item_min_str;
        const char *item_max_str;
        const char *item_kind;
  } items [] = {

#define CI_CFG_OPT(env, name, type, doc, bits, group, deflt, min, max, pres) \
      { .item_env = env, .item_name = #name, .item_deflt = deflt, \
        .item_doc = doc, .item_min_str=#min, .item_max_str=#max, .item_kind="per-process"},
#define CI_CFG_STR_OPT(env, name, type, doc, bits, group, deflt, min, max, pres) \
      { .item_env = env, .item_name = #name, .item_deflt_str = deflt, \
        .item_doc = doc, .item_min_str=#min, .item_max_str=#max, .item_kind="per-process"},
#include <ci/internal/opts_citp_def.h>
#undef CI_CFG_OPT
#undef CI_CFG_STR_OPT
#define CI_CFG_OPT(env, name, type, doc, bits, group, deflt, min, max, pres) \
      { .item_env = env, .item_name = #name, .item_deflt = deflt, \
        .item_doc = doc, .item_min_str=#min, .item_max_str=#max, .item_kind="per-stack"},
#define CI_CFG_STR_OPT(env, name, type, doc, bits, group, deflt, min, max, pres) \
      { .item_env = env, .item_name = #name, .item_deflt_str = deflt, \
        .item_doc = doc, .item_min_str=#min, .item_max_str=#max, .item_kind="per-stack"},
#include <ci/internal/opts_netif_def.h>
#undef CI_CFG_OPT
#undef CI_CFG_STR_OPT
  };

#define NUM_ITEMS ( sizeof items / sizeof items[0])

  /* Sort the items by env. */
  qsort (items, NUM_ITEMS, sizeof items[0], compare);

  if( argc == 2 && ! strcmp(argv[1], "html") ) {
    printf("<table>\n");
    printf("<tr><td>name</td><td>default</td><td>description</td>"
            "</tr>\n");
    unsigned i;
    for( i = 0; i < NUM_ITEMS; ++i )
      if( items[i].item_env[0] && items[i].item_doc[0] ) {
        if( items [i].item_deflt_str == NULL )
          printf("<tr><td>%s</td><td>%u</td><td> %s</td></tr>\n",
                 items[i].item_env, items[i].item_deflt, items [i].item_doc);
        else
          printf("<tr><td>%s</td><td>%s</td><td> %s</td></tr>\n",
                 items[i].item_env, items[i].item_deflt_str, items [i].item_doc);
      }
    printf("</table>\n");
  }
  else if( argc == 2 && ! strcmp(argv[1], "rtf") ) {
    /* Now print them out. */
    printf("{\\rtf1\\ansi\\deff0{\\fonttbl");
    printf("{\\f0 Calibri;}");
    printf("{\\f1 Courier New;}}");

    unsigned i;
    for(i = 0; i < NUM_ITEMS; ++i) {
      if (!items[i].item_env[0] || !items[i].item_doc[0])
        continue;

      printf("\\sb480 \\li0\\f0\\fs28 \\b %s \\plain", items [i].item_env);
      printf("\\par \\li240 \\sb120 \\fs20 Name: \\f1 %s \\f0 ",
              items [i].item_name);
      if( items [i].item_deflt_str == NULL )
        printf ("default: \\f1 %u \\f0", items [i].item_deflt);
      else
        printf ("default: \\f1 %s \\f0", items [i].item_deflt_str);
      if (is_min_str (items[i].item_min_str))
          printf ("    min: \\f1 %s \\f0", items[i].item_min_str);
      if (is_max_str (items[i].item_max_str))
          printf ("    max: \\f1 %s \\f0", items[i].item_max_str);
      printf("     %s\\par \\plain \\sb120 \\fs20", items[i].item_kind);
      if (strcmp(items [i].item_doc, "doc"))
        printf("%s", items [i].item_doc);
      printf("\\par");
    }
    printf("}");
  }
  else if( argc == 1 || (argc == 2 && ! strcmp(argv[1], "text")) ) {
    unsigned i;
    for(i = 0; i < NUM_ITEMS; ++i) {
      if (!items[i].item_env[0] || !items[i].item_doc[0])
        continue;

      if( items [i].item_deflt_str == NULL )
        printf("%-25s (%s, %s)\ndefault: %d\n",
             items[i].item_env, items[i].item_name, items[i].item_kind,
             items[i].item_deflt);
      else
        printf("%-25s (%s, %s)\ndefault: %s\n",
             items[i].item_env, items[i].item_name, items[i].item_kind,
             items[i].item_deflt_str);
      if (is_min_str (items[i].item_min_str))
        printf ("min: %s\n", items[i].item_min_str);
      if (is_max_str (items[i].item_max_str))
        printf ("max: %s\n", items[i].item_max_str);

      printf ("\n%s\n\n\n", items[i].item_doc);
    }
  }
  else {
    ci_app_usage("Expected html, rtf or text.");
  }
}


/* The CI_CFG_* options are dumped by the build process into an object file
 * with the following symbols. */
extern char _binary_onload_config_start[];
extern char _binary_onload_config_end[];

static void print_config(void)
{
  int len = _binary_onload_config_end - _binary_onload_config_start;
  printf("%.*s", len, _binary_onload_config_start);
}


/* Function to parse stack numbers from input command line.
 * @param [in/out] argc - pointer to nr of arguments.
 * @param [in/out] argv - pointer to arguments table to parse.
 * @param [out] p_stack_idx - pointer to the parsed collection s_stack_idx_col.
 * @return Int flag indicating if the stacks are present 1 or not 0.
 */
static int parse_stacks(int* argc, char** argv[], int** p_stack_idx)
{
  char dummy;
  int doing_stacks = 0, i = 0;

  s_stack_idx_col = calloc(*argc + 1, sizeof(int));
  s_present_stack_idx_col = calloc(*argc + 1, sizeof(int));
  *p_stack_idx = s_stack_idx_col;

  while( i < *argc )
  {
    unsigned stack_id = 0;
    if( sscanf((*argv)[i], "%u %c", &stack_id, &dummy) == 1 ) {
      doing_stacks = 1;
      s_stack_idx_col[s_stack_idx_count++] = stack_id;
    }
    else {
      break;
    }
    ++i;
  }

  /* Mark the end of the stack indexes. */
  if( doing_stacks ) {
    s_stack_idx_col[s_stack_idx_count] = STACK_END_MARKER;
    *argc -= s_stack_idx_count;
    *argv += s_stack_idx_count;
  }
  return doing_stacks;
}


/* Function to parse sockets numbers from input command line.
 * @param [in/out] argc - pointer to nr of arguments.
 * @param [in/out] argv - pointer to arguments table to parse.
 * @param [out] p_stack_idx - pointer to the parsed collection s_stack_idx_col.
 * @return Int flag indicating if the sockets are present 1 or not 0.
 */
static int parse_sockets(int* argc, char** argv[], int** p_stack_idx)
{
  char dummy;
  int doing_sockets = 0;
  int i = 0;
  unsigned sock_size = 0;
  unsigned stack_id = 0, sock_id = 0;

  s_sock_idx_col = calloc(*argc + 1, sizeof(int));
  while( i < *argc )
  {
    if( sscanf((*argv)[i], "%u:%u %c", &stack_id, &sock_id, &dummy) == 2 ) {
      doing_sockets = 1;
      s_stack_idx_col[s_stack_idx_count++] = stack_id;
      s_sock_idx_col[sock_size++] = sock_id;
    }
    else if( sscanf((*argv)[i], "%u:* %c", &stack_id, &dummy) == 1 ) {
      doing_sockets = 1;
      s_stack_idx_col[s_stack_idx_count++] = stack_id;
      s_sock_idx_col[sock_size++] = SOCK_ALL_MARKER;
    }
    else if( ! strcmp((*argv)[i], "*:*") ) {
      doing_sockets = 1;
      *p_stack_idx = NULL;
      s_stack_idx_col[s_stack_idx_count++] = STACK_END_MARKER;
      s_sock_idx_col[sock_size++] = SOCK_ALL_MARKER;
    }
    else {
      break;
    }
    ++i;
  }

  /* Mark the end of the stacks and sockets indexes. */
  if( doing_sockets ) {
    s_stack_idx_col[s_stack_idx_count] = STACK_END_MARKER;
    s_sock_idx_col[sock_size] = SOCK_END_MARKER;
    *argc -= s_stack_idx_count;
    *argv += s_stack_idx_count;
  }
  return doing_sockets;
}


/* Predicate function to filter stacks for function list_all_stacks2().
 * Filtering is done based on  the indexes in s_stack_idx_col.
 * @param [in/out] info - pointer to stack info structure.
 * @return To include stack return 1, and 0 otherwise.
 */
static int stackfilter_match_index(ci_netif_info_t *info)
{
  int i = 0;
  STACK_LOG_DUMP(ci_log(" [%s %d] count=%d, stack=%d", __func__, __LINE__,
                         s_stack_idx_count, info->ni_index));
  if( s_stack_idx_count == 0 ) {
    return 1;
  } else {
    while( i < s_stack_idx_count ) {
      if( s_stack_idx_col[i] == info->ni_index ) {
        if( info->ni_no_perms_exists ) {
          ci_log("User %d:%d cannot access full details of stack %d(%s) owned by "
                "%d:%d share_with=%d", (int) getuid(), (int) geteuid(),
                info->ni_no_perms_id, info->ni_no_perms_name,
                (int) info->ni_no_perms_uid, (int) info->ni_no_perms_euid,
                info->ni_no_perms_share_with);
          return 0;
        } else {
          s_present_stack_idx_col[s_present_stack_idx_count++] =
            s_stack_idx_col[i];
          STACK_LOG_DUMP(ci_log(" [%s %d] present_stack=%d", __func__,
                         __LINE__, info->ni_index));
          return 1;
        }

      }
      ++i;
    }
  }
  return 0; /* Not interested */
}


/* Function to remove all not present stacks from the s_stack_idx_col collection
 * using a a base all present collection of stacks in s_present_stack_idx_col.
 * @param [in] doing_sockets - flag that indicate socket option.
 */
static void remove_not_present_stacks(int doing_sockets)
{
  int i = 0, j = 0, present = 1;
  STACK_LOG_DUMP(ci_log(" [%s %d] s_present_stack_idx_count = %d ", __func__,
                        __LINE__, s_present_stack_idx_count));
  while( i < s_stack_idx_count ) {
    j = 0;
    present = 0;
    while( j < s_present_stack_idx_count ) {
      if( s_stack_idx_col[i] == s_present_stack_idx_col[j] ) {
        present = 1;
        break;
      }
      ++j;
    }

    if( present || s_stack_idx_col[i] == STACK_END_MARKER ) {
      ++i;
    } else {
      /* Stack not present remove it from stack and sock tables */
      int idx = i;
      STACK_LOG_DUMP(ci_log(" [%s %d] Removing[%d] = %d", __func__, __LINE__,
                            idx, s_stack_idx_col[idx]));
      ci_log("No such stack id: %d", s_stack_idx_col[idx]);

      while( idx < s_stack_idx_count ) {
        s_stack_idx_col[idx] = s_stack_idx_col[idx+1];
        ++idx;
      }
      if( doing_sockets ) {
        idx = i;
        while( idx < s_stack_idx_count ) {
          s_sock_idx_col[idx] = s_sock_idx_col[idx+1];
          ++idx;
        }
      }
      --s_stack_idx_count;
    }
  }
  free(s_present_stack_idx_col);
}

/* Function used for printing out list of stacks for debugging */
static void debug_print_stacks(void)
{
  int i = 0;
  char buffer[1024];
  int next_buffer = 0, len = sizeof(buffer);
  next_buffer += ci_scnprintf(buffer, len, "stacks [");
  while( i < s_stack_idx_count + 1 ) {
    next_buffer += ci_scnprintf(buffer + next_buffer, len - next_buffer, " %d",
                                s_stack_idx_col[i]);
    ++i;
  }
  snprintf(buffer + next_buffer, len - next_buffer, " ]");
  STACK_LOG_DUMP(ci_log(" [%s %d] %s", __func__, __LINE__, buffer));
}


/* Function to add sockets to the print list. It is using the stack values in
 * the s_stack_idx_col collection.
 */
static void add_socket(void)
{
  int i = 0;
  while( s_stack_idx_col[i] != STACK_END_MARKER || s_sock_idx_col[i] !=
          SOCK_END_MARKER ) {
    if( s_stack_idx_col[i] == STACK_END_MARKER && s_sock_idx_col[i] ==
        SOCK_ALL_MARKER ) {
      s_stack_idx_count = 0;
      list_all_stacks2(stackfilter_match_index, NULL, NULL, NULL);
      socket_add_all_all();
    }
    else if( s_sock_idx_col[i] == SOCK_ALL_MARKER ) {
      socket_add_all(s_stack_idx_col[i]);
    }
    else {
      socket_add(s_stack_idx_col[i], s_sock_idx_col[i]);
    }
    ++i;
  }
}

int main(int argc, char* argv[])
{
  int doing_stacks = 0;
  int doing_sockets = 0;
  /* An index of available stacks to process */
  int* stack_idx;
  int no_args = (argc == 1);

  ci_app_usage = usage;

  /* onload onload_stackdump check */
  if ( onload_is_present() ) {
    ci_log("onload_stackdump should not itself be run under onload acceleration.");
    return -1;
  }

  /* First handle commands that do not require the driver to be loaded. */
  if( argc == 2 && ! strcmp(argv[1], "doc") ) {
    print_docs(--argc, ++argv);
    return 0;
  }
  else if( argc == 2 && ! strcmp(argv[1], "config") ) {
    print_config();
    return 0;
  }

  ci_app_getopt("[stack-index]", &argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;

  /* Ensure we clean-up nicely when we exit. */
  atexit(atexit_fn);

  /* Get stacks numbers from command line */
  doing_stacks = parse_stacks(&argc, &argv, &stack_idx);

  /* Get sockets numbers from command line */
  doing_sockets = parse_sockets(&argc, &argv, &stack_idx);

  if( ! (doing_stacks || doing_sockets) && argc == 0 ) {
    stack_idx = NULL;
    doing_stacks = 1;
  }

  /* Initialization of necessary stacks only. */
  if( libstack_init() != 0 ) {
    return -1;
  }

  /* Special case for onload_stackdump called with no arguments 
   * - just list stacks and pids and return
   */
  if( no_args ) {
    libstack_stack_mapping_print();
    return 0;
  }

  list_all_stacks2(stackfilter_match_index, NULL, NULL, NULL);
  debug_print_stacks();
  remove_not_present_stacks(doing_sockets);
  debug_print_stacks();

  for( ; argc; --argc, ++argv ) {
    if( ! strcmp(argv[0], "all") ) {
      if( doing_sockets ) {
        cant_do_both();
      }
      doing_stacks = 1;
    }
    else if( ! strcmp(argv[0], "threads") ) {
      if( doing_sockets || doing_stacks )
        ci_app_usage("Cannot mix threads with other commands");
      if( cfg_nopids )
        ci_app_usage("Cannot mix threads command with --nopids");
      CI_TRY(libstack_threads_print());
    }
    else if( ! strcmp(argv[0], "env") ) {
      if( doing_sockets || doing_stacks )
        ci_app_usage("Cannot mix env with other commands");
      if( cfg_nopids )
        ci_app_usage("Cannot mix env command with --nopids");
      CI_TRY(libstack_env_print());
    }
    else if( ! strcmp(argv[0], "processes") ) {
      if( doing_sockets || doing_stacks )
        ci_app_usage("Cannot mix processes with other commands");
      if( cfg_nopids )
        ci_app_usage("Cannot mix processes command with --nopids");
      libstack_pid_mapping_print();
    }
    else if( ! strcmp(argv[0], "stacks") ) {
      if( doing_sockets || doing_stacks )
        ci_app_usage("Cannot mix stacks with other commands");
      libstack_stack_mapping_print();
    }
    else if( ! cfg_zombie && ! strcmp(argv[0], "kill") ) {
      ci_app_usage("Cannot use kill without -z");
      break;
    }
    else {
      if( !doing_sockets ) {
        doing_stacks = 1;
      }
      break;
    }
  }
  STACK_LOG_DUMP(ci_log(" [%s %d] doing_stacks=%d, doing_sockets=%d", __func__,
                        __LINE__, doing_stacks, doing_sockets));

  if( doing_sockets ) {
    if( doing_stacks ) {
      cant_do_both();
    }
    else {
      add_socket();
    }
  }

  ci_log_fn = ci_log_stdout;
  if( doing_stacks )
    do_stack_ops(argc, argv);
  if( doing_sockets )
    do_socket_ops(argc, argv);

  return 0;
}

/*! \cidoxg_end */
