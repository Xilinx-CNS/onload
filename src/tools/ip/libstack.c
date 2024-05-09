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
#define _GNU_SOURCE
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <ci/internal/ip.h>
#include <onload/ul.h>
#include <onload/cplane_ops.h>
#include <onload/driveraccess.h>
#include <onload/ioctl.h>
#include <onload/debug_intf.h>
#include <onload/debug_ops.h>
#include <onload/ul/tcp_helper.h>
#include <ci/app.h>
#include <etherfabric/vi.h>
#include <etherfabric/internal/internal.h>
#include "libstack.h"
#include <ci/internal/ip_signal.h>
#include <dirent.h>
#include <ctype.h>
#include <ci/internal/more_stats.h>
#include <ci/internal/stats_dump.h>
#include "sockbuf_filter.h"

#undef DO
#undef IGNORE

#define DO(_x) _x
#define IGNORE(_x)


#define MAX_PATHNAME 300


typedef struct {
  int		stack;
  int		id;
  void*		s;	/* misc state */
} socket_t;


struct pid_mapping {
  struct pid_mapping* next;
  int*                stack_ids;
  int                 n_stack_ids;
  pid_t               pid;
};
static struct pid_mapping* pid_mappings;


struct stack_mapping {
  struct stack_mapping* next;
  pid_t*                pids;
  int                   n_pids;
  int                   stack_id;
};
static struct stack_mapping* stack_mappings;


static int              signal_fired;

static netif_t**	stacks;
static int		stacks_size;
static ci_dllist	stacks_list;
static socket_t*	sockets;
static int		sockets_n, sockets_size;
static sockbuf_filter_t sft;

/* Config options -- may be modified by clients. */
int		cfg_lock;
int		cfg_nolock;
int             cfg_blocklock;
int		cfg_nosklock;
int		cfg_dump;
int		cfg_watch_msec = 1000;
unsigned	cfg_usec = 10000;
unsigned	cfg_samples = 1000;
int             cfg_notable;
int             cfg_zombie = 0;
int             cfg_nopids = 0;
const char*     cfg_filter = NULL;

/* 
 * In stackdump universe option: We need to print filters ouput and table only once. 
 * Use this global var to prevent it from printing on every stack.
 */
int universe_print_once = 1;

ci_inline void libstack_defer_signals(citp_signal_info* si)
{
  si->c.inside_lib = 1;
  ci_compiler_barrier();
}


ci_inline void libstack_process_signals(citp_signal_info* si)
{
  si->c.inside_lib = 0;
  ci_compiler_barrier();
  if( si->c.aflags & OO_SIGNAL_FLAG_HAVE_PENDING )
    citp_signal_run_pending(si);
}


static int __try_grab_stack_lock(ci_netif* ni, int* unlock,
                                 const char* caller)
{
  if( cfg_lock || cfg_nolock ) {
    *unlock = 0;
    return 1;
  }
  if( ! (*unlock = libstack_netif_trylock(ni)) )
    ci_log("%s: [%d] could not get lock", caller, NI_ID(ni));
  return *unlock;
}


#define try_grab_stack_lock(ni, unlock)                 \
  __try_grab_stack_lock((ni), (unlock), __FUNCTION__)


netif_t *stack_attached(int id)
{   if (id < 0 || id >= stacks_size)
        return NULL;
    else
        return stacks[id];
}


static int is_pid(const char* name)
{
  int i;
  for( i = 0; i < strlen(name); ++i ) {
    if( name[i] < '0' || name[i] > '9' )
      return 0;
  }
  return 1;
}


/*
 * Walk /proc/<pid/fd/ to check if any fds refer to onload.  Returns
 * list of onload stacks or -1 on failure.
 */
static int is_onloaded(pid_t pid, int** ret_stacks_ids)
{
  int i;
  char fd_dir_path[MAX_PATHNAME];
  snprintf(fd_dir_path, MAX_PATHNAME, "/proc/%d/fd", pid);
  DIR* fd_dir = opendir(fd_dir_path);
  if( ! fd_dir )
    return -1;

  int n_stacks = 0;
  int* stack_ids = NULL;
  struct dirent* ent;
#ifndef O_PATH
/* RHEL6 case */
#define O_PATH 0
#endif
  int dirfd = open(fd_dir_path, O_PATH | O_CLOEXEC | O_DIRECTORY);
  if( dirfd < 0 ) {
    closedir(fd_dir);
    return -1;
  }
  while( (ent = readdir(fd_dir)) ) {
    if( ent->d_name[0] == '.' )
      continue;
    char sym_buf[MAX_PATHNAME];
    ssize_t rc = readlinkat(dirfd, ent->d_name, sym_buf, MAX_PATHNAME);
    if( rc == -1 ) {
      close(dirfd);
      closedir(fd_dir);
      return rc;
    }
    sym_buf[rc] = '\0';
    if( ! strncmp(sym_buf, "onload", strlen("onload")) ) {
      char* ptr = strchr(sym_buf, '[');
      ptr = strchr(ptr, ':');
      ++ptr;
      int stack_id = atoi(ptr);
      int stack_seen = 0;
      for( i = 0; i < n_stacks; ++i ) {
        if( stack_ids[i] == stack_id )
          stack_seen = 1;
      }
      if( ! stack_seen ) {
        stack_ids = realloc(stack_ids, sizeof(*stack_ids) * (n_stacks + 1));
        stack_ids[n_stacks] = stack_id;
        ++n_stacks;
      }
    }
  }
  close(dirfd);
  closedir(fd_dir);
  *ret_stacks_ids = stack_ids;
  return n_stacks;
}


static int libstack_mappings_init(void)
{
  int rc, i;

  if( ! cfg_nopids ) {
    pid_t my_pid = getpid();

    DIR* proc = opendir("/proc");
    if( ! proc )
      CI_TRY(-1);

    /* Walk over entire '/proc/' looking into '/proc/<pid>/fd/' to see
     * if there are any onloaded fds. Fill in pid_mappings accordingly.
     */
    struct dirent* ent;
    while( (ent = readdir(proc)) ) {
      if( ! is_pid(ent->d_name) )
        continue;

      pid_t pid = atoi(ent->d_name);
      if( pid == my_pid )
        continue;

      /* http://www.novell.com/support/kb/doc.php?id=3649220 some kernel
       * versions on SUSE have a pid=0 directory which is seen in "ls
       * /proc" but isn't accessible so don't try to read it.
       */
      if( pid == 0 )
        continue;

      int* stack_ids;
      rc = is_onloaded(pid, &stack_ids);
      if( rc == 0 )
        continue;
      if( rc == -1 ) {
        /* EACCES: do not have permissions for this process
         * ENOENT: process have died while we were running here
         * ESRCH: No process, same as ENOENT */
        if( errno == EACCES || errno == ENOENT || errno == ESRCH )
          continue;
        fprintf(stderr, "%s: error %d (%s)\n",
                __FUNCTION__, errno, strerror(errno));
        closedir(proc);
        CI_TRY(-1);
        return -1;
      }

      struct pid_mapping* pm = calloc(1, sizeof(*pm));
      pm->pid         = pid;
      pm->stack_ids   = stack_ids;
      pm->n_stack_ids = rc;
      pm->next        = pid_mappings;
      pid_mappings    = pm;
    }

    closedir(proc);
  }
  else {
    pid_mappings = NULL;
  }

  /* Set stack ids in stack_mappings using debug ioctl
   */
  ci_netif_info_t info;
  oo_fd fd;
  rc = oo_fd_open_versioned(&fd);
  if( rc == -ENOENT || rc == -ENXIO ) {
    fprintf(stderr, "Could not open /dev/onload (rc=%d) - "
                    "check Onload drivers are loaded\n", rc);
    errno = -rc;
    return -1;
  }
  else if( rc == -ELIBACC || rc == -EINVAL ) {
    /* Note: older drivers not supporting driver check will return -EINVAL,
     * new libraries will return -ELIBACC */
    fprintf(stderr, "Could not open /dev/onload (rc=%d) - "
                    "check Onload driver version matches that of library\n", rc);
    errno = ELIBACC;
    return -1;
  }
  CI_TRY(rc);
  info.mmap_bytes = 0;
  info.ni_exists = 0;
  i = 0;
  while( i >= 0 ) {
    info.ni_index = i;
    STACK_LOG_DUMP(ci_log(" [%s %d] idx = %d", __func__, __LINE__, i));
    info.ni_orphan = cfg_zombie;
    info.ni_subop = CI_DBG_NETIF_INFO_GET_NEXT_NETIF;
    CI_TRY(oo_ioctl(fd, OO_IOC_DBG_GET_STACK_INFO, &info));
    int stack_id = -1;
    if( info.ni_exists )
      stack_id = info.ni_index;
    else if( info.ni_no_perms_exists ) {
      stack_id = info.ni_no_perms_id;
    }

    if( stack_id != -1 ) {
      struct stack_mapping* sm = calloc(1, sizeof(*sm));
      sm->stack_id = stack_id;
      sm->next = stack_mappings;
      stack_mappings = sm;
    }
    i = info.u.ni_next_ni.index;
  }
  CI_TRY(oo_fd_close(fd));

  /* Fill in pids in stack_mappings using pid_mappings
   */
  struct pid_mapping* pm = pid_mappings;
  while( pm ) {
    for( i = 0; i < pm->n_stack_ids; ++i ) {
      struct stack_mapping* sm = stack_mappings;
      int found_stack = 0;
      while( sm ) {
        if( pm->stack_ids[i] == sm->stack_id ) {
          sm->pids = realloc(sm->pids, sizeof(*sm->pids) * (sm->n_pids + 1));
          sm->pids[sm->n_pids] = pm->pid;
          ++sm->n_pids;
          found_stack = 1;
        }
        sm = sm->next;
      }
      if( ! found_stack && ! cfg_zombie )
        fprintf(stderr, "Warning: Traversing /proc found stack %d"
                " which debug ioctl did not\n", pm->stack_ids[i]);
    }
    pm = pm->next;
  }

  return 0;
}


void libstack_stack_mapping_print_pids(int stack_id)
{
  const int buf_len = 61;
  char buf[buf_len];
  int i, consumed = 0;
  struct stack_mapping* sm = stack_mappings;
  int ilen = 0;
  int pid = 0;
  
  if( cfg_nopids )
    return;

  while( sm && sm->stack_id != stack_id )
    sm = sm->next;
  if( sm == NULL ) {
    ci_log("No stack_mapping for stack %d found", stack_id);
    return;
  }

  consumed += snprintf(&buf[consumed], buf_len - consumed, "pids: ");
  for( i = 0; i < sm->n_pids; ++i ) {
    /*
     * check if adding another pid hits/exceeds line length: if so,
     * print line, reset counters & buffer, add indentation
     * ilen initialised to 2 as PID + , will always be length >= 2
     */
    pid = sm->pids[i];
    ilen = 2;
    while( pid > 9 ) {
      pid = pid / 10;
      ++ilen;
    }

    if( (ilen + consumed) > buf_len ) {
      ci_log("%s", buf);
      bzero(buf, buf_len);
      consumed = 0;
      consumed += snprintf(&buf[consumed], buf_len - consumed, "      ");
    }

    if( i == sm->n_pids - 1 )
      consumed += snprintf(&buf[consumed], buf_len - consumed, "%d",
                           sm->pids[i]);
    else
      consumed += snprintf(&buf[consumed], buf_len - consumed, "%d,",
                           sm->pids[i]);
  }
  ci_log("%s", buf);
}


void libstack_stack_mapping_print(void)
{
  int i;
  struct stack_mapping* sm;

  if( ! stack_mappings )
    return;

  if( cfg_nopids )
    ci_log("#stack-id stack-name");
  else
    ci_log("#stack-id stack-name      pids");

  for( sm = stack_mappings; sm != NULL; sm = sm->next ) {
    ci_log_nonl("%-9d ", sm->stack_id);

    stack_attach(sm->stack_id);
    netif_t* netif = stack_attached(sm->stack_id);

    if( netif == NULL ) {
      ci_log("inaccessible");
      continue;
    }
    if( ! netif->ni.state )
      ci_log_nonl("<zombie>        ");
    else if( strlen(netif->ni.state->name) != 0 )
      ci_log_nonl("%-16s", netif->ni.state->name);
    else
      ci_log_nonl("-               ");

    if( !cfg_nopids ) {
      if( sm->n_pids == 0 )
        ci_log_nonl("-");
      else {
        for( i = 0; i < sm->n_pids; ++i ) {
          ci_log_nonl("%d", sm->pids[i]);
          if( i != sm->n_pids - 1 )
            ci_log_nonl(",");
        }
      }
    }
    ci_log(" ");
  }
}

static void print_cmdline(int pid)
{
  int i, cnt;
  char cmdline_path[MAX_PATHNAME];
  snprintf(cmdline_path, MAX_PATHNAME, "/proc/%d/cmdline", pid);
  int cmdline = open(cmdline_path, O_RDONLY);
  char buf[MAX_PATHNAME];
  while( (cnt = read(cmdline, buf, MAX_PATHNAME)) > 0 ) {
    for( i = 0; i < cnt; ++i ) {
      if( buf[i] == '\0' )
        ci_log_nonl(" ");
      else
        ci_log_nonl("%c", buf[i]);
    }
  }
  close(cmdline);
  ci_log(" ");
}

void libstack_pid_mapping_print(void)
{
  int i;
  struct pid_mapping* pm = pid_mappings;
  int max_spacing = 0;

  if( ! pid_mappings ) {
    if( cfg_nopids )
      fprintf(stderr, "No PID state as --nopids set on command line\n");
    return;
  }

  while( pm ) {
    if( max_spacing < pm->n_stack_ids * 2 + 1 )
      max_spacing = pm->n_stack_ids * 2 + 1;
    pm = pm->next;
  }

  ci_log_nonl("#pid      stack-id");
  if( max_spacing > strlen("stack-id") ) {
    for(i = 0; i < max_spacing - strlen("stack-id") - 1; ++i )
      ci_log_nonl(" ");
  }
  else
    ci_log_nonl(" ");
  ci_log("cmdline");

  pm = pid_mappings;
  while( pm ) {
    ci_log_nonl("%-10d", pm->pid);
    for( i = 0; i < pm->n_stack_ids; ++i ) {
      ci_log_nonl("%d", pm->stack_ids[i]);
      if( i != pm->n_stack_ids - 1 )
        ci_log_nonl(",");
    }
    if( max_spacing > strlen("stack-id") ) {
      for( i = 0; i < max_spacing - pm->n_stack_ids * 2; ++i )
        ci_log_nonl(" ");
    }
    else {
      for( i = 0; i < strlen("stack-id") - pm->n_stack_ids * 2 + 2; ++i )
        ci_log_nonl(" ");
    }

    print_cmdline(pm->pid);
    pm = pm->next;
  }
}


static int get_int_from_tok_str(char * str, const char * tok, int i, long * res)
{
  char * p;

  str = strtok_r(str, tok, &p);
  while( str && i ) {
    str = strtok_r(NULL, tok, &p);
    --i;
  }

  if(str) {
    *res = atol(str);
    return 1;
  }
  return 0;
}


int libstack_threads_print(void)
{
  char task_path[MAX_PATHNAME];

  if( ! pid_mappings ) {
    if( cfg_nopids )
      fprintf(stderr, "No PID state as --nopids set on command line\n");
    return 0;
  }

  struct pid_mapping* pm = pid_mappings;

  ci_log("#pid thread affinity priority realtime");

  while( pm ) {
    snprintf(task_path, MAX_PATHNAME, "/proc/%d/task", pm->pid);
    DIR* task_dir = opendir(task_path); 

    struct dirent* ent;
    while( (ent = readdir(task_dir)) ) {
      if( ent->d_name[0] == '.' )
        continue;

      ci_log_nonl("%d %s ", pm->pid, ent->d_name);

      /* task affinity */
      char file_path[MAX_PATHNAME];
      snprintf(file_path, MAX_PATHNAME, "/proc/%d/task/%s/status",
               pm->pid, ent->d_name);
      FILE* status = fopen(file_path, "r");
      char buf[1000];
      char* c;
      do {
        c = fgets(buf, MAX_PATHNAME, status);
      } while( c && strncmp(buf, "Cpus_allowed:", strlen("Cpus_allowed:")) );
      char* ptr = strchr(buf, ':');
      ++ptr;
      while( isspace(*ptr) )
        ++ptr;
      char* newline = strchr(ptr, '\n');
      *newline = '\0';
      ci_log_nonl("%s ", ptr);
      fclose(status);

      snprintf(file_path, MAX_PATHNAME, "/proc/%d/task/%s/stat",
               pm->pid, ent->d_name);
      int stat = open(file_path, O_RDONLY);
      long cnt = read(stat, buf, 1000);
      close(stat);
      while( cnt && (buf[cnt-1] != ')') ) {
        cnt--;
      }
      if( get_int_from_tok_str(&buf[cnt], " ", 15, &cnt) ) {
        if( cnt < 0 )
          ci_log_nonl("%ld 1\n", (-cnt)-1);
        else
          ci_log_nonl("%ld 0\n", cnt-20);
      }
      else
        ci_log_nonl("N/A N/A");

      if( pm->next )
        ci_log(" ");
    }
    pm = pm->next;
    closedir(task_dir);
  }
  return 0;
}


static int get_file_size(const char* path)
{
  int fd = open(path, O_RDONLY);
  if( fd == -1 )
    return -1;
  char buf[128];
  int len = 0;
  while( 1 ) {
    ssize_t rc = read(fd, buf, 128);
    if( rc == -1 )
      return -1;
    len += rc;
    if( rc == 0 )
      return len;
  }
}


static int libstack_pid_env_print(int pid)
{
  int rc;
  int env = -1;
  char *buf = NULL;

  ci_log_nonl("cmdline: ");
  print_cmdline(pid);
  char env_path[MAX_PATHNAME];
  snprintf(env_path, MAX_PATHNAME, "/proc/%d/environ", pid);

  int file_len = get_file_size(env_path);
  if( file_len < 0 ) {
    rc = file_len;
    goto out;
  }

  env = open(env_path, O_RDONLY);
  if( env < 0 ) {
    rc = env;
    goto out;
  }

  buf = calloc(1, file_len);
  rc = read(env, buf, file_len);
  if( rc < 0 )
    goto out;

  if( rc != file_len ) {
    fprintf(stderr, "%s: Read less than expected amount\n", __FUNCTION__);
    goto out;
  }

  char* var = buf;
  while( var ) {
    if( ! strncmp(var, "EF_", strlen("EF_")) )
      ci_log_nonl("env: %s\n", var);
    if( ! strncmp(var, "LD_PRELOAD", strlen("LD_PRELOAD")) )
      ci_log_nonl("env: %s\n", var);
    if( ! strncmp(var, "TP_LOG", strlen("TP_LOG")) )
      ci_log_nonl("env: %s\n", var);
    while( *var != '\0' )
      ++var;
    ++var;
    if( var - buf >= file_len )
      break;
  }

 out:
  free(buf);
  if( env >= 0 )
    close(env);

  return rc;
}

int libstack_env_print(void)
{
  ci_log("transport opt hdr: " OO_STRINGIFY(TRANSPORT_CONFIG_OPT_HDR));

  if( ! pid_mappings ) {
    if( cfg_nopids )
      fprintf(stderr, "No environment state as --nopids set on command line\n");
    return 0;
  }

  struct pid_mapping* pm = pid_mappings;
  while( pm ) {
    ci_log("--------------------------------------------");
    ci_log("pid: %d", pm->pid);
    libstack_pid_env_print(pm->pid);
    pm = pm->next;
  }
  ci_log("--------------------------------------------");
  return 0;
}


int stack_attach(unsigned id)
{
  netif_t* n;

  if( id < stacks_size && stacks[id] )  return 1;

  if( id >= stacks_size ) {
    int new_size = CI_MAX(stacks_size * 2, 8);
    new_size = CI_MAX(new_size, id + 1);
    stacks = realloc(stacks, new_size * sizeof(stacks[0]));
    CI_TEST(stacks);
    memset(stacks+stacks_size, 0, (new_size-stacks_size) * sizeof(stacks[0]));
    stacks_size = new_size;
  }
  CI_TEST(n = (netif_t*) malloc(sizeof(*n)));
  CI_ZERO(n);  /* bc: must zero-out UL netif */

  if( ! cfg_zombie ) {
    /* Possibly, this stack was already destroyed, so do not CI_TRY here. */
    int rc = ci_netif_restore_id(&n->ni, id, true);
    if( rc != 0 )
        return 0;
  }
  stacks[id] = n;
  ci_dllist_push_tail(&stacks_list, &n->link);

  if( cfg_lock )  libstack_netif_lock(&n->ni);

  return 1;
}

void stack_detach(netif_t* n, int locked)
{
  IGNORE(ci_log("detaching netif %d at %p (given %p)\n",
		NI_ID(&n->ni), &n->ni, n););
  if( locked )  libstack_netif_unlock(&n->ni);
  ci_dllist_remove_safe(&n->link); /* take off stacks_list, if present */

  if( ! cfg_zombie ) {
    int fd = ci_netif_get_driver_handle(&n->ni);
    int id = NI_ID(&n->ni);

    /* Unmap. */
    ci_netif_dtor(&n->ni);
    CI_TRY(ef_onload_driver_close(fd));
    
    stacks[id] = 0;
  }
}


void list_all_stacks2(stackfilter_t *filter,
                      stack_ni_fn_t *post_attach, stack_ni_fn_t *pre_detach,
                      oo_fd *p_fd)
{
  ci_netif_info_t info;
  int i = 0;
  oo_fd fd = (oo_fd) -1;

  if( p_fd )
    fd = *p_fd;
  if( fd == (oo_fd) -1 ) {
    CI_TRY(oo_fd_open(&fd));
    if( p_fd )
      *p_fd = fd;
  }

  info.mmap_bytes = 0;
  info.ni_exists = 0;

  while( i >= 0 ) {
    info.ni_index = i;
    info.ni_orphan = cfg_zombie;
    info.ni_subop = CI_DBG_NETIF_INFO_GET_NEXT_NETIF;
    CI_TRY(oo_ioctl(fd, OO_IOC_DBG_GET_STACK_INFO, &info));

    if( info.ni_exists ) {
      /* Are we already attached? */
      if( i < stacks_size && stacks[i] != NULL ) {
        /* Is the stack dead?  Should we detach? */
        if( info.rs_ref_count == 0 ) {
          IGNORE(ci_log("No app is using stack %d", i));
          if( pre_detach )
            pre_detach(&stacks[i]->ni);
          stack_detach(stacks[i], 0);
        }
      }
      else if( filter == NULL || filter(&info) ){
        /* New stack, let's attach */
        IGNORE(ci_log("new stack %3d: %u", info.ni_index, i));
        if( stack_attach(i) && post_attach )
          post_attach(&stacks[i]->ni);
      }
    } else if( info.ni_no_perms_exists ) {
      if( filter == NULL || filter(&info) ) {
        ci_log("User %d:%d cannot access full details of stack %d(%s) owned by "
              "%d:%d share_with=%d", (int) getuid(), (int) geteuid(),
              info.ni_no_perms_id, info.ni_no_perms_name,
              (int) info.ni_no_perms_uid, (int) info.ni_no_perms_euid,
              info.ni_no_perms_share_with);
      }
    }
    i = info.u.ni_next_ni.index;
  }

  if( p_fd == NULL )
    CI_TRY(oo_fd_close(fd));
}

void for_each_stack(void (*fn)(ci_netif* ni), int only_once)
{
  netif_t* n;
  CI_DLLIST_FOR_EACH2(netif_t, n, link, &stacks_list) {
    fn(&n->ni);
    if( only_once )
      break;
  }
}


void for_each_stack_id(void (*fn)(int id, void* arg), void* arg)
{
  int id;
  for (id=0; id<stacks_size; id++)
    if (stacks[id] != 0)
       (*fn)(id, arg);
}


void stacks_detach_all(void)
{
  netif_t* n;

  while (ci_dllist_not_empty(&stacks_list)) {
    n = CI_CONTAINER(netif_t, link, ci_dllist_start(&stacks_list));
    stack_detach(n, cfg_lock);
  }
}


static void do_socket_op(const socket_op_t* op, socket_t* s)
{
  citp_waitable_obj* wo;
  netif_t* n = stacks[s->stack];
  int ni_unlock = 0;
  int s_unlock = 0;
  int ok;

  if( ! (op->flags & FL_NO_LOCK) &&
      ! __try_grab_stack_lock(&n->ni, &ni_unlock, op->name) )
    return;

  if( s->id < (int) n->ni.state->n_ep_bufs ) {
    wo = SP_TO_WAITABLE_OBJ(&n->ni, s->id);

    if( (op->flags & FL_LOCK_SOCK) && ! cfg_nosklock &&
        ! (s_unlock = ci_sock_trylock(&n->ni, &wo->waitable)) ) {
      ci_log("%s: [%d:%d] can't get sock lock (--nosocklock may help)",
             op->name, s->stack, s->id);
      return;
    }

    ok = 1;
    if( (op->flags & FL_TCPC) && ! (wo->waitable.state&CI_TCP_STATE_TCP_CONN) )
      ok = 0;
    if( (op->flags & FL_TCPA) && ! (wo->waitable.state & CI_TCP_STATE_TCP) )
      ok = 0;
    if( (op->flags & FL_UDP) && wo->waitable.state != CI_TCP_STATE_UDP )
      ok = 0;
    if( ! CI_TCP_STATE_IS_SOCKET(wo->waitable.state) )
      ok = 0;

    if( ok )
      if( sockbuf_filter_matches(&sft, wo) )
        op->fn(&n->ni, &wo->tcp);

    if( s_unlock )
      ci_sock_unlock(&n->ni, &wo->waitable);
  }

  if( ni_unlock )
    libstack_netif_unlock(&n->ni);
}


void for_each_socket(const socket_op_t* op)
{
  socket_t* s;
  for( s = sockets; s < sockets + sockets_n; ++s )
    do_socket_op(op, s);
}


static void* more_stats_getter(void* to, const void* from, size_t len)
{
  ci_assert_equal(len, sizeof(more_stats_t));
  get_more_stats((ci_netif*) from, (more_stats_t*) to);
  return to;
}


static void clear_stats(const stat_desc_t* stats_fields, int n_stats_fields,
                        void* stats)
{
  const stat_desc_t* s;
  for( s = stats_fields; s < stats_fields + n_stats_fields; ++s ) {
    switch(s->size) {
      case sizeof(ci_uint32):
        *(ci_uint32*) ((char*) stats + s->offset) = 0u;
        break;
      case sizeof(ci_uint64):
        *(ci_uint64*) ((char*) stats + s->offset) = 0u;
        break;
      default:
        ci_assert(0);
    }
  }
}


ci_inline unsigned tv_delta(const struct timeval* a, const struct timeval* b)
{
  return (a->tv_sec - b->tv_sec) * 1000u + (a->tv_usec - b->tv_usec) / 1000u;
}


static void print_stats_header_line(const stat_desc_t* stats_fields,
                                    int n_stats_fields)
{
  const stat_desc_t* s;
  int j, i = 1;

  ci_log_nonl("#\ttime(%d)", i++);
  for( s = stats_fields; s < stats_fields + n_stats_fields; ++s )
    ci_log_nonl("\t%s(%d)", s->name, i++);
  ci_log(" ");
  printf("#");
  for( j = 1; j < i; ++j )  ci_log_nonl("\t(%d)", j);
  ci_log(" ");
}


static void watch_stats(const stat_desc_t* stats_fields, int n_stats_fields,
                        int stats_len_bytes, void* stats_src,
                        void* (*get_stats)(void* to, const void* from,
                                           size_t len))
{
  unsigned line_len = n_stats_fields * 20;
  char* line = malloc(line_len);
  unsigned time_msec = 0, target_msec = 0;
  struct timeval start, now;
  void* p = malloc(stats_len_bytes);
  void* c = malloc(stats_len_bytes);
  const stat_desc_t* s;
  int lo = 0, line_i;

  get_stats(c, stats_src, stats_len_bytes);
  gettimeofday(&start, 0);

  for( line_i = 0; ; ++line_i ) {
    memcpy(p, c, stats_len_bytes);
    target_msec += cfg_watch_msec;
    ci_sleep(target_msec - time_msec);
    get_stats(c, stats_src, stats_len_bytes);
    gettimeofday(&now, 0);
    time_msec = tv_delta(&now, &start);
    if( ! cfg_notable ) {
      if( (line_i & 0xf) == 0 )
        print_stats_header_line(stats_fields, n_stats_fields);
      lo = ci_scnprintf(line, line_len, "\t%.02f", (double) time_msec / 1000);
    }
    else
      ci_log("=====================================================");
    for( s = stats_fields; s < stats_fields + n_stats_fields; ++s ) {
      unsigned long long v = 0; /* placate compiler */
      switch(s->size) {
        case sizeof(ci_uint32):
          v = *(ci_uint32*) ((char*) c + s->offset);
          if( s->flags & STAT_COUNT )
            v -= *(ci_uint32*) ((char*) p + s->offset);
          break;
        case sizeof(ci_uint64):
          v = *(ci_uint64*) ((char*) c + s->offset);
          if( s->flags & STAT_COUNT )
            v -= *(ci_uint64*) ((char*) p + s->offset);
          break;
        default:
          assert(0);
      }
      if( ! cfg_notable ) {
        lo += ci_scnprintf(line+lo, line_len-lo, "\t %llu", v);
      }
      else
        ci_log("%30s: %llu", s->name, v);
    }
    if( ! cfg_notable ) {
      ci_log("%s", line);
      fflush(stdout);
    }
  }
  free(line);
  free(p);
  free(c);
}

/**********************************************************************
**********************************************************************/

void socket_add(int stack_id, int sock_id)
{
  netif_t* n = stacks[stack_id];
  socket_t* s;

  if( ! n )  return;

  if( sockets_n == sockets_size ) {
    int new_size = CI_MAX(sockets_size * 2, MAX_PATHNAME);
    sockets = realloc(sockets, new_size * sizeof(sockets[0]));
    CI_TEST(sockets);
    sockets_size = new_size;
  }

  s = &sockets[sockets_n++];
  s->stack = stack_id;
  s->id = sock_id;
  s->s = 0;
}


void socket_add_all(int stack_id)
{
  netif_t* n = stacks[stack_id];
  int i;

  if( ! n )  return;

  for( i = 0; i < (int)n->ni.state->n_ep_bufs; ++i ) {
    citp_waitable_obj* wo = SP_TO_WAITABLE_OBJ(&n->ni, i);
    if( ! CI_TCP_STATE_IS_SOCKET(wo->waitable.state) )  continue;
    socket_add(stack_id, i);
  }
}


void socket_add_all_all(void)
{
  netif_t* n;
  CI_DLLIST_FOR_EACH2(netif_t, n, link, &stacks_list)
    socket_add_all(NI_ID(&n->ni));
}

/**********************************************************************
***********************************************************************
**********************************************************************/

/* Wrapper for the various state-dumping ioctls: keeps trying with
 * larger buffers until it gets the whole output.
 */

#define DVB_LOG_FAILURE  1
typedef int (*oo_dump_request_fn_t)(void* args, void* buf, int buf_len);

static int dump_via_buffers(oo_dump_request_fn_t dump_req_fn, void* arg,
                            unsigned flags)
{
  int buf_len = 8192;
  char* buf;
  int rc;
  while( 1 ) {
    if( (buf = malloc(buf_len)) == NULL ) {
      if( flags & DVB_LOG_FAILURE )
        ci_log("%s: Out of memory", __FUNCTION__);
      return -ENOMEM;
    }
    rc = dump_req_fn(arg, buf, buf_len);
    if( rc >= 0 && rc <= buf_len )
      ci_log_stdout_nonl(buf);
    free(buf);
    if( rc < 0 ) {
      if( flags & DVB_LOG_FAILURE )
        ci_log("%s: failed (%d)", __FUNCTION__, -rc);
      return rc;
    }
    if( rc <= buf_len )
      break;
    buf_len = rc;
  }

  return 0;
}

/**********************************************************************
***********************************************************************
**********************************************************************/

static void dump_sock_qs(ci_netif* ni, ci_tcp_state* ts)
{ ci_tcp_state_dump_qs(ni, S_SP(ts), cfg_dump); }


static void for_each_tcp_socket(ci_netif* ni,
				void (*fn)(ci_netif*, ci_tcp_state*))
{
  int id;
  for( id = 0; id < (int)ni->state->n_ep_bufs; ++id ) {
    citp_waitable_obj* wo = SP_TO_WAITABLE_OBJ(ni, id);
    if( wo->waitable.state == CI_TCP_LISTEN ||
        ! (wo->waitable.state & CI_TCP_STATE_TCP) )
      continue;
    if( sockbuf_filter_matches(&sft, wo) )
      fn(ni, &wo->tcp);
  }
}


/**********************************************************************
***********************************************************************
**********************************************************************/

uint64_t arg_u[1];
const char* arg_s[2];


#if ! CI_CFG_UL_INTERRUPT_HELPER
void dump_kernel_stats_via_buffer(int id, dump_stack_args *args)
{
  int rc;

  CI_TRY(oo_fd_open(&args->fp));
  rc = dump_via_buffers(oo_debug_dump_stack, args, 0);
  CI_TRY(oo_fd_close(args->fp));

  switch( -rc ) {
  case 0:
    /* Success. */
    break;
  case EPERM:
    ci_log("Permission denied - please run as root to access orphan stacks");
    break;
  case ENOMEM:
    ci_log("Out of memory.");
    break;
  default:
    ci_log("No such orphan stack %d (error %d).", id, -rc);
  }
}


void zombie_stack_dump(int id, void *arg)
{
  dump_stack_args args;

  args.stack_id = id;
  args.orphan_only = 1;
  args.op = __CI_DEBUG_OP_DUMP_STACK__;

  dump_kernel_stats_via_buffer(id, &args);
}


void zombie_stack_netstat(int id, void *arg)
{
  dump_stack_args args;

  args.stack_id = id;
  args.orphan_only = 1;
  args.op = __CI_DEBUG_OP_NETSTAT_STACK__;

  dump_kernel_stats_via_buffer(id, &args);
}


void zombie_stack_kill(int id, void *arg)
{
  int rc;
  oo_fd fd;
  
  CI_TRY(oo_fd_open(&fd));
  rc = oo_debug_kill_stack(fd, id);
  CI_TRY(oo_fd_close(fd));
  
  switch( -rc ) {
  case 0:
    /* Success. */
    ci_log("Orphan stack %d state killed", id);
    break;
  case EPERM:
    ci_log("Permission denied - please run as root to access orphan stacks");
    break;
  default:
    ci_log("No such orphan stack %d (error %d)\n", id, -rc);
  }
}


void zombie_stack_lots(int id, void *arg)
{
  int i = 0;
  dump_stack_args args;
  args.stack_id = id;
  args.orphan_only = 1;

  int ops[] = { __CI_DEBUG_OP_NETIF_DUMP__,  __CI_DEBUG_OP_NETIF_DUMP_EXTRA__,
                __CI_DEBUG_OP_DUMP_SOCKETS__, __CI_DEBUG_OP_STACK_STATS__,
                __CI_DEBUG_OP_STACK_MORE_STATS__, __CI_DEBUG_OP_IP_STATS__,
                __CI_DEBUG_OP_TCP_STATS__, __CI_DEBUG_OP_TCP_EXT_STATS__,
                __CI_DEBUG_OP_UDP_STATS__,
                __CI_DEBUG_OP_NETIF_CONFIG_OPTS_DUMP__,
                __CI_DEBUG_OP_STACK_TIME__ };

  for( i = 0; i < sizeof(ops) / sizeof(ops[0]); ++i ) {
    args.op = ops[i];
    dump_kernel_stats_via_buffer(id, &args);
  }
}
#endif


static void stack_dump(ci_netif* ni)
{
  ci_netif_state* ns = ni->state;
  unsigned id;

  ci_log("============================================================");
  ci_netif_dump(ni);
  ci_log("--------------------- sockets ------------------------------");

  for( id = 0; id < ns->n_ep_bufs; ++id ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, id);
    if( wo->waitable.state != CI_TCP_STATE_FREE &&
        sockbuf_filter_matches(&sft, wo) ) {
      citp_waitable_dump_to_logger(ni, &wo->waitable, "",
                                   ci_log_dump_fn, NULL);
      ci_log_dump_fn(NULL,
              "------------------------------------------------------------");
    }
  }
}

static void stack_netif(ci_netif* ni)
{
  ci_netif_dump(ni);
}


#if ! CI_CFG_UL_INTERRUPT_HELPER
static void stack_vi_info(ci_netif* ni)
{
  int rc;
  dump_stack_args args;
  args.stack_id = NI_ID(ni);
  args.orphan_only = 0;
  args.op = __CI_DEBUG_OP_VI_INFO__;

  CI_TRY(oo_fd_open(&args.fp));
  rc = dump_via_buffers(oo_debug_dump_stack, (void *)&args, 0);
  CI_TRY(oo_fd_close(args.fp));

  switch( -rc ) {
  case 0:
    /* Success. */
    break;
  case EPERM:
    ci_log("Permission denied - please run as root to access stacks");
    break;
  case ENOMEM:
    ci_log("Out of memory.");
    break;
  default:
    ci_log("No such stack %d (error %d).", args.stack_id, -rc);
  }
}
#endif


static void stack_netif_extra(ci_netif* ni)
{
  ci_netif_dump_extra(ni);
}


static void stack_netstat(ci_netif* ni)
{
  ci_netif_print_sockets(ni);
}

static void stack_dmaq(ci_netif* ni)
{
  ci_netif_dump_dmaq(ni, cfg_dump);
}

static void stack_timeoutq(ci_netif* ni)
{
  ci_netif_dump_timeoutq(ni);
}

static void stack_opts(ci_netif* ni)
{
  ci_log("ci_netif_config_opts_dump: %d", NI_ID(ni));
  ci_netif_config_opts_dump(&NI_OPTS(ni), NULL, NULL);
}

static void stack_stats(ci_netif* ni)
{
  ci_netif_stats stats;
  memcpy(&stats, &ni->state->stats, sizeof(ci_netif_stats));
  ci_log("-------------------- ci_netif_stats: %d ---------------------",
         NI_ID(ni));
  ci_dump_stats(netif_stats_fields, N_NETIF_STATS_FIELDS, &stats, 0, NULL,
                NULL);
}

static void stack_stats_describe(ci_netif* ni)
{
  ci_netif_stats stats;
  memcpy(&stats, &ni->state->stats, sizeof(ci_netif_stats));
  ci_log("-------------------- ci_netif_stats: %d ---------------------",
         NI_ID(ni));
  ci_dump_stats(netif_stats_fields, N_NETIF_STATS_FIELDS, &stats, 1, NULL,
                NULL);
}

static void stack_clear_stats(ci_netif* ni)
{
  clear_stats(netif_stats_fields, N_NETIF_STATS_FIELDS, &ni->state->stats);
}

static void stack_dstats(ci_netif* ni)
{
  dstats_t stats;
  get_dstats(&stats, &ni->state->stats, sizeof(stats));
  ci_log("-------------------- ci_netif_stats: %d ---------------------",
         NI_ID(ni));
  ci_dump_stats(netif_dstats_fields, N_NETIF_DSTATS_FIELDS, &stats, 0, NULL,
                NULL);
}

static void stack_more_stats(ci_netif* ni)
{
  more_stats_t stats;
  get_more_stats(ni, &stats);
  ci_log("-------------------- more_stats: %d -------------------------",
         NI_ID(ni));
  ci_dump_stats(more_stats_fields, N_MORE_STATS_FIELDS, &stats, 0, NULL, NULL);
}

static void stack_more_stats_describe(ci_netif* ni)
{
  more_stats_t stats;
  get_more_stats(ni, &stats);
  ci_log("-------------------- more_stats: %d -------------------------",
         NI_ID(ni));
  ci_dump_stats(more_stats_fields, N_MORE_STATS_FIELDS, &stats, 1, NULL, NULL);
}

#if CI_CFG_SUPPORT_STATS_COLLECTION

static void stack_ip_stats(ci_netif* ni)
{
  ci_ip_stats_count stats;
  memcpy(&stats, &ni->state->stats_snapshot.ip, sizeof(stats));
  ci_log("--------------------- ci_ip_stats: %d -----------------------",
         NI_ID(ni));
  ci_dump_stats(ip_stats_fields, N_IP_STATS_FIELDS, &stats, 0, NULL, NULL);
}

static void stack_ip_stats_describe(ci_netif* ni)
{
  ci_ip_stats_count stats;
  memcpy(&stats, &ni->state->stats_snapshot.ip, sizeof(stats));
  ci_log("--------------------- ci_ip_stats: %d -----------------------",
         NI_ID(ni));
  ci_dump_stats(ip_stats_fields, N_IP_STATS_FIELDS, &stats, 1, NULL, NULL);
}

static void stack_tcp_stats(ci_netif* ni)
{
  ci_tcp_stats_count stats;
  memcpy(&stats, &ni->state->stats_snapshot.tcp, sizeof(stats));
  ci_log("-------------------- ci_tcp_stats: %d -----------------------",
         NI_ID(ni));
  ci_dump_stats(tcp_stats_fields, N_TCP_STATS_FIELDS, &stats, 0, NULL, NULL);
}

static void stack_tcp_stats_describe(ci_netif* ni)
{
  ci_tcp_stats_count stats;
  memcpy(&stats, &ni->state->stats_snapshot.tcp, sizeof(stats));
  ci_log("-------------------- ci_tcp_stats: %d -----------------------",
         NI_ID(ni));
  ci_dump_stats(tcp_stats_fields, N_TCP_STATS_FIELDS, &stats, 1, NULL, NULL);
}

static void stack_tcp_ext_stats(ci_netif* ni)
{
  ci_tcp_ext_stats_count stats;
  memcpy(&stats, &ni->state->stats_snapshot.tcp_ext, sizeof(stats));
  ci_log("-------------------- ci_tcp_ext_stats: %d -------------------",
         NI_ID(ni));
  ci_dump_stats(tcp_ext_stats_fields, N_TCP_EXT_STATS_FIELDS, &stats, 0, NULL,
                NULL);
}

static void stack_tcp_ext_stats_describe(ci_netif* ni)
{
  ci_tcp_ext_stats_count stats;
  memcpy(&stats, &ni->state->stats_snapshot.tcp_ext, sizeof(stats));
  ci_log("-------------------- ci_tcp_ext_stats: %d -------------------",
         NI_ID(ni));
  ci_dump_stats(tcp_ext_stats_fields, N_TCP_EXT_STATS_FIELDS, &stats, 1, NULL,
                NULL);
}

static void stack_udp_stats(ci_netif* ni)
{
  ci_udp_stats_count stats;
  memcpy(&stats, &ni->state->stats_snapshot.udp, sizeof(stats));
  ci_log("-------------------- ci_udp_stats: %d -----------------------",
         NI_ID(ni));
  ci_dump_stats(udp_stats_fields, N_UDP_STATS_FIELDS, &stats, 0, NULL, NULL);
}

static void stack_udp_stats_describe(ci_netif* ni)
{
  ci_udp_stats_count stats;
  memcpy(&stats, &ni->state->stats_snapshot.udp, sizeof(stats));
  ci_log("-------------------- ci_udp_stats: %d -----------------------",
         NI_ID(ni));
  ci_dump_stats(udp_stats_fields, N_UDP_STATS_FIELDS, &stats, 1, NULL, NULL);
}

static void stack_watch_ip_stats(ci_netif* ni)
{
  watch_stats(ip_stats_fields, N_IP_STATS_FIELDS, sizeof(ci_ip_stats_count),
              &ni->state->stats_snapshot.ip, memcpy);
}

static void stack_watch_tcp_stats(ci_netif* ni)
{
  watch_stats(tcp_stats_fields, N_TCP_STATS_FIELDS, sizeof(ci_tcp_stats_count),
              &ni->state->stats_snapshot.tcp, memcpy);
}

static void stack_watch_tcp_ext_stats(ci_netif* ni)
{
  watch_stats(tcp_ext_stats_fields, N_TCP_EXT_STATS_FIELDS,
              sizeof(ci_tcp_ext_stats_count),
              &ni->state->stats_snapshot.tcp_ext, memcpy);
}

#endif

static void stack_analyse(ci_netif* ni)
{
  int i, n_samples = 100000000;
  int locked = 0;
  int contended = 0;
  int deferred = 0;
  int primed_any = 0;
  int primed_all = 0;
  int spinner = 0;

  for( i = 0; i < n_samples; ++i ) {
    if( ci_netif_is_locked(ni) )
      ++locked;
    if( ni->state->lock.lock & CI_EPLOCK_FL_NEED_WAKE )
      ++contended;
    if( ni->state->lock.lock & CI_EPLOCK_NETIF_SOCKET_LIST )
      ++deferred;
    if( ci_netif_is_primed(ni) )
      ++primed_all;
    if( ni->state->evq_primed != 0 )
      ++primed_any;
    if( ci_netif_is_spinner(ni) )
      ++spinner;
  }

#undef r
#define r(nm)  ci_log("%-20s: %5.01f%%", #nm, nm * 100.0 / n_samples)
  r(locked);
  r(contended);
  r(deferred);
  r(primed_any);
  r(primed_all);
  r(spinner);
#undef r
}

static void stack_packets(ci_netif* ni)
{
  int unlock;
  if( try_grab_stack_lock(ni, &unlock) )
    ci_netif_pkt_dump_all(ni);
  if( unlock )
    libstack_netif_unlock(ni);
}

static void stack_time(ci_netif* ni)
{
  ci_stack_time_dump(ni, NULL, NULL);
}

static void stack_time_init(ci_netif* ni)
{
  ci_ip_timer_state* ipts = IPTIMER_STATE(ni);
  ipts->ci_ip_time_ms2tick_fxp =
    (((ci_uint64)ipts->khz) << 32) /
    (1u << ipts->ci_ip_time_frc2tick);
}

static void stack_timers(ci_netif* ni)
{
  ci_ip_timer_state_dump(ni);
}

static void stack_filter_table(ci_netif* ni)
{
  ci_netif_filter_dump(ni);
}

static void stack_filters(ci_netif* ni)
{
  filter_dump_args args = {ci_netif_get_driver_handle(ni), OO_SP_NULL};
  dump_via_buffers(ci_tcp_helper_ep_filter_dump, &args, DVB_LOG_FAILURE);
}

#if CI_CFG_ENDPOINT_MOVE
static void stack_clusters(ci_netif* ni)
{
  cluster_dump_args args = {ci_netif_get_driver_handle(ni)};
  dump_via_buffers(ci_tcp_helper_cluster_dump, &args, DVB_LOG_FAILURE);
}
#endif

static void stack_qs(ci_netif* ni)
{
  int unlock;
  if( try_grab_stack_lock(ni, &unlock) )
    for_each_tcp_socket(ni, dump_sock_qs);
  if( unlock )
    libstack_netif_unlock(ni);
}

static void stack_lock(ci_netif* ni)
{
  if( cfg_lock )
    ci_log("%s: already locked due to --lock option", __FUNCTION__);
  else
    libstack_netif_lock(ni);
}

static void stack_lock_flags(ci_netif* ni)
{
  libstack_netif_lock(ni);
  ef_eplock_holder_set_flags(&ni->state->lock, arg_u[0]);
}

static void stack_trylock(ci_netif* ni)
{
  if( ! libstack_netif_trylock(ni) )
    ci_log("%s: [%d] failed", __FUNCTION__, NI_ID(ni));
}

static void stack_unlock(ci_netif* ni)
{
  if( cfg_lock )
    ci_log("%s: refusing due to --lock option", __FUNCTION__);
  else if( ! ef_eplock_is_locked(&ni->state->lock) )
    ci_log("%s: ERROR: stack %d not locked", __FUNCTION__, NI_ID(ni));
  else
    libstack_netif_unlock(ni);
}

static void stack_netif_unlock(ci_netif* ni)
{
  if( cfg_lock )
    ci_log("stupid");
  else {
    if( ! ci_netif_is_locked(ni) )
      ci_log("%d: not locked", NI_ID(ni));
    else
      libstack_netif_unlock(ni);
  }
}

static void stack_lock_force_wake(ci_netif* ni)
{
  ci_uint64 v;
  if( ! cfg_lock )  libstack_netif_lock(ni);
  do
    v = ni->state->lock.lock;
  while( ci_cas64u_fail(&ni->state->lock.lock,v,v|CI_EPLOCK_FL_NEED_WAKE) );
  if( ! cfg_lock )  libstack_netif_unlock(ni);
}

static void stack_poll(ci_netif* ni)
{
  int unlock = 0;
  if( try_grab_stack_lock(ni, &unlock) ) {
    int rc = ci_netif_poll(ni);
    if( unlock )  libstack_netif_unlock(ni);
    ci_log("%d: ci_netif_poll: rc=%d", NI_ID(ni), rc);
  }
}

static void stack_poll_nolock(ci_netif* ni)
{
  int rc = ci_netif_poll(ni);
  ci_log("%s: [%d] ci_netif_poll: rc=%d", __FUNCTION__, NI_ID(ni), rc);
}

static void stack_spin_poll(ci_netif* ni)
{
  ci_uint64 now_frc;
  ci_log("%s: [%d]", __FUNCTION__, NI_ID(ni));
  while( 1 ) {
    ci_frc64(&now_frc);
    if( ci_netif_need_poll_spinning(ni, now_frc) ) {
      if( ci_netif_trylock(ni) ) {
        ci_netif_poll(ni);
        libstack_netif_unlock(ni);
      }
    }
    else if( ! ni->state->is_spinner )
      ni->state->is_spinner = 1;
    ci_spinloop_pause();
  }
}

static void stack_prime(ci_netif* ni)
{
  int rc;
  citp_signal_info* si = citp_signal_get_specific_inited();
  libstack_defer_signals(si);
  rc = ef_eplock_lock_or_set_single_flag(&ni->state->lock,
                                         CI_EPLOCK_NETIF_NEED_PRIME);
  if( rc ) {
    ef_eplock_holder_set_single_flag(&ni->state->lock,
                                     CI_EPLOCK_NETIF_NEED_PRIME);
    libstack_netif_unlock(ni);
  }
  else
    libstack_process_signals(si);
}

static void stack_reset_primed(ci_netif* ni)
{
  stack_lock(ni);
  ni->state->evq_primed = 0;
  stack_unlock(ni);
}

static void stack_wake(ci_netif* ni)
{
  int unlock;
  if( try_grab_stack_lock(ni, &unlock) ) {
    int rc_wake;
    rc_wake = ci_netif_force_wake(ni, 0);
    if( unlock )  libstack_netif_unlock(ni);
    ci_log("%d: ci_netif_force_wake: rc=%d", NI_ID(ni), rc_wake);
  }
}

static void stack_wakeall(ci_netif* ni)
{
  int unlock;
  if( try_grab_stack_lock(ni, &unlock) ) {
    int rc_wake;
    rc_wake = ci_netif_force_wake(ni, 1);
    if( unlock )  libstack_netif_unlock(ni);
    ci_log("%d: ci_netif_force_wake: rc=%d", NI_ID(ni), rc_wake);
  }
}

static void stack_rxpost(ci_netif* ni)
{
  ci_uint32 nic_index = CI_DEFAULT_NIC; /* TODO: support multiple NICs */
  int unlock;
  if( try_grab_stack_lock(ni, &unlock) ) {
    ci_netif_rx_post_all_batch(ni, nic_index);
    if( unlock )  libstack_netif_unlock(ni);
    ci_log("%d: ci_netif_rx_post", NI_ID(ni));
  }
}


static void stack_sizeof(ci_netif* ni)
{
# define log_sizeof(x)  ci_log("%30s: %d", #x, (int) sizeof(x))
  log_sizeof(ci_netif);
  log_sizeof(ci_netif_state);
  log_sizeof(ci_netif_config);
  log_sizeof(ci_netif_config_opts);
  log_sizeof(ci_netif_ipid_cb_t);
  log_sizeof(ci_netif_filter_table_entry_fast);
  log_sizeof(ci_netif_filter_table_entry_ext);
  log_sizeof(ci_netif_filter_table);
  log_sizeof(ci_ip_cached_hdrs);
  log_sizeof(ci_ip_timer);
  log_sizeof(ci_ip_timer_state);
  log_sizeof(citp_waitable);
  log_sizeof(citp_waitable_obj);
  log_sizeof(ci_sock_cmn);
  log_sizeof(ci_tcp_state);
  log_sizeof(ci_tcp_socket_cmn);
  log_sizeof(ci_tcp_state_synrecv);
  log_sizeof(ci_tcp_socket_listen);
  log_sizeof(ci_tcp_socket_listen_stats);
  log_sizeof(ci_tcp_options);
  log_sizeof(ci_udp_state);
  log_sizeof(ci_udp_socket_stats);
  log_sizeof(struct oo_pipe);
  log_sizeof(struct oo_ep_header);
  log_sizeof(struct oo_sock_cplane);
  log_sizeof(ci_active_wild);
  log_sizeof(ci_netif_stats);
  log_sizeof(ci_ip_pkt_fmt);
  log_sizeof(ci_ip_pkt_fmt_prefix);
  log_sizeof(ci_ip_sock_stats);
  log_sizeof(ci_ip_sock_stats_count);
  log_sizeof(ci_ip_sock_stats_range);
}

static void stack_leak_pkts(ci_netif* ni)
{
  int unlock;
  if( try_grab_stack_lock(ni, &unlock) ) {
    int i;
    for( i = 0; i < (int)arg_u[0]; ++i ) {
      ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(ni, 0);
      if( ! pkt )  break;
      if( ci_cfg_verbose )
	ci_log("%d: leaked pkt %d", NI_ID(ni), OO_PKT_FMT(pkt));
    }
    if( unlock )  libstack_netif_unlock(ni);
    ci_log("%d: leaked %d packet buffers", NI_ID(ni), i);
  }
}

static void stack_alloc_pkts(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pp = OO_PP_NULL;
  int i;
  if( ! cfg_lock )  libstack_netif_lock(ni);
  for( i = 0; i < (int) arg_u[0]; ++i ) {
    pkt = ci_netif_pkt_alloc(ni, 0);
    if( pkt == NULL ) {
      ci_log("%d: allocated %d buffers", NI_ID(ni), i);
      break;
    }
    pkt->next = pp;
    pp = OO_PKT_P(pkt);
  }
  while( OO_PP_NOT_NULL(pp) ) {
    pkt = PKT_CHK(ni, pp);
    pp = pkt->next;
    ci_netif_pkt_release(ni, pkt);
  }
  if( ! cfg_lock )  libstack_netif_unlock(ni);
}

static void stack_alloc_pkts_hold(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pp = OO_PP_NULL;
  int i;
  if( ! cfg_lock )  libstack_netif_lock(ni);
  for( i = 0; i < (int) arg_u[0]; ++i ) {
    pkt = ci_netif_pkt_alloc(ni, 0);
    if( pkt == NULL ) {
      ci_log("%d: allocated %d buffers", NI_ID(ni), i);
      break;
    }
    pkt->next = pp;
    pp = OO_PKT_P(pkt);
  }
  if( 1 ) {
    libstack_netif_unlock(ni);
    while( ! signal_fired )
      sleep(1000);
    libstack_netif_lock(ni);
  }
  while( OO_PP_NOT_NULL(pp) ) {
    pkt = PKT_CHK(ni, pp);
    pp = pkt->next;
    ci_netif_pkt_release(ni, pkt);
  }
  if( ! cfg_lock )  libstack_netif_unlock(ni);
}

static void stack_alloc_pkts_block(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pp = OO_PP_NULL;
  int i, locked = cfg_lock;
  int rc;

  for( i = 0; i < (int) arg_u[0]; ++i ) {
    rc = ci_netif_pkt_alloc_block(ni, NULL, &locked, CI_TRUE, &pkt);
    if( rc != 0 ) {
      ci_log("%d: allocated %d buffers, rc=%d", NI_ID(ni), i, rc);
      break;
    }
    pkt->next = pp;
    pp = OO_PKT_P(pkt);
  }
  if( ! locked ) {
    libstack_netif_lock(ni);
    locked = 1;
  }
  ni->state->n_async_pkts -= i;
  while( OO_PP_NOT_NULL(pp) ) {
    pkt = PKT_CHK(ni, pp);
    pp = pkt->next;
    ci_netif_pkt_release(ni, pkt);
  }
  if( ! cfg_lock )
    libstack_netif_unlock(ni);
}

static void stack_nonb_pkt_pool_n(ci_netif* ni)
{
  volatile ci_uint64 *nonb_pkt_pool_ptr;
  ci_uint64 link;
  unsigned id, n, n_async_pkts;
  ci_ip_pkt_fmt* pkt;
  oo_pkt_p pp;

  nonb_pkt_pool_ptr = &(ni->state->nonb_pkt_pool);
 again:
  n_async_pkts = ni->state->n_async_pkts;
  link = *nonb_pkt_pool_ptr;
  id = link & 0xffffffff;
  if( id != 0xffffffff ) {
    if( ci_cas64u_fail(nonb_pkt_pool_ptr, link,
                       0x00000000ffffffffllu | (link & 0xffffffff00000000llu)) )
      goto again;
    OO_PP_INIT(ni, pp, id);
    pkt = PKT(ni, pp);
    n = 0;
    while( 1 ) {
      ++n;
      if( OO_PP_IS_NULL(pkt->next) )
        break;
      pkt = PKT(ni, pkt->next);
    }
    ci_netif_pkt_free_nonb_list(ni, id, pkt);
  }
  else {
    n = 0;
  }
  ci_log("%s: [%d] n_async_pkts=%d nonb_pkt_pool_n=%d", __FUNCTION__,
         NI_ID(ni), n_async_pkts, n);
}

static void stack_alloc_nonb_pkts(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  int n = 0, n_from_nonb;
  oo_pkt_p pp;
  oo_pkt_p* ppi = &pp;
  int n_to_alloc = arg_u[0];
  for( ; n < n_to_alloc; ++n ) {
    if( (pkt = ci_netif_pkt_alloc_nonb(ni)) == NULL )
      break;
    pkt->refcount = 0;
    __ci_netif_pkt_clean(pkt);
    *ppi = OO_PKT_P(pkt);
    ppi = &pkt->next;
  }
  n_from_nonb = n;
  if( n < n_to_alloc ) {
    if( ! cfg_lock )
      libstack_netif_lock(ni);
    for( ; n < n_to_alloc; ++n ) {
      if( (pkt = ci_netif_pkt_alloc(ni, 0)) == NULL )
        break;
      pkt->refcount = 0;
      __ci_netif_pkt_clean(pkt);
      *ppi = OO_PKT_P(pkt);
      ppi = &pkt->next;
    }
    ni->state->n_async_pkts += n - n_from_nonb;
    if( ! cfg_lock )
      libstack_netif_unlock(ni);
  }
  if( n != 0 )
    ci_netif_pkt_free_nonb_list(ni, pp, CI_CONTAINER(ci_ip_pkt_fmt,next,ppi));
  ci_log("%s: [%d] put %d on nonb-pool (was %d)", __FUNCTION__, NI_ID(ni),
         n, n_from_nonb);
}

static void stack_nonb_thrash(ci_netif* ni)
{
  ci_ip_pkt_fmt* pkt;
  int i, iter = arg_u[0];
  int n = 0;

  {
    ci_ip_pkt_fmt p;
    ci_uint64 link = 0;
    ci_uint64 u;
    p.next = (ci_int32) 0xffffffff;
    u = ((unsigned)OO_PP_ID(p.next)) | (link & 0xffffffff00000000llu);
    ci_log("u=%"CI_PRIx64, u);
    exit(1);
  }

  for( i = 0; i < iter; ++i ) {
    pkt = ci_netif_pkt_alloc_nonb(ni);
    if( pkt != NULL ) {
      pkt->refcount = 0;
      __ci_netif_pkt_clean(pkt);
      ci_netif_pkt_free_nonb_list(ni, OO_PKT_P(pkt), pkt);
      ++n;
    }
  }
  ci_log("%s: [%d] iter=%d n=%d", __FUNCTION__, NI_ID(ni), iter, n);
}

static void stack_txpkt(ci_netif* ni)
{
  int pkt_id = arg_u[0];
  if( IS_VALID_PKT_ID(ni, pkt_id) ) {
    ci_ip_pkt_fmt* pkt = __PKT(ni, pkt_id);
    ci_tcp_pkt_dump(ni, pkt, 0, 0);
  }
  else
    ci_log("%d: bad pkt=%d", NI_ID(ni), pkt_id);
}

static void stack_rxpkt(ci_netif* ni)
{
  int pkt_id = arg_u[0];
  if( IS_VALID_PKT_ID(ni, pkt_id) ) {
    ci_ip_pkt_fmt* pkt = __PKT(ni, pkt_id);
    ci_tcp_pkt_dump(ni, pkt, 1, 0);
  }
  else
    ci_log("%d: bad pkt=%d", NI_ID(ni), pkt_id);
}

static void stack_segments(ci_netif* ni)
{
  int i, pkt_id = arg_u[0];
  oo_pkt_p buf;
  if( IS_VALID_PKT_ID(ni, pkt_id) ) {
    ci_ip_pkt_fmt* pkt = __PKT(ni, pkt_id);
    ci_log("%d: pkt=%d n_buffers=%d", NI_ID(ni), pkt_id, pkt->n_buffers);
    buf = OO_PKT_P(pkt);
    for( i = 0; i < pkt->n_buffers; ++i ) {
      ci_ip_pkt_fmt* apkt = PKT_CHK(ni, buf);
      ci_log("  %d: "EF_ADDR_FMT":%d", i, pkt_dma_addr(ni, apkt, pkt->intf_i),
             apkt->buf_len);
      buf = apkt->frag_next;
    }
  }
  else
    ci_log("%d: bad pkt=%d", NI_ID(ni), pkt_id);
}

static void stack_ev(ci_netif* ni)
{
  int rc = ef_eventq_put(ef_vi_resource_id(ci_netif_vi(ni, 0)), 
			 ci_netif_get_driver_handle(ni), 0xff);
  ci_log("%d: ef_eventq_put: rc=%d", NI_ID(ni), rc);
}

static void stack_ul_poll(ci_netif* ni)
{
  int i;

  NI_OPTS(ni).spin_usec = arg_u[0];
  ni->state->sock_spin_cycles =
                    oo_usec_to_cycles64(ni, NI_OPTS(ni).spin_usec);

  /* Update spin value for each socket */
  for( i = 0; i < (int)ni->state->n_ep_bufs; ++i ) {
    citp_waitable_obj* wo = SP_TO_WAITABLE_OBJ(ni, i);
    if( wo->waitable.state != CI_TCP_STATE_FREE )
      wo->waitable.spin_cycles =  ni->state->sock_spin_cycles;
  }
}

static void stack_timer_timeout(ci_netif* ni)
{
  NI_OPTS(ni).timer_usec = arg_u[0];
}

static void stack_timer_prime(ci_netif* ni)
{
  NI_OPTS(ni).timer_prime_usec = arg_u[0];
  ni->state->timer_prime_cycles =
    oo_usec_to_cycles64(ni, NI_OPTS(ni).timer_prime_usec);
}

#if CI_CFG_RANDOM_DROP
static void stack_rxdroprate(ci_netif* ni)
{
  NI_OPTS(ni).rx_drop_rate = arg_u[0]? RAND_MAX/arg_u[0] : 0;
}
#endif

static void stack_tcp_rx_checks(ci_netif* ni)
{
  NI_OPTS(ni).tcp_rx_checks = arg_u[0];
}

static void stack_tcp_rx_log_flags(ci_netif* ni)
{
  NI_OPTS(ni).tcp_rx_log_flags = arg_u[0];
}

static void stack_watch_stats(ci_netif* ni)
{
  watch_stats(netif_stats_fields, N_NETIF_STATS_FIELDS, sizeof(ci_netif_stats),
              &ni->state->stats, memcpy);
}

static void stack_watch_more_stats(ci_netif* ni)
{
  watch_stats(more_stats_fields, N_MORE_STATS_FIELDS, sizeof(more_stats_t),
              ni, more_stats_getter);
}

static void stack_set_opt(ci_netif* ni)
{
  const char* opt_name = arg_s[0];

#undef CI_CFG_OPTFILE_VERSION
#undef CI_CFG_OPT
#undef CI_CFG_STR_OPT
#undef CI_CFG_OPTGROUP
#define CI_CFG_OPT(env, name, type, doc, bits, group, default, min, max, pres) \
    if( ! strcmp(opt_name, #name) ) {                                   \
      unsigned opt_val;                                                 \
      char dummy;                                                       \
      if( sscanf(arg_s[1], " %u %c", &opt_val, &dummy) != 1 ) {         \
        ci_log("Bad argument to '%s' (expected unsigned)", opt_name);   \
      }                                                                 \
      NI_OPTS(ni).name = opt_val;                                       \
      return;                                                           \
    }
#define CI_CFG_STR_OPT(env, name, type, doc, bits, group, default, min, max, pres) \
    if( ! strcmp(opt_name, #name) ) {                                   \
      if( strlen(arg_s[1]) < sizeof(type) ) {                           \
        ci_log("Bad argument to '%s' (string too long)", opt_name);     \
      }                                                                 \
      strcpy(NI_OPTS(ni).name, arg_s[1]);                               \
      return;                                                           \
    }
#include <ci/internal/opts_netif_def.h>

  ci_log("unknown option: %s", opt_name);
}

static void stack_get_opt(ci_netif* ni)
{
  const char* opt_name = arg_s[0];

#undef CI_CFG_OPTFILE_VERSION
#undef CI_CFG_OPT
#undef CI_CFG_STR_OPT
#undef CI_CFG_OPTGROUP
#define CI_CFG_OPT(env, name, type, doc, bits, group, default, min, max, pres) \
    if( ! strcmp(opt_name, #name) ) {                                     \
      ci_log("[%d] %s: %d", NI_ID(ni), opt_name, (int) NI_OPTS(ni).name); \
      return;                                                             \
    }
#define CI_CFG_STR_OPT(env, name, type, doc, bits, group, default, min, max, pres) \
    if( ! strcmp(opt_name, #name) ) {                                     \
      ci_log("[%d] %s: %s", NI_ID(ni), opt_name, NI_OPTS(ni).name);       \
      return;                                                             \
    }
#include <ci/internal/opts_netif_def.h>

  ci_log("unknown option: %s", opt_name);
}

static void stack_set_rxq_limit(ci_netif* ni)
{
  ni->state->rxq_limit = arg_u[0];
}

static void process_dump(ci_netif* ni)
{
  char task_path[MAX_PATHNAME];
  char buf[MAX_PATHNAME];
  struct stack_mapping* sm = stack_mappings;
    
  if( cfg_nopids ){ //pid mappings not available
    ci_log("No environment state as --nopids set on command line");
    return;
  }

  int stack_id = NI_ID(ni);

  while( sm && sm->stack_id != stack_id )
    sm = sm->next;
  if( sm == NULL ) {
    ci_log_nonl("No stack_mapping for stack %d found", stack_id);
    return;
  }
  
  int i, pid;
  for( i = 0; i < sm->n_pids; ++i ) {
    pid = sm->pids[i];
    ci_log("--------------------------------------------");
    snprintf(task_path, MAX_PATHNAME, "/proc/%d/task", pid);
    DIR* task_dir = opendir(task_path);
    /* We treat failure to open the pid dir as non-fatal, as this legitimately
     * occurs if the process exited since we learned about it. */
    if ( task_dir == NULL ) {
      ci_log("failed reading /proc/%d/task directory. error: %s", pid, strerror(errno));
      continue;
    }
    struct dirent* ent;

    while( (ent = readdir(task_dir)) ) {
      if( ent->d_name[0] == '.' )
        continue;

      ci_log_nonl("PID: %d Thread: %s", (int) sm->pids[i], ent->d_name);
      char file_path[MAX_PATHNAME];
      snprintf(file_path, MAX_PATHNAME, "/proc/%d/task/%s/status",(int) sm->pids[i], ent->d_name);
      /* open the command line */
      FILE* status = fopen(file_path, "r");
      /* check if fopen succeeded */
      if ( status == NULL ) {
        ci_log("failed reading the /proc/%d/task/%s/status file. error: %s",(int) sm->pids[i], ent->d_name, strerror(errno));
        continue;
      }
      char line[1024];
      char values[3][256];
      char labels[][256] = {
        "Cpus_allowed:",
        "voluntary_ctxt_switches:",
        "nonvoluntary_ctxt_switches:"
      };

      int j;
      /* check each line in the file */
      while( fgets(line, sizeof(line), status) != NULL ) {
        /* we're looking for three counters */
        for( j = 0; j < 3; j++ ) {
          int len = strlen(labels[j]);
          /* find the required counter */
          if( strncmp(line, labels[j], len) == 0 ) {
            char *tmp = line + len;
            /* remove the first character. 
            ** output of counters in /proc/pid/task/pid/status (from source code) 
            ** contains /t character as the first character. */
            tmp++;
            /* remove newline and print */
            tmp[strcspn(tmp, "\n")] = '\0';
            /* Copy the counter values in array and later print them */
            strncpy(values[j], tmp, (sizeof(tmp)-1));
            /* extra safety: terminating the string */
            values[i][sizeof(values[j]) - 1] = 0;
          }
        }
      }
      ci_log_nonl(" Cpus_allowed: %s voluntary_ctxt_switches: %s nonvoluntary_ctxt_switches: %s",values[0],values[1],values[2]);
      fclose(status);
      /* read /proc/pid/task/pid/stat */
      snprintf(file_path, MAX_PATHNAME, "/proc/%d/task/%s/stat",(int) sm->pids[i], ent->d_name);
      int stat = open(file_path, O_RDONLY);
      /* check if open succeeded */
      if ( stat == -1 ) {
        ci_log("failed reading /proc/%d/task/%s/stat file. error: %s",(int) sm->pids[i], ent->d_name,strerror(errno));
        continue;
      }
      long cnt = read(stat, buf, MAX_PATHNAME);
      close(stat);

      while( cnt > 0 && (buf[cnt-1] != ')') ) {
        cnt--;
      }
      /* get the values for priority and realtime for the threads */
      if( get_int_from_tok_str(&buf[cnt], " ", 15, &cnt) ) { 
        if( cnt < 0 ) {
          ci_log_nonl(" priority: %ld realtime: 1\n", (-cnt)-1 );
        }    
        else {
          ci_log_nonl(" priority: %ld realtime: 0\n", cnt-20 );
        }
      }
      else {
        ci_log_nonl("priority: N/A realtime: N/A");
      }
    }
    closedir(task_dir);
    
    libstack_pid_env_print(pid);
  }
  ci_log("--------------------------------------------");
}


static void stack_universe(ci_netif* ni)
{
  if(universe_print_once == 1){
    ci_log("--------------------- Filters output  ------------------------------");
    ci_netif_filter_dump(ni);
    filter_dump_args args = {ci_netif_get_driver_handle(ni), OO_SP_NULL};
    dump_via_buffers(ci_tcp_helper_ep_filter_dump, &args, DVB_LOG_FAILURE);
    universe_print_once = 0;
  }
  ci_log("============================================================");
  ci_netif_dump(ni);
  ci_netif_dump_extra(ni);
  libstack_stack_mapping_print_pids(NI_ID(ni));
  ci_log("--------------------- sockets ------------------------------");
  ci_netif_dump_sockets(ni);
  stack_stats(ni);
  stack_more_stats(ni);

#if CI_CFG_SUPPORT_STATS_COLLECTION
  stack_ip_stats(ni);
  stack_tcp_stats(ni);
  stack_tcp_ext_stats(ni);
  stack_udp_stats(ni);
#endif
  
  ci_log("--------------------- vi stats ------------------------------");
  ci_netif_dump_vi_stats(ni);
  ci_log("--------------------- config opts --------------------------");
  ci_netif_config_opts_dump(&NI_OPTS(ni), NULL, NULL);
  ci_log("--------------------- stack time ---------------------------");
  stack_time(ni);
  ci_log("--------------------- process env --------------------------");
  process_dump(ni);
}

static void stack_lots(ci_netif* ni)
{
  ci_log("============================================================");
  ci_netif_dump(ni);
  ci_netif_dump_extra(ni);
  libstack_stack_mapping_print_pids(NI_ID(ni));
  ci_log("--------------------- sockets ------------------------------");
  ci_netif_dump_sockets(ni);
  stack_stats(ni);
  stack_more_stats(ni);

#if CI_CFG_SUPPORT_STATS_COLLECTION
  stack_ip_stats(ni);
  stack_tcp_stats(ni);
  stack_tcp_ext_stats(ni);
  stack_udp_stats(ni);
#endif

  ci_log("--------------------- config opts --------------------------");
  ci_netif_config_opts_dump(&NI_OPTS(ni), NULL, NULL);
  ci_log("--------------------- stack time ---------------------------");
  stack_time(ni);
  ci_log("--------------------- process env --------------------------");
  process_dump(ni);
}

static void stack_describe_stats(ci_netif* ni){
  ci_log("============================================================");
  stack_stats_describe(ni);
  stack_more_stats_describe(ni);

#if CI_CFG_SUPPORT_STATS_COLLECTION
  stack_ip_stats_describe(ni);
  stack_tcp_stats_describe(ni);
  stack_tcp_ext_stats_describe(ni);
  stack_udp_stats_describe(ni);
#endif

}

static void stack_reap_list(ci_netif* ni)
{
  if( ! cfg_lock )  libstack_netif_lock(ni);
  ci_netif_dump_reap_list(ni, 0);
  if( ! cfg_lock )  libstack_netif_unlock(ni);
}

static void stack_reap_list_verbose(ci_netif* ni)
{
  if( ! cfg_lock )  libstack_netif_lock(ni);
  ci_netif_dump_reap_list(ni, 1);
  if( ! cfg_lock )  libstack_netif_unlock(ni);
}

static void stack_pkt_reap(ci_netif* ni)
{
  if( ! cfg_lock )  libstack_netif_lock(ni);
  ci_netif_try_to_reap(ni, 1000000);
  if( ! cfg_lock )  libstack_netif_unlock(ni);
}

static void stack_hwport_to_base_ifindex(ci_netif* ni)
{
  int i;
  for( i = 0; i < CI_CFG_MAX_HWPORTS; ++i )
    ci_log("hwport[%d] ->= %d", i,
           oo_cp_hwport_vlan_to_ifindex(ni->cplane, i, 0, NULL));
}

static void stack_vi_stats(ci_netif* ni)
{
  ci_netif_dump_vi_stats(ni);
}

/**********************************************************************
***********************************************************************
**********************************************************************/

#define STACK_OP_A(nm, help, args, n_args, fl)          \
  { (#nm), (stack_##nm), (NULL), (help), (args), (n_args), (fl) }

#define STACK_OP_AU(nm, h, ah)    STACK_OP_A(nm, (h), (ah), 1, FL_ARG_U)
#define STACK_OP_AX(nm, h, ah)    STACK_OP_A(nm, (h), (ah), 1, FL_ARG_X)
#define STACK_OP_F(nm, help, fl)  STACK_OP_A(nm, (help), NULL, 0, (fl))
#define STACK_OP(nm, help)        STACK_OP_A(nm, (help), NULL, 0, 0)

#if ! CI_CFG_UL_INTERRUPT_HELPER
#define ZOMBIE_STACK_OP(nm, help)           \
  { (#nm), (NULL), (zombie_stack_##nm), (help), (NULL), 0, (FL_ID) }

static const stack_op_t zombie_stack_ops[] = {
  ZOMBIE_STACK_OP(dump, "[requires -z] show core state stack and sockets"),
  ZOMBIE_STACK_OP(kill, "[requires -z] terminate orphan/zombie stack"),
  ZOMBIE_STACK_OP(netstat, "[requires -z] show netstat like output for sockets"),
  ZOMBIE_STACK_OP(lots, "[requires -z] dump state, opts, stats orphan stacks"),
};

#define N_ZOMBIE_STACK_OPS                                     \
  (sizeof(zombie_stack_ops) / sizeof(zombie_stack_ops[0]))
#endif

static const stack_op_t stack_ops[] = {
  STACK_OP(dump,               "show core state of stack and sockets"),
  STACK_OP(netif,              "show core per-stack state"),
#if ! CI_CFG_UL_INTERRUPT_HELPER
  STACK_OP(vi_info,            "show vi information per-stack state"),
#endif
  STACK_OP(netif_extra,        "show extra per-stack state"),
  STACK_OP(netstat,            "show netstat like output for sockets"),
  STACK_OP(dmaq,               "show state of DMA queue"),
  STACK_OP(timeoutq,           "show state of timeout queue"),
  STACK_OP(opts,               "show configuration options"),
  STACK_OP(stats,              "show stack statistics"),
  STACK_OP(describe_stats,     "show stack statistics with description"),
  STACK_OP(clear_stats,        "reset stack statistics"),
  STACK_OP(dstats,             "show derived statistics"),
  STACK_OP(more_stats,         "show more stack statistics"),
#if CI_CFG_SUPPORT_STATS_COLLECTION
  STACK_OP(ip_stats,           "show IP statistics"),
  STACK_OP(tcp_stats,          "show TCP statistics"),
  STACK_OP(tcp_ext_stats,      "show TCP extended stats"),
  STACK_OP(udp_stats,          "show UDP statistics"),
  STACK_OP(watch_ip_stats,     "show running IP stats"),
  STACK_OP(watch_tcp_stats,    "show running TCP stats"),
  STACK_OP(watch_tcp_ext_stats,"show running TCP-ext"),
#endif
  STACK_OP(analyse,            "analyse state over time"),
  STACK_OP(packets,            "show packets queued on netif"),
  STACK_OP(time,               "show stack timers"),
  STACK_OP(time_init,          "(re-)initialize stack timers"),
  STACK_OP(timers,             "dump state of stack timers"),
  STACK_OP(filter_table,       "show stack software filter table"),
  STACK_OP_F(filters,          "show stack hardware filters", FL_ONCE),
#if CI_CFG_ENDPOINT_MOVE
  STACK_OP_F(clusters,         "show clusters", FL_ONCE),
#endif
  STACK_OP(qs,                 "show queues for each socket in stack"),
  STACK_OP(lock,               "lock the stack"),
  STACK_OP_AX(lock_flags,      "lock the stack and set lock flags", "<flags>"),
  STACK_OP(trylock,            "try to lock the stack"),
  STACK_OP(unlock,             "unlock the stack"),
  STACK_OP(netif_unlock,       "unlock the netif"),
  STACK_OP(lock_force_wake,    "force a wake to test lock"),
  STACK_OP(poll,               "poll stack"),
  STACK_OP(poll_nolock,        "poll stack without locking"),
  STACK_OP(spin_poll,          "spin polling stack"),
  STACK_OP(prime,              "prime stack (enable interrupts)"),
  STACK_OP(reset_primed,       "reset evq_primed (should re-enable interrupts)"),
  STACK_OP(wake,               "force wakeup of sleepers"),
  STACK_OP(wakeall,            "force wakeup of everyone"),
  STACK_OP(rxpost,             "refill RX ring"),
  STACK_OP(sizeof,             "sizes of datastructures"),
  STACK_OP(ev,                 "post a h/w event to stack"),
  STACK_OP(watch_stats,        "show running statistics"),
  STACK_OP(watch_more_stats,   "show more statistics"),
  STACK_OP_AU(leak_pkts,       "drain allocation of packet buffers",
                                 "<pkt-id>"),
  STACK_OP_AU(alloc_pkts,      "allocate more pkt buffers", "<num>"),
  STACK_OP_AU(alloc_pkts_hold, "allocate and hold pkts 'till USR1", "<num>"),
  STACK_OP_AU(alloc_pkts_block,"allocate pkt buffers (blocking)", "<num>"),
  STACK_OP(nonb_pkt_pool_n,    "count number of packets in non-blocking pool"),
  STACK_OP_AU(alloc_nonb_pkts, "allocate nonb pkt buffers", "<num>"),
  STACK_OP_AU(nonb_thrash,     "allocate and free nonb pkt buffers", "<num>"),
  STACK_OP_AU(txpkt,           "show content of transmit packet", "<pkt-id>"),
  STACK_OP_AU(rxpkt,           "show content of receive packet", "<pkt-id>"),
  STACK_OP_AU(segments,        "show segments in packet", "<pkt-id>"),
  STACK_OP_AU(ul_poll,         "set user level polling cycles option "
                                 "(overwrites SO_BUSY_POLL values)",
                                 "<cycles>"),
  STACK_OP_AU(timer_timeout,   "set timer timeout option", "<usec>"),
  STACK_OP_AU(timer_prime,     "set timer priming option", "<cycles>"),
#if CI_CFG_RANDOM_DROP
  STACK_OP_AU(rxdroprate,      "set reception drop rate option", "<1-in-n>"),
#endif
  STACK_OP_AX(tcp_rx_checks,   "set reception check bitmap option", "<mask>"),
  STACK_OP_AX(tcp_rx_log_flags,"set reception logging bitmap option","<mask>"),
  STACK_OP_A(set_opt,          "set stack option", "<name> <val>", 2,
             FL_ARG_SV),
  STACK_OP_A(get_opt,          "get stack option", "<name>", 1, FL_ARG_S),
  STACK_OP_AU(set_rxq_limit,   "set the rxq_limit", "<limit>"),
  STACK_OP(lots,               "dump state, opts, stats"),
  STACK_OP(universe,           "filters, vi stats, threads with context switches, dump state, opts, stats"),
  STACK_OP(reap_list,          "dump list of sockets on the reap_list"),
  STACK_OP(reap_list_verbose,  "dump sockets on the reap_list"),
  STACK_OP(pkt_reap,           "reap packet buffers from sockets"),
  STACK_OP(hwport_to_base_ifindex,"dump mapping between hwport and interfaces"),
  STACK_OP(vi_stats,"show per-VI interface stats. (Higher overhead, so only "
           "call occasionally)"),
};
#define N_STACK_OPS	(sizeof(stack_ops) / sizeof(stack_ops[0]))


void for_each_stack_op(stackop_fn_t* fn, void* arg)
{
  const stack_op_t* op;
  for( op = stack_ops; op < stack_ops + N_STACK_OPS; ++op )
    (*fn)(op, arg);
#if ! CI_CFG_UL_INTERRUPT_HELPER
  for( op = zombie_stack_ops; 
       op < zombie_stack_ops + N_ZOMBIE_STACK_OPS;
       ++op )
    (*fn)(op, arg);
#endif
}


const stack_op_t* get_stack_op(const char* name)
{
  const stack_op_t* op;
  const stack_op_t* ops;
  int n;
#if ! CI_CFG_UL_INTERRUPT_HELPER
  if( cfg_zombie ) {
    n = N_ZOMBIE_STACK_OPS;
    ops = zombie_stack_ops;
  } 
  else
#endif
  {
    n = N_STACK_OPS;
    ops = stack_ops;
  }
  for( op = ops; op < ops + n || (op = NULL); ++op )
    if( ! strcmp(op->name, name) )
      break;
  return op;
}


/**********************************************************************
***********************************************************************
**********************************************************************/

static void socket_dump(ci_netif* ni, ci_tcp_state* ts) {
  ci_log("------------------------------------------------------------");
  citp_waitable_dump(ni, &ts->s.b, "");
}

static void socket_qs(ci_netif* ni, ci_tcp_state* ts) {
  ci_log("------------------------------------------------------------");
  ci_tcp_state_dump_qs(ni, S_SP(ts), cfg_dump);
}

static void socket_lock(ci_netif* ni, ci_tcp_state* ts)
{ ci_sock_lock(ni, &ts->s.b); }

static void socket_unlock(ci_netif* ni, ci_tcp_state* ts)
{ ci_sock_unlock(ni, &ts->s.b); }

static void socket_trylock(ci_netif* ni, ci_tcp_state* ts) {
  if( ! ci_sock_trylock(ni, &ts->s.b) )
    ci_log("%d:%d trylock: failed", NI_ID(ni), S_SP(ts));
}

static void socket_filters(ci_netif* ni, ci_tcp_state* ts)
{
  filter_dump_args args = {ci_netif_get_driver_handle(ni), S_SP(ts)};
  dump_via_buffers(ci_tcp_helper_ep_filter_dump, &args, DVB_LOG_FAILURE);
}

static void socket_ul_poll(ci_netif* ni, ci_tcp_state* ts)
{
  ts->s.b.spin_cycles = oo_usec_to_cycles64(ni, arg_u[0]);
}

static void socket_nodelay(ci_netif* ni, ci_tcp_state* ts)
{ ci_bit_set(&ts->s.s_aflags, CI_SOCK_AFLAG_NODELAY_BIT); }

static void socket_nagle(ci_netif* ni, ci_tcp_state* ts)
{ ci_bit_clear(&ts->s.s_aflags, CI_SOCK_AFLAG_NODELAY_BIT); }

static void socket_cork(ci_netif* ni, ci_tcp_state* ts)
{ ci_bit_set(&ts->s.s_aflags, CI_SOCK_AFLAG_CORK_BIT); }

static void socket_uncork(ci_netif* ni, ci_tcp_state* ts)
{ ci_bit_clear(&ts->s.s_aflags, CI_SOCK_AFLAG_CORK_BIT); }

static void socket_advance(ci_netif* ni, ci_tcp_state* ts) {
  if( ! ci_ip_queue_is_empty(&ts->send) )
    ci_tcp_tx_advance(ts, ni);
}

static void socket_ack(ci_netif* ni, ci_tcp_state* ts) {
  ci_ip_pkt_fmt* pkt = ci_netif_pkt_alloc(ni, 0);
  if( pkt )
    ci_tcp_send_ack(ni, ts, pkt, CI_FALSE);
  else
    ci_log("%d:%d failed to allocate packet buffer", NI_ID(ni), S_SP(ts));
}

static void socket_rst(ci_netif* ni, ci_tcp_state* ts)
{ ci_tcp_send_rst(ni, ts); }

static void socket_set_mss(ci_netif* ni, ci_tcp_state* ts)
{
  ts->eff_mss = (ci_uint16) CI_MIN(arg_u[0], (1 << sizeof(ts->eff_mss)) - 1);
  ci_tcp_tx_change_mss(ni, ts, true/*may send*/);
}

static void socket_set_sndbuf(ci_netif* ni, ci_tcp_state* ts)
{
  ts->s.so.sndbuf = arg_u[0];
  ci_tcp_set_sndbuf(ni, ts);
}

static void socket_set_rcvbuf(ci_netif* ni, ci_tcp_state* ts)
{
  ts->s.so.rcvbuf = arg_u[0];
}

static void socket_set_cwnd(ci_netif* ni, ci_tcp_state* ts)
{ ts->cwnd = arg_u[0]; }

static void socket_send(ci_netif* ni, ci_tcp_state* ts) {
  ci_iovec iov;
  int rc;

  CI_IOVEC_LEN(&iov) = arg_u[0];
  CI_TEST(CI_IOVEC_BASE(&iov) = malloc(arg_u[0]));

  /* ?? NB. Blocking currently broken due to signal deferral stuff
  ** requiring us to have registered thread data.
  */
  rc = ci_tcp_sendmsg(ni, ts, &iov, 1, MSG_DONTWAIT);
  ci_log("sendmsg(%d:%d, %d, 0) = %d",
	 NI_ID(ni), S_SP(ts), (int) CI_IOVEC_LEN(&iov), rc);
}

static void socket_recv(ci_netif* ni, ci_tcp_state* ts) {
  ci_tcp_recvmsg_args args;
  ci_iovec iov;
  struct msghdr msg;
  int rc;

  CI_IOVEC_LEN(&iov) = arg_u[0];
  CI_TEST(CI_IOVEC_BASE(&iov) = malloc(arg_u[0]));

  CI_ZERO(&msg);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  /* ?? NB. Blocking currently broken due to signal deferral stuff
  ** requiring us to have registered thread data.
  */
  ci_tcp_recvmsg_args_init(&args, ni, ts, &msg, MSG_DONTWAIT);
  rc = ci_tcp_recvmsg(&args);
  ci_log("recvmsg(%d:%d, %d, 0) = %d",
	 NI_ID(ni), S_SP(ts), (int) CI_IOVEC_LEN(&iov), rc);
}

static void socket_ppl_corrupt_loop(ci_netif* ni, ci_tcp_state* ts)
{
  /* Put this socket on the post-poll-list and corrupt the list by creating
   * a loop.
   */
  ci_netif_put_on_post_poll(ni, &ts->s.b);
  ts->s.b.post_poll_link.next = oo_ptr_to_statep(ni, &ts->s.b.post_poll_link);
}

/**********************************************************************/

ci_inline unsigned t_usec(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (unsigned) ((ci_uint64) tv.tv_sec * 1000000 + tv.tv_usec);
}


/* Return true if arg is a TCP connection in a state that can pass data. */
ci_inline int is_tcp_stream(citp_waitable_obj* wo)
{
  return ( (wo->waitable.state
            & (CI_TCP_STATE_TCP_CONN | CI_TCP_STATE_NOT_CONNECTED
               | CI_TCP_STATE_SYNCHRONISED))
           == (CI_TCP_STATE_TCP_CONN | CI_TCP_STATE_SYNCHRONISED) );
}


typedef struct {
  unsigned	rx, tx;
} sockets_bw_sample_t;

static void sockets_bw_poll(int i)
{
  sockets_bw_sample_t* sam;
  citp_waitable_obj* wo;
  socket_t* s;

  for( s = sockets; s < sockets + sockets_n; ++s ) {
    netif_t* n = stacks[s->stack];
    if( s->id >= (int)n->ni.state->n_ep_bufs )  continue;
    wo = SP_TO_WAITABLE_OBJ(&n->ni, s->id);
    if( ! is_tcp_stream(wo) )  continue;
    sam = (sockets_bw_sample_t*) s->s + i;
    sam->rx = tcp_rcv_nxt(&wo->tcp);
    sam->tx = tcp_snd_nxt(&wo->tcp);
  }
}

void sockets_watch_bw(void)
{
  sockets_bw_sample_t* sam;
  unsigned* times;
  citp_waitable_obj* wo;
  socket_t* s;
  unsigned i, boff, blen;
  char* b;

  for( s = sockets; s < sockets + sockets_n; ++s )
    CI_TEST(s->s = malloc(cfg_samples * sizeof(sockets_bw_sample_t)));
  CI_TEST(times = malloc(cfg_samples * sizeof(times[0])));

  times[0] = t_usec();
  sockets_bw_poll(0);
  for( i = 1; i < cfg_samples; ++i ) {
    do times[i] = t_usec();
    while( (unsigned) (times[i] - times[i-1]) < cfg_usec );
    sockets_bw_poll(i);
  }

  ci_log_nonl("# usec delta");
  for( s = sockets; s < sockets + sockets_n; ++s ) {
    ci_uint32 be32;
    netif_t* n = stacks[s->stack];
    if( s->id >= (int)n->ni.state->n_ep_bufs )  continue;
    wo = SP_TO_WAITABLE_OBJ(&n->ni, s->id);
    if( ! is_tcp_stream(wo) )  continue;
    be32 = tcp_raddr_be32(&wo->tcp);
    ci_log_nonl(" "CI_IP_PRINTF_FORMAT,CI_IP_PRINTF_ARGS(&be32));
  }
  ci_log(" ");
  blen = sockets_n * 2 * 10 + 20;
  CI_TEST(b = (char*) malloc(blen));

  for( i = 1; i < cfg_samples; ++i ) {
    boff = ci_scnprintf(b, blen, "%u %u",
                        times[i] - times[0], times[i] - times[i-1]);
    for( s = sockets; s < sockets + sockets_n; ++s ) {
      netif_t* n = stacks[s->stack];
      if( s->id >= (int)n->ni.state->n_ep_bufs )  continue;
      wo = SP_TO_WAITABLE_OBJ(&n->ni, s->id);
      if( ! is_tcp_stream(wo) )  continue;
      sam = (sockets_bw_sample_t*) s->s;
      boff += ci_scnprintf(b+boff, blen-boff, " %u %u",
                           SEQ_SUB(sam[i].rx, sam[i-1].rx),
                           SEQ_SUB(sam[i].tx, sam[i-1].tx));
    }
    ci_log("%s", b);
  }

  free(b);
  free(times);
  for( s = sockets; s < sockets + sockets_n; ++s )  free(s->s);
}

/**********************************************************************/

void sockets_bw(void)
{
  unsigned t_start, t_end, usec, txbw, rxbw;
  sockets_bw_sample_t* sam;
  citp_waitable_obj* wo;
  socket_t* s;

  for( s = sockets; s < sockets + sockets_n; ++s )
    CI_TEST(s->s = malloc(2 * sizeof(sockets_bw_sample_t)));

  t_start = t_usec();
  sockets_bw_poll(0);
  ci_sleep(cfg_watch_msec);
  t_end = t_usec();
  sockets_bw_poll(1);
  usec = t_end - t_start;

  for( s = sockets; s < sockets + sockets_n; ++s ) {
    netif_t* n = stacks[s->stack];
    if( s->id >= (int)n->ni.state->n_ep_bufs )  continue;
    wo = SP_TO_WAITABLE_OBJ(&n->ni, s->id);
    if( ! is_tcp_stream(wo) )  continue;
    sam = (sockets_bw_sample_t*) s->s;
    txbw = (unsigned) ((ci_uint64) (sam[1].tx - sam[0].tx) * 8 / usec);
    rxbw = (unsigned) ((ci_uint64) (sam[1].rx - sam[0].rx) * 8 / usec);
    if( txbw || rxbw )
      ci_log("%d:%d  %d %d", NI_ID(&n->ni), s->id, txbw, rxbw);
  }

  for( s = sockets; s < sockets + sockets_n; ++s )  free(s->s);
}

/**********************************************************************/

static int sockets_watch_poll(socket_t* s, int first_time)
{
  citp_waitable_obj* wo;

  netif_t* n = stacks[s->stack];
  if( s->id >= (int)n->ni.state->n_ep_bufs )  return 0;
  wo = SP_TO_WAITABLE_OBJ(&n->ni, s->id);
  if( ! (wo->waitable.state & CI_TCP_STATE_TCP_CONN) )  return 0;
  if( !first_time && ! memcmp(wo, s->s, sizeof(*wo)) )  return 0;
  memcpy(s->s, wo, sizeof(*wo));
  citp_waitable_dump(&n->ni, &wo->waitable, "");
  return 1;
}


void sockets_watch(void)
{
  socket_t* s;

  for( s = sockets; s < sockets + sockets_n; ++s ) {
    CI_TEST(s->s = malloc(sizeof(citp_waitable_obj)));
    sockets_watch_poll(s, 1);
  }

  while( 1 ) {
    int did_anything = 0;
    ci_sleep(cfg_watch_msec);
    for( s = sockets; s < sockets + sockets_n; ++s )
      did_anything += sockets_watch_poll(s, 0);
    if( did_anything )  ci_log(" ");
  }

  for( s = sockets; s < sockets + sockets_n; ++s )  free(s->s);
}

/**********************************************************************
***********************************************************************
**********************************************************************/

#define SOCK_OP_A(nm, fl, help, args, n_args)     \
  { #nm, socket_##nm, help, args, n_args, (fl) }

#define SOCK_OP_F(nm, fl, help)        SOCK_OP_A(nm, fl, help, NULL, 0)
#define SOCK_OP(nm, help)              SOCK_OP_A(nm, 0,  help, NULL, 0)

#define TCPC_OP_A(nm, fl, help, args, n_args)     \
    SOCK_OP_A(nm, (fl)|FL_TCPC, help, args, n_args)
#define TCPC_OP_AU(nm, help, args)     TCPC_OP_A(nm, FL_ARG_U, help, args, 1)
#define TCPC_OP(nm, help)              SOCK_OP_A(nm, FL_TCPC, help, "", 0)


static const socket_op_t socket_ops[] = {
  SOCK_OP_F (dump,    FL_NO_LOCK,
             "show socket content"),
  TCPC_OP   (qs,
             "show queues on socket"),
  SOCK_OP_F (lock,    FL_NO_LOCK,
             "lock socket"),
  SOCK_OP_F (unlock,  FL_NO_LOCK,
             "unlock socket"),
  SOCK_OP_F (trylock, FL_NO_LOCK,
             "try to lock socket"),
  SOCK_OP_F (filters, FL_NO_LOCK,
             "show socket's filter info"),
  SOCK_OP_A (ul_poll, FL_NO_LOCK | FL_ARG_U,
             "set user level polling cycles option", "<ul_poll>", 1),
  TCPC_OP   (nodelay,
             "set socket option TCP_NODELAY"),
  TCPC_OP   (nagle,
             "unset socket option TCP_NODELAY"),
  TCPC_OP   (cork,
             "set socket option TCP_CORK"),
  TCPC_OP   (uncork,
             "unset socket option TCP_CORK"),
  TCPC_OP   (advance,
             "advance socket TCP transmission"),
  TCPC_OP   (ack,
             "send ACK"),
  TCPC_OP   (rst,	 "send RST"),
  TCPC_OP_AU(set_mss,
             "set TCP socket maximum segment size", "<mss>"),
  TCPC_OP_AU(set_sndbuf,
             "set socket SO_SNDBUF", "<sndbuf>"),
  TCPC_OP_AU(set_rcvbuf,
             "set socket SO_RCVBUF", "<rcvbuf>"),
  TCPC_OP_AU(set_cwnd,
             "set congestion window size", "<cwnd>"),
  TCPC_OP_AU(send,
             "transmit bytes on socket", "<bytes>"),
  TCPC_OP_AU(recv,
             "receive bytes on TCP socket", "<bytes>"),
  TCPC_OP   (ppl_corrupt_loop,
             "corrupt post-poll-list with a loop"),
};
#define N_SOCKET_OPTS	(sizeof(socket_ops) / sizeof(socket_ops[0]))


void for_each_socket_op(void(*fn)(const socket_op_t* op, void* arg), void *arg)
{
  const socket_op_t* op;
  for( op = socket_ops; op < socket_ops + N_SOCKET_OPTS; ++op )
    (*fn)(op, arg);
}


const socket_op_t *get_socket_op(const char* name)
{
  const socket_op_t* op;
  for( op = socket_ops; op < socket_ops + N_SOCKET_OPTS || (op = NULL); ++op )
    if( ! strcmp(op->name, name) )
      break;
  return op;
}


/**********************************************************************
***********************************************************************
**********************************************************************/

static void signal_handler(int signum)
{
  signal_fired = 1;
}


int libstack_init()
{
  if( cfg_filter )
    if( ! sockbuf_filter_prepare(&sft, cfg_filter) )
      return -1;
  ci_set_log_prefix("");
  ci_dllist_init(&stacks_list);
  if( libstack_mappings_init() )
    return -1;
  CI_TEST(signal(SIGUSR1, signal_handler) != SIG_ERR);
  return 0;
}

void libstack_end(void)
{
  stacks_detach_all();
  sockbuf_filter_free(&sft);
}

int libstack_netif_lock(ci_netif* ni)
{
  citp_signal_info* si = citp_signal_get_specific_inited();
  int rc;

  libstack_defer_signals(si);
  rc = ci_netif_lock(ni);
  if( rc != 0 )
    libstack_process_signals(si);
  return rc;
}
void libstack_netif_unlock(ci_netif* ni)
{
  ci_netif_unlock(ni);
  libstack_process_signals(citp_signal_get_specific_inited());
}
int libstack_netif_trylock(ci_netif* ni)
{
  citp_signal_info* si = citp_signal_get_specific_inited();
  int rc;

  libstack_defer_signals(si);
  rc = ci_netif_trylock(ni);
  if( rc )
    return rc;

  /* failed to get lock: process signals */
  libstack_process_signals(si);
  return rc;
}
