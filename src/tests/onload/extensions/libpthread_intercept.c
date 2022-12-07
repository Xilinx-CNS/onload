/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2015-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  ab
**  \brief  Example for pthread interception
**   \date  2014/11/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/* Intercept pthread calls, to call the extension library.       */
/* This is an EXAMPLE.  We do NOT recommend using this directly. */
/* but instead suggest that you use it as a basis for your own.  */

/*
 * Format of directives file.
 * One line per directive.
 * name xxx yyy
 *   Means that sockets in a thread thread with the name xxx will get a stack
 *   with the name yyy
 *   Use name _ to indicate no acceleration.
 * num ### xxx
 *   Means that sockets in the the #'th thread to be created will get a stack
 *   with the name xxx
 * set protocol 0
 *   Means that '%' in a stack name will NOT be replaced.
 *  Normally; it will be replaced with U for UDP sockets and T for TCP sockets
 * set default n
 *   0 : none.  If thread name not found, do not accelerate.
 *   1 : protocol.  If thread name not found, use TCP/UDP stack.
 *   2 : basic. If thread name not found, use default stack.  (Default)
 *   3 : cpu.  If thread name not found, use one per CPU.
 * Please note, config file parsing is not very robust.
 *
 * Examples:
 *   set default 1
 * This will split your UDP sockets, and your TCP sockets apart - useful
 * Splitting them apart this way helps, if different threads are using the
 * different types; but normally only one UDP and one TCP socket is in use at
 * a time.
 *
 *   name FEED_HANDLER feeds
 *   name ORDERING orders
 * This configuration calls out two specific threads to get their own stacks
 * while all other threads will use the default stack, shared between them.
 * This allows resources to be prioritised to these two (critical) threads.
 *
 *   num 2 orders
 *   num 4 feeds%
 *   num 5 feeds%
 *   num 6 feeds%
 *   set default 0
 *   set protocol 1
 * The same configuration as above; but where the threads have a defined order
 * of creation; but do not get names set that could be used.
 * In addition; threads not specifically named will not be accelerated at all,
 * and there will be two 'feeds' stacks - feedsU and feedsT; for TCP and UDP
 * sockets respectively.
*/

/*
 * Compilation:
 *   gcc -Wall -fPIC -shared -o libpthread_intercept.so.1 libpthread_intercept.c
 * Usage:
 *   LD_PRELOAD="libpthread_intercept.so.1 libonload.so" your_application
 *   (With appropriate LD_LIBRARY_PATH set)
*/


/* gnu source is needed for RTLD_NEXT */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <onload/extensions.h>

/* Maximium namelength for extensions API */
#define MAX_EXTNAME_LEN 8
/* pthread API says this is restricted to 16 characters, and in
 * one place says that includes a /0 and in another doesn't!
 * Play safe, one larger. */
#define MAX_THREADNAME_LEN 17

/* Explicitly declare them here, so that if the API changes
 * the compile will fail */
extern int pthread_create(pthread_t *, const pthread_attr_t *,
                          void *(*start_routine)(void *), void *);
extern int prctl(int, unsigned long, unsigned long, unsigned long,
                 unsigned long);
extern int pthread_setname_np(pthread_t thread, const char *name);
extern int socket(int socket_family, int socket_type, int protocol);
/* And then include the headers that ought to have them */
#include <sys/socket.h>
#include <pthread.h>
#include <linux/prctl.h>

/* Debug logging */
#define LIBNAME_PREFIX "onload_intercept: "
#define LOG_E(args ...) {             \
    fprintf(stderr, LIBNAME_PREFIX);  \
    fprintf(stderr, ## args );        \
    fprintf(stderr, "\n" ); }
#if DEBUG
#define LOG(args ...) {               \
    fprintf(stderr, LIBNAME_PREFIX);  \
    fprintf(stderr, ## args );        \
    fprintf(stderr, "\n" ); }
#else
#define LOG(args ...)
#endif

/* Remember mappings between threads and names */
struct mapping {
  pthread_t       tid;
  int             num;
  char            thread_name [MAX_THREADNAME_LEN + 1];
  char            ext_name    [MAX_EXTNAME_LEN + 1];
  struct mapping *next;
};

/* configuration directive for 'defaut' */
enum {
  CFG_DEFAULT_NONE,
  CFG_DEFAULT_PROTO,
  CFG_DEFAULT_BASIC,
  CFG_DEFAULT_CPU
};

/* Forward declares of functionality */
static void *intercept(char const *name);
static int ensure_intercepts(void);

/* These are the entry points from the intercepts */
static int created_new_thread(pthread_t tid);
static int apply_extname(int socket_type);
static void name_changed(pthread_t tid, char const *src);

/* Configuration loading */
static int ensure_config_loaded(void);
static char const *get_config_filename(void);
static int load_config(void);
static int directive_set(char const *name, int value);
static int add_mapping(const char *thread_name, const char *ext_name);
static int add_numeric(int num, const char *ext_name);

/* And these are the rest */
static int get_extname_for_thread(pthread_t tid, char *name);
static int remember_threadname(pthread_t tid, char const *name);
static int dump_table(void);
static void sanitise_name(char const *src, char *name, int length);
static void alter_name_for_socket(int socket_type, char *name);
static void alter_name_for_cpu(char *name);

/* Library-local-storage */
static pthread_mutex_t cfg_mutex;
static int cfg_name_by_protocol = 1;
static struct mapping *cfg_mapping = NULL;
static int cfg_default = CFG_DEFAULT_BASIC;
static int cfg_loaded = 0;

/* Passthrough mappings */
static int (*_pthread_create)(pthread_t *thread, const pthread_attr_t *,
                              void *(*start)(void *), void *) = NULL;
static int (*_pthread_setname_np)(pthread_t thread, const char *name) = NULL;
static int (*_prctl)(int, unsigned long, unsigned long, unsigned long,
                     unsigned long) = NULL;
static int (*_socket)(int socket_family, int socket_type, int protocol) = NULL;

/******************/
/** Interception **/
/******************/

/* Intercept the named function, returning the original */
static void *intercept(char const *name)
{
  void *rval;
  char const *err;
  /* Suggested usage from man(3) dlsym -
   * Clear error, then get symbol, then check for error.
   */
  dlerror();
  rval = dlsym(RTLD_NEXT, name);
  err = dlerror();
  if( err ) {
    LOG_E("dlsym failed: %s", err);
    rval = NULL;
  }
  return rval;
}


/* Set up all of our intercept functions, if they aren't already */
static int ensure_intercepts(void)
{
  int ok;
  if( !_pthread_create )
    _pthread_create = intercept("pthread_create");
  if( !_pthread_setname_np )
    _pthread_setname_np = intercept("pthread_setname_np");
  if( !_prctl ) _prctl = intercept("prctl");
  if( !_socket ) _socket = intercept("socket");
  /* Make sure everything is intercepted */
  ok = _pthread_create && _pthread_setname_np && _prctl && _socket;
  LOG("Intercepts set up %d", ok);
  return ok ? 0 : -EOPNOTSUPP;
}


/************************************/
/** System function implementation **/
/************************************/

/* Override standard thread creation function with our own
 * which if thread creation succeeds will call our created_new_thread
 * function to possibly set its stack name.
 */
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start)(void *), void *arg)
{
  pthread_t tid = 0;
  int rval;

  /* Make sure all the original functions are available */
  if( ensure_intercepts() < 0 )
    return -EOPNOTSUPP;
  /* Call the original function to create the thread */
  rval = _pthread_create(&tid, attr, start, arg);

  /* If it succeeds, go check if we need to rename it */
  if( rval >= 0 )
    created_new_thread(tid);
  /* Return the thread id via this pointer */
  if( thread )
    *thread = tid;

  LOG("pthread_create returning %d", rval);
  return rval;
}


/* Intercept prctl, as one of its options lets a user change
 * the name of a thread
 */
int
prctl(int option, unsigned long arg2, unsigned long arg3,
      unsigned long arg4, unsigned long arg5)
{
  int rval;

  /* Make sure we've got our passthrough set up */
  if( ensure_intercepts() < 0 )
    return -EOPNOTSUPP;
  /* Call the original prctl function */
  rval = _prctl(option, arg2, arg3, arg4, arg5);

  /* If this was a name setting call, check if we want to alter
   * stackname in resopnse */
  if( option == PR_SET_NAME && rval >= 0 )
    name_changed(pthread_self(), (char const *) arg2);

  LOG("prctl returning %d", rval);
  return rval;
}


/* Intercept thread_setname */
int pthread_setname_np(pthread_t thread, const char *name)
{
  int rval;

  /* Make sure we've got our passthrough set up */
  if( ensure_intercepts() < 0 )
    return -EOPNOTSUPP;
  /* Call the original function */
  rval = _pthread_setname_np(thread, name);

  /* Check and see whether the new name is interesting */
  if( rval >= 0 )
    name_changed(thread, name);

  LOG("pthread_setname_np returning %d", rval);
  return rval;
}


/*
 * We are intercepting socket() so that we can set the stackname in time.
 * We can't just do this when the stack's name is set; pthread_setname_np
 * allows this to be done from another thread; and onload_set_stackname
 * can only act on the current thread.  So we need to do it here instead.
*/
int socket(int socket_family, int socket_type, int protocol)
{
  int ok, ext_ok;

  /* Set up passthroughs */
  if( ensure_intercepts() < 0 )
    return -EOPNOTSUPP;

  /* Set up stack name based on socket type */
  ext_ok = apply_extname(socket_type);
  /* Actually create the socket */
  ok = _socket(socket_family, socket_type, protocol);

  /* Go back to old stack name, if we changed */
  if( ext_ok )
    onload_stackname_restore();

  LOG("socket returning %d", ok);
  return ok;
}


/* Debugging function - print out our mappings */
static int dump_table(void)
{
  int count = 0;
#if DEBUG
  struct mapping *ptr = cfg_mapping;
  if( !cfg_loaded ) return count;
  while( ptr ) {
    LOG("%s %d -> %s", ptr->thread_name, (int)ptr->tid, ptr->ext_name);
    count++;
    ptr = ptr->next;
  }
#endif
  return count;
}


/* The name of this thread changed - so remember the new name associated with
 * this thread id.
 */
static void name_changed(pthread_t tid, char const *src)
{
  char name[MAX_THREADNAME_LEN];
  /* We need our config loaded */
  ensure_config_loaded();

  LOG("name_changed(tid=%d name=%s)", (int)tid, src);

  /* Make sure name is truncated, zero terminated etc. */
  sanitise_name(src, name, MAX_THREADNAME_LEN);
  /* and store it */
  remember_threadname(tid, name);
}


/* A socket is created, we know its type - check if we should set a
 * new stackname, and do so.
 */
static int apply_extname(int socket_type)
{
  char name[MAX_EXTNAME_LEN];
  int ok;

  /* Need to have loaded the config from disk */
  ensure_config_loaded();

  LOG("apply_extname(%d) tid=%d", socket_type, (int)pthread_self());

  /* Find the name for this thread */
  ok = get_extname_for_thread(pthread_self(), name);
  LOG("get_extname_for_thread returned %d %s", ok, name);

  if( ok >= 0 ) {
    /* Store the current name, so we can restore it later */
    ok = onload_stackname_save();
    /* Adjust the name to account for socket type */
    alter_name_for_socket(socket_type, name);
    /* Adjust the name to account for CPU */
    alter_name_for_cpu(name);
    /* Check for 'do not accelerate' name, then set appropriate name */
    if( !strncasecmp("_", name, 2) )
      ok = onload_set_stackname(ONLOAD_THIS_THREAD, ONLOAD_SCOPE_GLOBAL,
                                ONLOAD_DONT_ACCELERATE);
    else
      ok = onload_set_stackname(ONLOAD_THIS_THREAD, ONLOAD_SCOPE_GLOBAL,
                                name);
    LOG("onload_set_stackname(\"%s\"): %d (%d)", name, ok, errno);
  }

  return ok;
}


/* A new thread has been created; all we know is the id
 * but also keep count, so that we can act on the n-th thread.
 */
static int created_new_thread(pthread_t tid)
{
  static int thread_num = 0;
  struct mapping *ptr = cfg_mapping;

  LOG("remember_threadnum(%p)", ptr);
  thread_num = thread_num + 1;

  /* Walk the table, looking for this number */
  while( ptr ) {
    if( ptr->num == thread_num ) {
      /* If we've found it, update the table to now have an id */
      ptr->tid = tid;
      LOG("Associated tid %d with %s", (int)tid, ptr->ext_name);
    }
    ptr = ptr->next;
  }
  return -ENOENT;
}


/* Make sure that a name is shurt enough and zero terminated */
static void sanitise_name(char const *src, char *dest, int length)
{
  /* API says this is restricted to 16 characters, and in
   * one place says that includes a /0 and in another doesn't.
   * best sanitise it to be safe */
  strncpy(dest, src, length);
  dest[length - 1] = '\0';
}


/* Replace '%' in name with socket type identifier */
static void alter_name_for_socket(int socket_type, char *name)
{
  char protocol;
  int i;

  /* If this isn't enabled, early exit */
  if( !cfg_name_by_protocol )
    return;

  /* T for TCP, U for UDP, ? for unknown */
  switch(socket_type) {
  case SOCK_STREAM:
    protocol = 'T';
    break;
  case SOCK_DGRAM:
    protocol = 'U';
    break;
  default:
    protocol = '?';
    break;
  }

  /* Special case, replace a blank name with single character */
  if( name[0] == '\0' ) {
    name[0] = protocol;
    name[1] = '\0';
    return;
  }

  /* Walk over the name, replacing matches */
  for( i = 0; i < MAX_EXTNAME_LEN; ++i ) {
    if( name[i] == '%' )
      name[i] = protocol;
  }
}

/* If desired, use a per-cpu name */
static void alter_name_for_cpu(char *name)
{
  if( strncasecmp("&CPU&", name, 6) )
      return;
  snprintf(name, MAX_EXTNAME_LEN, "%d-core", sched_getcpu() );
}

/*******************/
/** Configuration **/
/*******************/

/* If the config isn't already loaded, load it. */
static int ensure_config_loaded(void)
{
  if( !cfg_loaded ) {
    /* This needs thread safety */
    pthread_mutex_lock(&cfg_mutex);
    /* cfg_loaded must ONLY be set here */
    cfg_loaded = load_config();
    pthread_mutex_unlock(&cfg_mutex);
  }
  return cfg_loaded;
}


/* Where should we load from?  Get filename from LPI_INTERCEPT_CONFIG_FILE
 * In a real application you probably want to check a fallback location.
 */
static char const *get_config_filename(void)
{
  char const *env_name = getenv("LPI_INTERCEPT_CONFIG_FILE");
  if ( !env_name ) {
    LOG_E( "LPI_INTERCEPT_CONFIG_FILE not set, unable to load config." );
  }
  return env_name;
}


/* Actually load the configuration file.
 * You will almost certainly want to replace this with something better.
 */
static int load_config(void)
{
  FILE *fd = NULL;
  char buffer[256];
  char *extname = NULL;
  char *threadname = NULL;
  char *directive = NULL;
  char *check = NULL;
  int matches = 0;

  /* Belt and braces - if already loaded, don't re-load */
  if( cfg_loaded )
    return cfg_loaded;

  /* Find out where we load from */
  char const *filename = get_config_filename();
  if ( !filename )
    return 0;
  LOG("Load Config from %s", filename);

  /* Try and open that file */
  fd = fopen(filename, "r");
  if( !fd ) {
    LOG_E("Opening file \"%s\" failed (error %d: %s)", filename, errno,
          strerror(errno));
    return -errno;
  }

  /* Loop over the file */
  while( !feof(fd) ) {
    check = fgets(buffer, 255, fd);
    /* Check nothing went wrong */
    if( ferror(fd) || (!check && !feof(fd)) )
      LOG_E("Reading file \"%s\" failed: %d %s", filename, errno,
            strerror(errno));
    if( buffer[0] == '#' )
      continue;

    buffer[255] = '\0';
    /* sscanf isn't particularly safe - a real application should use a better parser */
    matches = sscanf(buffer, "%ms%ms%ms", &directive, &threadname, &extname);
    if( matches < 3 )
      break;
    LOG("Read: %s %s %s", directive, threadname, extname);
    if( !strncasecmp("set", directive, 4) )
      directive_set(threadname, atoi(extname));
    else if( !strncasecmp("name", directive, 5) )
      add_mapping(threadname, extname);
    else if( !strncasecmp("num", directive, 4) )
      add_numeric(atoi(threadname), extname);
    else
      LOG_E("Invalid directive: %s", directive);
    free(directive);
    free(threadname);
    free(extname);
  }

  LOG("Load Complete");
  fclose(fd);
  /* Debug print the loaded table */
  dump_table();
  return 1;
}


/* We've been given a mapping between thread id and thread name
 * remember it, to go with mapping from thread name to stack name,
 * so that we can then map from thread id to stack name.
 */
static int remember_threadname(pthread_t tid, char const *name)
{
  struct mapping *ptr = cfg_mapping;
  LOG("remember_threadname(%p)", ptr);
  /* Walk over the whole table */
  while( ptr ) {
    /* forget the old name for this thread id, if any */
    if( pthread_equal(ptr->tid, tid) )
      ptr->tid = 0;
    /* Find the matching thread name */
    if( !strncmp(name, ptr->thread_name, MAX_THREADNAME_LEN) ) {
      /* And remember this new thread id to match it */
      ptr->tid = tid;
      LOG("Associated tid %d with known name %s", (int)tid, name);
    }
    ptr = ptr->next;
  }
  return -ENOENT;
}


/* Given a thread id - what stackname should be used?
 * Copy the stack-name into 'name'
 */

static int get_extname_for_thread(pthread_t tid, char *name)
{
  struct mapping *ptr = cfg_mapping;

  LOG("get_extname_for_thread(%d)", (int)tid);

  /* Walk the table */
  while( ptr ) {
    /* Technically tid's may not be integers; so use the provided comparison
     * function to find the entry that matches. */
    if( pthread_equal(ptr->tid, tid) ) {
      /* Found it - copy the stackanme out */
      strncpy(name, ptr->ext_name, MAX_EXTNAME_LEN);
      return 0;
    }
    ptr = ptr->next;
  }
  /* No match */

  /* Are we using default of 'none'?  Set it. */
  if( cfg_default == CFG_DEFAULT_NONE ) {
    strncpy(name, "_", MAX_EXTNAME_LEN);
    return 0;
  }
  /* Are we using default of 'protocol'?  Set it. */
  else if( cfg_default == CFG_DEFAULT_PROTO ) {
    strncpy(name, "%", MAX_EXTNAME_LEN);
    return 0;
  }
  /* Default of 'cpu'?  Record that. */
  else if ( cfg_default == CFG_DEFAULT_CPU ) {
    strncpy(name, "&CPU&", MAX_EXTNAME_LEN);
    return 0;
  }

  /* No name at all?  Blank and return failure code. */
  name[0] = '\0';
  return -ENOENT;
}


/* Handle 'set xxx yyy' in the config file. */
static int directive_set(char const *name, int value)
{
  if( !strncasecmp(name, "protocol", 9) )
    cfg_name_by_protocol = value;
  else if( !strncasecmp(name, "default", 8) )
    cfg_default = value;
  else
    return -EINVAL;
  return 0;
}


/* Handle: name xxxx yyyyy in config file -
 *   Insert a mapping between thread and stack name into our table
 */
static int add_mapping(const char *thread_name, const char *ext_name)
{
  struct mapping *data = calloc(1, sizeof(struct mapping));

  if( !data )
    return -ENOMEM;

  /* Make sure the provided names are short enough, null terminated etc. */
  sanitise_name(thread_name, data->thread_name, MAX_THREADNAME_LEN);
  sanitise_name(ext_name, data->ext_name, MAX_EXTNAME_LEN);
  /* We don't (yet) know the thread id. */
  data->tid = -1;
  /* We know it's not a numeric entry. */
  data->num = -1;
  /* Insert at the head of the linked list */
  data->next = cfg_mapping;
  cfg_mapping = data;
  return 0;
}


/* Handle config file entry: num nnnn yyyyy -
 *   Add a numeric entry to the table 'give the n-th thread ext_name'
 */
static int add_numeric(int num, const char *ext_name)
{
  struct mapping *data = calloc(1, sizeof(struct mapping));

  if( !data )
    return -ENOMEM;

  /* Make sure the name is short enough, null terminated etc. */
  sanitise_name(ext_name, data->ext_name, MAX_EXTNAME_LEN);
  /* We don't know the thread's name (it might never have one) */
  data->thread_name[0] = '\0';
  /* We don't (yet) know the thread id. */
  data->tid = -1;
  /* We do know it is numeric, and the number */
  data->num = num;
  /* Insert at the head of the linked list */
  data->next = cfg_mapping;
  cfg_mapping = data;
  return 0;
}

