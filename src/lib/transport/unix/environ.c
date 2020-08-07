/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  mjs
**  \brief  Operations for environment handling
**   \date  2005/02/15
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_unix */
 
#define _GNU_SOURCE /* For dladdr() */
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <dlfcn.h>

#include <internal.h>

static char *empty_env[] = { NULL };
static char **saved_env;
static unsigned int saved_env_count;

/*! Identiry LD_PRELOAD variable */
static int env_is_ld_preload(const char *var)
{
  ci_assert(var);
  return (strncmp(var, "LD_PRELOAD=", 11) == 0);
}

/*! Identify our environment variables (including LD_PRELOAD).
** \param  var      Variable definition to test
** \return          True or false
*/
static int is_our_env_var(const char *var)
{
  ci_assert(var);
  return (env_is_ld_preload(var)
          || (strncmp(var, "EF_", 3) == 0)
          || (strncmp(var, "CI_", 3) == 0)
          || (strncmp(var, "TP_", 3) == 0));
}


/*! Hit every page of p in reverse order, to avoid potential stack smashing
**  vulnerabilities by ensuring that the guard page gets hit. gcc does this
**  automatically if -fstack-check is on, but we don't require that. */
static void* touch_alloca(void* p, size_t bytes)
{
  ci_assert_nequal(bytes, 0);
  --bytes;
  bytes &= CI_PAGE_MASK;
  for( ; ; ) {
    ((char*)p)[bytes] = 0;
    if( ! bytes )
      break;
    bytes -= CI_PAGE_SIZE;
  }
  return p;
}


/*! Return the number of elements needed to be allocated prior to calling
**  citp_environ_handle_args */
size_t citp_environ_count_args(const char* arg, va_list args)
{
  size_t n = 1;
  if( arg ) {
    va_list args2;
    va_copy(args2, args);
    do {
      ++n;
    } while( va_arg(args2, char*) );
  }
  return n;
}


/*! Build an argv[] from a va_list.  If env_ptr is not NULL, it is assumed that
**  an environment pointer is expected after the NULL arg at the end of the
**  list.
** \param  argv     Caller-allocated array of size citp_environ_count_args()
** \param  arg      First argument
** \param  args     Remaining arguments
** \param  env_ptr  Output environment pointer, or NULL
** \return          The constructed argv[] array
*/
void citp_environ_handle_args(char** argv, const char* arg, va_list args,
                              char*** env_ptr)
{
  unsigned int n = 0;

  touch_alloca(argv, citp_environ_count_args(arg, args) * sizeof(char*));
  argv[n] = (char *)arg;
  while (argv[n++])
    argv[n] = va_arg(args, char *);
  if (env_ptr) {
    *env_ptr = va_arg(args, char **);
  }
}


/*! Check to see if our LD_PRELOAD is still present.  If not, assume that we
**  need to restore both LD_PRELOAD and any other EF_xxx or CI_xxx variables
**  that were saved at initialisation.
** \param  env      Original environment
** \param  bytes_reqd Number of bytes the caller needs to allocate before
**                  calling citp_environ_make_preload()
** \return          New environment with LD_PRELOAD etc. guaranteed present
**
** \TODO  We don't cope with LD_PRELOADs containing multiple components yet...
*/
char* const* citp_environ_check_preload(char* const* env, size_t* bytes_reqd)
{
  char* const* env_ptr;
  char *ld_preload = NULL;
  unsigned int env_count = 0;

  *bytes_reqd = 0;
  if (saved_env_count == 0) {
    return env;
  }
  
  if (!env) {
    env = empty_env;
  }
  env_ptr = env; 
  while (*env_ptr != NULL) {
    if (strncmp(*env_ptr, "LD_PRELOAD=", 11) == 0) {
        ld_preload = *env_ptr;
    }
    env_ptr++;
    env_count++;
  }
  env_ptr++;
  if (ld_preload) {
    /* If LD_PRELOAD is still set, we assume that any other changes that may
     * have been made to EF_xxx or CI_xxx vars are deliberate, so we just
     * return the original environment.
     */
    return env;
  } else {
    *bytes_reqd = sizeof(char *) * (env_count + saved_env_count + 1);
    return env;
  }
}


/*! Phase 2 of citp_environ_check_preload, to be called iff bytes_reqd is
**  nonzero. Constructs the new environment based on saved EF options */
void citp_environ_make_preload(char* const* env, char** new_env,
                               size_t new_env_bytes)
{
  char* const* old_env_ptr = env ? env : empty_env;
  char **new_env_ptr = new_env;
  unsigned int n;

  touch_alloca(new_env, new_env_bytes);
  for (n = 0; n < saved_env_count ; n++) {
    *new_env_ptr++ = saved_env[n];
    Log_V(log("%s: restored %s", __FUNCTION__, saved_env[n]));
  }
  while (*old_env_ptr != NULL) {
    if (!is_our_env_var(*old_env_ptr)) {
      *new_env_ptr++ = *old_env_ptr;
    }
    old_env_ptr++;
  }
  *new_env_ptr = NULL;
}


/* Find the path to the onload library we are running */
static const char *citp_find_loaded_library(void)
{
  Dl_info   my_dl;

  dladdr(citp_find_loaded_library, &my_dl);
  return my_dl.dli_fname;
}

/*! Initialise - called on startup to save away any relevant current
**  environment variables.
** \return          0 for success, -1 for failure
*/
int citp_environ_init(void)
{
  char **env_ptr;
  size_t mem_needed = 0;
  unsigned int n;
  char *string_buf, *p;

  const char *lib_path = NULL;
  const char *ld_preload_value = NULL;

  env_ptr = __environ ? __environ : empty_env;
  saved_env_count = 0;
  while (*env_ptr != NULL) {
    if (is_our_env_var(*env_ptr)) {
      mem_needed += strlen(*env_ptr) + 1;
      saved_env_count++;
      if (env_is_ld_preload(*env_ptr))
        ld_preload_value = *env_ptr + 11;
    }
    /* temporary hack for djr */
    if (strcmp(*env_ptr, "EF_NO_PRELOAD_RESTORE=1") == 0) {
        Log_V(log("Environment restore disabled"));
        saved_env_count = 0;
        return 0;
    }
    /* end temporary hack */
    env_ptr++;
  }
  if (saved_env_count == 0) {
    Log_V(log("Invoked without LD_PRELOAD?  Environment restore disabled."));
    return 0;
  }

  /* Add ourself to LD_PRELOAD if we've been asked to. */
  if (getenv("EF_LD_PRELOAD")) {
    const char *full_path = citp_find_loaded_library();

    ci_assert(full_path);
    ci_assert(strrchr(full_path, '/'));
    lib_path = strrchr(full_path, '/') + 1;

    /* Correct LD_PRELOAD value should be the same as lib_path, or at least
     * start with lib_path+':'. */
    if ((!ld_preload_value ||
       (strlen(ld_preload_value) < strlen(lib_path) ||
       (strncmp(ld_preload_value, lib_path,
                strlen(lib_path)) != 0) ||
       ((ld_preload_value[strlen(lib_path)] != ':') &&
        (ld_preload_value[strlen(lib_path)] != '\0'))
      ))) {

      mem_needed += strlen(lib_path); /* Add our library */
      if (!ld_preload_value) {
        mem_needed += 12; /* Add "LD_PRELOAD=" line */
        saved_env_count++;
      }
      if (ld_preload_value && ld_preload_value[0] == '\0')
        ld_preload_value = NULL; /* Do not set ":" at the end */
      if (ld_preload_value)
        mem_needed++; /* Add ':' separator */
      Log_V(log("%s: LD_PRELOAD=\"%s\", but we are loaded as %s",
                __FUNCTION__, ld_preload_value ? : "", full_path));
    }
    else
      lib_path = NULL;
  }

  saved_env = malloc((saved_env_count + 1) * sizeof(char *));
  string_buf = malloc(mem_needed);
  if ((saved_env == NULL) || (string_buf == NULL)) {
    Log_E(log("malloc() for environment save area failed"));
    return -1;
  }
  
  env_ptr = __environ ? __environ : empty_env;
  p = string_buf;
  n = 0;
  while (*env_ptr != NULL) {
    if (lib_path && env_is_ld_preload(*env_ptr)) {
      char *ptr = p;
      strcpy(p, "LD_PRELOAD=");
      p += 11;
      strcpy(p, lib_path);
      p += strlen(lib_path);
      if (ld_preload_value) {
        strcpy(p, ":");
        strcpy(p + 1, ld_preload_value);
        p += strlen(ld_preload_value) + 1;
      }
      p += 1;
      saved_env[n++] = ptr;
      Log_V(log("%s: saved %s", __FUNCTION__, ptr));
      lib_path = NULL;
    } else if (is_our_env_var(*env_ptr)) {
      strcpy(p, *env_ptr); /* Safe, we know we have enough memory */
      saved_env[n++] = p;
      Log_V(log("%s: saved %s", __FUNCTION__, p));
      p += (strlen(*env_ptr) + 1);
    }
    env_ptr++;
  }
  if (lib_path) {
    /* There were no LD_PRELOAD, so we should add it */
    char *ptr = p;
    strcpy(p, "LD_PRELOAD=");
    p += 11;
    strcpy(p, lib_path);
    p += strlen(lib_path) + 1;
    saved_env[n++] = ptr;
    Log_V(log("%s: added and saved %s", __FUNCTION__, ptr));
  }
  saved_env[n] = NULL;
  ci_assert_equal(n, saved_env_count);
  ci_assert_equal(p, &string_buf[mem_needed]);
  
  return 0;
}

/*! \cidoxg_end */
