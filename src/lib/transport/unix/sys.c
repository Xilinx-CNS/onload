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
  
/*! \cidoxg_lib_transport_unix */
 
/* This is required for RTLD_NEXT from dlfcn.h */
#define _GNU_SOURCE

#include <internal.h>
#include <dlfcn.h>

static int load_sym_fail(const char* sym)
{
  Log_E(log("citp_find_calls: ERROR: dlsym(\"%s\") failed '%s'",
            sym, dlerror()));
  return -1;
}


static int
citp_find_all_sys_calls(void)
{
  /*
  ** RTLD_NEXT can be used in place of a library handle, and means 'find
  ** the next occurence of the symbol in the library search order'.
  ** However, it is only available in recent glibc (2.2.5 has it, 2.1.2
  ** doesn't).  If it is not defined, we have to open libc ourselves, and
  ** hope we get the name right!
  */

  /*
  ** NB. If RTLD_NEXT is not defined, we ought to look in libpthread before
  ** we go to libc, since the former adds thread cancellation tests to some
  ** of the sys calls (those prefixed by __libc_).
  */

#ifndef RTLD_NEXT
  void* dlhandle;
  const char* lib = "libc.so.6";  /* ?? */
  dlhandle = dlopen(lib, RTLD_NOW | RTLD_GLOBAL);
  if( dlhandle == 0 ) {    
    Log_E(log("%s: ERROR: dlopen(%s) failed dlerror=%s",
              __FUNCTION__, lib, dlerror()));
    return -1;
  }
# define CI_MK_DECL(ret, fn, args)              \
  ci_sys_##fn = dlsym(dlhandle, #fn);           \
  if( ci_sys_##fn == NULL )                     \
    return load_sym_fail(#fn);
#else
# define CI_MK_DECL(ret, fn, args)                                      \
  ci_sys_##fn = dlsym(RTLD_NEXT, #fn);                                  \
  if( ci_sys_##fn == NULL ) {                                           \
    /*                                                                  \
     * NOTE: the socket tester uses dlopen() on libcitransport.so and so \
     *       lookup using RTLD_NEXT may fail in this case. If it does then \
     *       try RTLD_DEFAULT to search all libraries.                  \
     */                                                                 \
    ci_sys_##fn = dlsym(RTLD_DEFAULT, #fn);                             \
  }                                                                     \
  if( ci_sys_##fn == NULL )                                             \
    return load_sym_fail(#fn);
#endif

#include <onload/declare_syscalls.h.tmpl>

#ifndef RTLD_NEXT
  if( dlclose(dlhandle) != 0 )
    Log_E(log("%s: ERROR: dlclose != 0", __FUNCTION__));
#endif

  return 0;
}


extern int __open(const char*, int, ...);
extern ssize_t __read(int, void*, size_t);
extern ssize_t __write(int, const void*, size_t);
extern int __close(int);
extern int __sigaction(int signum, const struct sigaction *act,
                       struct sigaction* oldact);

int
citp_basic_syscall_init(void)
{
  /* This is a small set of basic syscalls separated from the rest in order
   * to resolve order-of-initialization problems with other preload libraries.
   * The specific target here was jemalloc, notably os_overcommits_proc()
   * therein. jemalloc initializes itself on first malloc, which happens
   * during dlsym() in our initialization and hence causes infinite recursion
   * (or actually deadlock because there's a non-recursive mutex in the call
   * stack). libc exports many of its functions under alternate names, like
   * the double underscore ones here, so we can use them as a simplistic
   * dlsym.
   * Note that these symbols are re-resolved in citp_syscall_init so that if
   * there are stacked preload libraries, both of which try to intercept these
   * functions, then they have a chance of working once Onload is fully
   * initialized because RTLD_NEXT will find them where direct double-
   * underscore references didn't. */
  ci_sys_open = __open;
  ci_sys_read = __read;
  ci_sys_write = __write;
  ci_sys_close = __close;
  ci_sys_sigaction = __sigaction;
  return 0;
}


int
citp_syscall_init(void)
{
  if (citp_find_all_sys_calls() < 0)
    return -1;

  return 0;
}


#include <sys/stat.h>
#define ONLOAD_DEV       "/dev/onload"
#define citp_major(dev) ((dev) & 0xff00)

/*! \cidoxg_end */
