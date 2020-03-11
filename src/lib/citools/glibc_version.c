/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/tools.h>

#ifdef __GLIBC__

#include <dlfcn.h>
#include <gnu/libc-version.h>
#include <stdlib.h>


/* Certain versions of glibc, when compiled with NPTL, store a magic variable
 * off TLS (i.e. hanging off gs:), that tells us whether we're running
 * multithreaded or not.  This function determins whether we're linked against
 * a glibc that works this way.  It returns 1 if we are, or 2 if we're not.
 */
int ci_glibc_gs_is_multihreaded_offset CI_HV = -1;


int ci_glibc_gs_get_is_multihreaded_offset (void)
{
#if defined(_CS_GNU_LIBPTHREAD_VERSION)
  char buf [128];
  int doit = 1;
  char* s = getenv ("EF_SKIP_LOCKS");
  if( s )  doit = atoi(s);
  if( doit ) {
    /* Environment indicates we do the lock hacks -- check NPTL version */
    int conf = confstr(_CS_GNU_LIBPTHREAD_VERSION, buf, sizeof(buf));
    if( conf ) {
      if(  strstr(buf, "NPTL 2.3") ||
	   strstr(buf, "NPTL 0.6") ||
	  !strcmp(buf, "NPTL 0.34") )
	return 0xc;
    }
    /* Unknown NPTL version; play it safe */
  }
#endif
  return -2;
}

int
ci_glibc_uses_nptl (void) {
#if defined(_CS_GNU_LIBPTHREAD_VERSION)
  char buf [128];
  int conf = confstr (_CS_GNU_LIBPTHREAD_VERSION, buf, 127);
  if (conf)
    return (strstr (buf, "NPTL") == buf);

#endif
  return 0;
}

int ci_glibc_nptl_broken(void) {
  char buf [128];
  int conf;

#if defined(_CS_GNU_LIBPTHREAD_VERSION)
  ci_assert(ci_glibc_uses_nptl());

  conf = confstr (_CS_GNU_LIBPTHREAD_VERSION, buf, 127);
  if(conf){
    if(!strcmp(buf, "NPTL 0.29"))
      return 1;

    /* Success if version detected and not 0.29 */
    return 0;
  }
#endif

  /* TODO - what happens if we can't find out the version - for now we
     default to failing, but give different rc so caller can tell*/
  return -1;
}

#endif  /* __GLIBC__ */
