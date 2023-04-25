/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  al
**  \brief  Declaration of common helper functions, global variables.
**   \date  2005/09
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_common  */

#ifndef _CI_TRANSPORT_COMMON_H_
#define _CI_TRANSPORT_COMMON_H_

#include <ci/internal/ip.h>
#include <ci/internal/citp_opts.h>
#include <onload/ul/rwlock.h>


/**********************************************************************
 ** Logging
 */

extern unsigned citp_log_level CI_HV;

#define Log_C_always(c,x)    do{ if(c) do{ x; }while(0); }while(0)
#ifdef NDEBUG
# define Log_C(c,x)          do{}while(0)
#else
# define Log_C               Log_C_always
#endif

#define Log_FL(f,x)          Log_C(citp_log_level & (f), x);
#define Log_FL_always(f,x)   Log_C_always(citp_log_level & (f), x);

#define Log_E(x)      Log_FL(CI_UL_LOG_E, x)
#define Log_U(x)      Log_FL(CI_UL_LOG_U, x)
#define Log_S(x)      Log_FL(CI_UL_LOG_S, x)
#define Log_V(x)      Log_FL(CI_UL_LOG_V, x)
#define Log_SEL(x)    Log_FL(CI_UL_LOG_SEL, x)
#define Log_POLL(x)   Log_FL(CI_UL_LOG_POLL, x)
#define Log_VPOLL(x)  Log_FL(CI_UL_LOG_VPOLL, x)
#define Log_VVPOLL(x) Log_FL(CI_UL_LOG_VVPOLL, x)
#define Log_VSS(x)    Log_FL(CI_UL_LOG_VSS, x)
#define Log_VSC(x)    Log_FL(CI_UL_LOG_VSC, x)
#define Log_EP(x)     Log_FL(CI_UL_LOG_EP, x)
#define Log_LIB(x)    Log_FL(CI_UL_LOG_LIB, x)
#define Log_CALL(x)   Log_FL(CI_UL_LOG_CALL, x)
#define Log_CLUT(x)   Log_FL(CI_UL_LOG_CLUT, x)
#define Log_PT(x)     Log_FL(CI_UL_LOG_PT, x)
#define Log_VPT(x)    Log_FL(CI_UL_LOG_VPT, x)
#define Log_VTC(x)    Log_FL(CI_UL_LOG_VTC, x)
#define Log_VV(x)     Log_FL(CI_UL_LOG_VV, x)
#define Log_VVTC(x)   Log_FL(CI_UL_LOG_VVTC, x)
#define Log_VE(x)     Log_FL(CI_UL_LOG_VE, x)
#define Log_VVE(x)    Log_FL(CI_UL_LOG_VVE, x)

#define log  ci_log

# define Log_CALL_RESULT(x) \
  Log_CALL(ci_log("%s returning %d (errno %d)",__FUNCTION__,x,errno))
# define Log_CALL_RESULT_PTR(x) \
  Log_CALL(ci_log("%s returning %p (errno %d)",__FUNCTION__,x,errno))
# define Log_CALL_RESULT_WITH_SA(x, sa, p_sa_len) \
  Log_CALL(                                                             \
    if( sa != NULL && p_sa_len != NULL )                                \
      ci_log("%s returning %d addr "OO_PRINT_SOCKADDR_FMT" (errno %d)", \
             __FUNCTION__,x,OO_PRINT_SOCKADDR_ARG(sa,*p_sa_len),errno); \
    else                                                                \
      ci_log("%s returning %d (errno %d)",__FUNCTION__,x,errno);        \
  )

ci_inline void citp_set_log_level(unsigned log_level) {
  citp_log_level = log_level;
}

/**********************************************************************
 ** Transport library user-level lock
 */

typedef oo_rwlock		citp_ul_lock_t;
extern citp_ul_lock_t		citp_ul_lock CI_HV;


/**********************************************************************
 ** Netif initialisation (netif_init.c).
 */

extern void citp_cmn_netif_init_ctor(unsigned netif_dtor_mode) CI_HF;

/* Check the active netifs to look for one with
 * a matching ID
 * \param id     ID to look for (as returned by NI_ID())
 * \return       ptr to UL netif or NULL if not found
 */
extern ci_netif* citp_find_ul_netif(int id, int locked) CI_HF;

/*! Allocate and initialise a common-pool netif (if necessary) and
  return it  */
extern int citp_netif_alloc_and_init(ef_driver_handle*, ci_netif**) CI_HF;

/* Find the current process stack. */
extern int
citp_netif_get_process_stack(ci_netif** out_ni, const char* stackname) CI_HF;


/* Recreate a netif for a 'probed' user-level endpoint */
extern int citp_netif_recreate_probed(ci_fd_t caller_fd,
                                      ef_driver_handle* fd,
				      ci_netif** out_ni) CI_HF;

/* Initialize a netif reference count */
ci_inline void citp_netif_init_ref(ci_netif* ni )
{
  oo_atomic_set(&ni->ref_count, 1);
}

/* Add a reference to a netif */
ci_inline void citp_netif_add_ref( ci_netif* ni ) {
  ci_assert(ni);
  CI_MAGIC_CHECK(ni, NETIF_MAGIC);
  oo_atomic_inc(&ni->ref_count);
}

/*! Handles release of resources etc. when the ref count hits
** zero.  Call with [locked] = 0 if the fd table lock is NOT held
** or [locked] != 0 if * the fd table lock IS held.
*/
extern void __citp_netif_ref_count_zero( ci_netif* ni, int locked ) CI_HF;

/*! Release one ref count, when the ref count hits zero the netif will be
** freed.  Call with [locked] = 0 if the fd table lock is NOT held
** or [locked] != 0 if * the fd table lock IS held.
*/
ci_inline void citp_netif_release_ref( ci_netif* ni, int locked ) {
  ci_assert(ni);
  CI_MAGIC_CHECK(ni, NETIF_MAGIC);
  if( oo_atomic_dec_and_test(&ni->ref_count) )
    __citp_netif_ref_count_zero(ni, locked);
}

/*! Platform specific hook called after creating a netif */
extern void citp_netif_ctor_hook(ci_netif* ni, int realloc) CI_HF;

/*! Platform specific hook called prior to freeing a netif */
extern void citp_netif_free_hook(ci_netif* ni) CI_HF;

/*! Get any active netif for this process */
extern ci_netif* __citp_get_any_netif(void) CI_HF;

/*! Is there a netif in this process */
extern int citp_netif_exists(void) CI_HF;

/*! Get all (or as many as will fit) active netifs for this process 
 * and increment their ref. counts */
extern int citp_get_active_netifs(ci_netif **result, int maxnum);

/*! Mark all active netifs as shared */
extern void __citp_netif_mark_all_shared(void) CI_HF;

/*! Remove extra references that protect against destruction  */
extern void __citp_netif_unprotect_all(void) CI_HF;

/*! Mark all active netifs as "not for use by new sockets" */
extern void __citp_netif_mark_all_dont_use(void) CI_HF;

/*! Free and destruct a netif */
extern void __citp_netif_free(ci_netif* ni) CI_HF;

/*! Exit hook, to be called from any exit(),_exit() or
 * SIGTERM-SIG_DFL handler. */
extern void oo_exit_hook(int status) CI_HF;

/**********************************************************************
 ** Protocol-agnostic common
 */

/* common handler for TCP & UDP setsockname. */
ci_inline void __citp_getsockname(ci_sock_cmn* s, struct sockaddr* sa,
				  socklen_t* salen)
{
  ci_addr_t addr = s->laddr;
  int af = ipcache_af(&s->pkt);

  CI_TEST(sa);
  CI_TEST(salen);

  ci_addr_to_user(sa, salen, af, s->domain, sock_lport_be16(s),
                  CI_IPX_ADDR_PTR(af, addr), s->cp.so_bindtodevice);
}


#endif
/*! \cidoxg_end */
