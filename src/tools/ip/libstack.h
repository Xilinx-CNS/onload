/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  cgg
**  \brief  Header to provide access to UL stack and socket functions
**   \date  2005/01/19
**    \cop  (c) Solarflare Communications Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_tests_ef */

#ifndef _CI_LIB_STACK_H
#define _CI_LIB_STACK_H

#include <ci/internal/ip.h> /* for ef_driver_handle */
#include <onload/driveraccess.h>
#include <onload/debug_intf.h>
#include <onload/signals.h>

#ifdef __cplusplus
extern "C" {
#endif


#define FL_NO_LOCK		0x1       /* netif lock not needed  */
#define FL_LOCK_SOCK		0x2       /* sock lock is needed    */
#define FL_ARG_U                0x4       /* args: unsigned         */
#define FL_ARG_X                0x8       /* args: unsigned hex     */
#define FL_ARG_SV               0x10      /* args: string, variant */
#define FL_TCPA                 0x20      /* any TCP socket needed  */
#define FL_TCPC                 0x40      /* TCP connection needed  */
#define FL_UDP                  0x80      /* UDP socket needed      */
#define FL_ONCE                 0x100     /* only apply to first stack */
#define FL_ARG_S                0x200     /* args: string           */
#define FL_ID                   0x400     /* op takes ID instead of netif */

#define MAX_TS		32


const static int STACK_END_MARKER = -1;
const static int SOCK_END_MARKER  = -1;
const static int SOCK_ALL_MARKER  = -2;

#if 0
#define STACK_LOG_DUMP(x) (x)
#else
#define STACK_LOG_DUMP(x)
#endif

/**********************************************************************
********************** config *****************************************
**********************************************************************/

extern int		cfg_lock;
extern int		cfg_nolock;
extern int		cfg_blocklock;
extern int		cfg_nosklock;
extern int		cfg_dump;
extern int		cfg_watch_msec;
extern unsigned		cfg_usec;
extern unsigned		cfg_samples;
extern int		cfg_notable;
extern int		cfg_zombie;
extern int              cfg_nopids;
extern int		ci_cfg_verbose;
extern const char*	cfg_filter;

/**********************************************************************
********************** stacks *****************************************
**********************************************************************/

    
typedef struct {
  ci_netif	ni;
  ci_tcp_state	ts[MAX_TS];
  int		changed[MAX_TS];
  ci_dllink	link;
} netif_t;


/* Arguments for ops are stored here. */
extern uint64_t    arg_u[1];
extern const char* arg_s[2];

typedef struct stack_op_s stack_op_t;
    
typedef void stackop_fn_t(const stack_op_t *op, void *arg);
typedef void stack_ni_fn_t(ci_netif *ni);
typedef void stackid_fn_t(int id, void *arg);
typedef int stackfilter_t(ci_netif_info_t *info);
    
struct stack_op_s {
  const char*	name;
  stack_ni_fn_t*fn;   /* used when !(flags & FL_ID) */
  stackid_fn_t *id_fn; /* used when  (flags & FL_ID) */
  const char*   help;
  const char*   args;
  int           n_args;
  unsigned	flags;
} /* stack_op_t */;

extern void for_each_stack_op(stackop_fn_t *fn, void * arg);
extern const stack_op_t* get_stack_op(const char *name);
extern void for_each_stack(stack_ni_fn_t *fn, int only_once);
extern void for_each_stack_id(stackid_fn_t *fn, void *arg);
extern void list_all_stacks2(stackfilter_t *filter,
                             stack_ni_fn_t *post_attach,
                             stack_ni_fn_t *pre_detach,
                             oo_fd *p_fd);
extern int stack_attach(unsigned id);
extern void stack_detach(netif_t* n, int locked);
extern void stacks_detach_all(void);
extern netif_t* stack_attached(int id);

/**********************************************************************
********************** sockets ****************************************
**********************************************************************/

typedef struct socket_op_s socket_op_t;
    
typedef void socketop_fn_t(const socket_op_t *op, void *arg);
typedef void socket_ni_fn_t(ci_netif*, ci_tcp_state*);

struct socket_op_s {
  const char*	name;
  socket_ni_fn_t*fn;
  const char*   help;
  const char*   args;
  int           n_args;
  unsigned	flags;
} /* socket_op_t */;


extern void for_each_socket_op(socketop_fn_t *fn, void * arg);
extern const socket_op_t *get_socket_op(const char *name);

extern void for_each_socket(const socket_op_t* op);
extern void socket_add(int stack_id, int sock_id);
extern void socket_add_all(int stack_id);
extern void socket_add_all_all(void);

extern void sockets_bw(void);
extern void sockets_watch_bw(void);
extern void sockets_watch(void);

/**********************************************************************
********************** libstack ***************************************
**********************************************************************/

extern int /*rc*/ libstack_init(sa_sigaction_t* signal_handlers);
extern void libstack_stack_mapping_print(void);
extern void libstack_pid_mapping_print(void);
extern int libstack_env_print(void);
extern int libstack_threads_print(void);
extern void libstack_end(void);
extern int libstack_netif_lock(ci_netif* ni);
extern void libstack_netif_unlock(ci_netif* ni);
extern int libstack_netif_trylock(ci_netif* ni);

#ifdef __cplusplus
}
#endif


#endif /* _CI_LIB_STACK_H */


