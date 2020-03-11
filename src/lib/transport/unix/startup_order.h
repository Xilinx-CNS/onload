/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/* First of all, allow to use ci_log */
STARTUP_ITEM(CITP_INIT_LOGGING, citp_setup_logging_early)

/* resolve ci_sys_* symbols for a 'basic' set of syscalls, sufficient to get
 * other early-init libraries functional */
STARTUP_ITEM(CITP_INIT_BASIC_SYSCALLS, citp_basic_syscall_init)

/* resolve ci_sys_* symbols: now we fake-hanlde the intercepted calls.
 * The only calls we really handle here are exec*() */
STARTUP_ITEM(CITP_INIT_SYSCALLS, citp_syscall_init)

/* We can't easily fake-fandle execl*() functions, so we should prepare
 * to handle them properly ASAP. */
STARTUP_ITEM(CITP_INIT_ENVIRON, citp_environ_init)

/* read efabcfg database */
STARTUP_ITEM(CITP_INIT_CFG, citp_cfg_init)
/* init CITP_OPTS, including CITP_OPTS.log_level:
 * logging fully-functional now. */
STARTUP_ITEM(CITP_INIT_TRANSPORT, citp_transport_init)
/* onload extension library */
STARTUP_ITEM(CITP_INIT_ONLOADEXT, oo_extensions_init)
/* fork hooks should be ready (but disabled) before fdtable and netif */
STARTUP_ITEM(CITP_INIT_FORK_HOOKS, ci_setup_fork)
/* fdtable */
STARTUP_ITEM(CITP_INIT_FDTABLE, citp_fdtable_ctor)

/* init citp_netif_info */
STARTUP_ITEM(CITP_INIT_NETIF, citp_netif_init_ctor)

/* handle TCP and UDP protocols: now we are going to properly handle all
 * the intercepted functions. */
STARTUP_ITEM(CITP_INIT_PROTO, citp_transport_register)
