/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2006-2020 Xilinx, Inc. */
#include <internal.h>

# include <onload/common.h>
# include <ci/internal/trampoline.h>
# include <asm/unistd.h>
#include <onload/ul/tcp_helper.h>
#include <onload/signals.h>


int
citp_init_trampoline(ci_fd_t fd)
{
  int rc;
  int i;
  ci_tramp_reg_args_t args;

  args.max_signum = NSIG;
  CI_USER_PTR_SET(args.signal_handler_postpone, citp_signal_intercept);
  for( i = 0; i <= OO_SIGHANGLER_DFL_MAX; i++ )
    CI_USER_PTR_SET(args.signal_handlers[i], citp_signal_handlers[i]);
  CI_USER_PTR_SET(args.signal_data, citp_signal_data);
  CI_USER_PTR_SET(args.signal_sarestorer, citp_signal_sarestorer_get());
  args.sa_onstack_intercept = CITP_OPTS.sa_onstack_intercept;

  rc = ci_sys_ioctl (fd, OO_IOC_IOCTL_TRAMP_REG, &args);

  if(rc == -1)
    ci_log ("Error %d registering trampoline handler", errno);

  return rc;
}

