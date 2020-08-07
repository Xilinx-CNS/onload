/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  slp
**  \brief  Interface for invoking debug ops on resources.
**   \date  2004/08/30
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */

#ifndef __ONLOAD_DEBUG_OPS_H__
#define __ONLOAD_DEBUG_OPS_H__

#include <onload/unix_intf.h>


#if ! CI_CFG_UL_INTERRUPT_HELPER
typedef struct {
  ci_fd_t fp;
  int stack_id;
  int orphan_only;
  int op;
} dump_stack_args;

/*! dump inode for a file descriptor */
ci_inline int
oo_debug_dump_stack(void* opaque, void* buf, int buf_len)
{
  int rc;
  dump_stack_args* args = opaque;
  ci_debug_onload_op_t op;
  op.what = args->op;
  op.u.dump_stack.stack_id = args->stack_id;
  op.u.dump_stack.orphan_only = args->orphan_only;
  CI_USER_PTR_SET(op.u.dump_stack.user_buf, buf);
  op.u.dump_stack.user_buf_len = buf_len;
  rc = oo_debug_op(args->fp, &op);
  return rc;
}


ci_inline int
oo_debug_kill_stack(ci_fd_t fp, int stack_id) 
{
  int rc;
  ci_debug_onload_op_t op;
  op.what = __CI_DEBUG_OP_KILL_STACK__;
  op.u.stack_id = stack_id;
  rc = oo_debug_op(fp, &op);
  return rc;
}
#endif

#endif  /* __ONLOAD_DEBUG_OPS_H__ */
/*! \cidoxg_end */
