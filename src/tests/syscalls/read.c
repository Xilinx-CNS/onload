/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2004 Xilinx, Inc. */
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

/*! \cidoxg_tests_syscalls */

#include <unistd.h>


int main(int argc, char* argv[])
{
  char buf[1];

  return read(STDIN_FILENO, buf, 1) == 1 ? 0 : 1;
}

/*! \cidoxg_end */
