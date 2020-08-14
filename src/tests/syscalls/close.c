/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2005 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  mjs
**  \brief  Test closing file descriptors beyond normal range
**   \date  2005/03/29
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_tests_syscalls */
 
#include <stdio.h>
#include <unistd.h>

int main(void)
{
  int i;

  for (i=3; i<8192; i++) {
    printf("closing %d\n", i);
    close(i);
  }

  return 0;
}

/*! \cidoxg_end */

