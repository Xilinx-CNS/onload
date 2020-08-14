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
#include <sys/uio.h>


int main(int argc, char* argv[])
{
  char message1[] = "hello,";
  char message2[] = " world\n";
  struct iovec v[2];

  v[0].iov_base = message1;
  v[0].iov_len = sizeof(message1);
  v[1].iov_base = message2;
  v[1].iov_len = sizeof(message2);

  return writev(STDOUT_FILENO, v, 2) == v[0].iov_len + v[1].iov_len ? 0 : 1;
}


/*! \cidoxg_end */
