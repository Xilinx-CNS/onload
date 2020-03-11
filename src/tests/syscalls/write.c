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
  char message[] = "hello, world\n";

  return write(STDOUT_FILENO, message, sizeof(message)-1) == sizeof(message)-1
    ? 0 : 1;
}

/*! \cidoxg_end */
