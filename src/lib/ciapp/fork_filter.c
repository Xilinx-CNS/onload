/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>
#include <unistd.h>


int ci_fork_filter(char* const argv[])
{
  int fd[2], rc;

  CI_TRY_RET(pipe(fd));
  CI_TRY_RET(rc = fork());

  if( rc == 0 ) {	/* child */
    CI_TRY_RET(dup2(fd[1], STDOUT_FILENO));
    CI_TRY_RET(close(fd[0]));
    CI_TRY_RET(close(fd[1]));
    CI_TRY_RET(execvp(argv[0], argv));
  }
  else {		/* parent */
    CI_TRY_RET(dup2(fd[0], STDIN_FILENO));
    CI_TRY_RET(close(fd[0]));
    CI_TRY_RET(close(fd[1]));
  }

  return 0;
}

/*! \cidoxg_end */
