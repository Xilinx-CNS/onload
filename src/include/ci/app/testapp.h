/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app */

#ifndef __CI_APP_TESTAPP_H__
#define __CI_APP_TESTAPP_H__

#include <ci/net/ethernet.h>
#include <ci/net/sockopts.h> /* for ci_tcp_info */


/**********************************************************************
****************** Initialisation, cmd line args etc. *****************
**********************************************************************/

/*! Comment? */
typedef struct ci_cfg_desc_s {
  char         short_name;
  const char*  long_name;
  unsigned int type;
# define CI_CFG_FLAG   1
# define CI_CFG_INT    2
# define CI_CFG_UINT   3
# define CI_CFG_STR    4
# define CI_CFG_USAGE  5
# define CI_CFG_FN     6
# define CI_CFG_IRANGE 7
# define CI_CFG_INT64  8
# define CI_CFG_UINT64 9
  void*        value;
  const char*  usage;
  void       (*fn)(const char*, const struct ci_cfg_desc_s*);
  /* for CI_CFG_FN */
} ci_cfg_desc;


/* 'standard' options                      defaults:       */
extern int         ci_cfg_quiet;		/* 0               */
extern int         ci_cfg_verbose;	/* 0               */
extern int         ci_cfg_iter;		/* 1               */
extern int	   ci_cfg_port;		/* 0               */
extern unsigned    ci_cfg_protocol;	/* 6 (IPPROTO_TCP) */
extern const char *ci_cfg_nic_name;     /* "0" */
extern int         ci_cfg_nic_index;    /* 0 */
extern ci_uint8    ci_cfg_shost[ETH_ALEN];
extern ci_uint8    ci_cfg_dhost[ETH_ALEN];

extern int         ci_app_standard_opts;
/*< true - set this to false to turn off standard opts */

extern const char* ci_appname;
extern char*       ci_cmdline;

extern unsigned    ci_app_cpu_khz;


  /*! Initialises a few things, and sets the log prefix to the name of the
  ** application.  [argc] and [argv] are optional (set as zero).
  */
extern void ci_app_startup(int argc, char* argv[]);

  /*! Parse the command line for config options and specify a basic usage
  ** message.  All arguments are optional.
  */
extern void ci_app_getopt(const char* usage, int* argc, char* argv[],
			  const ci_cfg_desc*, int how_many);

  /*! The 'usage' function.  Replace this to customise usage output. */
extern void (*ci_app_usage)(const char* msg);

  /*! The default 'usage' function.  Gives details of the 'standard'
  ** options, and any application-specifed options.
  ** NB: this function does not return. To add extra usage
  ** information, call ci_app_usage_default_noexit() instead.
  */
extern void ci_app_usage_default(const char* msg);
extern void ci_app_usage_default_noexit(const char* msg);

  /*! The section of the default 'usage' function giving details of the
  ** 'standard' options only.
  */
extern void ci_app_usage_standard_default(void);


  /*! Print usage info for config options.  If [opts] is zero, then the
  ** 'standard' options are displayed.
  */
extern void ci_app_opt_usage(const ci_cfg_desc* opts, int n_opts);

  /*! Dump system info to stdout, prefixed with '# '. */
extern void ci_app_dump_sys_info(void);


/**********************************************************************
************************* Useful I/O helpers. *************************
**********************************************************************/

  /*! Reads exactly [len] bytes from [fileno] into [buf].  Returns the
  ** number of bytes actually read.  This will only be less than [len] if
  ** an error or EOF occurred.
  */
extern int  ci_read_exact(int fileno, void* buf, int len);

  /*! Writes exactly [len] bytes to [fileno].  Returns the number of bytes
  ** written.  This will only be less than [len] if an error occurs.
  */
extern int  ci_write_exact(int fileno, const void* buf, int len);

  /*! Reads from the given stream until EOF, and puts the result in a
  ** buffer which is returned in [*pbuf].  This should be used to read the
  ** entire input in one go, and should only be called once for a given
  ** stream.
  **
  ** [*len] will be set to the number of bytes retrieved.  [len_limit]
  ** places an upper-bound on the amount of data that will be consumed.
  */
extern int  ci_swallow_input(int fileno, int len_limit, char** pbuf, size_t* len);

  /*! Returns 0 on success, or -ve error code. */
extern int  ci_app_put_record(int fileno, const void* buf, int bytes);

  /*! Returns 0 on success or EOF.  In the case of EOF, [*bytes_out] is set
  ** to 0.  Returns -E2BIG if the record exceeds the buffer length.  In
  ** this case the entire record is consumed, but the contents of [buf] are
  ** undefined.  For other errors, -1 or an error code is returned.
  */
extern int  ci_app_get_record(int fileno, void* buf, int buf_len,
			      size_t* bytes_out);

  /*! Receives exactly [len] bytes from [sock] into [buf].  Returns the
  ** number of bytes actually read.  This will only be less than [len] if
  ** an error or EOF occurred.
  */
extern int  ci_recv_exact(int sock, void* buf, size_t len, int flags);


/**********************************************************************
******************************** Misc. ********************************
**********************************************************************/

extern void ci_dump_select_set(ci_log_fn_t, const fd_set* fds);


  /*! Dump information about a file descriptor to the log.  Returns -1 if
  ** the file descriptor is bad (closed or -ve).  Otherwise it returns 1
  ** for file descriptors that invoke the efab driver, and 0 for all
  ** others.
  */
extern int ci_fd_dump(int fd);

  /*! Dumps information about all file descriptors up to and including
  ** [max].
  */
extern void ci_fd_dump_all(int max);

  /*! Do sufficient work to keep the CPU busy for the given length of time.
  ** It may of course take longer than the given length of time to complete
  ** if there is contention for the CPU (ie. interrupts, hyperthreading or
  ** scheduling).
  **
  ** The first call will take much longer, as the function calibrates
  ** itself.  For accurate calibration it is important to ensure the
  ** processor is largely idle during this first call.
  */
extern void ci_dummy_work(unsigned usec);

extern void ci_dump_tcp_info(ci_log_fn_t, const struct ci_tcp_info*);


#endif  /* __CI_APP_TESTAPP_H__ */
/*! \cidoxg_end */
