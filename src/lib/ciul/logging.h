/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  Logging functions.
**   \date  2007/05/18
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_ul */
#ifndef __EF_VI_LOGGING_H__
#define __EF_VI_LOGGING_H__


#if !defined(__KERNEL__)
extern int ef_log_level;
#endif

extern __printf(1, 2) void ef_log(const char* fmt, ...);

#ifdef __KERNEL__
# define EF_VI_LOG(l,x)
#else
# define EF_VI_LOG(l,x)	do{ if(unlikely(ef_log_level>=(l))) {x;} }while(0)
#endif

#define LOGAV(x)	EF_VI_LOG(1,x)
#ifdef NDEBUG
# define LOG(x)
# define LOGV(x)
# define LOGVV(x)
# define LOGVVV(x)
#else
# define LOG(x)         do { x; } while(0)
# define LOGV(x)	EF_VI_LOG(1,x)
# define LOGVV(x)	EF_VI_LOG(2,x)
# define LOGVVV(x)	EF_VI_LOG(3,x)
#endif


#endif  /* __EF_VI_LOGGING_H__ */
