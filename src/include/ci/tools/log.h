/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */
/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

/*
 * \author  djr
 *  \brief  Functions for logging and pretty-printing.
 *   \date  2002/08/07
 */

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_LOG_H__
#define __CI_TOOLS_LOG_H__

#include <stdarg.h>
#ifndef __KERNEL__
# include <sys/select.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**********************************************************************
 * Logging.
 */

/* size of internal log buffer */ 
#define  CI_LOG_MAX_LINE        512
/* uses of ci_log must ensure that all trace messages are shorter than this */ 
#define  CI_LOG_MAX_MSG_LENGTH        (CI_LOG_MAX_LINE-50)

extern void ci_vlog(const char* fmt, va_list args)  CI_HF;
extern void ci_log(const char* fmt, ...) CI_PRINTF_LIKE(1,2) CI_HF;
extern void ci_log_dump_fn(void* unused, const char* fmt, ...)
                           CI_PRINTF_LIKE(2,3) CI_HF;

  /*! Set the prefix for log messages.
  **
  ** Uses the storage pointed to by \em prefix.  Therefore \em prefix must
  ** be allocated on the heap, or statically.
  */
extern void ci_set_log_prefix(const char* prefix)  CI_HF;

typedef void (*ci_log_fn_t)(const char* msg);
extern ci_log_fn_t  ci_log_fn  CI_HV;

/* Log functions. */
extern void ci_log_null(const char* msg) CI_HF;
extern void ci_log_stderr(const char* msg) CI_HF;
extern void ci_log_stdout(const char* msg) CI_HF;
extern void ci_log_syslog(const char* msg) CI_HF;

/*! Call the following to install special logging behaviours. */
extern void ci_log_buffer_till_fail(void) CI_HF;
extern void ci_log_buffer_till_exit(void) CI_HF;

#ifndef __KERNEL__
extern void __ci_log_unique(const char* msg) CI_HF;
extern ci_log_fn_t __ci_log_unique_fn CI_HV;
ci_inline void ci_log_uniquify(void) {
  if( ci_log_fn != __ci_log_unique ) {
    __ci_log_unique_fn = ci_log_fn;
    ci_log_fn = __ci_log_unique;
  }
}
#endif

extern void ci_log_file(const char* msg) CI_HF;
extern int  ci_log_file_fd CI_HV;

extern void __ci_log_nth(const char* msg) CI_HF;
extern ci_log_fn_t __ci_log_nth_fn CI_HV;
extern int  ci_log_nth_n CI_HV;  /* default 100 */
ci_inline void ci_log_nth(void) {
  if( ci_log_fn != __ci_log_nth ) {
    __ci_log_nth_fn = ci_log_fn;
    ci_log_fn = __ci_log_nth;
  }
}

/* Message ratelimiting functions */
extern void
ci_rlvlog(int* limit, const char* fmt, va_list args) CI_HF;
extern void
ci_rllog(int* limit, const char* fmt, ...) CI_PRINTF_LIKE(2,3) CI_HF;

#define CI_RLLOG(LIMIT, ...) do { \
    static int rate_limit = LIMIT; \
    ci_rllog(&rate_limit, __VA_ARGS__); \
  } while(0)


extern int  ci_log_level  CI_HV;

extern int  ci_log_options  CI_HV;
#define CI_LOG_PID		0x01
#define CI_LOG_TID		0x02
#define CI_LOG_TIME		0x04
#define CI_LOG_DELTA		0x08
#define CI_LOG_CPU		0x10

/**********************************************************************
 * Pretty-printing.
 */

extern char ci_printable_char(char c) CI_HF;

extern void (*ci_hex_dump_formatter)(char* buf, const ci_octet* s,
				     int i, int off, int len) CI_HV;
extern void ci_hex_dump_format_octets(char*,const ci_octet*,int,int,int) CI_HF;
extern void ci_hex_dump_format_single_octets(char*,const ci_octet*,int,int,int) CI_HF;
extern void ci_hex_dump_format_dwords(char*,const ci_octet*,int,int,int) CI_HF;

extern void (*ci_hex_dump_stringifier)(char* buf, const ci_octet* s,
				       int offset, int len) CI_HV;
extern void ci_hex_dump_format_stringify(char*,const ci_octet*,int,int) CI_HF;

extern void ci_hex_dump_row(char* buf, volatile const void* s, int len,
			    ci_ptr_arith_t address) CI_HF;
  /*!< A row contains up to 16 bytes.  Row starts at [address & 15u], so
  ** therefore [len + (address & 15u)] must be <= 16.
  */

extern void ci_hex_dump(ci_log_fn_t, volatile const void*,
			int len, ci_ptr_arith_t address) CI_HF;

extern int  ci_hex_dump_to_raw(const char* src_hex, void* buf,
			       unsigned* addr_out_opt, int* skip)  CI_HF;
  /*!< Recovers raw data from a single line of a hex dump.  [buf] must be at
  ** least 16 bytes long.  Returns the number of bytes written to [buf] (in
  ** range 1 -> 16), or -1 if [src_hex] doesn't contain hex data.  Does not
  ** cope with missing bytes at the start of a line.
  */

extern int ci_format_eth_addr(char* buf, const void* eth_mac_addr,
			      char sep)  CI_HF;
  /*!< This will write 18 characters to <buf> including terminating null.
  ** Returns number of bytes written excluding null.  If [sep] is zero, ':'
  ** is used.
  */

extern int ci_parse_eth_addr(void* eth_mac_addr,
			     const char* str, char sep) CI_HF;
  /*!< If [sep] is zero, absolutely any separator is accepted (even
  ** inconsistent separators).  Returns 0 on success, -1 on error.
  */

extern int ci_format_ip4_addr(char* buf, unsigned addr_be32) CI_HF;
  /*!< Formats the IP address (in network endian) in dotted-quad.  Returns
  ** the number of bytes written (up to 15), excluding the null.  [buf]
  ** must be at least 16 bytes long.
  */

/**********************************************************************
 * Error checking.
 */

#ifdef __GNUC__
# define CI_NORETURN __attribute__((noreturn)) void
#else
# define CI_NORETURN void
#endif

extern CI_NORETURN (*ci_fail_stop_fn)(void) CI_HV;

#ifndef __KERNEL__
extern CI_NORETURN ci_fail_exit(void) CI_HF;
extern CI_NORETURN ci_fail_hang(void) CI_HF;
extern CI_NORETURN ci_fail_stop(void) CI_HF;
extern CI_NORETURN ci_fail_abort (void) CI_HF;
#endif
extern CI_NORETURN ci_fail_bomb(void) CI_HF;
extern void ci_backtrace(void) CI_HF;

extern CI_NORETURN
__ci_fail(const char* fmt, ...) CI_PRINTF_LIKE(1,2) CI_HF;

#define ci_warn(x)							   \
  do{ ci_log("WARN at %s:%d", __FILE__, __LINE__); }while(0)

#define ci_fail(x)							   \
  do{ ci_log("FAIL at %s:%d", __FILE__, __LINE__);  __ci_fail x; }while(0)

extern void __ci_sys_fail(const char* fn, int rc,
			  const char* file, int line) CI_HF;
#define ci_sys_fail(fn, rc)  __ci_sys_fail(fn, rc, __FILE__, __LINE__)

/**********************************************************************
 * Logging to buffer (src/citools/log_buffer.c)
 */

/*! Divert ci_log() messages to the log buffer
 *  normally they go to the  system console */
extern void ci_log_buffer_till_fail(void) CI_HF;

/*! Dump the contents of the log buffer to the system console */
extern void ci_log_buffer_dump(void) CI_HF;


/**********************************************************************
 * Some useful pretty-printing.
 */

#define CI_SOCKCALL_FLAGS_FMT	"%s%s%s%s%s%s%s%s%s%s%s"

#define CI_SOCKCALL_FLAGS_PRI_ARG(x)		\
  (((x) & MSG_OOB         ) ? "OOB "         :""),	\
  (((x) & MSG_PEEK        ) ? "PEEK "        :""),	\
  (((x) & MSG_DONTROUTE   ) ? "DONTROUTE "   :""),	\
  (((x) & MSG_EOR         ) ? "EOR "         :""),	\
  (((x) & MSG_CTRUNC      ) ? "CTRUNC "      :""),	\
  (((x) & MSG_TRUNC       ) ? "TRUNC "       :""),	\
  (((x) & MSG_WAITALL     ) ? "WAITALL "     :""),	\
  (((x) & MSG_DONTWAIT    ) ? "DONTWAIT "    :""),	\
  (((x) & MSG_NOSIGNAL    ) ? "NOSIGNAL "    :""),	\
  (((x) & MSG_ERRQUEUE    ) ? "ERRQUEUE "    :""),	\
  (((x) & MSG_CONFIRM     ) ? "CONFIRM "     :"")

/* To make a string from an arbitrary macro (such as CI_CFG_MAX_HWPORTS), use
 * OO_STRINGIFY(CI_CFG_MAX_HWPORTS). */
#define OO_STRINGIFY1(x) #x
#define OO_STRINGIFY(x) OO_STRINGIFY1(x)

#ifdef __cplusplus
}
#endif

#endif  /* __CI_TOOLS_LOG_H__ */
/*! \cidoxg_end */
