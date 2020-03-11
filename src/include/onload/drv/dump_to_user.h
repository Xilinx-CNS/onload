/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_DRV_DUMP_TO_USER_H__
#define __ONLOAD_DRV_DUMP_TO_USER_H__


typedef void (*oo_dump_log_fn_t)(void* log_fn_arg, const char* fmt, ...)
  __attribute__((format(printf,2,3)));

typedef void (*oo_dump_fn_t)(void* oo_dump_fn_arg, oo_dump_log_fn_t log,
                             void* log_arg);

extern int oo_dump_to_user(oo_dump_fn_t, void* dump_fn_arg,
                           void* user_buf, int user_buf_len);


#endif  /* __ONLOAD_DRV_DUMP_TO_USER_H__ */
