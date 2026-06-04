/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2025, Advanced Micro Devices, Inc. */

#ifndef CI_TOOLS_ONLOAD_SERVER_H
#define CI_TOOLS_ONLOAD_SERVER_H

#include <stdarg.h>
#include <stdbool.h>

#define CI_DAEMON_LOG_TO_KERN (1u << 0)
#define CI_DAEMON_CHDIR_ROOT  (1u << 1)
#define CI_DAEMON_CLOSE_FDS   (1u << 2)

extern CI_NORETURN ci_server_init_failed_v(const char* srv_name,
                                           const char* msg, va_list args);

extern CI_NORETURN ci_server_init_failed(const char* srv_name,
                                         const char* msg, ...);

extern void ci_server_set_log_prefix(char** log_prefix, const char* srv_bin);

extern void ci_server_daemonise(char** log_prefix,
                                const char* srv_name, const char* srv_bin,
                                unsigned flags);

#endif /* CI_TOOLS_ONLOAD_SERVER_H */
