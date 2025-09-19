/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2025, Advanced Micro Devices, Inc. */

#ifndef CI_TOOLS_ONLOAD_SERVER_H
#define CI_TOOLS_ONLOAD_SERVER_H

#include <stdbool.h>

extern CI_NORETURN ci_server_init_failed(const char* srv_name,
                                         const char* msg, ...);

extern void ci_server_set_log_prefix(char** log_prefix, const char* srv_bin);

extern void ci_server_daemonise(bool log_to_kern, char** log_prefix,
                                const char* srv_name, const char* srv_bin);

#endif /* CI_TOOLS_ONLOAD_SERVER_H */
