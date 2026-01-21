/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2026, Advanced Micro Devices, Inc. */

/*
 * Shrub utility functions shared between libciul and shrub_controller.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <etherfabric/internal/shrub_shared.h>


void shrub_log_to_fd(int fd, char* buf, size_t buflen, const char* fmt, ...)
{
  va_list args;
  int len;

  va_start(args, fmt);
  len = vsnprintf(buf, buflen, fmt, args);
  va_end(args);
  write(fd, buf, len + 1);
}
