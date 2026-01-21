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
  int full_write;

  va_start(args, fmt);
  full_write = vsnprintf(buf, buflen, fmt, args);
  va_end(args);

  /* vsnprintf returns the number of characters that would have been written
   * (excluding null terminator) if the buffer was large enough.
   * If full_write >= buflen, truncation occurred and only buflen-1 characters
   * were actually written to buf.
   */
  if( full_write > 0 ) {
    size_t bytes_to_write = (full_write >= buflen) ? buflen - 1 : full_write;
    write(fd, buf, bytes_to_write + 1);
  }
}
