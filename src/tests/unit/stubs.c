/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2022 AMD, Inc. */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

/* Resolve references to global variables */
__attribute__ ((weak)) unsigned ci_tp_log = 0;
__attribute__ ((weak)) unsigned ci_tp_max_dump = 0;
__attribute__ ((weak)) void (*ci_log_fn)(const char* msg) = NULL;
__attribute__ ((weak)) int  (*ci_sys_ioctl)(int, long unsigned int, ...) = NULL;

/* Allow the unit under test to call ci_log (with no effect) */
__attribute__ ((weak)) void ci_log(const char* fmt, ...) {}

