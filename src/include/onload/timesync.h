/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#ifndef __TIMESYNC_H__
#define __TIMESYNC_H__

#if !defined(UNIT_TEST_EPOLL) && defined(__KERNEL__)
#include <linux/eventpoll.h>
#else
#define NSEC_PER_MSEC 1000000L
#define NSEC_PER_SEC  1000000000L
#endif /* !defined(UNIT_TEST_EPOLL) */

/* Require a frequency of at least 400MHz  */
#define TIMESYNC_MIN_CPU_KHZ 400000ULL
/* Code assumes a max CPU frequency of 10GHz */
#define TIMESYNC_MAX_CPU_KHZ 10000000ULL

#endif /* __TIMESYNC_H__ */
