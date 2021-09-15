/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2019 Xilinx, Inc. */
#ifndef WIRE_ORDER_H
#define WIRE_ORDER_H

/* Default port the server runs on */
#define DEFAULT_PORT              2048

/* Default size of the listen queue */
#define DEFAULT_LISTEN_BACKLOG    100

/* Default number of events to request in onload_ordered_epoll_wait() */
#define DEFAULT_MAX_EPOLL_EVENTS  10

/* Flags for configuring the server setup. */
#define WIRE_ORDER_CFG_FLAGS_UDP 1

#define WIRE_ORDER_CFG_LEN 8
#define WIRE_ORDER_CFG_FLAGS_OFST 0
#define WIRE_ORDER_CFG_N_SOCKS_OFST 4

#ifdef __has_attribute
#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#endif
#endif

#ifndef fallthrough
#define fallthrough do{}while(0) /*fallthrough*/
#endif

#endif /* WIRE_ORDER_H */
