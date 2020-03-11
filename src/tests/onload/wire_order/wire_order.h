/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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

#endif /* WIRE_ORDER_H */
