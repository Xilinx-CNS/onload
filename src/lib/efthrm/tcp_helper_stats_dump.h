/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __TCP_HELPER_STATS_DUMP_H__
#define __TCP_HELPER_STATS_DUMP_H__


void dump_stack_to_logger(void* netif, oo_dump_log_fn_t logger, void* log_arg);

void full_netif_dump_to_logger(void* netif, oo_dump_log_fn_t logger,
                               void* log_arg);

void full_netif_dump_extra_to_logger(void* netif, oo_dump_log_fn_t logger,
                                     void* log_arg);

void full_dump_sockets_to_logger(void* netif, oo_dump_log_fn_t logger,
                                 void* log_arg);

void full_dump_stack_stat_to_logger(void* netif, oo_dump_log_fn_t logger,
                                    void* log_arg);

void full_dump_stack_more_stat_to_logger(void* netif, oo_dump_log_fn_t logger,
                                         void* log_arg);

void full_dump_ip_stats_to_logger(void* netif, oo_dump_log_fn_t logger,
                                  void* log_arg);

void full_dump_tcp_stats_to_logger(void* netif, oo_dump_log_fn_t logger,
                                   void* log_arg);

void full_dump_tcp_ext_stats_to_logger(void* netif, oo_dump_log_fn_t logger,
                                       void* log_arg);

void full_dump_udp_stats_to_logger(void* netif, oo_dump_log_fn_t logger,
                                   void* log_arg);

void full_dump_netif_config_opts_to_logger(void* netif, oo_dump_log_fn_t logger,
                                           void* log_arg);

void full_dump_stack_time_to_logger(void* netif, oo_dump_log_fn_t logger,
                                    void* log_arg);

/*! Dump a stack's netif and sockets state to a buffer or (if NULL) to syslog */
int tcp_helper_dump_stack(unsigned id, unsigned orphan_only, void* user_buf,
                          int user_buf_len, int op);

#endif  /* __TCP_HELPER_STATS_DUMP_H__ */
