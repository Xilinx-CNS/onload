/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __RTT_H__
#define __RTT_H__

#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>


struct rtt_endpoint {
  void (*ping)(struct rtt_endpoint*);
  void (*pong)(struct rtt_endpoint*);
  void (*cleanup)(struct rtt_endpoint*);
  void (*reset_stats)(struct rtt_endpoint*);
  void (*dump_info)(struct rtt_endpoint*, FILE*);
};


struct rtt_options {
  size_t  ping_frame_len;
  size_t  pong_frame_len;
  int     n_warm_ups;
  int     n_iters;
  int     inter_iter_gap_ns;
};


#define RTT_TEST(x)                                                     \
  ({                                                                    \
    typeof(x) __x = (x);                                                \
    if( ! __x ) {                                                       \
      fprintf(stderr, "ERROR: %s: TEST(%s) failed\n", __func__, #x);    \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      fprintf(stderr, "ERROR: errno=%d (%s)\n", errno, strerror(errno)); \
      abort();                                                          \
    }                                                                   \
    __x;                                                                \
  })


#define RTT_TRY(x)                                                      \
  ({                                                                    \
    int __rc = (x);                                                     \
    if( __rc < 0 ) {                                                    \
      fprintf(stderr, "ERROR: %s: TRY(%s) failed\n", __func__, #x);     \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",                   \
              __rc, errno, strerror(errno));                            \
      abort();                                                          \
    }                                                                   \
    __rc;                                                               \
  })


#define CONTAINER_OF(c_type, mbr_name, p_mbr)                   \
  ( (c_type*) ((char*)(p_mbr) - offsetof(c_type, mbr_name)) )


enum rtt_dir {
  RTT_DIR_TX   = 0x1,
  RTT_DIR_RX   = 0x2,
};


typedef int rtt_constructor_fn(struct rtt_endpoint** ep_out,
                               const struct rtt_options*, unsigned dirs,
                               const char** args, int n_args);

extern rtt_constructor_fn rtt_tcp_build_endpoint;
extern rtt_constructor_fn rtt_udp_build_endpoint;
extern rtt_constructor_fn rtt_efvi_build_endpoint;


extern int rtt_err(const char* fmt, ...);


#endif  /* __RTT_H__ */
