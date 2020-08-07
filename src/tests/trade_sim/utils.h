/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2019 Xilinx, Inc. */
#ifndef __UTILS_H__
#define __UTILS_H__


#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <errno.h>


#ifndef MAP_HUGETLB
/* Not always defined in glibc headers.  If the running kernel does not
 * understand this flag it will ignore it and you may not get huge pages.
 * (In that case ef_memreg_alloc() may fail when using packed-stream mode).
 */
# define MAP_HUGETLB  0x40000
#endif


#ifdef __PPC__
# define huge_page_size    (16ll * 1024 * 1024)
#elif defined(__x86_64__) || defined(__i386__)
# define huge_page_size    (2ll * 1024 * 1024)
#elif defined(__aarch64__)
# define huge_page_size    (2ll * 1024 * 1024)
#else
# error "Please define huge_page_size"
#endif


#define TRY(x)                                                  \
  do {                                                          \
    int __rc = (x);                                             \
    if( __rc < 0 ) {                                            \
      fprintf(stderr, "ERROR: TRY(%s) failed\n", #x);           \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",           \
              __rc, errno, strerror(errno));                    \
      abort();                                                  \
    }                                                           \
  } while( 0 )


#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: TEST(%s) failed\n", #x);          \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      abort();                                                  \
    }                                                           \
  } while( 0 )


#ifndef SO_TIMESTAMPING
# define SO_TIMESTAMPING                 37
#endif
#ifndef SOF_TIMESTAMPING_TX_HARDWARE
# define SOF_TIMESTAMPING_TX_HARDWARE    (1<<0)
# define SOF_TIMESTAMPING_TX_SOFTWARE    (1<<1)
# define SOF_TIMESTAMPING_RX_HARDWARE    (1<<2)
# define SOF_TIMESTAMPING_RX_SOFTWARE    (1<<3)
# define SOF_TIMESTAMPING_SOFTWARE       (1<<4)
# define SOF_TIMESTAMPING_SYS_HARDWARE   (1<<5)
# define SOF_TIMESTAMPING_RAW_HARDWARE   (1<<6)
#endif


extern void sock_put_int(int sock, int i);
extern int sock_get_int(int sock);

extern int sock_get_ifindex(int sock, int* ifindex_out);

extern int getaddrinfo_storage(int family,
                               const char* host, const char* port,
                               struct sockaddr_storage* sas);

extern int mk_socket(int family, int socktype,
                     int op(int sockfd, const struct sockaddr *addr,
                            socklen_t addrlen),
                     const char* host, const char* port);


/* Helper functions to query host configuration */
extern void get_ipaddr_of_intf(const char* intf, char** ipaddr_out);
extern void get_ipaddr_of_vlan_intf(const char* intf, int vlan,
                                    char** ipaddr_out);
extern int my_getaddrinfo(const char* host, const char* port,
                          struct addrinfo**ai_out);
extern int parse_host(const char* s, struct in_addr* ip_out);
extern int parse_interface(const char* s, int* ifindex_out);


#endif  /* __UTILS_H__ */
