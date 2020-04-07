#define _GNU_SOURCE
#include <stdio.h>
#include <ci/app.h>
#include <ci/tools/utils.h> /* for toeplitz hash */
#include <onload/extensions.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>


#define ENV_VAR "LD_TPROXY_PRELOAD"

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT	19
#endif

#define RSS_KEY_LEN 40

/* this is the hash key used by onload */
static const ci_uint8 rx_hash_key[RSS_KEY_LEN] = {
  0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
  0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
  0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
  0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
  0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
};


enum {
  HASH_NONE = 0,
  HASH_SRC = 0x1,
  HASH_DST = 0x2,
  HASH_ALL = HASH_SRC | HASH_DST,
};


static const char* hash_type_names[4] = {
  "none", "src", "dst", "all" };

static int (*original_listen)(int sockfd, int backlog);
static int (*original_connect)(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen);

static void store_le32(ci_uint8** b, ci_uint32 v)
{
  memcpy(*b, &v, sizeof(v));
  *b += sizeof(v);
}

static void store_16B(ci_uint8** b, const uint8_t* bytes)
{
  memcpy(*b, bytes, 16);
  *b += 16;
}


static void store_le16(ci_uint8** b, ci_uint16 v)
{
  memcpy(*b, &v, sizeof(v));
  *b += sizeof(v);
}


ci_uint8 t[36][256];
ci_uint8 t_div[128];

static void hash_table_prepare(int size)
{
  int j;
  for(j = 0; j < 128; ++j)
    t_div[j] = j % size;
}

static void toeplitz_hash_prepare(void)
{
  int i, j;
  for(i = 0; i < 36; ++i ) {
    for(j = 0;j < 256;++j) {
      ci_uint8 d[36] = {};
      d[i] = j;
      t[i][j] = ci_toeplitz_hash(rx_hash_key, d, sizeof(d));
    }
  }
}

ci_uint8 toeplitz_hash_get(const ci_uint8* d, int size)
{
  int i;
  int v = 0;
  for(i = 0; i < size; ++i, ++d)
    v ^= t[i][*d];
  return t_div[v & 0x7F];
}


/* Come up with the same hash as hardware */
static int gen_hash(int hash_type,
             const struct sockaddr_in *laddr,
             const struct sockaddr_in *raddr)
{
  ci_uint8 b[12];
  ci_uint8* bp = b;
  unsigned v;
  if( raddr && (hash_type & HASH_SRC) )
    store_le32(&bp, raddr->sin_addr.s_addr);
  if( laddr && (hash_type & HASH_DST) )
    store_le32(&bp, laddr->sin_addr.s_addr);
  if( raddr && (hash_type & HASH_SRC) )
    store_le16(&bp, raddr->sin_port);
  if( laddr && (hash_type & HASH_DST) )
    store_le16(&bp, laddr->sin_port);
  if( bp == b ) return -1;
  v = toeplitz_hash_get(b, bp - b);
  return v;
}

/* Come up with the same hash as hardware */
static int gen_hash6(int hash_type,
             const struct sockaddr_in6 *laddr,
             const struct sockaddr_in6 *raddr)
{
  ci_uint8 b[36];
  ci_uint8* bp = b;
  unsigned v;
  if( raddr && (hash_type & HASH_SRC) )
    store_16B(&bp, raddr->sin6_addr.s6_addr);
  if( laddr && (hash_type & HASH_DST) )
    store_16B(&bp, laddr->sin6_addr.s6_addr);
  if( raddr && (hash_type & HASH_SRC) )
    store_le16(&bp, raddr->sin6_port);
  if( laddr && (hash_type & HASH_DST) )
    store_le16(&bp, laddr->sin6_port);
  if( bp == b ) return -1;
  v = toeplitz_hash_get(b, bp - b);
  return v;
}

static struct context {
  int do_transparent;
  int do_bind;
  int hash_type;
  int hash_size;
  int hash_id;
  struct in_addr bind_start;
  struct in_addr bind_end;
} tlisten = {}, tconnect = {};

static struct context6 {
  int do_transparent;
  int do_bind;
  int hash_type;
  int hash_size;
  int hash_id;
  struct in6_addr bind_start;
  struct in6_addr bind_end;
} tlisten6 = {}, tconnect6 = {};

static int verbose = 0;

#define IP_FMT "%s"
#define IP_PORT_FMT "%s:%d"
#define IP6_PORT_FMT "[%s]:%d"
#define IP_PRM(af,a) (&({ \
  struct { char buf[INET6_ADDRSTRLEN ] ;} s; \
  inet_ntop(af, a, s.buf, sizeof(s.buf)); \
  s; }).buf[0])
#define IP_PORT_PRM(af,a,p) IP_PRM(af,a), ntohs(p)

static void apply(struct context* c, int sockfd,
                  const struct sockaddr_in *raddr)
{
  if ( ! c->do_transparent )
    return;
  int on = 1;
  if( setsockopt(sockfd, SOL_IP, IP_TRANSPARENT, &on, sizeof on) ) {
    fprintf(stderr, "tproxy_preload: ERROR: Setting transparent failed "
            "with rc %d\n", errno);
    return;
  }
  if( ! c->do_bind )
    return;

  int bind_retries = 100;
  int i;
  int rc = 0;
  /* We do not track addresses used so occasional
    * collision and bind failure might be possible.
    */
  for( i = 0; i < bind_retries; ++i ) {
    struct sockaddr_in addr = {};
    addr.sin_addr.s_addr =
        htonl(ntohl(c->bind_start.s_addr) + rand() % (1 +
              ntohl(c->bind_end.s_addr) - ntohl(c->bind_start.s_addr)));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((rand() % 65000) + 1);
    if( (c->hash_type & HASH_DST) ) {
      if( c->hash_id < 0 ) {
        struct onload_stat s = {};
        rc = onload_fd_stat(sockfd, &s);
        if( rc != 1 || s.stack_name == NULL )
          return;
        fprintf(stderr, "%s", s.stack_name);
        sscanf(strrchr(s.stack_name, '-'), "-c%d", &c->hash_id);
        fprintf(stderr, "%d", c->hash_id);
      }
      while( gen_hash(c->hash_type, &addr, raddr) != c->hash_id ) {
        /* hardware on this RSS will not support this */
        if( verbose >= 2 )
          fprintf(stderr, "tproxy_preload: not binding to "IP_PORT_FMT" as will not "
                          "match RSS got %d vs wanted %d\n",
                          IP_PORT_PRM(AF_INET, &addr.sin_addr, addr.sin_port),
                          gen_hash(c->hash_type, &addr, raddr),
                          c->hash_id);
        ++addr.sin_port;
      }
    }
    /* we do not want addresses ending with .0 */
    if( (ntohl(addr.sin_addr.s_addr) & 0xFF) == 0 || addr.sin_port == 0)
      continue;
    if( verbose )
      fprintf(stderr, "tproxy_preload: binding %d, to "IP_PORT_FMT"\n",
              sockfd, IP_PORT_PRM(AF_INET, &addr.sin_addr, addr.sin_port));
    rc = bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
    if( rc == 0 || errno != EADDRINUSE )
      break;
  }
  if( rc != 0 && errno != EINPROGRESS ) {
    if( errno == EINVAL ) {
      if( verbose ) {
        /* EINVAL often means that socket is already bound */
        struct sockaddr_in addr = {};
        socklen_t alen = sizeof(addr);
        rc = getsockname(sockfd, &addr, &alen);
        fprintf(stderr, "tproxy_preload: ERROR: already bound to "
                IP_PORT_FMT" rc %d\n",
                IP_PORT_PRM(AF_INET, &addr.sin_addr, addr.sin_port), rc);
      }
      /* otherwise ignore EINVAL as would produce
        * flood of message with ab */
    }
    else
      fprintf(stderr, "tproxy_preload: ERROR: Transparent bind failed "
              "with rc %d\n", errno);
  }
}

static void apply6(struct context6* c, int sockfd,
                   const struct sockaddr_in6 *raddr)
{
  if ( ! c->do_transparent )
    return;
  int on = 1;
  if( setsockopt(sockfd, SOL_IP, IP_TRANSPARENT, &on, sizeof on) ) {
    fprintf(stderr, "tproxy_preload: ERROR: Setting transparent failed "
            "with rc %d\n", errno);
    return;
  }
  if( ! c->do_bind )
    return;

  int bind_retries = 100;
  int i;
  int rc = 0;
  /* We do not track addresses used so occasional
    * collision and bind failure might be possible.
    */
  for( i = 0; i < bind_retries; ++i ) {
    struct sockaddr_in6 addr = {};
    addr.sin6_addr = c->bind_start;
    /* TODO: Make sure s6_addr is in valid range
     * currently we just dodge bottom 24 bit */
    int v = rand();
    int j;
    for( j = 0; j < 3; ++j, v>>= 8 )
      addr.sin6_addr.s6_addr[13+j] += v & 0xFF;

    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons((rand() % 65000) + 1);
    if( (c->hash_type & HASH_DST) ) {
      if( c->hash_id < 0 ) {
        struct onload_stat s = {};
        rc = onload_fd_stat(sockfd, &s);
        if( rc != 1 || s.stack_name == NULL )
          return;
        fprintf(stderr, "%s", s.stack_name);
        sscanf(strrchr(s.stack_name, '-'), "-c%d", &c->hash_id);
        fprintf(stderr, "%d", c->hash_id);
      }
      while( gen_hash6(c->hash_type, &addr, raddr) != c->hash_id ) {
        /* hardware on this RSS will not support this */
        if( verbose >= 2 )
          fprintf(stderr, "tproxy_preload: not binding to "IP6_PORT_FMT" as will not "
                          "match RSS got %d vs wanted %d\n",
                          IP_PORT_PRM(AF_INET6, &addr.sin6_addr, addr.sin6_port),
                          gen_hash6(c->hash_type, &addr, raddr),
                          c->hash_id);
        ++addr.sin6_port;
      }
    }
    /* we do not want addresses ending with .0 */
    if( addr.sin6_addr.s6_addr[15] == 0 || addr.sin6_port == 0)
      continue;
    if( verbose )
      fprintf(stderr, "tproxy_preload: binding %d, to "IP6_PORT_FMT"\n",
              sockfd, IP_PORT_PRM(AF_INET6, &addr.sin6_addr, addr.sin6_port));
    rc = bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
    if( rc == 0 || errno != EADDRINUSE )
      break;
  }
  if( rc != 0 && errno != EINPROGRESS ) {
    if( errno == EINVAL ) {
      if( verbose ) {
        /* EINVAL often means that socket is already bound */
        struct sockaddr_in6 addr = {};
        socklen_t alen = sizeof(addr);
        rc = getsockname(sockfd, &addr, &alen);
        fprintf(stderr, "tproxy_preload: ERROR: already bound to "
                IP6_PORT_FMT" rc %d\n",
                IP_PORT_PRM(AF_INET6, &addr.sin6_addr, addr.sin6_port), rc);
      }
      /* otherwise ignore EINVAL as would produce
        * flood of message with ab */
    }
    else
      fprintf(stderr, "tproxy_preload: ERROR: Transparent bind failed "
              "with rc %d\n", errno);
  }
}

int listen(int sockfd, int backlog)
{
  apply(&tlisten, sockfd, NULL);
  if( verbose && tlisten.do_transparent )
    fprintf(stderr, "tproxy_preload: listen\n");
  return original_listen(sockfd, backlog);
}


int connect(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen)
{
  int connect_retries = 10;
  int rc;
  do {
    if( addr->sa_family == AF_INET ) {
      apply(&tconnect, sockfd, (const struct sockaddr_in *)addr);
      if( verbose && (tconnect.do_transparent || tconnect.do_bind) )
        printf("tproxy_preload: connect\n");
    }
    if( addr->sa_family == AF_INET6 ) {
      apply6(&tconnect6, sockfd, (const struct sockaddr_in6 *)addr);
      if( verbose && (tconnect6.do_transparent || tconnect6.do_bind) )
        printf("tproxy_preload: connect6\n");
    }
    rc = original_connect(sockfd, addr, addrlen);
  } while( rc !=0 && errno == EADDRINUSE && connect_retries-- );
  return rc;
}


static void query_symbols(void)
{
  original_listen = dlsym(RTLD_NEXT, "listen");
  if( dlerror() != NULL ) {
      fprintf(stderr,
              "tproxy_preload: ERROR: Original listen symbol not found.\n");
      exit(1);
  }
  original_connect = dlsym(RTLD_NEXT, "connect");
  if( dlerror() != NULL ) {
      fprintf(stderr,
              "tproxy_preload: ERROR: Original connect symbol not found.\n");
      exit(1);
  }
}


static void parse_params(void)
{
  const char *next;
  const char *curr = getenv(ENV_VAR);
  char addr_s[INET6_ADDRSTRLEN];
  char addr_e[INET6_ADDRSTRLEN];
  char hash_name[4]; /* src, dst, all */
  int seed;
  int rc;
  if( curr == NULL ) {
    fprintf(stderr, "tproxy_preload: " ENV_VAR " not defined\n");
    exit(2);
  }
  (void) apply6;
  do {
      next = strchr(curr, ',');
      /* process curr to next-1 */
      if( ((rc = sscanf(curr, "connect_bind=%46[0-9a-fA-F:.]-%46[0-9a-fA-F:.]@hash=%3[a-z]:%d/%d",
                       addr_s, addr_e, hash_name, &tconnect.hash_id, &tconnect.hash_size)) >= 1) &&
          (inet_aton(addr_s, &tconnect.bind_start) &&
            inet_aton(rc >= 2 ? addr_e : addr_s, &tconnect.bind_end)) ) {
        tconnect.do_bind = 1;
        if( rc >= 3 ) {
          if( strcmp(hash_name, "dst") == 0 )
            tconnect.hash_type = HASH_DST;
          else if( strcmp(hash_name, "src") == 0 )
            tconnect.hash_type = HASH_SRC;
          else if( strcmp(hash_name, "all") == 0 )
            tconnect.hash_type = HASH_ALL;
          else {
            fprintf(stderr, "Invalid hash_type %s\n", hash_name);
            exit(3);
          }
          if( rc < 4 )
            tconnect.hash_size = atoi(getenv("EF_CLUSTER_SIZE"));
          if( rc < 5 )
            tconnect.hash_id = -1;
          hash_table_prepare(tconnect.hash_size);
          toeplitz_hash_prepare();
        }
      }
      if( ((rc = sscanf(curr, "connect6_bind=%46[0-9a-fA-F:.]-%46[0-9a-fA-F:.]@hash=%3[a-z]:%d/%d",
                       addr_s, addr_e, hash_name, &tconnect6.hash_id, &tconnect6.hash_size)) >= 1) &&
          (inet_pton(AF_INET6, addr_s, &tconnect6.bind_start) &&
            inet_pton(AF_INET6, rc >= 2 ? addr_e : addr_s, &tconnect6.bind_end)) ) {
        tconnect6.do_bind = 1;
        if( rc >= 3 ) {
          if( strcmp(hash_name, "dst") == 0 )
            tconnect6.hash_type = HASH_DST;
          else if( strcmp(hash_name, "src") == 0 )
            tconnect6.hash_type = HASH_SRC;
          else if( strcmp(hash_name, "all") == 0 )
            tconnect6.hash_type = HASH_ALL;
          else {
            fprintf(stderr, "Invalid hash_type %s\n", hash_name);
            exit(3);
          }
          if( rc < 4 )
            tconnect6.hash_size = atoi(getenv("EF_CLUSTER_SIZE"));
          if( rc < 5 )
            tconnect6.hash_id = -1;
          hash_table_prepare(tconnect6.hash_size);
          toeplitz_hash_prepare();
        }
      }
      else if( strncmp(curr, "connect6", 8) == 0 )
        tconnect6.do_transparent = 1;
      else if( strncmp(curr, "connect", 7) == 0 )
        tconnect.do_transparent = 1;
      else if( strncmp(curr, "listen6", 7) == 0 )
        tlisten6.do_transparent = 1;
      else if( strncmp(curr, "listen", 6) == 0 )
        tlisten.do_transparent = 1;
      else if( strncmp(curr, "verbose", 7) == 0 )
        verbose = 1;
      else if( (rc = sscanf(curr, "seed=%d", &seed)) == 1 )
        srand(seed);
      else {
        fprintf(stderr, "Invalid parameter %s\n", curr);
        exit(3);
      }
      curr = next + 1;
  } while( next != NULL );
}


void init(void) __attribute__ ((constructor));

void init(void)
{
  srand(time(NULL));
  query_symbols();
  parse_params();

  if( verbose ) {
    fprintf(stderr, "tproxy_preload: forcing IP_TRANSPARENT "
            "on listen %d, connect %d\n",
            tlisten.do_transparent, tconnect.do_transparent);
    fprintf(stderr, "tproxy_preload: forcing bind "
            "on connect %d\n", tconnect.do_bind);
    fprintf(stderr, "tproxy_preload: connect rss "
            "type %s %d/%d\n", hash_type_names[tconnect.hash_type],
            tconnect.hash_id, tconnect.hash_size);
    fprintf(stderr, "tproxy_preload: ipv6: forcing IP_TRANSPARENT "
            "on listen %d, connect %d\n",
            tlisten6.do_transparent, tconnect6.do_transparent);
    fprintf(stderr, "tproxy_preload: ipv6: forcing bind "
            "on connect %d\n", tconnect6.do_bind);
    fprintf(stderr, "tproxy_preload: ipv6: connect rss "
            "type %s %d/%d\n", hash_type_names[tconnect6.hash_type],
            tconnect6.hash_id, tconnect6.hash_size);
  }
}
