#define _GNU_SOURCE
#include <stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <sched.h>
#include <unistd.h>

/* Sync Preload Library
 * a preload library allowing to synchronize multiple network-communicating
 * processes.
 *
 * Synchronisation requires the process to issue either:
 *  * listen() - which marks process' readiness
 *  * connect(AF_INTET...) - which marks process' readiness and performs wait
 *    until external trigger is set
 *
 * Communication with controlling entity is maintained with shared memory.
 */

#define ENV_VAR "LD_SYNC_PRELOAD"
#define INFO "sync_preload: "

struct shm_s {
  volatile char go;
  volatile int32_t ready __attribute__((aligned(64)));
};

int sync_on_connect = 0;
int sync_on_listen = 0;
int verbose = 0;
volatile int done = 0;

#define SHM_NAME_LEN 128
char shm_name[SHM_NAME_LEN + 1] = {};

static int (*original_listen)(int sockfd, int backlog);
static int (*original_connect)(int sockfd, const struct sockaddr *addr,
                               socklen_t addrlen);

int wait_on_shm(const char* shm_name, int wait)
{
  struct shm_s* shm;

  int shm_fd = shm_open(shm_name, O_RDWR, 0);
  if( shm_fd < 0 ) {
      fprintf(stderr, INFO "Failed to open shm %s\n", shm_name);
      exit(1);
  }

  shm = mmap(0, 4096, PROT_READ | PROT_WRITE,
             MAP_SHARED, shm_fd, 0);
  if( shm == NULL || shm == MAP_FAILED ) {
      fprintf(stderr, INFO "Failed to map shm errno %d\n", errno);
      exit(1);
  }
  if( shm->go ) {
   fprintf(stderr, INFO "Shm set before readiness reported\n");
    exit(2);
  }

  (void) __sync_fetch_and_add(&shm->ready, 1);

  while ( wait && shm->go == 0 && ! done )
    sched_yield();

  close(shm_fd);
  done = 1;
  return 0;
}


int listen(int sockfd, int backlog)
{
  if( ! done &&  sync_on_listen ) {
    if( verbose )
      fprintf(stderr, INFO "listen\n");
    wait_on_shm(shm_name, 0);
    if( verbose )
      fprintf(stderr, INFO "go\n");
  }
  return original_listen(sockfd, backlog);
}


int connect(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen)
{
  if( ! done && sync_on_connect &&
    addr->sa_family == AF_INET ) {
    if( verbose )
      fprintf(stderr, INFO "connect\n");
    wait_on_shm(shm_name, 1);
    if( verbose )
      fprintf(stderr, INFO "go\n");
  }
  return original_connect(sockfd, addr, addrlen);
}


static void query_symbols(void)
{
  original_listen = dlsym(RTLD_NEXT, "listen");
  if( dlerror() != NULL ) {
      fprintf(stderr, INFO "ERROR: Original listen symbol not found.\n");
      exit(1);
  }
  original_connect = dlsym(RTLD_NEXT, "connect");
  if( dlerror() != NULL ) {
      fprintf(stderr, INFO "ERROR: Original connect symbol not found.\n");
      exit(1);
  }
}

#define STR(a) STR_(a)
#define STR_(a) #a

static void parse_params(void)
{
  const char *next;
  const char *curr = getenv(ENV_VAR);
  int got_name = 0;
  if( curr == NULL ) {
    fprintf(stderr, INFO ENV_VAR " not defined\n");
    exit(3);
  }
  do {
      next = strchr(curr, ',');
      /* process curr to next-1 */
      if( sscanf(curr, "shm=%" STR(SHM_NAME_LEN) "[^,]", shm_name) == 1 )
        got_name = 1;
      else if( strncmp(curr, "connect", 7) == 0 )
        sync_on_connect = 1;
      else if( strncmp(curr, "listen", 6) == 0 )
        sync_on_listen = 1;
      else if( strncmp(curr, "verbose", 7) == 0 )
        verbose = 1;
      else {
        fprintf(stderr, INFO "Invalid parameter %s\n", curr);
        exit(4);
      }
      curr = next + 1;
  } while( next != NULL );
  if( ! got_name || ! (sync_on_connect || sync_on_listen) ) {
    fprintf(stderr, INFO
            "sync_preload requires shm path and either connect or listen\n"
            "  " ENV_VAR "=shm=<path_to_shm>[,connect][,listen][,verbose]\n"
            "got:\n  " ENV_VAR "=%s\n", getenv(ENV_VAR));
    exit(5);
  }
}


void init(void) __attribute__ ((constructor));

void init(void)
{
  query_symbols();
  parse_params();

  if( verbose ) {
    fprintf(stderr, INFO "syncing on listen %d, connect %d\n",
            sync_on_listen, sync_on_connect);
    fprintf(stderr, INFO "shm=%s\n ", shm_name);
  }
}
