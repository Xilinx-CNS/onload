/**************************************************************************\ 
*//*! \dup.c 
** <L5_PRIVATE L5_SOURCE> 
** \author Greg Law (gel) 
** \brief Multithreaded tests of u/l FD stuff, particularly wrt dup and dup2
** \date 2005/01/11
** \cop  (c) Level 5 Networks Limited. 
** </L5_PRIVATE> 
*//* 
\**************************************************************************/ 

/*! \cidoxg_tests_syscalls */

/*! This tester exposes (at least) one outstanding bug in the library (or
 * possibly in the tester itself, though unlikely).
 * \TODO: Fix bug or report on bugzilla
 */

/*! Tests the user-level fd stuff, by concurrently doing nasty things such as
 * opening, closing, duping and reading on a file-descriptor.  The following
 * syscalls are called: socket, connect, dup, dup2, close, read and write.
 * Note that ONLY CONNECT, READ and WRITE ARE CALLED CONCURRENTLY!  That is,
 * all calls to socket, dup, dup2 and close are made with a fat global lock
 * held.  Calls to connect, read and write are not.  i.e. we test socket
 * creation and destruction while things are happen concurrently underneath.
 * (Note that this realitively simple testing found about half a dozen bugs!)
 * i.e. we do not test concurrent creation/destruction of sockets.  Also note
 * that we only really test that the system as a whole stays up under the
 * aforementioned concurrent ops, we don't test that the sockets send/receive
 * exactly the right data in the right order.  Both these limitations exist
 * simply because such tests would be relatively tricky to implement.
 * Concurrent calls to socket creation/destruction are tricky only because we
 * need to keep various bits of accounting info (namely the 'sockets' array;
 * see below), and these need to be kept in sync.  Testing that the system does
 * the right thing in the light of race conditions is obviously quite tuff.
 *
 * This test program is run in one of two modes: client or server.  The server
 * sits on a remote machine and exists just to keep the client going -- it's
 * the client that does all the "clever" stuff, and typically it's in the
 * client we'd expect to discover any bugs.  All the server does is spin in a
 * loop, accepting connections from the client, and sending data for the client
 * to read.  The client requests data by just sending a byte on a socket; for
 * each byte the server receives on a socket it will return the string "Hello,
 * world!\n" (or whatever the CHECK_STR macro is defined to be).
 */
/* \TODO: Test conccurent socket creation/destruction
 * \TODO: Test that the system "does the right thing" as well just staying up.
 * \TODO: Test combindations of OS sockets and L5 sockets
 */

#define _XOPEN_SOURCE 600  /*!< Needed for certain POSIX features (timeouts) */
#define _GNU_SOURCE

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include <stdbool.h>

#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <ci/app.h>

/*! The string the server will return to the client */
#define CHECK_STR ("Hello, world!\n")

/************************************
 * Logging
 */
#define LOGV(x)		do{if(!ci_cfg_quiet)do{x;}while(0);}while(0)
#define LOGVV(x)	do{if(ci_cfg_verbose)do{x;}while(0);}while(0)

/*! Configure the number of the threads the tester will run (not including
 * "control thread"), and the number of sockets to be used.
 *
 * \TODO: These should probably be run-time command-line options.
 */
enum {SOCK_COUNT = 10};
enum {THREAD_COUNT = 10};

/*! We keep an array of sock_rec structures, one for each socket. */
struct sock_rec {
  /*! The fd of this socket.  Zero fd means socket doesn't exist (i.e. this slot
   * in the array is 'free'.  (zero fd is technically a valid fd, but we know
   * we're not going to create a socket on top stdin, so we're ok)
   */
  volatile int  fd;

  /*! If 'fd' is non-zero, this field is true while the socket is connected */
  volatile bool is_connected;

  /*! If 'fd' is non-zero, true while data are being read from socket */
  volatile bool is_reading;

  /*! We keep a 'lifetime counter' to guard against the race whereby we write a
   * request byte, then get closed, then the fd gets recycled, then we read.
   * In such a case we'll never get sent the data!  Each time a new socket is
   * created on this array slot, we inc the lifetime, to enable any concurrent
   * reads to know to give up waiting for the data.
   */
  volatile long lifetime;

  pthread_rwlock_t rwlock;

  const char *by;
  /* A string for debugging that tells us how this socket was created
   * (socket, dup, dup2), or alternatively says "closed" or "closed by dup"
   */
} sockets [SOCK_COUNT];


/*! This function runs the server.  It simply spins in a loop, accepting
 ** connections, and sending the CHECK_STR once for each byte received on any
 ** accepted socket.  The server runs in a single thread, and uses select to
 ** know when there are data to read.
 **
 ** \param port The port number on which sockets should be accepted
 **
 ** \return 0 for success, or error-code for failure
 */
int
do_server (short port) {
  struct sockaddr_in sin;
  fd_set fdset;
  int nfds;
  int r;
  int s;
  int prev_q = 0;
 
  nfds = 0;
  s = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (s == -1) {
    perror ("Cannot create listening socket");
    return errno;
  }

  sin.sin_family=AF_INET;
  sin.sin_addr.s_addr=htonl(INADDR_ANY);
  sin.sin_port=htons (port);

  if (bind(s, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
    perror ("Server cannot bind");
    return errno;
  }

  if(listen (s, 10000)) {
    perror ("Server cannot listen");
    return errno;
  }

  LOGV (printf ("server bound to socket %d, port=%d; accept...\n", s, port));

  /* We'll do non-blocking ops on the socket */
  r = fcntl (s, F_SETFL, O_NONBLOCK);
  ci_assert (!r);

  FD_ZERO (&fdset);

  while (1) {
    int a, i;
    int fd = 3;
    struct timespec time;
    static struct timeval zero_timeout = {0,0};
    static char spinner[] = {'|', '/', '-', '\\'};
    static int spin_idx = 0;
    fd_set fdset_copy;
    
    a = accept (s, NULL, 0);
    if (a > 0) {
      if (a+1 > nfds)
        nfds = a+1;
      FD_SET (a, &fdset);
    }
    else {
      ci_assert (a == -1);
    }

    if (!nfds)
      continue;

    fdset_copy = fdset;

    /* To reassure the user all is well, we print a little spinner thingie
     * at a rate of 10 "frames" per second (anything more clogs up network with
     * teminal traffic!)
     */
    r = clock_gettime (CLOCK_REALTIME, &time);
    ci_assert (!r);
    if ((time.tv_nsec / 100000000) != prev_q) {
      LOGV (printf ("\r%4d %c", nfds, spinner [spin_idx++ % sizeof spinner]));
      fflush (stdout);
      prev_q = time.tv_nsec / 100000000;
    }

    /* Now let's see if anything's ready for reading */
    i = select (nfds, &fdset_copy, NULL, NULL, &zero_timeout);
    if (i < 0) {
      perror ("[Warning] Error on select");
      continue;
    }

    while (i) {
      if (FD_ISSET (fd, &fdset_copy)) {
        char c;
        i--;
        /* Read the char and write (note: this fd is blocking) */
        LOGVV (ci_log ("Reading a byte from fd=%d\n", fd));
        r = read (fd, &c, 1);

        if (r < 1) {
          /* Socket got closed from under our feet; just continue */
          if (r) {
            /* r==0 means simply EOF, otherwise error (not surprising though;
             * we're testing for robustness in the light of race conditions)
             */
            LOGVV(ci_log ("[Warning]: Error %d on fd %d", r, fd));
            LOGVV(perror (" (socket closed under our feet?)"));
          }
          close (fd);
          FD_CLR (fd, &fdset);
        }
        else {
          ci_assert (r == 1);

          LOGVV (ci_log ("Read me a '%d'; writing reply\n", c));
          r = write (fd, CHECK_STR, sizeof (CHECK_STR));
          if (r != sizeof (CHECK_STR))
            perror ("[Warning]: failed to write all the bytes");
          LOGVV (ci_log ("Wrote %d bytes", r));
        }
      }
      fd++;
    }
  }

  return 0;
}

/*****************************************************************************/
/*! The client. This is where all the "action" is.  The client creates its
 * woker-threads, which at random call the functions:
 *  create_socket,
 *  connect_socket,
 *  close_socket,
 *  dup_socket,
 *  read_socket,  and
 *  write_socket
 * all of which do the "obvious" thing
 */

/*! We keep a global lock to keep our internal state synchronized.  The lock
 * should be accessed always via the lock/unlock macros
 */
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
#define lock()  do { \
  int r = pthread_mutex_lock (&mtx); \
  if (r) ci_log ("lock from %s:%d failed w/ err %d\n", __FILE__, __LINE__, r); \
  ci_assert (!r); \
} while (0)

#define unlock()  do { \
  int r = pthread_mutex_unlock (&mtx); \
  if (r) ci_log ("unlock from %s:%d failed w/ err %d\n", __FILE__, __LINE__, r); \
  ci_assert (!r); \
} while (0)


/*! In order to know when it is sensible to do certain things, we keep a
 * counter for the number of open sockets, and one for the number of connected
 * sockets (the former will always be greater than or equal to the latter).
 * Keeping this is a large part of why socket creation/destruction is
 * synchronized.
 *
 * \TODO: Remove these global counters in order to enable socket
 * creation/destruction to become concurrent.
 */
static int n_open_socks = 0;
static int n_connected_socks = 0;
static int n_total_connections = 0;

/*! A global to record the address of the server we're talking to.  A bit
 * dirty, but saves us passing it parameters to all the worker threads
 */
static struct sockaddr_in server_addr;

/*! By default the test runs fro 1 minute (can be altered via the -t
 * command-line option)
 */
static int secs_remaining = 20;
static int start_secs;
static int server_port;
static int ephem_exhausted;

static int finish = 0;
static int wait_for_threads = 0;
static pthread_t threads[THREAD_COUNT];

/*! We maintain the maximum socket fd we're using */
static int minfd = __INT_MAX__, maxfd = 0;

/* Some diagnostic characters that change as we run to give the user confidence
 * things are progressing.  One 'spinner' per thread
 */
static int thread_spinners [THREAD_COUNT];

/* This is the concurrency level.  Higher levels of concurrency mean that we're
 * able to do less sanity checking, so it's a trade-off.
 *
 * Currently only levels 0 and 1 are supported.
 */
static int concurrency = 0;

/*! Because we're closing/duping sockets as we read/write over them, we expect
 * to receive errors from time to time.  Determining which errors are really to
 * be expected is a tricky business.  Instead we simply record how many
 * failures there's been, and the user can use this number to decide whether
 * all is well, or if something has gone wrong (should generally be around 90%
 * or more, depending on how many threads we're running with)
 */
ci_atomic_t n_ops = CI_ATOMIC_INITIALISER (1),
          n_fails = CI_ATOMIC_INITIALISER (0);

/*! Exit, waiting for child threads to end if requested.
 **
 ** \param ret Return code
 */
CI_NORETURN
clean_exit (int ret) {
  int i, r;
  (void)r;

  if (wait_for_threads) {
    for (i = 0; i < THREAD_COUNT; i++) {
      if (pthread_self() == threads[i]) {
        finish = 1;
        LOGVV (printf ("(clean exit: invoked by thread %d with rc %d)\n",
                       i, ret));
        pthread_exit (NULL);
      }
    }

    LOGVV (printf ("(clean exit: invoked by top level with rc %d)\n", ret));
    finish = 1;
    for (i = 0; i < THREAD_COUNT; i++) {
      LOGVV (printf ("(clean exit: parent waiting for thread %d)\n", i));
      r = pthread_join (threads[i], NULL);
      ci_assert (!r);
    }
    LOGVV (printf ("(clean exit: done)\n"));
  }

  exit (ret);
}


/*! We have a pretty simple function to check that the invariants hold.  This
 ** really means just making sure the n_open_socks and n_connected_socks
 ** globals correspond to what's in the array.  This function tends to get
 ** called at the beginning and end of the client ops caled by worker threads.
 **
 ** \TODO: When the n_open_socks and n_connected_socks globals are removed (in
 ** order to pave the way for concurrent socket creation/destruction ops), then
 ** this function will become essentially useless.
 */
void
_check_invs (const char *file, unsigned line, const char *func) {
  int i, con_count = 0, open_count = 0;
  struct stat tmp;

  if (concurrency) {
    /* Hmm... can we do anything at all with low but non-zero concurrency? */
    return;
  }

  lock ();

  for (i = 0; i < SOCK_COUNT; i++) {
    int fd = sockets [i].fd;
    if (fd) {
      int r;
      volatile int err;
      open_count++;
      r = fstat (fd, &tmp);
      if (r) {
        err = errno;
        ci_log ("DOH! fstat (%d) fails with errno=%d (by=%s)",
                fd, err, sockets [i].by);
        ci_log ("Called from %s:%d:%s", file, line, func);
        ci_assert (false);
      }

      ci_assert (fd >= minfd);
      ci_assert (fd <= maxfd);
    }

    if (sockets [i].is_connected) {
      con_count++;
      ci_assert (fd);
    }
  }

  if (con_count != n_connected_socks)
    ci_log ("n_connected socks is %d; should be %d\n", n_connected_socks, con_count);
  ci_assert (con_count == n_connected_socks);

  if (open_count != n_open_socks)
    ci_log ("n_open socks is %d; should be %d\n", n_open_socks, open_count);
  ci_assert (open_count == n_open_socks);

  ci_assert (n_open_socks >= n_connected_socks);

  unlock ();
}

#define check_invs() _check_invs (__FILE__, __LINE__, __FUNCTION__)

/*! Creates a socket and inserts it in an element in the 'sockets' array */
void
create_socket (void) {
  int slot, sock_fd;

  check_invs ();

  if (!concurrency)
    lock ();

  sock_fd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (sock_fd == -1) {
    if (errno == ENOMEM) {
      /* We've got the maximum number of sockets; carry on regardless */
      if (!concurrency)
        unlock ();
      check_invs();
      return;
    }
    ci_log ("Failed to create socket");
    clean_exit (2);
  }

  if (concurrency)
    lock ();

  /* Set the fd async. so future reads are async.  Do this /before/ we
   * we connect the socket, because reads/writes happen unprotected (any read
   * that gets in before this will fail because the socket is not connected)
   */
  if (fcntl (sock_fd, F_SETFL, O_NONBLOCK)) {
    /* Seems the socket has been closed from under our feet.  This has probably
     * happened when someone else dup2-ed ontop of us, then closed us.
     * Nothing more to do here.
     */
    ci_log ("Could not make fd non-blocking");
    ci_assert (concurrency);
    unlock ();
    return;
  }

  for (slot = 0; slot < SOCK_COUNT; slot++)
    if (sockets[slot].fd == 0) break;

  if (slot < SOCK_COUNT) {
    int k;

    if (sock_fd > maxfd)
      maxfd = sock_fd;
    if (sock_fd < minfd)
      minfd = sock_fd;

    LOGVV (ci_log ("Range is %d to %d\n", minfd, maxfd));

    /* Make sure we hadn't previously received this FD */
    for (k = 0; k < SOCK_COUNT; k++)
      if (sockets [k].fd == sock_fd)
        break;
    if (k == SOCK_COUNT) {
      sockets [slot].fd = sock_fd;
      sockets [slot].by = "socket";
      n_open_socks++;
      sockets [slot].lifetime++;
    }
    else
      close (sock_fd);
  }
  else
    close (sock_fd);

  unlock ();

  check_invs ();
}


/*! Closes a socket at random (if there are any open to close; otherwise it
 ** does nothing)
 */
void
close_socket (void) {
  int r, i;


  if (ephem_exhausted)
    /* Out of ephemeral ports; don't close because it means we won't be able
     * to connect later!
     */
    return;

  check_invs ();

  LOGVV (ci_log ("Doing close\n"));

  if (concurrency < 3)
    lock (); /*!< Socket destruction all synchronous for now */

  if (n_open_socks) {
    int count = -1;
    LOGVV (ci_log ("Chosing\n"));

    if (concurrency >= 2) {
      /* Don't try for too long if concurrent -- there may not be any! */
      count = SOCK_COUNT * 3;
    }


    do {
      i = random () % SOCK_COUNT;
    } while (count-- && !sockets [i].fd);
    LOGVV (ci_log ("Chosen %d from slot %d); calling close...\n", sockets [i].fd, i));

    /* Make sure we can't close the reopen while someone else is doing
     * connect, hence there's no chance someone will connect a blocking
     * socket.  We need to prevent socket destruction/recreation between the
     * lookup of the fd and connect on it; taking write lock here does that
     */
    pthread_rwlock_wrlock (&sockets[i].rwlock);
    r = close (sockets [i].fd);
    sockets [i].by = "close";
    pthread_rwlock_unlock (&sockets [i].rwlock);
    if (r) {
      ci_log ("Failed to close socket %d (error %d)", sockets [i].fd, errno);
      if (!concurrency)
        clean_exit (3);
    }
    LOGVV (ci_log ("Close returns %d\n", r));

    n_open_socks--;

    if (sockets [i].is_connected) {
      n_connected_socks--;
      sockets [i].is_connected = false;
      sockets [i].is_reading = false;
    }
    sockets [i].fd = 0;
    ci_assert ((concurrency >= 3) || (n_connected_socks >= 0));
    ci_assert ((concurrency >= 3) || (n_open_socks >= 0));
  }

  if (concurrency < 3)
    unlock ();

  check_invs ();
}


/*! Choose a socket at random.  The 'connected' param
 **
 ** \param connected  says whether or not we require the socket to be already
 **        connected (if false, will only return sockets that are not currently
 **        connected)
 **
 ** \return A slot in the 'sockets' array that can be used
 */
int
choose_socket (bool connected) {
  int i;
  int count = -1;

  if (concurrency >= 2)
    count = SOCK_COUNT * 3;

  /* Chose a socket to connect on.  Note that there might be none available,
   * in which case we just spin until we find one.  Also note that even once
   * we've selected one there is a chance that the socket won't be valid, due
   * to race conditions.  It might have been closed from under our feet, or
   * it might have already been connected from under our feet.  This is exactly
   * what we're trying to test for!
   */

  LOGVV (ci_log ("Choosing a socket...\n"));
  do {
    i = rand () % SOCK_COUNT;
    if (!count--)
      return 3;
  } while ((!sockets [i].fd) || (sockets [i].is_connected != connected));

  LOGVV (ci_log ("Chosen %d (fd=%d)\n", i, sockets [i].fd));
  return i;
}



/*! Take a random socket and connect to it.
 ** Note that unlike create/close, this function is NOT protected by a lock.
 ** This means that access will not be serialised, and in parcitular that
 ** sockets may be disappearing "beneath our feet".
 */
void
connect_socket (int me) {
  int e, i, r, fd;

  check_invs ();

  /* Avoid excessive spinning */
  if ((!n_open_socks) || (n_connected_socks >= n_open_socks)) {
    /* Avoid spinning too much if there are no open socks, or all socks are
     * already connected
     */
    return;
  }

  if (concurrency < 2) {
    ci_assert (n_connected_socks < SOCK_COUNT);
    ci_assert (n_connected_socks >= 0);
  }

  LOGVV (ci_log ("%d socks open, %d connected; connecting another..",
      n_open_socks, n_connected_socks));

  i = choose_socket (false);

  /* Something is seriously fscked up here.  Taking rwlocks seems to lock the
   * whole thing up -- even taking, then immediately releasing.  Same behavior
   * on pthreads or our own rwlocks, and same on kernel or ul stack.  :-(
   * For now we just take the fat mutex, and live with the fact that connects
   * are now serialised too.
   */
  pthread_rwlock_rdlock (&sockets [i].rwlock);
  fd = sockets [i].fd;  /* Protect against being closed from under our feet */

  if (!fd) {
    pthread_rwlock_unlock (&sockets [i].rwlock);
    return;
  }

  r = fcntl (fd, F_SETFL, O_NONBLOCK);
  ci_assert ((errno == EBADF) || !r);

  LOGVV (ci_log ("call connect (%d, %p, %zd)...\n", fd, &server_addr, sizeof server_addr));

  /* Sockets need to be non-blocking, because we must have no chance of ever
   * doing a blocking read.  We don't want to synchronise with locks, so the
   * only thing to do is to make the connect non-blocking.  So we'll spin until
   * either the connect succeeds or fails.
   */
  do {
    thread_spinners [me]++;
    r = connect (fd, (struct sockaddr*)&server_addr, sizeof server_addr);
    e = errno;
  }
  while (r && ((e == EINPROGRESS) || (e == EALREADY)));

  pthread_rwlock_unlock (&sockets [i].rwlock);
  
  ephem_exhausted = 0;

  LOGVV (ci_log ("Back from connect (%d): %d/%d)\n", fd, r, e));
  if (r && e != EISCONN) {
    switch (e) {
      case ECONNREFUSED:
      case ETIMEDOUT:
      case ENETUNREACH:
      case EBUSY:
      case ECONNABORTED:
        ci_log ("\n\nError %d on connect; is the server listening?", errno);
        clean_exit (3);

      case EADDRINUSE:
      case EADDRNOTAVAIL:
        /* This means there are no ephemeral ports left.  Stop closing
         * sockets, otherwise we'll run out!
         */
        ephem_exhausted = 1;
        /* fall through */

      default:
        ci_log ("Error %d on connect\n", e);
        ci_atomic_inc (&n_fails);
    }
  }
  else {
    /* Take the lock to ensure we do our accounting properly.  Note that we've
     * already done the connect by this point, so connect is still called
     * concurrently, it's just this bit of accounting that's done serially
     */
    lock ();
    if (sockets [i].fd) {
      /* The only way fd is zero is if it was closed from under our feet.
       * In which case the connect will also have been undone from under our
       * feet.
       */
      if (sockets [i].is_connected == false) {
        LOGVV (ci_log ("new connection (%d)\n", fd));
        sockets [i].is_connected = true;
        n_connected_socks++;
        n_total_connections++;
      }
    }
    unlock ();
  }

  check_invs ();
}

/*! Select a socket at random and read some data from it */
void
read_socket (void) {
  int fd, i, r;
  char buff [sizeof CHECK_STR];

  check_invs ();

  LOGVV (ci_log ("%d open sockets, of which %d connected\n",
       n_open_socks, n_connected_socks));
  if (n_connected_socks == 0)
    return;
  i = choose_socket (true);

  /* Lower the probability that all threads block reading */
  if (sockets [i].is_reading)
    return;

  sockets [i].is_reading = true;
  fd = sockets [i].fd;
  if (fd) { /* Guard against race whereby socket gets closed from under our feet */
    char c;
    long fd_lifetime;
    static char sequence_char = 'a';

    lock ();
    c = sequence_char++;
    unlock ();

    /* First ask the server to send us some data to read (by simply sending
     * a single character over the socket
     */
    LOGVV (ci_log ("write seq. byte '%d'...\n", c));
    fd_lifetime = sockets [i].lifetime;
    if (write (fd, &c, 1) != 1) {
      /* Someone has probably closed socket from under our feet */
      LOGVV(ci_log ("[Warning] Failed to write char on fd %d (errno %d)", 
		    fd, errno));
      ci_atomic_inc (&n_fails);
    }
    else {
      size_t bytes_read = 0;
      LOGVV (ci_log ("written; read some bytes from socket %d...\n", fd));

      /* Must be stuff for us to read, unless the fd has been recycled.
       * We want to avoid locking around the read (we're testing for races), so
       * we keep reading until we detect the fd's reuse
       */
      do {
        //LOGVV (ci_log ("reading into %p+%d\n", buff, bytes_read));
        r = read (fd, buff+bytes_read, (sizeof CHECK_STR)-bytes_read);
        ci_assert ((r >= 0) || (errno != 1001));
        if (r > 0)
          bytes_read += r;
        if (sockets [i].lifetime != fd_lifetime) {
          LOGVV (ci_log ("Lifetime bumped from %ld to %ld\n",
               fd_lifetime, sockets [i].lifetime));
          break;
        }

        if (r > 0)
          LOGVV (ci_log ("********** READ %d bytes\n", r));
        else {
          if (errno != EAGAIN) {
            LOGVV (ci_log ("Error %d; read %zu of %zu bytes\n",
                           errno, bytes_read, sizeof CHECK_STR));
            break;
          }
        }
      } while (bytes_read < (int)sizeof CHECK_STR);

      LOGVV (ci_log ("read returned %d\n", r));
      if (r == -1) {
        LOGVV(ci_log ("[Warning]: error %d on read (%d)", errno, fd));
        ci_atomic_inc (&n_fails);
      }
      else {
        /* Looks good; let's just check the string itself */
        LOGVV (ci_log ("read a total of %zu bytes\n", bytes_read));
        if ((bytes_read != sizeof (CHECK_STR)) ||
            strncmp (buff, CHECK_STR, sizeof (CHECK_STR))) {
          /* Hmm, we didn't read the right thing back.  Need to do some thinking
           * about how we can assure ourselves that we're doing the right thing
           * here.
           */
          if (bytes_read > 0) {
            ci_assert (bytes_read <= sizeof (CHECK_STR));
            buff [bytes_read] = 0;
          }
          else
            buff [(sizeof CHECK_STR) - 1] = 0;

          ci_log ("[Warning] read garbage '%s'\n", buff); 
          ci_atomic_inc (&n_fails);
        }
        else
          LOGVV (ci_log ("String OK: %s", buff));
      }
    }
  }
  sockets [i].is_reading = false;

  check_invs ();
}

/*! Chose a socket at random and dup it */
void
dup_socket (bool do_dup2) {
  int i, j, newfd;

  check_invs ();

  /* dups happen serialised (as do open/close).  Note reads and connects still
   * happen concurrently beneath them.  TODO: have dups happen concurrently
   */

  if (concurrency < 2)
    lock ();

  if ((n_open_socks > 0) && (n_open_socks < SOCK_COUNT)) {
    int count = -1;

    if (concurrency >= 2)
      count = SOCK_COUNT * 4;

    /* Chose source dup */
    do {
      i = rand () % SOCK_COUNT;
    } while (count-- && !sockets [i].fd);

    /* Chose dest dup */
    do {
      j = rand () % SOCK_COUNT;
    } while (count-- && sockets [j].fd);

    if (!count)
      return;

    if (!do_dup2) {
      int k;
      if (concurrency < 2) {
        ci_assert (minfd > 2);
        ci_assert (sockets [i].fd >= minfd);
      }
      newfd = dup (sockets [i].fd);

      if (newfd == -1) {
        ci_log ("[Warning] Failed to dup (%d); error %d", sockets [i].fd, errno);
        ci_atomic_inc (&n_fails);
      }

      /* Make sure we hadn't previously received this FD */
      if (!concurrency) {
        for (k = 0; k < SOCK_COUNT; k++)
          ci_assert (sockets [k].fd != newfd);
      }
    }
    else {
      int k, r;

      /* Choose a new target FD that is different to existing one.
       * (I guess testing dup2(x,x) would be worthwhile, even if it is an odd
       * thing for the user to do!)
       */
      do {
        newfd = (random() % (SOCK_COUNT*2)) + 6;
      } while (newfd == sockets [i].fd);

      /* Will this result in closing of another socket */
      for (k = 0; k < SOCK_COUNT; k++) {
        if (sockets [k].fd == newfd) {
          pthread_rwlock_wrlock (&sockets [k].rwlock);
          break;
        }
      }

      LOGVV (ci_log ("Doing dup2 (%d, %d)  [%d]->[%d]\n", sockets [i].fd, newfd, i, j));
      r = dup2 (sockets [i].fd, newfd);
      if (concurrency < 2)
        ci_assert ((r == newfd) || (r == -1));
      if (r == -1) {
        ci_log ("[Warning] failed to dup2 (%d, %d): ",
                 sockets [i].fd, newfd);
        ci_atomic_inc (&n_fails);
        newfd = -1;
      }
      else if (k < SOCK_COUNT) {
        /* The above dup2 resulted in a close */
        LOGVV (ci_log ("dup2 results in a close of socket fd %d\n", sockets [k].fd));
        if (sockets [k].is_connected) {
          n_connected_socks--;
          sockets [k].is_connected = false;
        }
        sockets [k].fd = 0;
        sockets [k].by = "close_by";
        n_open_socks--;
      }


      if (k < SOCK_COUNT)
        pthread_rwlock_unlock (&sockets [k].rwlock);
    }

    if (newfd != -1) {
      if (concurrency < 2)
        ci_assert (sockets [j].fd == 0);

      if (!concurrency) {
        /* Check the newly created socket exists */
        struct stat tmp;
        if (fstat (newfd, &tmp) == -1) {
          ci_log ("Cannot fstat newly created fd %d (errno %d)", newfd, errno);
          ci_assert (0);
        }
      }

      sockets [j].is_connected = sockets [i].is_connected;
      sockets [j].is_reading = sockets [i].is_reading;
      sockets [j].fd = newfd;
      sockets [j].by = do_dup2 ? "dup2" : "dup";

      n_open_socks++;
      if (sockets [i].is_connected)
        n_connected_socks++;

      if(newfd > maxfd)
        maxfd = newfd;
      if (newfd < minfd)
        minfd = newfd;
    }
  }

  if (concurrency < 2)
    unlock ();

  check_invs ();
}


/*! Function to print the status line (let's the user know what's happening) */
void
print_status (FILE *f) {
  static char my_spinner[] = {'\\', '|', '/', '-'};
  static int my_spin_idx = 1;
  static int print_count = 0;
  int i;

  if (print_count)
    LOGV (fprintf (f, "\r"));

  print_count++;

  if ((start_secs - secs_remaining > 2) && (n_total_connections == 0)) {
    ci_log ("ERROR: No connections being made; is the server listening?\n");
    clean_exit (1);
  }

  LOGV (fprintf (f, "%c ", my_spinner [my_spin_idx++ % sizeof my_spinner]));
  for (i = 0; i < THREAD_COUNT; i++)
    LOGV (fprintf (f, "%c ", thread_spinners [i] % 26 + 65));

  LOGV (fprintf (f, "%c%3ds %3d%% :", ephem_exhausted ? '#' : ' ', secs_remaining,
          100 - (ci_atomic_read (&n_fails)*100 / ci_atomic_read (&n_ops))));
  for (i = 0; i < SOCK_COUNT; i++) {
    char c = ' ';
    if (sockets [i].is_connected)
      c = '*';
    if (sockets [i].is_reading)
      c = 'r';
    LOGV (fprintf (f, "%4d%c ", sockets [i].fd, c));
  }

  if (f != stdout)
    LOGVV (fprintf (f, "\n"));

  if (ci_cfg_verbose) {
    /* Print out the u/l table ref counts for all FDs */
    char ours;
    int i;
    for (i = minfd; i <= maxfd; i++) {
      /* Is this fd used by us? */
      int k;
      ours = '-';
      for (k = 0; k < SOCK_COUNT; k++) {
        if (sockets [k].fd == i)
          ours = '*';
      }
      ci_log ("%d%c ", i, ours);
    }
  }
  
  
  fflush (stdout);
}


/*! The body of the worker threads in the client.  Loops around, calling the
 ** various operations above at random.
 **
 ** \param p Not used; needed due to pthreads standard
 **
 ** \return Never returns (void* param due to pthreads standard)
 **/
void*
do_client (void *p) {
  int r;
  int me = (int)(ci_ptr_arith_t)p;
  (void)r;

  /* Client worker threads run at low priority */
  struct sched_param param;
  param.sched_priority = sched_get_priority_min (SCHED_OTHER);
  r = pthread_setschedparam (pthread_self(), SCHED_OTHER, &param);
  ci_assert (!r);

  /* We loop doing stuff at random */
  while (1) {
    int test = random () % 11;
    thread_spinners [me]++;
    if (finish) {
      LOGVV (ci_log ("Thread %d exiting\n", me));
      pthread_exit (NULL);
    }

    ci_atomic_inc (&n_ops);

    switch (test) {
      case 0:
        LOGVV (ci_log ("Thread %d doing test %d (create)\n", me, test));
        create_socket ();
        break;

      case 1:
        LOGVV (ci_log ("Thread %d doing test %d (close)\n", me, test));
        close_socket ();
        break;

      case 2:
        LOGVV (ci_log ("Thread %d doing test %d (connect)\n", me, test));
        connect_socket (me);
        break;

      case  3:
        LOGVV (ci_log ("Thread %d doing test %d (dup)\n", me, test));
        dup_socket (false);
        break;

      case  4:
        LOGVV (ci_log ("Thread %d doing test %d (dup2)\n", me, test));
        dup_socket (true);
        break;

        /* More chance of read than open/close/dup/dup2 */
      case  5:
      case  6:
      case  7:
      case  8:
      case  9:
      case 10:
        LOGVV (ci_log ("Thread %d doing test %d (read)\n", me, test));
        read_socket ();
        break;

      default:
        LOGVV (ci_log ("Thread %d doing test %d (BOGUS)\n", me, test));
        /* All cases should be handled */
        ci_assert (false);
    }

    LOGVV (print_status(stderr));
  }

  /* Control never reaches here */
  ci_assert (false);
}


/*! The server and the time to run for are configurable from command-line */
static ci_cfg_desc cfg_opts[] = {
  { 's', "server",CI_CFG_UINT, &server_port,
    "port on which to run as server"},
  { 't', "time",CI_CFG_UINT, &secs_remaining,
    "seconds to run for (default 20)"},
  { 'w', "wait",CI_CFG_FLAG, &wait_for_threads,
    "wait for threads to stop on exit"},
  { 'c', "concurrency",CI_CFG_UINT, &concurrency,
    "extra concurrently level (max=1; default=0)"},
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))


/*! You know what main does, right :-) */
int
main (int argc, char *argv[]) {
  struct timespec timer;
  static pthread_mutex_t wait_mtx = PTHREAD_MUTEX_INITIALIZER;

  const char *strict = getenv ("EF_FDTABLE_STRICT");
  if (!strict || strcmp (strict, "1")) {
    fprintf (stderr, "Please run me with EF_FDTABLE_STRICT=1\n");
    abort();
  }


  /* Let's not have SIGPIPE terminate the program.
   * (The races we deliberately provoke means we'll receive SIGPIPE due to
   * writing to or reading from a socket that has been closed under our feet)
   */
  signal(SIGPIPE, SIG_IGN);
  srand (1); /* Making things predictable makes debugging easier */

  ci_app_getopt("[server:port]", &argc, argv, cfg_opts, N_CFG_OPTS);
  --argc; ++argv;

  start_secs = secs_remaining;

  if (server_port) {
    if (argc)
      ci_app_usage ("Thrash sockets with concurrent ops [server:port]");
    return do_server (server_port);
  }
  else {
    int i, r, total, fails;
    struct sched_param param;

    if (argc != 1)
      ci_app_usage ("Thrash sockets with concurrent ops [server:port]");

    r = ci_hostport_to_sockaddr_in (argv[0], &server_addr);
    if (r) {
      ci_log ("Client could not resolve server %s\n", argv[2]);
      exit (4);
    }

    LOGV (printf ("Running client with %d threads / %d sockets, concurreny level=%d\n",
            THREAD_COUNT, SOCK_COUNT, concurrency));

    for (i = 0; i < SOCK_COUNT; i++) {
      r = pthread_rwlock_init (&sockets [i].rwlock, NULL);
      ci_assert (!r);
    }

    /* Create THREAD_COUNT threads.  Make this thread high priority first.
     * (Note: this will only work if the user is root)
     */
    param.sched_priority = sched_get_priority_max (SCHED_RR);
    pthread_setschedparam (pthread_self(), SCHED_RR, &param);

    for (i = 0; i < THREAD_COUNT; i++) {
      r = pthread_create (&threads[i], NULL, do_client, 
			  (void*)(ci_ptr_arith_t)i);
      ci_assert (!r);
    }

    pthread_mutex_lock (&wait_mtx);
    clock_gettime (CLOCK_REALTIME, &timer);

    /* Run the test for as long as apprioriate */
    while (--secs_remaining){
      while (timer.tv_nsec < 1000000000) {
        /* Wait for mutex to time out.  We use this rather than nanosleep et al,
         * because we want to use an absolute rather than relative timeout
         */
        pthread_mutex_timedlock (&wait_mtx, &timer);
        print_status (stdout);
        timer.tv_nsec += 100000000;
        if (finish) {
          clean_exit (1);
        }
      }
      timer.tv_nsec = 0;
      timer.tv_sec++;
    }

    total = ci_atomic_read (&n_ops);
    fails = ci_atomic_read (&n_fails);

    if (finish) {
      clean_exit (1);
    }
    else {
      /* If we get here, the world is well */
      LOGV (printf ("\n\n%d out of %d tests passed\n",
              total - fails, total));

      clean_exit (0);
    }
  }

  /* If we get here arguments were invalid */
  return 1;
}

/*! \cidoxg_end */
