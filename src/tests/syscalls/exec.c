/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author Robert Stonehouse
**  \brief Test probing for netifs after exec() and fork() calls 
**   \date January 2005 
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*
  Assumptions: - fds are not necessarily the same between client and server
                 as accept gets a new fd
	       - Only the client needs to worry about replays
               - Assumes ports are always chosen statically
               - fds->state is not the same (but is consistent) between
                 client and server
               - Rely on ordering of the sockets and not the fd numbers

  Strobe mode Data is passed as a set of CLI arguments to the exec()'ed process
              - exec_pos (iteration count)
              - first_port

  Not tested: - select() testing for write or exception status
              - select() expecting a timeout

  TODO: - use shared memory for logging
        - reenable UDP test mode
        - make supervisor timeout
        - set close on exec bits randomly
        - cope with "WARNING: short data read"
        - do_cleanup() should delete logs that have passed
        - enumerate message to supervisor and return codes better
        - add CLI options for number of children
              
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ci/app.h>
#include <ci/app/checkedsocket.h>
#include <ci/tools/dllist.h>
#include <ci/tools/magic.h>

//Contains globals, defines and struct definitions
#include "exec_struct.h"
#include "exec.h"

/**************************************************************************
 * FD_S STRUCTURE FUNCTIONS
 * Be careful about setting the fd_s state to INVALID as a function will
 *   probably call sanity_check_fd_s() which would fail
 **************************************************************************/

/*! Allocate and add an fd_s structure */
fd_s *add_fd_s(int fd) {
  ci_uint32 num_socks=0;
  fd_s *this_fds;

  // Check that fd is not replicated anywhere
  CI_DLLIST_FOR_EACH2(fd_s,this_fds,dllink,&fds_list) {
    if (PLAYING) {
      ci_assert(this_fds->fd!=INVALID_SOCK_FD);
      ci_assert_nequal(this_fds->fd,fd);
    }
    num_socks++;
  }
  ci_assert(num_socks==total_num_socks);
  ci_assert(total_num_socks<=MAX_SOCKS_PER_PROCESS);

  //Allocate and add to list
  this_fds        = malloc_fd_s();
  this_fds->fd    = fd; 
  this_fds->is_l5 = UNKNOWN;
  ci_dllist_push(&fds_list,&this_fds->dllink);
  total_num_socks++;

  return(this_fds);
}

/*! Close a fd_s and remove from the list */
void close_fd_s(fd_s *fds) {
  sanity_check_fd_s(fds);
  if (fds->state==CONNECTED) total_num_conns--;
  set_state(fds,INVALID);
  CI_MAGIC_CLEAR(fds,FD_S_MAGIC);
  ci_dllist_remove(&fds->dllink);
  total_num_socks--;
  free(fds);
}


/*! Allocate a new fd structure */
fd_s *malloc_fd_s() {
  fd_s *ret;
  ret=(fd_s*)calloc(1,sizeof(*ret));
  CI_TEST(ret);
  CI_MAGIC_SET(ret,FD_S_MAGIC);
  set_state(ret,INVALID);
  ret->close_on_exec = FALSE;
  ret->udp_data_sent = FALSE;
  return(ret);
}


/* sanity check a single fd_s list */
void sanity_check_fd_s(fd_s *fds) {
  ci_assert(fds);
  CI_MAGIC_CHECK(fds,FD_S_MAGIC);
  ci_assert(fds->state!=INVALID);
}


/*! Creates the socket_order string */
char *create_socket_order() {
  static char socket_order[MAX_SOCKET_ORDER_LEN];
  char *so_pos;
  fd_s *fds;
  so_pos = socket_order;

  so_pos += snprintf(so_pos, MAX_SOCKET_ORDER_LEN, "-o");
  CI_DLLIST_FOR_EACH2(fd_s, fds, dllink, &fds_list) {
    sanity_check_fd_s(fds);
    if (!fds->close_on_exec) {
      so_pos += sput_fd(so_pos,fds->fd);
      ci_assert( (so_pos+2) < (socket_order+MAX_SOCKET_ORDER_LEN) );
    }
  }
  *so_pos = 0;
  return(socket_order);
}


/*! Assumes that -o has been stripped off */
void parse_socket_order() {
  const char *so_pos;
  fd_s *fds;
  so_pos = socket_order_opt;

  CI_DLLIST_FOR_EACH2(fd_s, fds, dllink, &fds_list) {
    ci_assert(fds);
    ci_assert(fds->fd==INVALID_SOCK_FD);

    fds->fd = sget_fd(so_pos);
    so_pos += 2;
    if (LOG_SOCK_ORDER) DEBUG_LOG(" parse_socket_order(): Allocated fd from options = %d",fds->fd);
  }
  //ensure that the 0 at end of the option string is reached
  ci_assert(*so_pos==0);
  //ensure that the fork_order string was completely consumed
  ci_assert(*fork_order_opt==0);
  //ensure that no fds are at INVALID_SOCK_FD
  CI_DLLIST_FOR_EACH2(fd_s, fds, dllink, &fds_list) {
    sanity_check_fd_s(fds);
  }
}


/*! Print the 16 bit fd value to the string */
/* and increment the string pointer */
int sput_fd(char *str, int fd) {
  ci_assert((fd>0) && (fd<=MAX_FD));

  //Neither can be zero or the end of the option parsing happens
  *str     = (char)(33+(fd%64));
  *(str+1) = (char)(33+(fd/64));

  return(2);
}

/* Get a 16 bit fd value */
/* and increment the string pointer */
int sget_fd(const char *str) {
  int ret;

  ret = (*str-33) + (*(str+1)-33)*64;
  // check not the end of the string
  
  ci_assert((ret>0) && (ret<=MAX_FD));
  return(ret);
}


/* Return the fd or 0 if NULL passed in */
int get_fd(fd_s *fds) {
  int ret;
  if (fds) {
    ret=fds->fd;
  } else {
    ret=0;
  }
  if (PLAYING) ci_assert(ret!=INVALID_SOCK_FD);
  return(ret);
}

/**************************************************************************
 * STATE HANDLING FUNCTIONS
 **************************************************************************/

/*! Set the state for a given socket */
/*  Must be called anytime any socket state is changed */
void set_state(fd_s *fds, int state) {
  // cannot call sanity_check_fd_s here as this may be just malloc'ed
  ci_assert(fds);
  fds->state = state;
  fds->other_state = state;
}


/*! Set the state that the client would have */
/*   Only differs for functions that would are ignored on the server */
void set_other_state(fd_s *fds, int state) {
  // cannot call sanity_check_fd_s here as this may be just malloc'ed
  ci_assert(fds);
  fds->other_state = state;
}


/*! Advance the current position */
void adv_pos() {
  play_pos++;
  print_order();
}


/*! Check the state of a given socket */
/* This is a macro so that ci_assert reports correctly */
#define check_state(check_state_fd, check_state_state) \
  ci_assert_equal((check_state_fd)->state,(check_state_state))


/*! Print some info about the current position */
void print_pos() {
  DEBUG_LOG("play_pos=%d replay_pos=%d",play_pos,replay_pos);
}


/*! Print the order of fds */
void print_order() {
  fd_s *this_fds;

  if (LOG_ORDER&&((PLAYING&&LOG_PLAY)||LOG_REPLAY)) {
    fprintf(stderr,"at %d order is ",play_pos);
    CI_DLLIST_FOR_EACH2(fd_s,this_fds,dllink,&fds_list) {
      fprintf(stderr," %d",this_fds->fd);
    }
    fprintf(stderr,"\n");
  }
}

/*! Call close_fd_s() for all sockets marked close on exec */
void remove_close_on_exec() {
  fd_s *this_fds,*temp;
  CI_DLLIST_FOR_EACH3(fd_s,this_fds,dllink,&fds_list,temp) {
    if (this_fds->close_on_exec) {
      PLAY_LOG("Close on exec fd=%d",this_fds->fd);
      close_fd_s(this_fds);
    }
  }
}


/**************************************************************************
 * OPERATIONS CALLED BY MAIN
 * Decides how to transalte the call into a client / server(opposite) op
 * Must call check_exec_pos() and fds->ops_on_socket++ once at the start
 * Must call adv_pos() once at the end and at any interruptible places 
 * Must not call another X_socket() operation
 * No logging
 * Should not use the PLAYING condition
 * Should test the fd_s's passed in using sanity_check_fd_s
 * If randomly generated data is being used it should be done here
 * this ensures that both paths sees the same data
 **************************************************************************/
/*! Create a socket - updating the state */
fd_s *
create_socket(int type)
{
  fd_s *n;

  check_exec_pos();
  n=do_socket(type);
  adv_pos();
  return(n);
}

/*! Bind a socket to the given port */
void bind_socket(fd_s *fds, int port) {
  bind_socket_reverse(fds, port, 0);
}


/*! Bind a socket to the given port with a possible role reversal */
void bind_socket_reverse(fd_s *fds, int port, int reverse_client_server) {
  int this_is_server;

  check_exec_pos();
  fds->ops_on_socket++;
  sanity_check_fd_s(fds);

  this_is_server = reverse_client_server ? (!is_server) : is_server;
  

  if (!this_is_server) {
    do_bind(fds,port);
  } else {
    PLAY_LOG("Ignoring client bind() to rport=%d", port);
    fds->bind_pos = play_pos;
    fds->rport    = port;
    set_other_state(fds,BOUND);
  }
  //Port number must be set in client and server case
  fds->lport=port;
  adv_pos();
}


/*! Listen on a given socket */
void listen_socket(fd_s *fds) {
  check_exec_pos();
  fds->ops_on_socket++;
  sanity_check_fd_s(fds);

  if (!is_server) {
    do_listen(fds);
  } else {
    PLAY_LOG("Ignoring client listen()\n");
    fds->listen_pos = play_pos;
    set_other_state(fds,LISTENING);
  }
  adv_pos();
}


fd_s *accept_socket(fd_s *fds) {
  return(accept_socket_type_ok(fds,L5,OK));
}


/*! Accept a new connection and set the new fd */
fd_s *accept_socket_type_ok(fd_s *fds, is_l5_t is_l5, int ok) {
  fd_s *new_fds;
  check_exec_pos();
  fds->ops_on_socket++;
  sanity_check_fd_s(fds);

  if (!ok) {
    PLAY_LOG("Ignoring accept() due to too many open sockets");
    return(NULL);
  } else {

    new_fds=fds; // For ignoring cases and to get rid of compiler warning
    if (!is_server) {
      if (can_accept(fds,is_l5) && sync_after_listen(fds)) {
	new_fds       = do_accept(fds,is_l5);
      } else {
	PLAY_LOG("Ignoring accept(A) fd %d due to accecpt/connect order synchronisation",fds->fd);
      }
    } else {
      // server - keep fd num in sync
      if (can_connect(fds,is_l5) && sync_after_listen(fds)) {
	new_fds = do_socket(fds->type);
	do_connect(new_fds, fds->rport, is_l5);
	set_other_state(fds,LISTENING); //New socket must still listen
      } else {
	PLAY_LOG("Ignoring connect(B) fd %d due to accecpt/connect order synchronisation",fds->fd);
      }
    }
  }
  adv_pos();
  return(new_fds);
}


/* All three stages of socket connection */
fd_s *connect_socket(fd_s *fds,ci_uint16 port) {
  fds = connect_socket_type_ok(fds,port,L5,OK); //bind and listen
#ifdef SEPERATE_BIND_LISTEN
    fds = connect_socket_type_ok(fds,port,L5,OK);
#endif
  return(connect_socket_type_ok(fds,port,L5,OK));
}

/*! Connect to a server */
fd_s *connect_socket_type_ok(fd_s *fds,ci_uint16 port,is_l5_t is_l5,int ok) {
  fd_s *oldfds;

  if (!ok) {
    PLAY_LOG("Ignoring connect due to too many sockets");
  } else {
    check_exec_pos();
    fds->ops_on_socket++;
    sanity_check_fd_s(fds);

    if (!is_server) {
      /* Client */
      switch (fds->other_state) {
      case (CREATED):
	fds->lport = port;
	set_other_state(fds,LISTENING);
#ifndef SEPERATE_BIND_LISTEN
	PLAY_LOG("Client: Ignoring servers bind()/listen() fd=%d port=%d",fds->fd,port);
	fds->listen_pos = play_pos;
	break;
#else
	PLAY_LOG("Client: Ignoring servers bind() fd=%d port=%d",fds->fd,port);
	set_other_state(fds,BOUND);
	break;
      case (BOUND):
	PLAY_LOG("Client: Ignoring servers listen() fd=%d port=%d",fds->fd,port);
	fds->listen_pos = play_pos;
	set_other_state(fds,LISTENING);
	break;
#endif	
      case (LISTENING):
	if (can_connect(fds,is_l5) && sync_after_listen(fds)) {
	  //client - keep in sync
	  //accept will create a new socket so the client must mirror this
	  oldfds = fds;
	  fds = do_socket(oldfds->type);
	  fds->lport  = oldfds->lport;
	  do_connect(fds,fds->lport,is_l5);
	  do_close(oldfds);
	} else {
	  PLAY_LOG("Ignoring connect(C) fd=%d due to accecpt/connect order synchronisation",fds->fd);
	}
	break;
      default:
	ci_fail(("Unknown fds->other_state"));
      }
    } else {
      /* Server */
      switch (fds->state) {
      case (CREATED):
	do_bind(fds,port);
#ifndef SEPERATE_BIND_LISTEN
	do_listen(fds);
#endif      
	set_other_state(fds,CREATED);
	break;
	do_bind(fds,port);
#ifdef SEPERATE_BIND_LISTEN
      case (BOUND):
	do_listen(fds);
	set_other_state(fds,CREATED);
	break;
#endif      
      case (LISTENING):
	if (can_accept(fds,is_l5) && sync_after_listen(fds)) {
	  oldfds = fds;
	  fds = do_accept(fds,is_l5);
	  /* server - close the listening socket */
	  do_close(oldfds);
	} else {
	  PLAY_LOG("Ignoring accept(D) fd %d due to accecpt/connect order synchronisation",fds->fd);
	}
	break;
      default:
	ci_fail(("Unknown fds->other_state"));	
      }
    }
  }
  adv_pos();
  return(fds);
}


/*! Write data to a socket */
void
write_socket(fd_s *fds)
{
  check_exec_pos();
  sanity_check_fd_s(fds);
  fds->ops_on_socket++;
  do_gen_rand_data(fds); 

  if (!is_server) {
    do_write(fds);
  } else {
    do_read(fds);
  }
  adv_pos();
}


/*! Read data to a socket */
void
read_socket(fd_s *fds)
{
  check_exec_pos();
  sanity_check_fd_s(fds);
  fds->ops_on_socket++;
  do_gen_rand_data(fds);

  if (!is_server) {
    do_read(fds);
  } else {
    do_write(fds);
  }
  adv_pos();
}


/*! Close socket */
void close_socket(fd_s *fds) {
  close_socket_ok(fds, OK);
}


/*! Close socket */
void close_socket_ok(fd_s *fds, int ok) {
  check_exec_pos();
  if (!ok) {
    PLAY_LOG("Ignoring close due to too few open sockets");
  } else {
    sanity_check_fd_s(fds);
    do_close(fds);
  }
  adv_pos();
}


/*! Sendto */
void sendto_socket(fd_s *fds) {
  check_exec_pos();
  sanity_check_fd_s(fds);
  fds->ops_on_socket++;

  //Generate random data and send or receive
  do_gen_rand_data(fds);
  if (!is_server) {
    do_sendto(fds,fds->rport);
  } else {
    do_recvfrom(fds,fds->lport);
  }

  adv_pos();
}


void udp_sendto_type(fd_s *fds, ci_uint32 port, is_l5_t is_l5) {
  check_exec_pos();
  sanity_check_fd_s(fds);
  fds->ops_on_socket++;

  do_gen_rand_data(fds);
  if (!is_server) {
    if (can_sendto(fds, is_l5)) {
      do_sendto(fds,port);
    } else {
      PLAY_LOG("Ignoring sendto(A) fd %d due no synchronisation after bind",fds->fd);
    }
  } else {
    if (can_sendto(fds, is_l5)) {
      do_recvfrom(fds,port);
    } else {
      PLAY_LOG("Ignoring sendto(B) fd %d due no synchronisation after bind",fds->fd);
    }
  }
  
  adv_pos();
}


/*! Recvfrom */
void recvfrom_socket(fd_s *fds) {
  check_exec_pos();
  sanity_check_fd_s(fds);
  fds->ops_on_socket++;

  //Generate random data and send or receive
  do_gen_rand_data(fds);
  if (is_server) {
    do_sendto(fds,fds->rport);
  } else {
    do_recvfrom(fds,fds->lport);
  }

  adv_pos();
}

void udp_recvfrom_type(fd_s *fds, is_l5_t is_l5) {
  check_exec_pos();
  sanity_check_fd_s(fds);
  fds->ops_on_socket++;

  //Generate random data and send or receive
  do_gen_rand_data(fds);
  if (is_server) {
    if (can_sendto(fds, is_l5)) {
      do_sendto(fds,fds->rport);
    } else {
      PLAY_LOG("Ignoring sendto(C) fd %d due no synchronisation after bind",fds->fd);
    }
  } else {
    if (can_sendto(fds, is_l5)) {
      do_recvfrom(fds,fds->lport);
    } else {
      PLAY_LOG("Ignoring sendto(D) fd %d due no synchronisation after bind",fds->fd);
    }
  }

  adv_pos();
}

/*! Check that a pair of sockets can be created and data passed */
/*    Uses UNIX domain sockets */
/*    Forks to 2 processes to do this */
/*    Only needs executing on the client but done on both as this*/
/*      keeps random numbers in sync */
void
socket_pair_unix()
{
  int socks[2];
  int rc;
  fd_s *child, *parent;

  check_exec_pos();

  EXEC_TEST_TRY(socketpair(PF_UNIX, SOCK_STREAM, 0, socks));
  adv_pos(); // To ensure that the exec() is strobed across the code

  if (!fork()) {
    /* child  - must be mirror of parent */
    pid=getpid();
    child  = add_fd_s(socks[1]);
    set_state(child,CONNECTED);
    child->is_l5 = KERN;
    close(socks[0]);
    do_gen_rand_data(child);
    do_read(child);
    do_gen_rand_data(child);
    do_write(child);
    do_close(child);
    exit(0);
  } else {
    /* parent - must be mirror of child */
    parent = add_fd_s(socks[0]);
    set_state(parent,CONNECTED);
    parent->is_l5 = KERN;
    close(socks[1]);
    do_gen_rand_data(parent);
    do_write(parent);
    do_gen_rand_data(parent);
    do_read(parent);
    do_close(parent);
    
    /* reap the child */
    wait(&rc);
  }

  //Cleanup needed as do_close only closes if we are playing
  if (!PLAYING) {
    EXEC_TEST_TRY(close(socks[0]));
  }
  adv_pos();
}


fd_s *scm_rights_pass(fork_b dofork, fd_s *fds) {
  return(scm_rights_pass_ok(dofork, fds, OK));
}


fd_s *scm_rights_pass_ok(fork_b dofork, fd_s *fds, int ok) {
  fd_s *ret;
  check_exec_pos();
  int dupfd;

  if (!ok) {
    PLAY_LOG("Ignoring scm_rights_pass() due to too many sockets open");
    return(NULL);
  } else {
    if (!is_server) {
      ret = scm_rights_unix_client(dofork, fds);
    } else {
      //Need to match the adv_pos() called due to socketpair
      //adv_pos();
      
      EXEC_TEST_TRY(dupfd = dup(fds->fd)); 
      ret                = add_fd_s(dupfd);
      set_state(ret,fds->state);
      ret->type          = fds->type;
      ret->lport         = fds->lport;
      ret->rport         = fds->rport;
      ret->state         = fds->state;
      ret->other_state  = fds->other_state;
      ret->is_l5         = fds->is_l5;
      
      PLAY_LOG("dup(%d)=%d state is %d",fds->fd,ret->fd,ret->state);
    }
    
    // Mark both sockets as duplicates
    ret->is_dup = TRUE;
    fds->is_dup = TRUE;
  }

  adv_pos();
  return(ret);
}

/*! Passes file descriptor using SCM through an AF_UNIX socketpipe */
//    In the client
//    i)   Sets up a socketpipe
//    ii)  Forks
//    iii) Create new descriptors
//    iv)  Pass new_fd to the other side
//    v)   Close socketpipe
//    vi)  Kill parent
fd_s *scm_rights_unix_client(fork_b dofork, fd_s *fds) {
  int socks[2];
  int rfd;
  fd_s* ret;
  int local_pid;

  //  adv_pos(); // This is for the socketpair and calling exec

  if (PLAYING) {
    EXEC_TEST_TRY(socketpair(PF_UNIX, SOCK_STREAM, 0, socks));

    if (dofork==DOFORK) {
      // Forking case
      local_pid = fork();
      if (!local_pid) {
        // child
	EXEC_TEST_TRY(close(socks[0]));
	rfd = scm_rights_unix_child(socks[1]); // receive fd
	EXEC_TEST_TRY(close(socks[1]));
      } else {
        //parent
	EXEC_TEST_TRY(close(socks[1]));
	scm_rights_unix_parent(socks[0],fds); // send fd
	EXEC_TEST_TRY(close(socks[0]));
        exit(0);
      }
    } else {
      // Non forking case
      // Parent does the send and must be first
      scm_rights_unix_parent(socks[0],fds);  // send fd
      rfd = scm_rights_unix_child(socks[1]); // receive fd
      EXEC_TEST_TRY(close(socks[0]));
      EXEC_TEST_TRY(close(socks[1]));
    }
  } else {
    rfd = INVALID_SOCK_FD;
  }

  ret = add_fd_s(rfd);
  //Need to transfer state accross
  set_state(ret,fds->state);
  ret->type  = fds->type;
  ret->is_l5 = fds->is_l5; 
  PLAY_LOG("Update internal state from fd(%d)=%d -> fd(%d)=%d",fds->fd,fds->state,ret->fd,ret->state);

  return(ret);
}

// Unpack an fd from a unix domain socket
int scm_rights_unix_child(int fd) {
  struct iovec   vector;      // data from the child 
  struct msghdr  msg;	      // full message 
  int  rfd;                   // The received file descriptor
  char buf[1];                // Buffer of data to be sent (ignored on recv)

  /* set up the iovec for the file name */
  vector.iov_base = buf;
  vector.iov_len  = 1;

  /* the message we're expecting to receive */
  msg.msg_name    = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov     = &vector;
  msg.msg_iovlen  = 1;

  /* dynamically allocate so we can leave room for the file
     descriptor */
  {
    struct cmsghdr *cmsg;       // control message with the fd 

    cmsg               = malloc(sizeof(struct cmsghdr)+sizeof(int));
    cmsg->cmsg_len     = sizeof(struct cmsghdr) + sizeof(int);
    msg.msg_control    = cmsg;
    msg.msg_controllen = cmsg->cmsg_len;

    EXEC_TEST_TRY(recvmsg(fd, &msg, 0));

    memcpy(&rfd, CMSG_DATA(cmsg), sizeof(int));
    free(cmsg);
  }

  PLAY_LOG("SCM RIGHTS received (via fd=%d), fd=%d",fd,rfd);
  ci_assert(rfd<MAX_FD);  

  return(rfd);
}


// Package an fd and send over a unix socket
void scm_rights_unix_parent(int fd, fd_s *fds) {
  struct iovec    vector;    /* some data to pass w/ the fd */
  struct msghdr   msg;       /* the complete message */
  char buf[1];               // Buffer of data received (ignored)
  int len;

  // Send random data down the socket
  vector.iov_base = buf;
  vector.iov_len  = 1;
  
  /* Put together the first part of the message. */
  msg.msg_name    = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov     = &vector;
  msg.msg_iovlen  = 1;

  {
    int *fdptr;
    struct cmsghdr *cmsg;      /* the control message, which will */
                               /* include the fd */

    /* Now for the control message. We have to allocate room for
       the file descriptor. */
    cmsg             = malloc(sizeof(struct cmsghdr)+sizeof(int));
    ci_assert_nequal(cmsg, 0);
    cmsg->cmsg_len   = sizeof(struct cmsghdr) + sizeof(int);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    fdptr = (int *)CMSG_DATA(cmsg);
    memcpy(&fds->fd, fdptr, sizeof(*fdptr));

    msg.msg_control    = cmsg;
    msg.msg_controllen = cmsg->cmsg_len;

    // Send the message
    PLAY_LOG("SCM RIGHTS passing (via fd=%d), fd=%d state=%d",fd, fds->fd,fds->state);
    len = sendmsg(fd,&msg,0);
    ci_assert_equal(len, vector.iov_len);
    free(cmsg);
  }
}


/*! Call select() in the client, random delay and send some data from the server */
void
select_socket(fd_s *fds)
{
  fd_set rfds_orig;
  fd_set rfds;
  struct timeval tv;
  int rc;
  int max_fd;
  int num_rand_fd;
  int fdset;
  fd_s *this_fds;

  check_exec_pos();
  sanity_check_fd_s(fds);
  fds->ops_on_socket++;
  do_gen_rand_data(fds);

  if (!is_server) {
    PLAY_LOG("select_socket on fd=%d",fds->fd);
    if (PLAYING) {
      /* Wait up to five seconds. */
      tv.tv_sec = SELECT_TIMEOUT_SEC;
      tv.tv_usec = SELECT_TIMEOUT_USEC;
      FD_ZERO(&rfds_orig);
      ci_assert(fds->fd<__FD_SETSIZE);
      FD_SET(fds->fd,&rfds_orig);

      // Set some other random file descriptors
      num_rand_fd = random_int(0,MAX_RAND_SELECT_FDS,&randr_priv);
      max_fd = fds->fd + 1;
      while (num_rand_fd>0) {
	this_fds = get_random_open_socket(&randr_priv);
	if (LOG_RAND_SELECT) { PLAY_LOG("Adding (unused) fd %d to select",this_fds->fd); }
        ci_assert(this_fds->fd < __FD_SETSIZE);
	FD_SET(this_fds->fd, &rfds_orig);
        max_fd = (max_fd>this_fds->fd) ? max_fd : this_fds->fd;
	num_rand_fd--;
      }

      max_fd += random_int(0,MAX_RAND_SELECT_FDS,&randr_priv);
      do {
	//Setup structures again
	memcpy(&rfds,&rfds_orig,sizeof(rfds_orig));	

	// Call select
	if (LOG_SELECT) PLAY_LOG("maxfd for select =%d",max_fd);
	EXEC_TEST_TRY(rc=select(max_fd, &rfds, NULL, NULL, &tv));

	// There could be more than one file descriptor woken
	// as another write could occur from the server
	//ci_assert(rc>=1);
	fdset = FD_ISSET(fds->fd, &rfds);

	if (LOG_SELECT) {
	  int c;
	  for (c=0;c<max_fd;c++) {
	    if (FD_ISSET(c, &rfds)) {
	      PLAY_LOG("fd=%d ready to read (clearing)",c);
	      FD_CLR(c, &rfds_orig);
	    }
	  }

	}

      } while (!fdset);
    }
    do_read(fds);
  } else {
    do_random_sleep(MAX_RAND_SELECT_DELAY);
    do_write(fds);
  }
  adv_pos();
}

void socket_sleep_client(void) {
  check_exec_pos();
  if (!is_server) {
    do_random_sleep(SOAK_RANDOM_CLIENT_SLEEP);
  }
  PLAY_LOG("Sleep on client");
  adv_pos();
}

void socket_sleep_server(void) {
  check_exec_pos();
  if (is_server) {
    do_random_sleep(SOAK_RANDOM_SERVER_SLEEP);
  }
  PLAY_LOG("Sleep on server");
  adv_pos();
}

/**************************************************************************
 * FILE OPERATIONS (also called by main)
 * Should have the same constraints as SOCKET OPERATIONS
 * Only happen on the client (no replies needed by the server)
 **************************************************************************/

/*! Open a file */
fd_s *open_file(const char *pathname, int flags) {
  fd_s *fds=NULL;
  int ran;

  check_exec_pos();

  if (!is_server) {
    fds = do_file_open(pathname,flags);
  } else {
    ran = rand_r(&randr_sync);
    if (LOG_RANDOM) DEBUG_LOG("rand()=%x",ran);
  }

  adv_pos();
  return(fds);
}


/*! Close a file */
void close_file(fd_s *fds) {
  check_exec_pos();

  if (!is_server) {
    sanity_check_fd_s(fds);
    do_close(fds);
  }

  adv_pos();
}

/**************************************************************************
 * CLIENT ONLY OPERATIONS
 **************************************************************************/

/*! Fork and kill the parent process */
void fork_kill_parent() {
  pid_t local_pid;
  int old_pid = pid;

  PLAY_LOG("fork_kill_parent");
  if (!is_server && PLAYING) {
    PLAY_LOG("Inside fork_kill_parent");
    close_logfd();
    local_pid = fork();
    EXEC_TEST_TRY(local_pid);

    // parent exits
    if (local_pid!=0) {
      PLAY_LOG("pid %d to %d", old_pid, pid);
      exit(0);
    }

    // child
    pid=getpid();
    if (LOG_PID_CHANGE)
      ci_log("PID change[%d]: %s pid %d->%d",
	     cur_id,__FUNCTION__,old_pid,pid);

    create_log_file(cur_id, play_pos);
  }
  setup_timers(0);
  PLAY_LOG("After fork_kill_parent");
  adv_pos();
}


/*! Fork splitting the sockets between the parent and child */
/* This is done for both the client and the server */
/* and on replays -- TODO this could be expensive for the replay mechanism */
/* After the split the random streams will be the same but due to the different */
/* number of sockets then they will take differrent paths */
/* It would be possible for one fork to keep track of all others but not currently */
void
fork_split_socket()
{
  pid_t local_pid;
  int new_id=0;
  int old_id = cur_id;
  int old_pid = pid;
  int t;                     //temporary level
  fd_s *this_fds,*temp_fds;
  int parent_keep_dup;

  // If not upto the limit for children
  PLAY_LOG("fork_split");
  if ( (children<MAX_PROC_CHILDREN) && ((level+1)<MAX_PROC_LEVELS) ) {
    if (PLAYING) {
      // If playing add to the fork_order string
      close_logfd();
      //DO NOT LOG until this reopened
      EXEC_TEST_TRY( local_pid = fork() );
      ci_assert_lt(strlen(fork_order), MAX_FORK_ORDER_LEN);
      fork_order[strlen(fork_order)] = local_pid ? 'P' : 'C';
    } else {
      // If replaying read (and discard) the first character of fork_order
      ci_assert((*fork_order_opt=='P')||(*fork_order_opt=='C'));
      local_pid = (*fork_order_opt=='P');
      fork_order_opt++;
    }

    // If the child -  calculate a new id and next_port
    if (!local_pid) {
      ci_uint32 index;
      new_id = 0;
      pid=getpid();

      // Sum previous levels
      for (t=0;t<level;t++) { new_id+=(1<<(t*LOG_2_PROC_CHILDREN)); }
      // Get index in current level
      index = cur_id - new_id;
      new_id+=(1<<(level*LOG_2_PROC_CHILDREN));
      // Add for the next level - this is num per parent on nxt level * current index
      ci_assert((cur_id-new_id)>=0);
      new_id += (1<<(level*LOG_2_PROC_CHILDREN)) * index;
      new_id += children;
      set_next_port(new_id);
      level++;

      ci_assert_nequal(new_id, 0);
      cur_id = new_id;

      if (LOG_PID_CHANGE)
	ci_log("PID change[%d]: %s pid %d->%d",
	       cur_id,__FUNCTION__,old_pid,pid);

      setup_timers(0);
    } 

    // Create new log file and send old logging messages
    if (PLAYING) create_log_file(cur_id, play_pos);
    
    if (LOG_FORK_ORDER) {
      if (PLAYING) PLAY_LOG("fork order written - now '%s'",fork_order);
      else PLAY_LOG("fork order reading '%c'",*fork_order);	
    }

    if (!local_pid) {
      // New log file and register ourselves
      if (PLAYING) send_msg_to_supervisor("REG");
      PLAY_LOG("fork_split pid=%d old id=%d children=%d newid=%d level=%d next_port %d",
	       pid,old_id,children,new_id,level,next_port);
      children=0;
    } else {
      children++;
      PLAY_LOG("Num children is now %d",children);
    }

    // for each socket decide if it will be closed in this process
    // note that duplicated sockets must all go one way
    parent_keep_dup = random_distrib(1);
    CI_DLLIST_FOR_EACH3(fd_s,this_fds,dllink,&fds_list,temp_fds) {
      if (this_fds->is_dup) {
	// This is a duplicate socket - decision is made in parent_keep_dup
	if ((local_pid && !parent_keep_dup) ||
	    (!local_pid && parent_keep_dup)) {
	  do_close(this_fds);
	  if (LOG_FORK) PLAY_LOG("pid %d closing (dup)fd=%d",
				 (int)local_pid,this_fds->fd);
	}
      } else {
	// This is not a duplicate - decide if to close on parent/child randomly
	if (random_distrib(1)) { // 50% chance
	  if (local_pid && LOG_FORK)
	      PLAY_LOG("pid %d closing fd=%d",(int)local_pid,this_fds->fd);
	  if (local_pid) do_close(this_fds);
	} else {
	  if (!local_pid && LOG_FORK)
	      PLAY_LOG("pid %d closing fd=%d",(int)local_pid,this_fds->fd);
	  if (!local_pid) do_close(this_fds);
	}
      }
    }
  }
  // Might be no sockets left but this is OK
  PLAY_LOG("After fork split (pid=%d)", pid);
  adv_pos();
}


/*! Check that a close worked           */
/*    Operation does not call adv_pos() */
void check_invalid_fd(int fd) {
  int rc;
  char buf[1];

  //This fd can be invalid because the we might be replaying when this descriptor is saved
  if (!is_server && PLAYING && (fd!=INVALID_SOCK_FD)) {
    rc = read(fd,buf,1);
    CI_TEST((rc==-1) && (errno==EBADF));
  }
}


/*! Uses fcntl to set the close on exec bit */
void set_close_on_exec(fd_s *fds) {
  int arg;
  sanity_check_fd_s(fds);
  fcntl(fds->fd,F_SETFD,FD_CLOEXEC);
  if (!BUG_IGNORE_NO_REREAD_CLOSE_ON_EXIT) {
    arg=fcntl(fds->fd,F_GETFD);
    ci_assert(arg&FD_CLOEXEC);
  }
  fds->close_on_exec = TRUE;
}

/**************************************************************************
 * Conditional functions
 * Used to determine if an operation can occur at the current time
 **************************************************************************/
// Check another connection hasn't happened since the last connection
// on the other type of socket
int can_connect(fd_s *fds,is_l5_t is_l5) {
  int ok;
  ci_assert(is_l5!=UNKNOWN);
  ok=1;

  if (exec_pos==SOAK_TEST_EXEC_POS) {
    if (LOG_ACCEPT_CONNECT_SYNC) {
      if (is_l5==L5) PLAY_LOG("Connect breadk=%d bwritek=%d kern_connect=%d",
			      last_bread_kern_pos,last_bwrite_kern_pos,last_kern_connect);
      else           PLAY_LOG("Connect breadu=%d bwriteu=%d l5_connect=%d",
			      last_bread_l5_pos,  last_bwrite_l5_pos,  last_l5_connect);
    }
    if (is_l5==L5) ok = (CI_MIN(last_bread_kern_pos,last_bwrite_kern_pos) >= last_kern_connect);
    else           ok = (CI_MIN(last_bread_l5_pos,  last_bwrite_l5_pos)   >= last_l5_connect);
  }
  return(ok);
}

// Ensure that there has been a sync (of any type) since the listen() call
int sync_after_listen(fd_s *fds) {
  int last_sync;
  int ok;

  if (!WORKAROUND_LISTEN_FIRST || total_num_conns==0 || exec_pos!=SOAK_TEST_EXEC_POS) {
    ok = 1;
  } else {
    PLAY_LOG("last_bread_kern_pos %d,last_bwrite_kern_pos %d",last_bread_kern_pos,last_bwrite_kern_pos);
    PLAY_LOG("last_bread_l5_pos %d,last_bwrite_l5_pos %d",last_bread_l5_pos,last_bwrite_l5_pos);
    last_sync = CI_MAX( CI_MIN(last_bread_kern_pos,last_bwrite_kern_pos),
			CI_MIN(last_bread_l5_pos,  last_bwrite_l5_pos));
    ci_assert_nequal(fds->listen_pos,last_sync);
    ok = fds->listen_pos < last_sync;
    
    if(!ok) PLAY_LOG("Some op Ignored. sync_after_listen() returned 0. listen_pos=%d > last_sync=%d",
		     fds->listen_pos,last_sync);
  }
    
  return(ok);
}

// Check another connection hasn't happened since the last connection
// on the other type of socket
// Problem is that while order on the backlog is guaranteed it is not between L5 and kernel
int can_accept(fd_s *fds,is_l5_t is_l5) {
  int ok;
  ok=1;

  if (exec_pos==SOAK_TEST_EXEC_POS) {
    ci_assert(is_l5!=UNKNOWN);
    if (LOG_ACCEPT_CONNECT_SYNC) {
      if (is_l5==L5) PLAY_LOG("Accept breadk=%d bwritek=%d kern_accept fd=%d",
			      last_bread_kern_pos,last_bwrite_kern_pos,last_kern_accept);
      else           PLAY_LOG("Accept breadu=%d bwriteu=%d l5_accept fd=%d",
			      last_bread_l5_pos,  last_bwrite_l5_pos,  last_l5_accept);
    }
    if (is_l5==L5) ok = (CI_MIN(last_bread_kern_pos,last_bwrite_kern_pos) >= last_kern_accept);
    else           ok = (CI_MIN(last_bread_l5_pos,  last_bwrite_l5_pos)   >= last_l5_accept);
  } 
  return(ok);
}

// Check that a sendto can be performed
// A socket must be bound on the other side
int can_sendto(fd_s *fds,is_l5_t is_l5) {
  int ok;
  ok=1;

  if (exec_pos==SOAK_TEST_EXEC_POS) {
    ci_assert(is_l5!=UNKNOWN);

    if (LOG_SENDTO_SYNC) {
      if (is_l5==L5) PLAY_LOG("Accept breadk=%d bwritek=%d bind_pos fd=%d",
			      last_bread_kern_pos,last_bwrite_kern_pos,fds->bind_pos);
      else           PLAY_LOG("Accept breadu=%d bwriteu=%d bind_pos fd=%d",
			      last_bread_l5_pos,  last_bwrite_l5_pos,  fds->bind_pos);
    }
    //Must be a minimum of two items to preserve symmetry
    //Must be greater or equal so when initialised to 0 will give ok=TRUE
    if (is_l5==L5) ok = (CI_MIN(last_bread_l5_pos,  last_bwrite_l5_pos)   >= fds->bind_pos);
    else           ok = (CI_MIN(last_bread_kern_pos,last_bwrite_kern_pos) >= fds->bind_pos);
    if (fds->bind_pos==0) ok=FALSE;

  }
  return(ok);
}


/**************************************************************************
 * REAL OPERATIONS
 * Logging should be done here
 * Should not be sensitive to is_server
 * Should not call adv_pos()
 **************************************************************************/

/*! Returns an fd for a socket - optional check against tracked state */
fd_s *
do_socket(int type)
{
  int sockfd;
  fd_s *fds;

  ci_assert(type==SOCK_STREAM || type==SOCK_DGRAM);
  
  if (PLAYING) {
    int retry = 0;
    int retry_count = 0;
    
    do {
      sockfd = socket(AF_INET, type, 0);
      retry = (sockfd < 0) && (errno==EAGAIN || errno == EBUSY);
      if (retry) {
	if (retry_count++ <= 0) {
	    ALERT_LOG("id %d %05d socket - retrying - %s",
		      cur_id, play_pos, strerror(errno));
	}
	if (retry_count > CONNECT_BUSY_MSG_RETRIES+1) {
	    ALERT_LOG("id %d %05d socket - still retrying - %s",
		      cur_id, play_pos, strerror(errno));
	    retry_count = 1;
	}
	PLAY_LOG("socket - retry on '%s' rc %d", strerror(errno), errno);
	do_sleep(CONNECT_BUSY_DELAY);
      } 
    } while (retry);
    
    if (retry_count > 0)
	ALERT_LOG("id %d %05d socket - continuing", cur_id, play_pos);
     
    EXEC_TEST_TRY(sockfd);
    PLAY_LOG("socket() fd=%d type=%s",sockfd,type==SOCK_STREAM?"STREAM":"DGRAM");
  } else {
    PLAY_LOG("ignoring socket()");
    sockfd = INVALID_SOCK_FD;
  }
  fds = add_fd_s(sockfd);
  fds->type = type;
  set_state(fds,CREATED);
  return(fds);
}


#ifdef USE_CHECK_SOCKET

static int check_socket_inet(fd_s *fds, const char *info)
{ struct sockaddr_in inet_name;
  struct sockaddr *name = (struct sockaddr *)&inet_name;
  socklen_t len = sizeof(inet_name);
  int rc = getsockname(fds->fd, name, &len);

  if (rc < 0)
    ALERT_LOG("id %d %05d fd %d check %s :%d - failed to get socket name - %s",
	      cur_id, play_pos, fds->fd, info, fds->rport, strerror(errno));
  else if (name->sa_family != AF_INET) {
    ALERT_LOG("id %d %05d fd %d check %s :%d - socket has wrong protocol - "
	      "%d != %d (AF_INET)",
	      cur_id, play_pos, fds->fd, info, fds->rport, name->sa_family,
	      AF_INET);
    errno = EPROTOTYPE;
    rc = -1;
  }
  
  return rc;
}

#else  /* USE_CHECK_SOCKET */

#define check_socket_inet(fds, info) (0)

#endif /* USE_CHECK_SOCKET */


/*! Make a connection */
void do_connect(fd_s *fds,ci_uint16 port,is_l5_t is_l5) {
  struct sockaddr sa, *sa_p;
  socklen_t sa_len;
  int connect_rc;
  int retry = 0;

  sanity_check_fd_s(fds);
  check_state(fds,CREATED);
  ci_assert_ge(port, FIRST_PORT_NUM);
  ci_assert(is_l5!=UNKNOWN);

#if defined(NDEBUG)
#else
  ci_assert(can_connect(fds,is_l5) && sync_after_listen(fds));
#endif

  if (is_l5==L5) last_l5_connect   = play_pos;
  else           last_kern_connect = play_pos;

  PLAY_LOG("pre connect_%s(fd=%d,server_name=%s) prt=%d",
	   (is_l5==L5)?"l5":"kern",fds->fd,(is_l5==L5)?server_name:server_namek,
	   port);

  if (PLAYING) {
    int retry_count = 0;
    do {
      if (is_l5==L5) {
	other_side_sock.sin_port = htons(port);
	connect_rc=connect(fds->fd,(struct sockaddr*) &other_side_sock, sizeof(other_side_sock));
      } else {
	other_side_kern.sin_port = htons(port);
	connect_rc=connect(fds->fd,(struct sockaddr*) &other_side_kern, sizeof(other_side_kern));
      }
      check_timeout(0, 0);
      retry = (connect_rc==-1) &&
	      (errno == ECONNREFUSED || errno == EAGAIN ||
	       errno == EBUSY || errno == ETIMEDOUT || errno == ECONNRESET);
      if (retry) {
        /* We don't report connection refused - it happens too often */
	if (retry_count++ <= 0 && errno != ECONNREFUSED) {
	    ALERT_LOG("id %d %05d connect :%d - retrying - %s",
		   cur_id, play_pos, fds->rport, strerror(errno));
	}
	if (retry_count > CONNECT_BUSY_MSG_RETRIES+1) {
	    ALERT_LOG("id %d %05d connect :%d - still retrying - %s",
		   cur_id, play_pos, fds->rport, strerror(errno));
	    retry_count = 1;
	}
	/* PLAY_LOG("connect - retry on '%s' rc %d", strerror(errno), errno); */
	do_sleep(CONNECT_BUSY_DELAY);
      } else
        do_sleep(CONNECT_DELAY);
    } while (retry);
    if (retry_count > 0 && errno != ECONNREFUSED)
	ALERT_LOG("id %d %05d connect :%d - continuing",
		  cur_id, play_pos, fds->rport);
    EXEC_TEST_TRY(connect_rc);
    (void)check_socket_inet(fds, "after connect");
  }
  sa_p = &sa;
  sa_len=sizeof(sa);

  getsockname(fds->fd,sa_p,&sa_len);
  fds->rport = ntohs(((struct sockaddr_in*)sa_p)->sin_port);
  PLAY_LOG("connect_%s(fd=%d,server_name=%s,rport=%d) port=%d",
	   (is_l5==L5)?"l5":"kern",fds->fd,(is_l5==L5)?server_name:server_namek,
	   port,fds->rport);
  fds->is_l5 = is_l5;
  set_state(fds,CONNECTED);
  total_num_conns++;
}


/*! See if the timeout has expired and if so quit */
/*! There will always be a race on the two sides timing uot
 *  if we get an error and call this function if we are within
 *  allowance msec of the timeout then quit as a timeout
 */
static void check_timeout(int sig_handler, int allowance)
{
  ci_uint64 frc;

  //has the timeout expired if so break out of the loop
  if (mode==SOAK && end_frc != 0) {
    ci_frc64(&frc);
    if (frc >= (allowance ? end_frc_allowance : end_frc)) {
      if (running == 1) {
	running = 0;
	send_msg_to_supervisor(sig_handler?"ABT":"TMO");
      }
      PLAY_LOG("thread has timedout");
      close_logfd();
      setup_timers(1);
      exit(1);
    }
  } 
}
  
/*! Accept a connection */
fd_s *
do_accept(fd_s *fds,is_l5_t is_l5)
{
  struct sockaddr_in their_addr;  // connector's address information
  socklen_t sin_size;
  int new_fd;
  fd_s *new_fds;

  sanity_check_fd_s(fds);
  check_state(fds,LISTENING);
  ci_assert(is_l5!=UNKNOWN);

#if defined(NDEBUG)
#else
  ci_assert(can_accept(fds,is_l5) && sync_after_listen(fds));
#endif

  if (is_l5==L5) last_l5_accept   = play_pos;
  else           last_kern_accept = play_pos;

  PLAY_LOG("pre accept(fd=%d) prt=%d",fds->fd,fds->lport);

  if (PLAYING) {
    sin_size=sizeof(their_addr);

#if BUG_ACCEPT_RESTART
    new_fd = -1;
    errno = EINTR;
    while ( (new_fd == -1) && (errno == EINTR) )
#endif
    new_fd = accept(fds->fd, (struct sockaddr *) &their_addr, &sin_size);
    EXEC_TEST_TRY(new_fd);

    new_fds = add_fd_s(new_fd);
    new_fds->rport = ntohs(their_addr.sin_port);
    PLAY_LOG("accept(fd=%d) fd=%d lport=%d from %s rport=%d", 
	     fds->fd, new_fd, fds->lport, inet_ntoa(their_addr.sin_addr),new_fds->rport);
  } else {
    new_fds = add_fd_s(INVALID_SOCK_FD);
  }

  new_fds->type   = fds->type;
  new_fds->is_l5  = is_l5;
  new_fds->lport  = fds->lport;
  set_state(new_fds,CONNECTED);
  total_num_conns++;
  return(new_fds);
}


/*! Bind to a local port */
void do_bind(fd_s *fds, int port) {
  struct sockaddr_in my_addr;   // my address information
  int one = 1;
  sanity_check_fd_s(fds);

  check_state(fds,CREATED);
  my_addr.sin_family      = AF_INET;           // host byte order
  my_addr.sin_port        = htons(port);       // short, network byte order
  my_addr.sin_addr.s_addr = htonl(INADDR_ANY); // automatically fill with my IP

  //In-case something is in time-wait on this port
  setsockopt(fds->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  PLAY_LOG("bind(fd=%d,port %d)",fds->fd,port);
  if (fds->type==SOCK_DGRAM && fds->udp_data_sent) {
    PLAY_LOG("Ignoring bind due to UDP data already being sent");
  } else {
    if (PLAYING) {
      int bind_rc;
      int retry = 0;
      int retry_msg = 0;

      do {
        bind_rc = bind(fds->fd, (struct sockaddr *) &my_addr,
		       sizeof(struct sockaddr));
	retry = (bind_rc < 0 && (errno == EAGAIN || errno == EADDRINUSE));
	if (retry) {
	  if (!retry_msg) {
	      retry_msg=1;
	      ALERT_LOG("id %d %05d bind :%d - retrying - %s",
		     cur_id, play_pos, port, strerror(errno));
	  }
          PLAY_LOG("id %d %05d bind :%d - retry on '%s' (rc %d)",
		   cur_id, play_pos, port, strerror(errno), errno);
	  do_sleep(CONNECT_BUSY_DELAY);
	}
      } while (retry);
      EXEC_TEST_TRY(bind_rc);
    }
  }
  fds->lport    = port;
  fds->bind_pos = play_pos;
  set_state(fds,BOUND);
}


/*! Client listen */
void do_listen(fd_s *fds) {
  int listen_rc;
  int retry = 0;
  sanity_check_fd_s(fds);
  check_state(fds,BOUND);
  PLAY_LOG("listen(fd=%d,backlog=%d)",fds->fd,BACKLOG);
  if (PLAYING) {
    int retry_count = 0;
    do {
        listen_rc = listen(fds->fd, BACKLOG);
	retry = listen_rc < 0 && (errno == EAGAIN || errno == EBUSY);
	if (retry) {
	  if (retry_count++ <= 0) {
	      ALERT_LOG("id %d %05d listen :%d - retrying - %s",
		     cur_id, play_pos, fds->lport, strerror(errno));
	  }
	  if (retry_count > CONNECT_BUSY_MSG_RETRIES+1) {
	      ALERT_LOG("id %d %05d listen :%d - still retrying - %s",
		     cur_id, play_pos, fds->lport, strerror(errno));
	      retry_count = 1;
	  }
          /* PLAY_LOG("listen - retry on '%s' (rc %d)",
	              strerror(errno), errno); */
	  do_sleep(CONNECT_BUSY_DELAY);
	}
    }  while (retry);
    if (retry_count > 0) {
	ALERT_LOG("id %d %05d listen :%d - continuing",
		  cur_id, play_pos, fds->lport);
    }
    EXEC_TEST_TRY(listen_rc);
  }
  fds->listen_pos = play_pos;
  set_state(fds,LISTENING);
}


/*! Write some data */
void
do_write(fd_s *fds)
{
  ci_uint32 bytes_written;
  
  sanity_check_fd_s(fds);
  check_state(fds,CONNECTED);
  
  ci_assert(fds->is_l5!=UNKNOWN);
  if       (fds->is_l5==L5)   last_bwrite_l5_pos   = play_pos;
  else if  (fds->is_l5==KERN) last_bwrite_kern_pos = play_pos;

  PLAY_LOG("write(fd=%d,size=%d)",fds->fd,fds->rand_ready);
  if (PLAYING) {
    ci_assert(fds->rand_ready<=MAX_RAND_BUF_SIZE);
    (void)check_socket_inet(fds, "write");
    bytes_written = write(fds->fd,fds->rand_buf,fds->rand_ready);
    check_timeout(0, 0);
    if ((bytes_written==-1) && (errno == ECONNRESET))
      check_timeout(0, 100);
    
    // If this was the first connection could be a listen race
    if (bytes_written==-1) {
      if ((errno == ECONNRESET) &&
          (fds->ops_on_socket<=3) && BUG_LISTEN_RACE) {
        PLAY_LOG("Reconnect due to BUG_LISTEN_RACE");
        set_state(fds,CREATED);
        do_connect(fds,fds->rport,fds->is_l5);
      } else if (errno != EPIPE) {
        EXEC_TEST_TRY(bytes_written);
      }
    } else {
      if (bytes_written!=fds->rand_ready) {
        DEBUG_LOG("fd=%d lport=%d rport=%d\n",fds->fd,fds->lport,fds->rport);
        exec_test_assert_equal(bytes_written,fds->rand_ready);
      }
    }
  }
}


/*! sendto */
void do_sendto(fd_s *fds,int port) {
  ci_int32 bytes_sent;
  sanity_check_fd_s(fds);
  ci_assert_equal(fds->type, SOCK_DGRAM);

  PLAY_LOG("sendto(fd=%d,size=%d,port %d)",fds->fd,fds->rand_ready,port);
  if (PLAYING) {
    other_side_sock.sin_port = htons(port);
    (void)check_socket_inet(fds, "sendto");
    EXEC_TEST_TRY(bytes_sent = sendto(fds->fd, fds->rand_buf,fds->rand_ready,
			       MSG_DONTWAIT,
			       (struct sockaddr*) &other_side_sock,
			        sizeof(other_side_sock)));
    exec_test_assert_equal(bytes_sent, fds->rand_ready);
  }
  fds->udp_data_sent=TRUE;
}


/*! Read some data */
void do_read(fd_s *fds) { 
  ci_uint32 byte_count;
  ci_int32  read_bytes;

  sanity_check_fd_s(fds);
  check_state(fds,CONNECTED);

  ci_assert(fds->is_l5!=UNKNOWN);
  if       (fds->is_l5==L5)   last_bread_l5_pos   = play_pos;
  else if  (fds->is_l5==KERN) last_bread_kern_pos = play_pos;

  PLAY_LOG("read(fd=%d,size=%d)",fds->fd,fds->rand_ready);
  if (PLAYING) {
    ci_assert_le(fds->rand_ready, MAX_RAND_BUF_SIZE);
    (void)check_socket_inet(fds, "read");
    //Do the read() - deal with the case where the data is split up
    byte_count=0;
    do {
      read_bytes = read(fds->fd, fds->read_buf+byte_count,
			      fds->rand_ready-byte_count);

      check_timeout(0, 0);
      if ((read_bytes==-1) && (errno == ECONNRESET))
	check_timeout(0, 100);

      // If this was the first connection could be a listen race
      if (read_bytes==-1 && (errno == ECONNRESET)) {
        if ((fds->ops_on_socket<=3) && BUG_LISTEN_RACE) {
          PLAY_LOG("Reconnect due to BUG_LISTEN_RACE");
	  set_state(fds,CREATED);
	  do_connect(fds,fds->rport,fds->is_l5);
        }
      } else {
        EXEC_TEST_TRY(read_bytes);
      }
      
      if (LOG_READS) PLAY_LOG("Read %d bytes total %d bytes from fd=%d",
			      read_bytes,byte_count,fds->fd);
      byte_count += read_bytes;
      if (STRICT_RW) exec_test_assert_equal(byte_count,fds->rand_ready);
    } while (byte_count!=fds->rand_ready && read_bytes);

    //Test byte_count rather than fds->rand_ready as due to timeout
    //other end may quit and send truncated data

    if (byte_count != fds->rand_ready) {
      PLAY_LOG("short data read got %d expected %d",
	     byte_count, fds->rand_ready);
      ci_log("short data read got %d expected %d",
	     byte_count, fds->rand_ready);
    } else {
      if (memcmp(fds->rand_buf, fds->read_buf, byte_count)!=0) {
        //print_compare(byte_count, fds->read_buf, fds->rand_buf);
        ci_log("data corrupt?");
      }
    }
  }
}

/*! Read some data and compare to expected */
void do_recvfrom(fd_s *fds, int port) { 
  ci_uint32 bytes_recvd = 0;

  sanity_check_fd_s(fds);

  PLAY_LOG("recvfrom(fd=%d,size=%d)",fds->fd,fds->rand_ready);
  if (PLAYING) {
    other_side_sock.sin_port = htons(port);
    (void)check_socket_inet(fds, "recvfrom");
    
    EXEC_TEST_TRY(bytes_recvd = read(fds->fd,fds->read_buf,fds->rand_ready));

    exec_test_assert_equal(fds->rand_ready,bytes_recvd);
    if( memcmp(fds->rand_buf,fds->read_buf,fds->rand_ready)) {
      print_compare(fds->rand_ready, fds->read_buf, fds->rand_buf);
    }
    CI_TEST(!memcmp(fds->rand_buf,fds->read_buf,fds->rand_ready));
  }
  fds->udp_data_sent=TRUE;
}


/*! Close the client socket */
void do_close(fd_s *fds) {
  sanity_check_fd_s(fds);

  PLAY_LOG("close(fd=%d)",fds->fd);
  if (PLAYING) {
    (void)check_socket_inet(fds, "close");
    EXEC_TEST_TRY(close(fds->fd));
  }

  close_fd_s(fds);
}


/*! Open a file */
fd_s *do_file_open(const char *pathname, int flags) {
  fd_s *fds;
  int fd;

  fd = INVALID_SOCK_FD;  
  //Always create an fd_s as this is the equivalent of socket()
  if (PLAYING) {
    EXEC_TEST_TRY(fd = open(pathname,flags));
    ci_assert_ge(fd, 0);
  }

  PLAY_LOG("do_file_open(%s,%d)=%d",pathname,flags,fd);

  fds = add_fd_s(fd);
  set_state(fds,OPENFILE);
  sanity_check_fd_s(fds);
  return(fds);
}


/* Wrapper to do_exec2 */
void do_exec() {
  do_exec2(play_pos);
}


/*! Make an execlp() call to spawn this executable again */
void do_exec2(ci_uint32 pos) {
  char arg1[32];  //-r
  char arg2[32];  //-e
  char arg3[32];  //-i
  char arg4[32];  //-p
  char arg5[32];  //-z
  char arg6[32];  //-a
  char arg7[32];  //-b
  char arg9[32];  //-x
  char *socket_order;

  remove_close_on_exec();
  /* Be very careful about where adv_pos() is called */
  if (!is_server) {
    if (PLAYING) {
      ci_assert(real_prog_name);
      ci_assert(server_name);
      socket_order = create_socket_order();
      snprintf(arg1,32,"-r%d",pos+1); //cannot call adv_pos() as PLAY_LOG uses it
      snprintf(arg2,32,"-e%d",exec_pos);
      snprintf(arg3,32,"-i%d",cur_id);
      snprintf(arg4,32,"-p%d",supervisor_fd);
      snprintf(arg5,32,"-z%d",randr_sync_orig);
      snprintf(arg6,32,"-a%s",inet_ntoa(other_side_sock.sin_addr));
      snprintf(arg7,32,"-b%s",inet_ntoa(other_side_kern.sin_addr));
      snprintf(arg9,32,"-x%"CI_PRIu64,end_frc);

      /* Ensure that args printed to the log are the same as those exec'ed */
      PLAY_LOG("execlp'ing %s args %s %s %s %s %s %s %s %s %s -olength=%zu\n",real_prog_name,
	       arg1,arg2,arg3, arg4,arg5,arg6,arg7,arg9,fork_order,strlen(socket_order));
      adv_pos();  
      close_logfd();
      execlp(real_prog_name,real_prog_name,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg9,fork_order,socket_order,NULL);
      perror("Error calling execlp()");

      // Should never get here as the exec should have occured!
      ci_fail(("exec() should have occured"));
    } else if (PLAYPOINT) {
      //Fill in all the FD info
      parse_socket_order();
      PLAY_LOG("exec changed to parse_socket_order()");
    }
  } else {
    PLAY_LOG("Ignoring exec because this is the server");
  }
  adv_pos();
}


/*! Print a label into the log */
void main_label(char *text) {
  PLAY_LOG("===LABEL: %s",text);
}


/*! Check that the state does not indicate any open sockets */
void check_no_open_sockets() {
  ci_assert(ci_dllist_is_empty(&fds_list));
}


/*! Close all sockets */
void do_cleanup() {
  fd_s *this_fds;
  ci_uint32 this_pos;
  fd_s *temp;          // Temp used by CI_DLLIST_FOR_EACH3
  
  this_pos=play_pos; // maintain play_pos through the close calls

  PLAY_LOG("cleanup_sockets() **** Closing all sockets START");
  if (PLAYING) {
    CI_DLLIST_FOR_EACH3(fd_s,this_fds,dllink,&fds_list,temp) {
      close_socket(this_fds);
      play_pos=this_pos;
    }
  }
  ci_assert_equal(total_num_socks, 0);
  PLAY_LOG("cleanup_sockets() **** Closing all sockets END");
  adv_pos();

  //Ensure that nothing remians in the fd_s list
  check_no_open_sockets();
}


/* Generate some random data */
/*   Assumes that data is generated immediately before being used */
/*   Therefore dta generation is unecesarry if replaying */
void do_gen_rand_data(fd_s *fds) {
  ci_uint32 c;
  ci_uint32 i; // Random seed for generating the data

  sanity_check_fd_s(fds);

  fds->rand_ready = 1 + random_int(0,MAX_RAND_BUF_SIZE-1,&randr_sync);
  i = rand_r(&randr_sync)^0xA5A5A5A5; // XOR with a value so the stream is different

  if (LOG_RANDOM)
      DEBUG_LOG("Generated %d random bytes fd %d randr %x",
		fds->rand_ready,fds->fd,randr_sync);

  //Fill buffer with random data
  if (PLAYING) {
    for (c=0;c<fds->rand_ready;c+=4) {
      if (i & 1)  { i = (i >> 1) ^ LFSR_FEEDBACK0; }
      else        { i = (i >> 1); }
      *((int*)(fds->rand_buf+c)) = i;
      if (LOG_GEN_RANDOM) {
	DEBUG_LOG("Generating 0x%x (0x%x) LFSR is 0x%x",
		  c,*((int*)(fds->rand_buf+c)),i);
      }
    }
  }
}


/*! Get the next random number */
/*   This function is replicated in do_gen_rand_data */
inline void get_rand(ci_uint32 *j) {
  ci_uint32 i;
  i=*j;
  if (i & 1)  { i = (i >> 1) ^ LFSR_FEEDBACK0; }
  else        { i = (i >> 1); }
  *j=i;
}

/**************************************************************************
 * OTHER OPERATIONS
 **************************************************************************/

/*! Sleep for a set ammount of time */
void do_sleep(int sleeptime) {
  struct timespec left_tv;
  struct timespec delay_tv;

  delay_tv.tv_sec  = 0;
  delay_tv.tv_nsec = sleeptime;

  //Wait until we have waited this long
  while (nanosleep(&delay_tv,&left_tv)) {  
    memcpy(&delay_tv,&left_tv,sizeof(struct timeval));
  }
}


/*! Sleep for a random period of time */
void do_random_sleep(int maxtime) {
  int sleept;
  sleept = random_int(0,maxtime,&randr_priv);
  do_sleep(sleept);
}

/*! Handle a SIGALRM - necessary to support timeouts */
void sigpipe_handler(int signal)
{
  ci_log("got SIGPIPE");
}

/*! Setup signals */
void setup_signals(void)
{
  ci_assert_nequal(signal(SIGPIPE, sigpipe_handler), SIG_ERR);
}

/*! Handle a SIGALRM - necessary to support timeouts */
void timer_handler(int signal)
{
  //Timer reloads automatically
  check_timeout(1, 0);
  
  //check that we have made progress recently
  if (play_pos == timer_play_pos) {
    ci_log("[%d:%d]Error have not made progress", cur_id, play_pos);
    ci_log("Last item was '%s'", last_log_str);
    PLAY_LOG("Error have not made progress");
    send_msg_to_supervisor("PRG");
    close_logfd();
    exit(2);
  } else {
    timer_play_pos = play_pos;
  }
}

/*! Setup the timers */
void setup_timers(int end)
{
  struct itimerval itv;

  if (end_frc) {
    ci_assert_nequal(signal(SIGALRM, timer_handler), SIG_ERR);
    
    // after an exec there might be a large delay
    // as a replay (to recover all state) has to happen
    itv.it_interval.tv_sec  = end?0:2; //reload
    itv.it_interval.tv_usec = 0;
    itv.it_value.tv_sec     = end?0:2; //one-shot value
    itv.it_value.tv_usec    = 0;
    
    EXEC_TEST_TRY(setitimer(ITIMER_REAL, &itv, NULL));
  }
}


/*! Do any setup necessary */
void do_setup(int argc,char *argv[]) {
  int opt_len;

  //Anything that needs to be set as a default value
  real_prog_name=argv[0];
  exec_pos=0;
  supervisor_fd=0;
  total_num_socks = 0;
  total_num_conns = 0;
  randr_sync=NO_RAND_SEED;
  mode = SETUP;
  replay_pos = 0;

  ci_dllist_init(&fds_list);

  ci_app_getopt("[server]", &argc, argv, cfg_opts, N_CFG_OPTS);

  if (is_server) {
    if (LOG_BANNER) {
      ci_log("************ SERVER *****************");
      ci_log("Note that sequence numbers are not necessarily unique");
      ci_log("client connect() becomes bind(),listen(),accept()");
    }
  } else {
    if (LOG_BANNER) {
      ci_log("Client[%d:%d] replay_pos=%d\t", id_opt, pid, replay_pos);
    }
  }

  opt_len = socket_order_opt ? strlen(socket_order_opt)/4 : 0;
  if (LOG_CLI) {
    ci_log("Starting execution of '%s' with replay pos at %d exec_pos at %d socket_order len %d", \
	 real_prog_name, replay_pos, exec_pos, opt_len);
  }

  // Check that the address is supplied properly
  if (  (!l5_addr_opt != !kern_addr_opt) 
     || (!l5_addr_opt && (argc!=2)) 
     || (l5_addr_opt  && (argc!=1)) ) {
    ci_app_usage("Please supply both -a and -b or the name of the machine running the other side");
  }

  // Setup any globals
  server_name = argv[1];  
  last_command_pos = exec_pos+1; //Must do this iteration to work out the number of commands
  set_next_port(cur_id);

  // Protect against printf printing "(null)"
  if (fork_order_opt) snprintf(fork_order,sizeof(fork_order),"-g%s",fork_order_opt);
  else                snprintf(fork_order,sizeof(fork_order),"-g");

  //Resolve the supplied hostname for L5 socket
  if (l5_addr_opt) { 
    server_name = (char*)l5_addr_opt; 
  }
  EXEC_TEST_TRY(ci_host_port_to_sockaddr_in(server_name,0,&other_side_sock));

  //Resolve the supplied hostname for kernel socket
  if (kern_addr_opt) {
    server_namek = (char*)kern_addr_opt; 
  } else {
    server_namek = strdup(server_name);
    // Remove "-l" or "-m"
    if (!strncmp(server_name+strlen(server_name)-2,"-l",2)) {
      server_namek[strlen(server_name)-2]=0;
    } else if (!strncmp(server_name+strlen(server_name)-2,"-m",2)) {
      server_namek[strlen(server_name)-2]=0;
    } else {
      ci_log("*** NOT using L5 sockets as '-l' or '-m' hostname not supplied");
    }
  }
  EXEC_TEST_TRY(ci_host_port_to_sockaddr_in(server_namek,0,&other_side_kern));

  if (randr_sync==NO_RAND_SEED) {
    if (!is_server) {
      // Don't set top bit to ease signed<->unsigned problems
      randr_sync=time(NULL)&0x7FFFFFFF;
    }
  } else if (is_server) {
    ci_app_usage("Only supply -z to the client");
  }
  
  supervisor_process();       // Does not return for the supervisor
  setup_signals();
  setup_timers(0);
}


/*! Calculate end time if timeout requested - mut be after wait_forclient() */
void setup_end_time(void)
{
  unsigned cpu_khz;
  EXEC_TEST_TRY(ci_get_cpu_khz(&cpu_khz));

  if (timeout != 0) {
    ci_frc64(&start_frc);
    end_frc = start_frc + timeout * cpu_khz * (ci_uint64)1000;
    end_frc_allowance = end_frc - (cpu_khz * 100);
    if (start_frc > end_frc) ci_assert(0); // can't cope with wrapping case so bail
  } 
}


/*! Add a process into the supervisors linked list */
void supervisor_add_process(int pid, int id, ci_dllist *list) {
  process_list_s *this_proc;
  //Ensure that there isn't a duplicate
  CI_DLLIST_FOR_EACH2(process_list_s,this_proc,dllink,list) {
    ci_assert_nequal(this_proc->id,  id);
    ci_assert_nequal(this_proc->pid, pid);
  }
  this_proc=malloc(sizeof(*this_proc));
  CI_TEST(this_proc);
  this_proc->id=id;
  ci_dllist_push(list,&this_proc->dllink);
  if (LOG_SUPERVISOR_PIDS)
    ci_log("%s pid=%d id=%d", __FUNCTION__, pid, id);
}

/*! Remove a process from the supervisors linked list */
void supervisor_remove_process(int pid, int id, ci_dllist *list, int timeout) {
  process_list_s *this_proc,*temp_proc;
  int found;

  found=0;
  CI_DLLIST_FOR_EACH3(process_list_s,this_proc,dllink,list,temp_proc) {
    if (this_proc->id==id) {
      ci_assert(!found);
      found=1;
      ci_dllist_remove(&this_proc->dllink);
    }
  }
  if (!found) {
    ci_log("FIN/TMO/ABT received for unknown pid=%d id=%d timeout=%d",
	   pid, id, timeout);
    ci_assert(0);
  }
  if (LOG_SUPERVISOR_PIDS)
    ci_log("%s pid=%d id=%d timeout=%d",__FUNCTION__, pid, id, timeout);
}


/*! The loop of the supervising process */
void supervisor_process() {
  int socks[2];

  if (supervisor_fd==0) {
    EXEC_TEST_TRY(socketpair(PF_UNIX, SOCK_STREAM, 0, socks));
    supervisor_fd = socks[0];

    if (fork()) {
      char msg[SUPERVISOR_MSG_LEN+1];
      unsigned n;
      int got_id, got_pid;
      ci_dllist proclist;

      ci_dllist_init(&proclist);
      struct pollfd pfd = { socks[1], POLLIN, 0 };

      //supervisor process
      print_warnings();

      while (1) {
	sleep(1);
	//Process messages of thread registration/ending
        //Use id and not pid and fork_kill_parent() and exec()
        //do not register the new pid
	do {
	  EXEC_TEST_TRY(poll(&pfd,1,0));
	  EXEC_TEST_TRY(n=read(socks[1],msg,SUPERVISOR_MSG_LEN));
	  msg[n]=0;
	  if (LOG_SUPERVISOR) fprintf(stderr,"Supervisor reads %d %s\n",n,msg);
	  ci_assert_equal(n,SUPERVISOR_MSG_LEN);
	  
	  n=sscanf(msg+4,SUPERVISOR_MSG_FMT,&got_pid, &got_id);
	  ci_assert_equal(n,2);

	  if (!strncmp(msg,"REG",3)) {
	    supervisor_add_process(got_pid, got_id, &proclist);
	  } else if  (!strncmp(msg,"FIN",3)) {
	    supervisor_remove_process(got_pid, got_id, &proclist, 0);
	    if (ci_dllist_is_empty(&proclist)) {
	      ci_log("All proccesses have exited. Quitting.\n");
	      exit(0);
	    }
	  } else if  (!strncmp(msg,"TMO",3)) {
	    supervisor_remove_process(got_pid, got_id, &proclist, 1);
	    if (ci_dllist_is_empty(&proclist)) {
	      ci_log("All proccesses have exited. Quitting.\n");
	      exit(0);
	    }
	  } else if  (!strncmp(msg,"ABT",3)) {
	    supervisor_remove_process(got_pid, got_id, &proclist, 2);
	    if (ci_dllist_is_empty(&proclist)) {
	      ci_log("All proccesses have exited. Quitting.\n");
	      exit(0);
	    }
	  } else if  (!strncmp(msg,"PRG",3)) {
	    ci_log("Client[%d:%d] reports it is not making progress",
		   got_id, got_pid);
	    ci_log("Supervisor process goes crazy and kills everyone (killpg) ...");
	    killpg(getpgrp(),SIGINT); //everyone is going to die - including me
	    exit(3);
	  } else {
	    ci_log("Unknown supervisor command '%3.3s'\n",msg);
	    ci_assert(0);
	  }
	    
	} while (pfd.revents & POLLIN);

	//TODO ensure that all threads are still alive
        //now only have IDs. 
      }
      ci_assert(0);
    } else {
      // child
      pid = getpid();
      send_msg_to_supervisor("REG");
    }
  } 
}


/*! Register this worker process with the supervisor */
void send_msg_to_supervisor(char *op) {
  char msg[SUPERVISOR_MSG_LEN+1];
  int n;
  ci_assert_equal(strlen(op),3);
  ci_assert_equal(pid,getpid());
  ci_assert(supervisor_fd>2);
  n=snprintf(msg,SUPERVISOR_MSG_LEN+1,"%s "SUPERVISOR_MSG_FMT,op,pid,PLAYING?cur_id:id_opt);
  if (LOG_SUPERVISOR) DEBUG_LOG("send_msg_to_supervisor() %s",msg);
  ci_assert_equal(n,SUPERVISOR_MSG_LEN);
  EXEC_TEST_TRY(n=send(supervisor_fd,msg,SUPERVISOR_MSG_LEN,0));
  ci_assert_equal(n,SUPERVISOR_MSG_LEN);
}


/*! Do any setup needed for the current mode */
/* Often used at the start of each iteration */
void do_setup_mode(mode_enum modearg) {
  mode = modearg;
  gettimeofday(&tv, NULL);
  play_pos=0;
  randr_sync=randr_sync_orig;
  if (modearg==SOAK) exec_pos=SOAK_TEST_EXEC_POS;
}


/*! Print configuration warnings */
void print_warnings(void)
{
  if (BUG_IGNORE_NO_REREAD_CLOSE_ON_EXIT) 
    ci_log("BUG_IGNORE_NO_REREAD_CLOSE_ON_EXIT is enabled");
  if (BUG_LISTEN_RACE)
    ci_log("BUG_LISTEN_RACE is enabled");
  if (BUG_ACCEPT_RESTART)
    ci_log("BUG_ACCEPT_RESTART is enabled - bug 4002");
}


/*! Function that calls accept() and waits for the user to run the client */
/*  This will get called for exec'ed processes as well - but will REPLAY */
void wait_for_client() {
  fd_s *fds;
  char arg1[32];

  randr_sync_orig = randr_sync; // use as a temporary
  if (exec_pos==0) {
    fds = create_socket(SOCK_STREAM);
    fds = connect_socket(fds,SETUP_PORT_NUM);
    // send the random seed from client -> server
    if (is_server) {
      randr_sync=NO_RAND_SEED;
      EXEC_TEST_TRY(read(fds->fd,arg1,32));
      sscanf(arg1,"%u",&randr_sync);
    } else {
      randr_sync = randr_sync_orig;
      ci_log("random seed is %u",randr_sync);
      ci_log("recreate this using -z=%u",randr_sync);
      snprintf(arg1,sizeof(arg1),"%u",randr_sync);
      EXEC_TEST_TRY(write(fds->fd,arg1,strlen(arg1)+1));
    }
    gettimeofday(&tv, NULL);
    close_socket(fds);
    exec_pos++;
    last_command_pos++;
  }
  play_pos=0;

  // Generate randr_priv. 
  // By adding 1 should get a different random stream
  ci_assert(randr_sync!=NO_RAND_SEED);
  randr_priv = randr_sync+1;
  if (LOG_RANDOM) ci_log("randr_sync is %u",randr_sync);
  if (LOG_RANDOM) ci_log("randr_priv is %u",randr_priv);
  randr_sync_orig = randr_sync;
}


typedef struct port_range_struct
{   int from;
    int to;    /* inclusive */
} port_range_t;

#define SINGLETON_PORT(p)        { p, p }
#define PORT_RANGE(from_p, to_p) { from_p, to_p }
#define PORTLIST_END             { -1, -1 }

static port_range_t ignored_port_range[] =
{ SINGLETON_PORT(1080),   // socks
  SINGLETON_PORT(1494),   // citrix ica
  SINGLETON_PORT(1524),   // ingres
  SINGLETON_PORT(1758),   // tftp-mcast
  SINGLETON_PORT(2049),   // nfs
  SINGLETON_PORT(2809),   // corba
  SINGLETON_PORT(3130),   // sqid
  SINGLETON_PORT(3306),   // mysql
  SINGLETON_PORT(4321),   // remote whois
  SINGLETON_PORT(4444),   // Kerberos
  SINGLETON_PORT(6000),   // X
  PORT_RANGE(6010, 6020), // 10 X11 forwards
  SINGLETON_PORT(7100),   // xfs
  SINGLETON_PORT(8080),   // webcache
  PORTLIST_END
};

/*! Get the next port number */
/* Sets the global first_iter_port */
int get_next_port(){
  port_range_t *r = &ignored_port_range[0];
  next_port++;
  while (r->from >= 0)
  {   if (next_port>=r->from && next_port<=r->to)
	  next_port = r->to+1; 
      if (next_port>=MAX_PORT_NUM)
	  next_port = FIRST_PORT_NUM+1;
      r++;
  }
  if (LOG_PORT_ALLOC)
    ci_log("id=%d get_next_port=%d play_pos=%d",cur_id,next_port,play_pos);
  return(next_port);
} 

/*! set the next port number */
void set_next_port(int id)
{
  next_port = FIRST_PORT_NUM + id*MAX_FD;
  if (LOG_PORT_ALLOC)
    ci_log("id=%d for id=%d set_next_port=%d", cur_id, id, next_port);
}

/*! Decide if we need to run do_exec() on this cycle */
void check_exec_pos() {
  if ((mode==STROBE) && (exec_pos!=0) && (exec_pos==play_pos)) {
    do_exec2(play_pos);
  }
}


/*! Print out a side by side data comparison */
void print_compare(int size, char* data1,char* data2) {
  ci_uint32 a,b;
  int c;

  if (size==0) ci_log("No compare as size=0");
  for (c=0;c<size;c+=4) {
    a = *(int*)(data1+c);
    b = *(int*)(data2+c);
    if (a != b)
      ci_log("%8.8x: Was 0x%8.8x Expect 0x%8.8x", c, a, b );
  }
}

/*! Create a log file with a unique name */
void create_log_file(int lid,int lpos) {
  char fname[128];
  snprintf(fname,sizeof(fname),"%c%3.3d.%6.6d.log",is_server?'s':'c',lid,lpos);
  logfd=fopen(fname,"w+");
  EXEC_TEST_TRY(logfd?0:-1);
}

void close_logfd(void)
{
  fclose(logfd);
  logfd = NULL;
}

/**************************************************************************
 * RANDOMISED FUNCTIONS
 **************************************************************************/

/*! Get a random integer between min(inclusive) and max (exclusive) */
int random_int(int min, int max, unsigned int *seedp) {
  int ran;

  ci_assert_ge(max, 0); // Really only handle uints. 
                     // Here for catching usage errors
  if (max==0) {
    ran=0; //Avoid divide by zero
  } else {
    ran = rand_r(seedp) % max;
  }
  if (LOG_RANDOM) PLAY_LOG("random min=%d max=%d =%d",min,max,ran);
  return(ran);
}

/*! Pick a socket at random */
fd_s *
get_random_open_socket(ci_uint32 *ran)
{
  fd_s *this_fds;     // Iterators in FOR_EACH2 loop
  this_fds = NULL;
  int weight = 0;

  //This function gives greater weight to connections since the
  //WORKAROUND_LISTEN_FIRST fix means that they must occur twice before
  //data can flow
  CI_DLLIST_FOR_EACH2(fd_s,this_fds,dllink,&fds_list) {
    weight += (this_fds->state == CREATED &&
	       this_fds->listen_pos != 0)?  RAND_SECOND_CONNECT_WEIGHTING: 1;
  }
  
  //pick a random weight in the linked list
  weight = random_int(0,weight,ran);

  //walk the linked list to find the entry with this weight
  CI_DLLIST_FOR_EACH2(fd_s,this_fds,dllink,&fds_list) {
    if (weight <= 0) break;
    weight -= (this_fds->state == CREATED &&
	       this_fds->listen_pos != 0)? RAND_SECOND_CONNECT_WEIGHTING: 1;
  }
  ci_assert_le(weight, 0);
  if (LOG_RANDOM||LOG_OP_PICKED) 
    PLAY_LOG("choosing random socket fd=%d state=%d other_state=%d",
	     this_fds->fd,this_fds->state,this_fds->other_state);
  return(this_fds);
}


/*! Perform a random operation on the socket passed */
//    Use the rand_state_X static lists to pick an operation
void
perform_random_op(fd_s *fds,  rand_state_s ops[])
{
  ci_uint32 entries;  // Number of random entried to consider
  ci_uint32 total;    // Weight total
  ci_uint32 c;        // Loop iterator
  ci_uint32 op;       // Random operation
  int newok;          // True if creating a fd is OK
  int closeok;        // True if closing an fd is OK

  //Count the total weight
  total=0;
  entries=0;
  while (ops[entries].func!=NULL) {
    total += ops[entries].weight;
    entries++;
    ci_assert_lt(entries, 100); // A sanity check
  }
  ci_assert_gt(entries, 0);
  ci_assert_gt(total, 0);

  //Generate a random number to pick the operation
  if (LOG_SOAK) DEBUG_LOG("total weight=%d",total);
  ci_assert_gt(total, 0);
  op = random_int(0,total,&randr_sync);
  if (LOG_OP_PICKED) PLAY_LOG("picked op=%d",op);

  //Go through a second pass, deciding which entry to pick
  total=0;
  for (c=0;c<entries;c++) {
    if (ops[c].weight!=0) {
      //Must be >= and < to deal with zero indexed op
      if ((op>=total) && (op<total+ops[c].weight)) break;
    }
    total+=ops[c].weight;
  }
  ci_assert_le(c, entries);
  if (LOG_OP_PICKED) PLAY_LOG("Random entry chosen was %d func is %s",c,ops[c].func);

  // Check that there are enough file descriptors available
  newok   = (total_num_socks<=MAX_SOCKS_PER_PROCESS);
  closeok = (total_num_socks> (WORKAROUND_LISTEN_FIRST?2:1));

  //Perform the action
  //if (ok) must preceed anything that may use more fds
  if        (!strcmp(ops[c].func,"connect_l5"))        { connect_socket_type_ok(fds,get_next_port(),L5,newok);
  } else if (!strcmp(ops[c].func,"connect_kern"))      { connect_socket_type_ok(fds,get_next_port(),KERN,newok);
  } else if (!strcmp(ops[c].func,"bind"))              { bind_socket(fds,get_next_port());
  } else if (!strcmp(ops[c].func,"close"))             { close_socket_ok(fds,closeok);
  } else if (!strcmp(ops[c].func,"listen"))            { listen_socket(fds);
  } else if (!strcmp(ops[c].func,"accept_l5"))         { accept_socket_type_ok(fds,L5,newok);
  } else if (!strcmp(ops[c].func,"accept_kern"))       { accept_socket_type_ok(fds,KERN,newok);
  } else if (!strcmp(ops[c].func,"send"))              { write_socket(fds);
  } else if (!strcmp(ops[c].func,"recv"))              { read_socket(fds);
  } else if (!strcmp(ops[c].func,"exec"))              { do_exec();
  } else if (!strcmp(ops[c].func,"fork"))              { fork_kill_parent();
  } else if (!strcmp(ops[c].func,"forkexec"))          { fork_kill_parent(); do_exec();
  } else if (!strcmp(ops[c].func,"forksplit"))         { fork_split_socket();
  } else if (!strcmp(ops[c].func,"select"))            { select_socket(fds);
  } else if (!strcmp(ops[c].func,"scm_pass"))          { scm_rights_pass_ok(NOFORK,fds,newok); //TODO add more options here
  } else if (!strcmp(ops[c].func,"sendto"))            { sendto_socket(fds);
  } else if (!strcmp(ops[c].func,"sendto_l5_udp"))     { udp_sendto_type(fds,get_next_port(),L5);
  } else if (!strcmp(ops[c].func,"sendto_kern_udp"))   { udp_sendto_type(fds,get_next_port(),KERN);
  } else if (!strcmp(ops[c].func,"recvfrom"))          { recvfrom_socket(fds);
  } else if (!strcmp(ops[c].func,"recvfrom_l5_udp"))   { udp_recvfrom_type(fds,L5);
  } else if (!strcmp(ops[c].func,"recvfrom_kern_udp")) { udp_recvfrom_type(fds,KERN);
  } else if (!strcmp(ops[c].func,"sleep_c"))           { socket_sleep_client();
  } else if (!strcmp(ops[c].func,"sleep_s"))           { socket_sleep_server();
  } else {
    ci_fail(("Should decode all soak test operations '%s'",ops[c].func));
  }

}


/*! Returns TRUE (1:X) or FALSE */ 
int random_distrib(int x) {
  return(random_int(0,x+1,&randr_sync)==0);
}

/**************************************************************************
 * MAIN 
 **************************************************************************/
int main(int argc, char *argv[]) {
  pid=getpid();
  do_setup(argc,argv); // does not return for supervisor

  create_log_file(cur_id,replay_pos);

  wait_for_client(); // Needed - has to replay to maintain state
  setup_end_time();

  // Skip strobe test if in soak test
  if (TEST_STROBE && (exec_pos<SOAK_TEST_EXEC_POS)) {
    strobe_exec_over();
    ci_log("strobe test completed");
  }
  set_next_port(cur_id);
  if (TEST_SOAK) {
    soak_test();
    ci_log("soak test passed OK for id=%d (Please check others)",cur_id);
  }

  running = 0; // Do this first to avoid race - as it will quit shortly!
  send_msg_to_supervisor("FIN");
  PLAY_LOG("thread has completed its work");

  close_logfd();
  setup_timers(1);
  exit(0);
}


/*! Do a soak test */
void
soak_test()
{
  fd_s *fds;
  fd_state state;
  ci_uint32 n;

  do_setup_mode(SOAK);

  //Change the initial value set in the for loop if adding more 
  play_pos=0;
  if (ENABLE_TCP) create_socket(SOCK_STREAM);
  if (ENABLE_UDP) create_socket(SOCK_DGRAM);

  for (;(play_pos<SOAK_TEST_ITERS) || (end_frc!=0);n++) {
    check_timeout(0, 0); // does not return on timeout

    //choose if to create a socket 
    if (total_num_socks<MAX_SOCKS_PER_PROCESS) {
      if (ENABLE_TCP && random_distrib(RAND_CREATE_SOCKET_STREAM)) {
	create_socket(SOCK_STREAM);
	continue;
      }
      if (ENABLE_UDP && random_distrib(RAND_CREATE_SOCKET_DGRAM)) {
	create_socket(SOCK_DGRAM);
	continue;
      }
    }

    //create a socket if none are present
    if (total_num_socks==0) {
      create_socket(SOCK_STREAM);
      continue;
    }
    
    //pick an open socket
    //should always be able to get a socket as close'es are prevented if too few sockets
    fds = get_random_open_socket(&randr_sync);
    if (total_num_socks==0) {
      int type;
      if      (!ENABLE_TCP) type = SOCK_DGRAM;
      else if (!ENABLE_UDP) type = SOCK_STREAM;
      else                  type = (random_distrib(1)==0) ? SOCK_STREAM : SOCK_DGRAM;
      create_socket(type);
    } else {
      sanity_check_fd_s(fds);

      //pick an operation depending on the socket state
      //if this was a duplicate use the original socket
      //Always pick an operation from the clients point of view
      if (!is_server) state = fds->state;
      else            state = fds->other_state;

      if (fds->type==SOCK_STREAM) {
	switch (state) {
	case (CREATED):   perform_random_op(fds, rand_state_tcp_created);   break;
	case (BOUND):     perform_random_op(fds, rand_state_tcp_bound);     break;
	case (LISTENING): perform_random_op(fds, rand_state_tcp_listening); break;
	case (CONNECTED): perform_random_op(fds, rand_state_tcp_connected); break;
	default: 
	  ci_log("Unknown other_state %d",fds->other_state);
	  ci_fail(("Should decode all ops"));
	}
      } else if (fds->type==SOCK_DGRAM) {
	switch (state) {
	case (CREATED):   perform_random_op(fds, rand_state_udp_created);   break;
	case (BOUND):     perform_random_op(fds, rand_state_udp_bound);     break;
	default: 
	  ci_log("Unknown other_state %d",fds->other_state);
	  ci_fail(("Should decode all ops"));
	}
      } else {
	ci_fail(("Unknown socket type"));
      }
    }
  }

  do_cleanup();
}


/*! Main */		   
void strobe_exec_over() {
  fd_s *sa,*sb, *sc; //Temp sockets
  fd_s *da, *db;     //Datagram sockets
  int fd0;

  // Loop putting an exec() at every possible place
  for (;exec_pos<last_command_pos;exec_pos++) {
    //Some per iteration setup
    do_setup_mode(STROBE);

    if (PLAYING) {
      ci_log("\n========== ITERATION %d/%d ===================",exec_pos,last_command_pos);
    }

    /* An arbitrary program can be created here */
    /* Note that connect_socket returns an int to help program symmetry */
    /* fds are not actually supplied, instead pointers to a struct */
    /* For the client this will always be the same as the fd passed */
    /* For the server this will be the accepted fd and the listening fd is closed */  
    /* problem for the server as this sb=accept_socket(sa)  --> connect(sa) */
    /* no fds may be open at the end of the loop */
    /* Do not use hard coded port numbers - call get_next_port() */
    /* Might consider creating datagram sockets early as they cannot spin */
    /*   as they are inherently non-blocking */

    // Create some datagram sockets
    // Need to ensure that they are created on both client and server upfront
    // Call listen so that synchronisation is not a problem
    // Otherwise sendto can send data to nowhere and recvfrom never sees the data
    da=create_socket(SOCK_DGRAM);
    db=create_socket(SOCK_DGRAM);
    bind_socket_reverse(da,get_next_port(),1);
    bind_socket_reverse(db,get_next_port(),0);

    // Pass a listening socket across the exec  
    main_label("Pass listening");
    sa=create_socket(SOCK_STREAM);
    bind_socket(sa,get_next_port());
    listen_socket(sa);
    sb=accept_socket(sa);
    close_socket(sa);  
    write_socket(sb);
    read_socket(sb);
    close_socket(sb);

    // Pass a connected socket over the exec
    // this must be here if server is going to be run first
    main_label("Pass connected");
    sa=create_socket(SOCK_STREAM);
    // Must assign a new fd so the server which calls accept can mirror this.
    sb=connect_socket(sa,get_next_port()); 
    write_socket(sb);
    close_socket(sb);

    // multiple exec and check that L5 fd closes properly
    // explicit do_exec() to get exec() exec() case
    main_label("Exec exec");
    sa=create_socket(SOCK_STREAM);
    // Must assign a new fd so the server which calls accept can mirror this.
    sb=connect_socket(sa,get_next_port()); 
    write_socket(sb);
    do_exec();
    read_socket(sb);
    //TODO Fix this as it is broken. exec() can get in here
    fd0 = get_fd(sb);
    close_socket(sb);
    check_invalid_fd(fd0);

    // Pass datagram socket
    main_label("Datagram1");
    sendto_socket(da);
    close_socket(da);

    main_label("Datagram2");
    recvfrom_socket(db);
    close_socket(db);

    // Open a file - need to change to UNIX domain socket so that data can be monitored
    main_label("Open file test");
    sa = open_file("/dev/zero",O_RDWR); // Note this returns NULL for the server
    fd0 = get_fd(sa);
    close_file(sa);
    check_invalid_fd(fd0);

    // scm passing over unix domain sockets
    main_label("Socket pair test");
    socket_pair_unix();

    //Add SCM passing of different states
    main_label("SCM rights remote pass");
    sa=create_socket(SOCK_STREAM);
    sb=connect_socket(sa,get_next_port());
    sc=scm_rights_pass(NOFORK,sb);
    if (PLAYING&&!is_server) ci_assert_nequal(sb->fd,sc->fd);
    write_socket(sc);
    read_socket(sc);
    close_socket(sb);
    close_socket(sc);

    main_label("SCM rights remote pass with fork");
    sa=create_socket(SOCK_STREAM);
    sb=connect_socket(sa,get_next_port());
    sc=scm_rights_pass(DOFORK,sb);
    if (PLAYING&&!is_server) ci_assert_nequal(sb->fd,sc->fd);
    write_socket(sc);
    read_socket(sc);
    close_socket(sb);
    close_socket(sc);

    main_label("SCM rights remote pass then fork");
    sa=create_socket(SOCK_STREAM);
    sb=connect_socket(sa,get_next_port());
    sc=scm_rights_pass(NOFORK,sb);
    if (PLAYING&&!is_server) ci_assert_nequal(sb->fd,sc->fd);
    fork_kill_parent();
    write_socket(sc);
    read_socket(sc);
    close_socket(sb);
    close_socket(sc);

    main_label("SCM rights remote pass then fork exec");
    sa=create_socket(SOCK_STREAM);
    sb=connect_socket(sa,get_next_port());
    sc=scm_rights_pass(NOFORK,sb);
    if (PLAYING&&!is_server) ci_assert_nequal(sb->fd,sc->fd);
    fork_kill_parent();
    do_exec();
    write_socket(sc);
    read_socket(sc);
    close_socket(sb);
    close_socket(sc);

    // SCM passing of kernel socket
    // close on exec on kernel socket

    // close on exec on L5 socket
    main_label("Close on exec 0");
    sa=create_socket(SOCK_STREAM);
    // Must assign a new fd so the server which calls accept can mirror this.
    sb=connect_socket(sa,get_next_port()); 
    write_socket(sb);
    set_close_on_exec(sb);
    fd0 = get_fd(sb);
    do_exec();
    check_invalid_fd(fd0);

    // fork()-exec()
    main_label("fork exec 0");
    fork_kill_parent();


    // non-blocking read

    // poll
  
    // select
    main_label("Select");
    sa=create_socket(SOCK_STREAM);
    sb=connect_socket(sa,get_next_port());
    select_socket(sb);
    close_socket(sb);

    // End of arbitrary program
    // Ensure that no open sockets are passed over iterations
    last_command_pos=play_pos;
    replay_pos=0; // We know that playing must start at the given iteration

    check_no_open_sockets();
  }
  
  // check no extra fds stacking up 
}
