#include <sys/time.h> 
#include <stdio.h>

// use polled versions of connect, listen, read, write etc.
//#define USE_RW_SELECT  define or comment me out

#define READ_BUSY_MSG_DELAY 30  // Delay before user messsage (s)
#define CONNECT_BUSY_DELAY (500*1000) // Delay after failed connect (ns)
#define CONNECT_BUSY_MSG_RETRIES 60   // Retries between user messages

// check that the socket is still correctly formatted frequently
//#define USE_CHECK_SOCKET  //define or comment me out

// Seperate bind and listen on the server
// #define SEPERATE_BIND_LISTEN "define or comment out" 

//Parts of the test to exec
#define TEST_STROBE 0
#define TEST_SOAK   1

//Turn on different protocols
#define ENABLE_TCP 1
#define ENABLE_UDP 0

// Program settings
#define SOAK_TEST_ITERS 3500   // sensible max=20000 .. replays dominate after this
#define BACKLOG 10              // how many pending connections queue will hold
#define CONNECT_DELAY (10*1000) // Delay after connect (ns)
#define STRICT_RW 0             // Ensure that reads and writes get all the data at once
#define MAX_RAND_BUF_SIZE 10000 // Maximum ammount of data to send/recieve
                                // Must be a whole number of words
#define MAX_RAND_SELECT_FDS 8   // (8) Random range for more fds to be added to a select
#define MAX_FD_OVERESTIMATE 256 // (8) Random range for maxfd to be overspecified to select
#define MAX_PROC_CHILDREN 4     // (4) Maximum number of children allowed per prcess
                                // Must be a power of 2
#define LOG_2_PROC_CHILDREN 2   // (2) log base 2 of MAX_PROC_CHILDREN (0 for 1 child)
#define MAX_PROC_LEVELS 3       // (3) Maximum number of levels of process ancestry (0and1 are the same)
#define SUPERVISOR_MSG_LEN 28   // Length of messages sent to the supervisor process
#define SUPERVISOR_MSG_FMT "pid=%8d id=%8d"
//
#define FD_S_MAGIC 0x15b80d2f     // Magic number for the fd_s structure
#define MAX_SOCKET_ORDER_LEN 1024 // Max string length for socket_order
#define MAX_FORK_ORDER_LEN 1024   // Max string length for fork order 

#define MAX_RAND_SELECT_DELAY 1000*1000 //Maximum delay for select in ns
#define SELECT_TIMEOUT_SEC  1
#define SELECT_TIMEOUT_USEC 0
#define SOAK_RANDOM_CLIENT_SLEEP 10*1000 //ns
#define SOAK_RANDOM_SERVER_SLEEP 10*1000 //ns

#define MAX_SOCKS_PER_PROCESS 32
#define MAX_FD 1024
#define LFSR_FEEDBACK0 0x80000114
#define SOAK_TEST_EXEC_POS 999       // Iteration value that is recognised as a soak test

// Bugs and workarounds
// Please add warning message for each define
#define BUG_LISTEN_RACE 1
#define BUG_ACCEPT_RESTART 1
#define BUG_IGNORE_NO_REREAD_CLOSE_ON_EXIT 0
#define WORKAROUND_LISTEN_FIRST 0 // Always ensure bind()/listen() is called before accept()

// Logging settings
#define PLAYANDCI_LOG(_args...) \
        do { PLAY_LOG(_args); ci_log(_args); } while (0)
#define DEBUG_LOG PLAY_LOG
#define ALERT_LOG PLAYANDCI_LOG

#define LOG_PLAY                1 // Normal logging
#define LOG_REPLAY              0 // Log replay events as well as played events
#define LOG_BANNER              1 // Log a banner at startup
#define LOG_CLI                 0 // Log passed CLI arguments
#define LOG_DATA                0 // Log actual data send/received
#define LOG_RANDOM              0 // Log manipultion of random numbers
#define LOG_GEN_RANDOM          0 // Log generated random data
#define LOG_SOAK                0 // Log decisions made during a soak test
#define LOG_SOCK_ORDER          0 // Log creating and paring the socket order (CLI) string
#define LOG_ORDER               0 // Log the order of the fds_list at each step
#define LOG_OP_PICKED           0 // Log the random operation picked
#define LOG_RAND_SELECT         0 // Log random fds added to exec()'s
#define LOG_SELECT              0 // Log fd's woken by select
#define LOG_FORK                0 // Log forks and which sockets are closed
#define LOG_FORK_ORDER          0 // Log fork order
#define LOG_ACCEPT_CONNECT_SYNC 0 // Log synchronisation of L5/kernel accept/connects
#define LOG_SENDTO_SYNC         0 // Log the decsiion in the can_sendto() function
#define LOG_READS               0 // Log all parts of reads
#define LOG_SUPERVISOR          0 // Log information send to the supervisor
#define LOG_SUPERVISOR_PIDS     0 // Log PIDS and IDs sent to the supervisor
#define LOG_PORT_ALLOC          0 // Log port allocation from get_next_port()
#define LOG_PID_CHANGE          0 // Log PID changes due to fork() and exec()
//Variables that are defined or undef'ed
#undef  LOG_TIME                // Log a time against each log entry


#define INVALID_SOCK_FD 0xFFFF  // Invalid socket fd
#define NO_RAND_SEED 0x65fcd399
#define FIRST_PORT_NUM 1024     // Frist port number to be used
#define MAX_PORT_NUM 20000      // a bit random
#define SETUP_PORT_NUM 20001
#define TRUE  1
#define FALSE 0
#define OK  1
#define NOK 0

#define PLAY_LOG_COND ((PLAYING&&LOG_PLAY)||LOG_REPLAY)

// Macro for logging
//This should be called before the play_pos is advanced
#ifdef LOG_TIME

#define PLAY_LOG(fmt_string,...) \
 do { \
 ci_assert_nequal(logfd, 0); \
 if (PLAY_LOG_COND) \
 gettimeofday(&tv2,NULL); \
 if (PLAY_LOG_COND) \
 snprintf(last_log_str, sizeof(last_log_str), \
 "exec: %2.2d %3.3ld:%3.3ld %s %3.3d:%5.5d %16.16s " #fmt_string, cur_id, \
 (tv2.tv_sec-tv.tv_sec)%1000, \
 ((tv2.tv_usec-tv.tv_usec)>0) ? ((tv2.tv_usec-tv.tv_usec)/1000)%1000 : \
                                ((tv2.tv_usec-tv.tv_usec)/1000)%1000+1000, \
 PLAYING?"PLAY  ":"REPLAY", exec_pos, play_pos,__FUNCTION__, ##__VA_ARGS__); \
 fprintf(logfd, "%s\n", last_log_str); \
 fflush(logfd); \
 } while(0)

#else

#define PLAY_LOG(fmt_string,...) \
 do { \
 if (PLAY_LOG_COND) \
 snprintf(last_log_str, sizeof(last_log_str), \
 "exec: %2.2d %s %3.3d:%5.5d %16.16s " #fmt_string , cur_id, \
 PLAYING?"PLAY  ":"REPLAY", exec_pos, play_pos,__FUNCTION__, ##__VA_ARGS__); \
 fprintf(logfd, "%s\n", last_log_str); \
 fflush(logfd); \
 } while(0)

#endif

#define EXEC_TEST_TRY(x) \
 do { int val=(x); \
      if (val<0) ci_log("client[%d:%d] reports error ...",cur_id,pid); \
      CI_TRY(val); } while (0)

#define exec_test_assert_equal(a,b) \
  do { int x=(a); \
       int y=(b); \
       if (x!=y) ci_log("client[%d:%d] assertion fail ...",cur_id,pid); \
       ci_assert_equal(x,y); } while (0)

/* ENUMS */
typedef enum {CREATED=0,
	      BOUND, 
	      LISTENING, 
	      CONNECTING, 
	      CONNECTED, 
	      INVALID, 
	      OPENFILE, 
	      DUPLICATE
} fd_state;
typedef enum {DOFORK, NOFORK} fork_b;
typedef enum {UNKNOWN, L5,KERN} is_l5_t;
typedef enum {NO_UDP_SENT, UDP_SENT} udp_data_sent_t;
typedef enum {
  SETUP,         // Setup stage
  SINGLE,        // Tests that are run once
  STROBE,        // exec() being strobed at ever position
  SOAK,          // a soak test()
} mode_enum;

/* STRUCTURES */

// If adding anything that needs to be initialised please add to malloc_fd_s()
typedef struct fd_tag {
  ci_dllink dllink;
  ci_magic_t magic;

  char rand_buf[MAX_RAND_BUF_SIZE]; // Buffer for random data
  char read_buf[MAX_RAND_BUF_SIZE]; // Buffer for data being read
  ci_uint32 rand_ready;             // Ammount of random data that is ready
  
  // This represents the state of the client, or the server (not equal between them, but corresponds)
  // FREE is not necessary as should not be in the list
  fd_state state;
  // Mirrors the state of the client
  // This is useed for the soak test to decide on the next action
  // Set by all calls to set_state() and indepedantly
  // Needed as client is in CREATED, BOUND, LISTENING when server stays in CREATED
  // Vice-versa not necessary as server is in BOUND and LISTENING on a temporary socket
  fd_state other_state;
  ci_uint32 fd;         // File descriptor (integer)
  ci_int32 lport;       // My local port
  ci_int32 rport;       // My remote port
  int type;             // e.g. SOCK_STREAM
  is_l5_t is_l5;        // true if this is an L5 socket
  int is_dup;           // true if this is a dup'ed socket
                        // (via SCM on client or dup() call on the server
  int bind_pos;         // play_pos when bind was called - both client and server
                        // Could be genralised to play_pos of last op
  int udp_data_sent;    // True if any UDP data been passed on this socket
  int ops_on_socket;    // Number of socket API ops performed on this socket
  int listen_pos;       // Position at which listen was called on either side

  //Server

  //Client
  int close_on_exec;    // Flag to keep close on exit flag state
} fd_s;


/*! Structure used for description the random next state tables */
typedef struct rand_state_s_tag {
  char *func; // Name of the function
              // Could use function pointers here
  ci_uint32 weight;
} rand_state_s;


/*! Structure used in the server for the supervisor to track processes */
typedef struct process_list_s_tag {
  ci_dllink dllink;
  int pid;
  int id;
} process_list_s;


/* GLOBALS */
static int is_server;             // Is this the server instance
static int running = 1;           // still running - used avoid race in signal handler
char *real_prog_name;             // The name of this program from argv[0]
ci_dllist  fds_list;              // Linked list of fds items
struct timeval tv,tv2;            // Synchronised start time
ci_uint32 randr_sync;             // Random synchronised seed value
                                  // Must be used same number of times by client and server
                                  // Used to create randr value if fd_s
ci_uint32 randr_priv;             // Private random seed value
ci_uint32 total_num_socks;        // Number of sockets open i.e. if 2 fd0 and fd1 valid
ci_uint32 total_num_conns;        // Number of established connections
mode_enum mode;                   // The current mode
char *server_name;                // The other sides name (for L5 sockets)
char *server_namek;               // The other sides name (for kernel sockets)
int supervisor_fd;                // fd to communicate with the supervisor
FILE *logfd = NULL;               // Logging file descriptor
ci_uint64 start_frc;              // Start cycle time (used for timeout)
ci_uint64 end_frc = 0;            // End cycle time (used for timeout)
ci_uint64 end_frc_allowance;      // End cycle time (used allowane due to race)
char last_log_str[128];           // Last logged string

// Used to record synchronisation points (e.g. stream block read<->write)
ci_uint32 last_bread_kern_pos;  // Last pos of blocking read  of kern socket
ci_uint32 last_bread_l5_pos;    // Last pos of blocking read  of l5   socket
ci_uint32 last_bwrite_kern_pos; // Last pos of blocking write of kern socket
ci_uint32 last_bwrite_l5_pos;   // Last pos of blocking write of l5   socket

// connects and accepts are ordered corrected
// problem is that although they are in order for l5 or kernel
// might swap between l5 and kernel and order is not guarateed
ci_uint32 last_kern_accept;       // Last synchronisation point for kernel accept  calls
ci_uint32 last_l5_accept;         // Last synchronisation point for l5     accept  calls
ci_uint32 last_kern_connect;      // Last synchronisation point for kernel connect calls
ci_uint32 last_l5_connect;        // Last synchronisation point for l5     connect calls

/* CLIENT only */
ci_uint32 randr_sync_orig;        // Original randr_sync - used to pass on exec() 
static struct sockaddr_in other_side_sock; // L5 socket on the other side
static struct sockaddr_in other_side_kern; // Kernel socket on the other side 

// This string records the decisions used on forks in fork_split_socket
// "P" parent
// "C" child
// This is necessary because although there is a limited tree structure of processes
// a lead node might be created and then 
static char fork_order[MAX_FORK_ORDER_LEN];

static ci_uint32 play_pos=1;       // Current operation position.
static ci_uint32 timer_play_pos=0; // Play pos on the last timer
static ci_uint32 replay_pos;       // Position reached before the exec (CLI option)
static ci_uint32 exec_pos;         // Exec position (CLI option)
static ci_uint32 last_command_pos; // Last command in the loop 
static ci_uint32 next_port;        // Next port to be allocated
static ci_uint32 children;         // Number of children of this process
static ci_uint32 level;            // How deep in the process hierarchy is this
static ci_uint32 pid;              // The PID of this processes
static ci_uint32 timeout = 0;      // timeout (secs)

/* Used for CLI arguments */
static const char *socket_order_opt; // used to pass fd numbers for the used sockets
                                     // server: parses this CLI option
                                     // client: uses this to build CLI for exec call
static       char *fork_order_opt;   // The order of fork operations
static const char *l5_addr_opt;      // Host as dotted quad srting 
static const char *kern_addr_opt;    // Host as dotted quad string
static ci_uint32 cur_id = 0;         // The current id - note may be replaying
static int id_opt;                   // expected id at the replay point

#define PLAYING (play_pos>=replay_pos)
#define PLAYPOINT (play_pos+1==replay_pos)

/* STATICS */

/*! The server and the time to run for are configurable from command-line */
/* Ensure that pointers are passed */
static ci_cfg_desc cfg_opts[] = {
  { 'a', "othersidel5",  CI_CFG_STR,  &l5_addr_opt,             "(USED INTERNALLY) dotted quad address of L5 side"},
  { 'b', "othersidekern",CI_CFG_STR,  &kern_addr_opt,           "(USED INTERNALLY) dotted quad address of kernel side"},
  { 'e', "execpos",      CI_CFG_UINT, &exec_pos,                "(USED INTERNALLY) exec (iteration) pos"},
  { 'p', "supervisorfd", CI_CFG_UINT, &supervisor_fd,           "(USED INTERNALLY) fd to communicate with the supervisor process"},
  { 'o', "socketorder",  CI_CFG_STR,  &socket_order_opt,        "(USED INTERNALLY) socket order"},
  { 'g', "forkorder",    CI_CFG_STR,  &fork_order_opt,          "(USED INTERNALLY) fork order"},
  { 'r', "replay",       CI_CFG_UINT, &replay_pos,              "(USED INTERNALLY) replay upto current state"},
  { 'i', "id",           CI_CFG_UINT, &id_opt,                  "(USED INTERNALLY) Expected id at the play point"},
  { 'x', "end_frc",      CI_CFG_UINT64, &end_frc,               "(USED INTERNALLY) End time (cpu cycles)"},

  { 's', "server",       CI_CFG_FLAG, &is_server,               "set if this is the server"},
  { 'z', "srand",        CI_CFG_UINT, &randr_sync,              "random seed (default is to call time())"},
  { 't', "timeout",      CI_CFG_UINT, &timeout,                 "timeout (secs)"},
};
#define N_CFG_OPTS (sizeof(cfg_opts) / sizeof(cfg_opts[0]))


/**************************************************************************
 * RANDOM NEXT STATE PICKING
 *  Must end each structure with a NULL 1st entry
 **************************************************************************/
// Random probabilities
#define RAND_CREATE_SOCKET_STREAM 50 //Random probability to create a socket 1:X
#define RAND_CREATE_SOCKET_DGRAM  50 //Random probability to create a socket 1:X
#if WORKAROUND_LISTEN_FIRST
#define RAND_SECOND_CONNECT_WEIGHTING 10
#else
#define RAND_SECOND_CONNECT_WEIGHTING 1
#endif

static rand_state_s rand_state_tcp_created[] = {
  { "scm_pass",     0   }, //Due to bug of tracking state of dup()'ed fds
  { "exec",         2   },
  { "fork",         1   },
  { "forkexec",     1   },
  { "forksplit",    2   },
  { "close",        10  },
  { "bind",         400 },
  { "connect_l5",   400 }, // Also alter accept functions to alter l5/kern mix
  { "connect_kern", 4   },
  { "sleep_c",      1   },
  { "sleep_s",      1   },
  { NULL,           0   },
};


static rand_state_s rand_state_udp_created[] = {
  { "close",          10  },
  { "exec",           2   },
  { "fork",           1   },
  { "forkexec",       1   },
  { "forksplit",      2   },
  { "close",          10  },
  { "bind",           400 },
  { "sendto_l5_udp",  100 },
  { "sendto_kern_udp",10  },
  { "sleep_c",        1   },
  { "sleep_s",        1   },
  { NULL,             0   },
};


static rand_state_s rand_state_tcp_bound[] = {
  { "scm_pass",      0  }, //Due to bug of tracking state of dup()'ed fds
  { "exec",          2  },
  { "fork",          1  },
  { "forkexec",      1  },
  { "forksplit",     2  },
  { "close",         1  },
  { "listen",        40 },
  { "sleep_c",       1  },
  { "sleep_s",       1  },
  { NULL,            0  },
};

static rand_state_s rand_state_udp_bound[] = {
  { "close",             1   },
  { "recvfrom_l5_udp",   100 },
  { "recvfrom_kern_udp", 10  },
  { "exec",              2   },
  { "fork",              1   },
  { "forkexec",          1   },
  { "forksplit",         2   },
  { "close",             1   },
  { "sleep_c",           1   },
  { "sleep_s",           1   },
  { NULL,                0   },
};

static rand_state_s rand_state_tcp_listening[] = {
  { "scm_pass",    0   }, //Due to bug of tracking state of dup()'ed fds
  { "exec",        2   },
  { "fork",        1   },
  { "forkexec",    1   },
  { "forksplit",   2   },
  { "close",       10  },
  { "accept_l5",   400 },
  { "accept_kern", 4   },
  { "sleep_c",     1   },
  { "sleep_s",     1   },
  { NULL,          0   },
};

static rand_state_s rand_state_tcp_connected[] = {
  { "scm_pass", 2   },
  { "exec",     1   },
  { "fork",     1   },
  { "forkexec", 2   },
  { "forksplit",1   },
  { "close",    10  },
  { "send",     200 },
  { "recv",     100 },
  { "select",   0   },
  { "recvfrom", 0   },
  { "sendto",   0   },
  { "sleep_c",  1   },
  { "sleep_s",  1   },
  { NULL,       0   },
};
