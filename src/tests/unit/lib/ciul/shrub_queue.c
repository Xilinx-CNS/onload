/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: Copyright (C) 2025, Advanced Micro Devices, Inc. */

/* Functions under test */
#include "shrub_queue.h"

/* Test infrastructure */
#include "unit_test.h"

/* Dependencies */
#include "shrub_connection.h"
#include <etherfabric/ef_vi.h>
#include <sys/mman.h>
#include <assert.h>
#include <limits.h>

static const int buffer_fd = 10;
static const int server_fifo_fd = 11;

static const size_t buffer_bytes = 12345;
static const size_t buffer_count = 9;
static const size_t fifo_size = buffer_count + 4;
static const int client_fifo_fd = 42;
static const int qix = 3;
static const int qid = 4137316;

static struct ef_vi* vi;
static ef_shrub_buffer_id* server_fifo;
static struct ef_shrub_queue* queue;

static int buffer_seq = 1234; // sequence number, initially arbitrary
unsigned used_buffers = 0; // bitmask, initially unused
unsigned buffer_sentinels = 0xaaaaaaaa; // bitmask, initially arbitrary
static uint32_t buffer_sbseqs[32]; // Track sbseq for each buffer

static int buffer_sentinel(int index)
{
  return (buffer_sentinels >> index) & 1;
}

static ef_shrub_buffer_id buffer_id(int index)
{
  /* Use the actual sbseq that was assigned to this buffer */
  return ((uint64_t)buffer_sbseqs[index] << 32) | ((uint64_t)buffer_sentinel(index) << 31) | (uint64_t)index;
}

int ef_shrub_server_memfd_create(const char* name, size_t size, bool huge)
{
  if( huge ) {
    CHECK(size, >=, buffer_bytes * buffer_count);
    return buffer_fd;
  }
  else {
    CHECK(size, >=, fifo_size * sizeof(ef_shrub_buffer_id));
    return server_fifo_fd;
  }
}

int ef_shrub_server_mmap(void** addr_out, size_t size,
                         int prot, int flags, int fd, size_t offset)
{
  CHECK(size, >=, fifo_size * sizeof(ef_shrub_buffer_id));
  CHECK(prot, ==, PROT_WRITE);
  CHECK(flags, ==, MAP_SHARED | MAP_POPULATE);
  CHECK(fd, ==, server_fifo_fd);
  CHECK(offset, ==, 0);
  server_fifo = calloc(fifo_size, sizeof(ef_shrub_buffer_id));
  CHECK(server_fifo, !=, NULL);

  *addr_out = server_fifo;
  return 0;
}

struct mock_connection
{
  struct ef_shrub_connection connection;
  uint64_t buffer_refs;
  struct ef_shrub_client_state state;
};

struct ef_shrub_client_state*
ef_shrub_connection_client_state(struct ef_shrub_connection* connection)
{
  return &((struct mock_connection*)connection)->state;
}

static struct mock_connection*
shrub_connection_to_mock_connection(struct ef_shrub_connection* shrub_conn)
{
  return (struct mock_connection*)(
           (char*)shrub_conn - offsetof(struct mock_connection, connection)
         );
}

static int mock_attach(struct ef_vi* vi_, int qid_, int buf_fd,
                       unsigned n_superbufs, bool shared, bool interrupt)
{
  CHECK(vi_, ==, vi);
  CHECK(qid_, ==, qid);
  CHECK(buf_fd, ==, buffer_fd);
  CHECK(n_superbufs, ==, buffer_count);
  CHECK_FALSE(shared);
  return qix;
}

static void mock_detach(struct ef_vi* vi_, int qix_)
{
  CHECK(vi_, ==, vi);
  CHECK(qix_, ==, qix);
}

static int mock_next(struct ef_vi* vi_, int qix_, bool* sentinel, unsigned* sbseq)
{
  int index;
  CHECK(vi_, ==, vi);
  CHECK(qix_, ==, qix);

  for( index = 0; index < buffer_count; ++index ) {
    unsigned bit = 1u << index;
    if( (used_buffers & bit) == 0 ) {
      used_buffers |= bit;
      buffer_sentinels ^= bit;
      *sentinel = buffer_sentinel(index);
      *sbseq = buffer_seq++;
      buffer_sbseqs[index] = *sbseq;
      return index;
    }
  }

  return -EAGAIN;
}

static int expect_free = -1;
static void mock_free(struct ef_vi* vi_, int qix_, int buffer_index)
{
  unsigned bit = 1u << buffer_index;

  CHECK(vi_, ==, vi);
  CHECK(qix_, ==, qix);
  CHECK(buffer_index, ==, expect_free);
  CHECK(buffer_index, >=, 0);
  CHECK(used_buffers & bit, !=, 0); 
  used_buffers &= ~bit;
  expect_free = -1;
}

ef_vi_efct_rxq_ops mock_ops = {
  .attach = mock_attach,
  .detach = mock_detach,
  .next = mock_next,
  .free = mock_free,
};

/* Test setup */
static void init_test(void)
{
  STATE_ALLOC(struct ef_vi, vi_);
  vi = vi_;
  vi->efct_rxqs.ops = &mock_ops;
  STATE_STASH(vi);
}

static void open_queue(void)
{
  STATE_ALLOC(struct ef_shrub_queue, queue_);
  queue = queue_;
  ef_shrub_queue_open(queue, vi, buffer_bytes, buffer_count, fifo_size,
                      client_fifo_fd, server_fifo_fd, qid, false);
  STATE_STASH(queue);
}

static struct mock_connection* open_connection(void)
{
  int i;
  STATE_ALLOC(struct mock_connection, mock);
  mock->connection.queue = queue;
  mock->connection.next = queue->connections;
  queue->connections = &mock->connection;
  STATE_ACCEPT(queue, connections);

  mock->connection.client_fifo = calloc(fifo_size, sizeof(ef_shrub_buffer_id));
  mock->connection.server_fifo = calloc(fifo_size, sizeof(ef_shrub_buffer_id));
  mock->connection.buffer_refs = calloc(queue->buffer_count,
                                        sizeof(mock->connection.buffer_refs[0]));
  mock->connection.fifo_size = fifo_size;

  for( i = 0; i < fifo_size; ++i ) {
    mock->connection.client_fifo[i] = EF_SHRUB_INVALID_BUFFER;
    mock->connection.server_fifo[i] = EF_SHRUB_INVALID_BUFFER;
  }

  mock->buffer_refs = 0ull;
  for( i = 0; i < queue->buffer_count; ++i )
    mock->connection.buffer_refs[i] = false;

  STATE_STASH(mock);

  ef_shrub_queue_attached(queue, &mock->connection);
  return mock;
}

static void remove_connection(struct ef_shrub_connection** list,
                              struct ef_shrub_connection* conn)
{
  while( *list ) {
    if( *list == conn ) {
      *list = conn->next;
      break;
    }
    list = &(*list)->next;
  }
}

static void close_connection(struct mock_connection* conn)
{
  conn->connection.queue = NULL;
  STATE_ACCEPT(conn, connection.queue);
  remove_connection(&queue->connections, &conn->connection);
  STATE_ACCEPT(queue, connections);
}

static void assert_queue_ref_counts_valid(struct ef_shrub_queue* queue)
{
  struct ef_shrub_connection *shrub_conn;
  int buffer_idx;

  /* Our tracking mask must have space for the number of buffers used */
  assert(buffer_count <=
         sizeof(((struct mock_connection*)NULL)->buffer_refs) * CHAR_BIT);

  /* The real connection buffer_ref tracking must match our mock tracking */
  for( shrub_conn = queue->connections;
       shrub_conn;
       shrub_conn = shrub_conn->next ) {
    struct mock_connection* mock_conn =
      shrub_connection_to_mock_connection(shrub_conn);
    uint64_t real_ref_mask = 0ull;
    for( buffer_idx = 0; buffer_idx < buffer_count; buffer_idx++ )
      real_ref_mask |=
        ((uint64_t)shrub_conn->buffer_refs[buffer_idx] << buffer_idx);

    CHECK(mock_conn->buffer_refs, ==, real_ref_mask);
  }

  /* buffer[i] ref count = sum of connections with buffer_ref[i] */
  for( buffer_idx = 0; buffer_idx < buffer_count; buffer_idx++ ) {
    int ref_count = 0;
    for( shrub_conn = queue->connections;
         shrub_conn;
         shrub_conn = shrub_conn->next )
      ref_count += shrub_conn->buffer_refs[buffer_idx];

    CHECK(ef_shrub_queue_buffer_get_ref_count(queue, buffer_idx), ==,
          ref_count);
  }
}

static void mock_connection_take_buffer_ref(struct mock_connection* conn,
                                            int buffer_idx)
{
  conn->buffer_refs |= (1ull << buffer_idx);
  STATE_ACCEPT(conn, buffer_refs);
}

static void mock_connection_drop_buffer_ref(struct mock_connection* conn,
                                            int buffer_idx)
{
  conn->buffer_refs &= ~(1ull << buffer_idx);
  STATE_ACCEPT(conn, buffer_refs);
}

/* Tests */
static void test_shrub_queue_open(void)
{
  init_test();

  int rc;
  struct ef_shrub_queue queue;
  rc = ef_shrub_queue_open(&queue, vi, buffer_bytes, buffer_count, fifo_size,
                           client_fifo_fd, server_fifo_fd, qid, false);
  CHECK(rc, ==, 0);
  CHECK(queue.shared_fds[EF_SHRUB_FD_BUFFERS], ==, buffer_fd);
  CHECK(queue.shared_fds[EF_SHRUB_FD_SERVER_FIFO], ==, server_fifo_fd);
  CHECK(queue.shared_fds[EF_SHRUB_FD_CLIENT_FIFO], ==, client_fifo_fd);
  CHECK(queue.buffer_bytes, ==, buffer_bytes);
  CHECK(queue.buffer_count, ==, buffer_count);
  CHECK(queue.fifo_index, ==, 0);
  CHECK(queue.fifo_size, ==, fifo_size);
  CHECK(queue.connection_count, ==, 0);
  CHECK(queue.ix, ==, qix);
  CHECK(queue.qid, ==, qid);
  CHECK(queue.vi, ==, vi);
  CHECK(queue.connections, ==, NULL);
  assert_queue_ref_counts_valid(&queue);

  ef_shrub_queue_close(&queue);

  STATE_FREE(vi);
}

static void test_shrub_queue_connections(void)
{
  int i, connection_count = 4;
  struct mock_connection* c[connection_count];

  init_test();
  open_queue();

  /* Empty queue: first index is zero */
  c[0] = open_connection();
  STATE_UPDATE(queue, connection_count, 1);
  STATE_UPDATE(c[0], state.server_fifo_index, 0);
  assert_queue_ref_counts_valid(queue);

  /* First poll will put all available buffers in the queue
   * FIXME: probably should wait for connections. */
  int old_seq = buffer_seq;
  ef_shrub_queue_poll(queue);
  STATE_UPDATE(c[0], connection.server_fifo_index, buffer_count);
  STATE_UPDATE(c[0], connection.queue_fifo_index, buffer_count);
  STATE_UPDATE(queue, fifo_index, buffer_count);
  CHECK(buffer_seq, ==, old_seq + buffer_count);
  for( i = 0; i < buffer_count; ++i )
    CHECK(queue->fifo[i], ==, buffer_id(i));

  for( i = 0; i < buffer_count; ++i )
    mock_connection_take_buffer_ref(c[0], i);
  assert_queue_ref_counts_valid(queue);

  /* New connection: oldest buffer is still at index zero */
  c[1] = open_connection();
  STATE_UPDATE(queue, connection_count, 2);
  STATE_UPDATE(c[1], state.server_fifo_index, 0);
  STATE_UPDATE(c[1], connection.server_fifo_index, buffer_count);
  STATE_UPDATE(c[1], connection.queue_fifo_index, buffer_count);

  /* Free the oldest buffer by releasing it from both connections */
  c[0]->connection.client_fifo[0] = 0;
  ef_shrub_queue_poll(queue);
  STATE_UPDATE(c[0], connection.client_fifo_index, 1);
  CHECK(queue->fifo[0], ==, buffer_id(0));

  for( i = 0; i < buffer_count; ++i )
    mock_connection_take_buffer_ref(c[1], i);
  mock_connection_drop_buffer_ref(c[0], 0);
  assert_queue_ref_counts_valid(queue);

  c[1]->connection.client_fifo[0] = 0;
  expect_free = 0;
  ef_shrub_queue_poll(queue);
  STATE_UPDATE(c[1], connection.client_fifo_index, 1);
  STATE_UPDATE(queue, fifo_index, buffer_count + 1);
  STATE_UPDATE(c[0], connection.server_fifo_index, buffer_count + 1);
  STATE_UPDATE(c[0], connection.queue_fifo_index, buffer_count + 1);
  STATE_UPDATE(c[1], connection.server_fifo_index, buffer_count + 1);
  STATE_UPDATE(c[1], connection.queue_fifo_index, buffer_count + 1);

  CHECK(expect_free, ==, -1);
  CHECK(buffer_seq, ==, old_seq + buffer_count + 1);
  CHECK(queue->fifo[0], ==, EF_SHRUB_INVALID_BUFFER);
  for( i = 1; i < buffer_count; ++i )
    CHECK(queue->fifo[i], ==, buffer_id(i));
  CHECK(queue->fifo[buffer_count], ==, buffer_id(0));

  /* We have dropped all references to the new buffer, and it has been reposted
   * so now all connections have this buffer again. */
  mock_connection_take_buffer_ref(c[0], 0);
  assert_queue_ref_counts_valid(queue);

  /* A new connection will start at the next index (1) */
  c[2] = open_connection();
  STATE_UPDATE(queue, connection_count, 3);
  STATE_UPDATE(c[2], state.server_fifo_index, 0);
  STATE_UPDATE(c[2], connection.server_fifo_index, buffer_count);
  STATE_UPDATE(c[2], connection.queue_fifo_index, buffer_count + 1);
  for( i = 0; i < buffer_count; ++i )
    mock_connection_take_buffer_ref(c[2], i);
  assert_queue_ref_counts_valid(queue);

  /* Free a more recent buffer */
  expect_free = 3;
  c[0]->connection.client_fifo[1] = expect_free;
  c[1]->connection.client_fifo[1] = expect_free;
  c[2]->connection.client_fifo[0] = expect_free;
  ef_shrub_queue_poll(queue);
  STATE_UPDATE(c[0], connection.client_fifo_index, 2);
  STATE_UPDATE(c[1], connection.client_fifo_index, 2);
  STATE_UPDATE(c[2], connection.client_fifo_index, 1);
  CHECK(expect_free, ==, -1);
  STATE_UPDATE(c[0], connection.server_fifo_index, buffer_count + 2);
  STATE_UPDATE(c[0], connection.queue_fifo_index, buffer_count + 2);
  STATE_UPDATE(c[1], connection.server_fifo_index, buffer_count + 2);
  STATE_UPDATE(c[1], connection.queue_fifo_index, buffer_count + 2);
  STATE_UPDATE(c[2], connection.server_fifo_index, buffer_count + 1);
  STATE_UPDATE(c[2], connection.queue_fifo_index, buffer_count + 2);

  /* The older buffers are removed to make space in the FIFO, but not freed */
  CHECK(buffer_seq, ==, old_seq + buffer_count + 2);
  for( i = 0; i < 4; ++i )
    CHECK(queue->fifo[i], ==, EF_SHRUB_INVALID_BUFFER);
  for( i = 4; i < buffer_count; ++i )
    CHECK(queue->fifo[i], ==, buffer_id(i));
  CHECK(queue->fifo[buffer_count], ==, buffer_id(0));
  CHECK(queue->fifo[buffer_count + 1], ==, buffer_id(3));
  STATE_UPDATE(queue, fifo_index, buffer_count + 2);

  /* All connections dropped their ref to `expect_free` at the same time so
   * they should all have dropped and retaken references to it within the same
   * poll. */
  assert_queue_ref_counts_valid(queue);

  /* A new connection will start after the gap at index 4 */
  c[3] = open_connection();
  STATE_UPDATE(queue, connection_count, 4);
  STATE_UPDATE(c[3], state.server_fifo_index, 0);
  STATE_UPDATE(c[3], connection.server_fifo_index, buffer_count - 2);
  STATE_UPDATE(c[3], connection.queue_fifo_index, buffer_count + 2);

  /* By this point, 0 has been freed and reposted at the end, and 3 has been
   * freed by all (and reposted to the fifo). So the new connection has refs
   * to [3, buffer_count) and 0. */
  mock_connection_take_buffer_ref(c[3], 0);
  for( i = 3; i < buffer_count; i++ )
    mock_connection_take_buffer_ref(c[3], i);
  assert_queue_ref_counts_valid(queue);

  /* Release a buffer from three connections and close the fourth */
  c[0]->connection.client_fifo[2] = 5;
  c[1]->connection.client_fifo[2] = 5;
  c[2]->connection.client_fifo[1] = 5;
  ef_shrub_queue_poll(queue);
  STATE_UPDATE(c[0], connection.client_fifo_index, 3);
  STATE_UPDATE(c[1], connection.client_fifo_index, 3);
  STATE_UPDATE(c[2], connection.client_fifo_index, 2);

  mock_connection_drop_buffer_ref(c[0], 5);
  mock_connection_drop_buffer_ref(c[1], 5);
  mock_connection_drop_buffer_ref(c[2], 5);
  assert_queue_ref_counts_valid(queue);

  expect_free = 5;
  ef_shrub_queue_detached(queue, &c[3]->connection);
  CHECK(expect_free, ==, -1);
  STATE_UPDATE(queue, connection_count, 3);
  for( i = 0; i < 6; ++i )
    CHECK(queue->fifo[i], ==, EF_SHRUB_INVALID_BUFFER);
  for( i = 6; i < buffer_count; ++i )
    CHECK(queue->fifo[i], ==, buffer_id(i));
  CHECK(queue->fifo[buffer_count], ==, buffer_id(0));
  CHECK(queue->fifo[buffer_count + 1], ==, buffer_id(3));

  /* The closed connection should have no remaining references */
  for( i = 0; i < buffer_count; i++ )
    mock_connection_drop_buffer_ref(c[3], i);
  assert_queue_ref_counts_valid(queue);

  /* Close the connection fully before the server recycles the buffer as we'll
   * end up with a stale reference otherwise. */
  close_connection(c[3]);

  /* The freed buffer is recycled on the next poll */
  CHECK(queue->fifo[buffer_count + 2], ==, EF_SHRUB_INVALID_BUFFER);
  ef_shrub_queue_poll(queue);
  CHECK(queue->fifo[buffer_count + 2], ==, buffer_id(5));
  STATE_UPDATE(queue, fifo_index, buffer_count + 3);
  STATE_UPDATE(c[0], connection.server_fifo_index, buffer_count + 3);
  STATE_UPDATE(c[0], connection.queue_fifo_index, buffer_count + 3);
  STATE_UPDATE(c[1], connection.server_fifo_index, buffer_count + 3);
  STATE_UPDATE(c[1], connection.queue_fifo_index, buffer_count + 3);
  STATE_UPDATE(c[2], connection.server_fifo_index, buffer_count + 2);
  STATE_UPDATE(c[2], connection.queue_fifo_index, buffer_count + 3);

  mock_connection_take_buffer_ref(c[0], 5);
  mock_connection_take_buffer_ref(c[1], 5);
  mock_connection_take_buffer_ref(c[2], 5);
  assert_queue_ref_counts_valid(queue);

  /* Check that older buffers (no longer in the fifo) are freed correctly. */
  /* Leave buffer 1 until we have reused its old slot. */
  for( i = 0; i < 3; ++i ) {
    expect_free = (i + 1) * 2; /* 2,4,6 */
    c[0]->connection.client_fifo[3+i] = expect_free;
    c[1]->connection.client_fifo[3+i] = expect_free;
    c[2]->connection.client_fifo[2+i] = expect_free;
    ef_shrub_queue_poll(queue);
    /* all references to this buffer dropped and reacquired */
    assert_queue_ref_counts_valid(queue);
    STATE_UPDATE(c[0], connection.client_fifo_index, 4+i);
    STATE_UPDATE(c[1], connection.client_fifo_index, 4+i);
    STATE_UPDATE(c[2], connection.client_fifo_index, 3+i);
    CHECK(expect_free, ==, -1);
    STATE_UPDATE(queue, fifo_index, i);
    STATE_UPDATE(c[0], connection.server_fifo_index, i);
    STATE_UPDATE(c[0], connection.queue_fifo_index, i);
    STATE_UPDATE(c[1], connection.server_fifo_index, i);
    STATE_UPDATE(c[1], connection.queue_fifo_index, i);
    STATE_UPDATE(c[2], connection.server_fifo_index,
                 (buffer_count + 3 + i) % fifo_size);
    STATE_UPDATE(c[2], connection.queue_fifo_index, i);
    CHECK(queue->fifo[i], ==, buffer_id(expect_free));
  }

  STATE_UPDATE(queue, fifo_index, 2);
  STATE_UPDATE(c[0], connection.server_fifo_index, 2);
  STATE_UPDATE(c[0], connection.queue_fifo_index, 2);
  STATE_UPDATE(c[1], connection.server_fifo_index, 2);
  STATE_UPDATE(c[1], connection.queue_fifo_index, 2);
  STATE_UPDATE(c[2], connection.server_fifo_index, 1);
  STATE_UPDATE(c[2], connection.queue_fifo_index, 2);

  CHECK(queue->fifo[0], ==, buffer_id(4));
  CHECK(queue->fifo[1], ==, buffer_id(6));
  for( i = 2; i < 7; ++i )
    CHECK(queue->fifo[i], ==, EF_SHRUB_INVALID_BUFFER);
  for( i = 7; i < buffer_count; ++i )
    CHECK(queue->fifo[i], ==, buffer_id(i));
  CHECK(queue->fifo[buffer_count + 1], ==, buffer_id(3));
  CHECK(queue->fifo[buffer_count + 2], ==, buffer_id(5));
  CHECK(queue->fifo[buffer_count + 3], ==, buffer_id(2));

  /* Free buffer 1, whose old slot has been reused */
  expect_free = 1;
  c[0]->connection.client_fifo[6] = 1;
  c[1]->connection.client_fifo[6] = 1;
  c[2]->connection.client_fifo[5] = 1;
  ef_shrub_queue_poll(queue);
  STATE_UPDATE(c[0], connection.client_fifo_index, 7);
  STATE_UPDATE(c[1], connection.client_fifo_index, 7);
  STATE_UPDATE(c[2], connection.client_fifo_index, 6);
  CHECK(expect_free, ==, -1);
  STATE_UPDATE(queue, fifo_index, 3);
  STATE_UPDATE(c[0], connection.server_fifo_index, 3);
  STATE_UPDATE(c[0], connection.queue_fifo_index, 3);
  STATE_UPDATE(c[1], connection.server_fifo_index, 3);
  STATE_UPDATE(c[1], connection.queue_fifo_index, 3);
  STATE_UPDATE(c[2], connection.server_fifo_index, 2);
  STATE_UPDATE(c[2], connection.queue_fifo_index, 3);

  /* all references to buffer 1 dropped and reacquired */
  assert_queue_ref_counts_valid(queue);

  CHECK(queue->fifo[0], ==, buffer_id(4));
  CHECK(queue->fifo[1], ==, buffer_id(6));
  CHECK(queue->fifo[2], ==, buffer_id(1));
  for( i = 3; i < 7; ++i )
    CHECK(queue->fifo[i], ==, EF_SHRUB_INVALID_BUFFER);
  for( i = 7; i < buffer_count; ++i )
    CHECK(queue->fifo[i], ==, buffer_id(i));
  CHECK(queue->fifo[buffer_count + 1], ==, buffer_id(3));
  CHECK(queue->fifo[buffer_count + 2], ==, buffer_id(5));
  CHECK(queue->fifo[buffer_count + 3], ==, buffer_id(2));

  for( i = 0; i < connection_count; ++i )
    STATE_FREE(c[i]);
  STATE_FREE(queue);
  STATE_FREE(vi);
}

int main(void)
{
  TEST_RUN(test_shrub_queue_open);
  TEST_RUN(test_shrub_queue_connections);
  TEST_END();
}
