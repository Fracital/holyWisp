/*
 * server/internal.h - the server's private structures, shared by server.c, conn.c, stream.c and
 * egress.c. Not installed.
 *
 * Threads: hw_server is created and torn down by the controlling thread. Each hw_worker runs its
 * own loop thread and owns every hw_conn and hw_stream it accepted. Only the _Atomic counters in
 * hw_server are touched from more than one thread.
 */
#ifndef HOLYWISP_SERVER_INTERNAL_H
#define HOLYWISP_SERVER_INTERNAL_H

#include "holywisp/buf.h"
#include "holywisp/loop.h"
#include "holywisp/map.h"
#include "holywisp/net.h"
#include "holywisp/server.h"

#include <pthread.h>
#include <stdatomic.h>

#define HW_READ_CHUNK       (64 * 1024) // one recv(2) from a remote or a client
#define HW_STREAM_MAX_ADDRS 8           // addresses tried per CONNECT, in resolver order

typedef struct hw_worker {
	hw_server *server;
	hw_loop *loop;
	int listen_fd;
	int index;
	pthread_t thread;
	int thread_started;
	uint8_t *scratch; // HW_READ_CHUNK bytes for remote reads
} hw_worker;

struct hw_server {
	hw_server_config cfg;
	hw_worker *workers;
	int nworkers;
	hw_resolver *resolver;
	uint16_t port;
	int started;
	_Atomic int stopped;

	_Atomic uint64_t connections_total;
	_Atomic uint64_t connections_active;
	_Atomic uint64_t streams_total;
	_Atomic uint64_t streams_active;
	_Atomic uint64_t bytes_in;
	_Atomic uint64_t bytes_out;
};

enum conn_state {
	CONN_HTTP = 0,   // reading the request head
	CONN_HTTP_REPLY, // plain HTTP response queued; close once flushed
	CONN_WS,         // WebSocket established
	CONN_CLOSED
};

// One WebSocket client. Owned by its worker's loop thread.
typedef struct hw_conn {
	hw_worker *w;
	int fd;
	enum conn_state state;
	hw_buf rbuf; // bytes from the client not yet parsed
	hw_buf wbuf; // frames to the client not yet written
	hw_buf frag; // reassembly of a fragmented binary message
	int frag_active;
	hw_map streams; // stream_id -> hw_stream
	int is_v2;
	int handshake_done; // v2: client INFO received; v1: always
	int stream_confirm; // v2 extension: CONTINUE a stream once it connects
	int authenticated;
	hw_timer *handshake_timer;
	int write_armed; // HW_EV_WRITE requested
	int paused;      // remote reads suspended: wbuf past the high-water mark
	int closing;
	char peer[HW_ADDR_STR_LEN];
} hw_conn;

enum stream_state {
	STREAM_RESOLVING = 0,
	STREAM_CONNECTING,
	STREAM_OPEN,
	STREAM_CLOSED
};

// One relayed TCP or UDP connection. Owned by its connection's loop thread.
typedef struct hw_stream {
	hw_conn *conn;
	uint32_t id;
	uint8_t type; // HW_STREAM_TCP / HW_STREAM_UDP
	enum stream_state state;
	int fd;
	hw_buf out;         // toward the remote; UDP entries are [u32 len][datagram]
	uint32_t remaining; // DATA packets left before we owe the client a CONTINUE
	int continue_due;   // the window closed while `out` still had bytes queued
	int read_armed;
	hw_resolve_req *resolve;
	hw_timer *connect_timer;
	struct sockaddr_storage addrs[HW_STREAM_MAX_ADDRS];
	socklen_t addr_lens[HW_STREAM_MAX_ADDRS];
	int naddrs;
	int addr_idx;
	char host[256];
	uint16_t port;
} hw_stream;

// conn.c
void conn_accept(hw_worker *w, int fd, const struct sockaddr *peer);
// Queue one Wisp packet (already laid out) as a binary WebSocket frame.
int conn_send_packet(hw_conn *c, const uint8_t *packet, size_t len);
// Queue a DATA packet for stream_id with `len` payload bytes copied from `data`.
int conn_send_data(hw_conn *c, uint32_t stream_id, const uint8_t *data, size_t len);
int conn_send_continue(hw_conn *c, uint32_t stream_id, uint32_t remaining);
int conn_send_close(hw_conn *c, uint32_t stream_id, uint8_t reason);
// Flush what can be written now; arms HW_EV_WRITE for the rest. Closes the conn on error.
void conn_flush(hw_conn *c);
// Tear down the client and all its streams; the memory is released on the next loop iteration.
void conn_close(hw_conn *c);

// stream.c
void stream_open(hw_conn *c, uint32_t id, uint8_t type, const char *host, size_t host_len, uint16_t port);
// DATA from the client. Takes care of flow control and queuing.
void stream_on_data(hw_stream *s, const uint8_t *data, size_t len);
// Close the remote side, tell the client when send_close, remove from the connection, free.
void stream_close(hw_stream *s, uint8_t reason, int send_close);
// Stop/resume reading from the remote (connection-level backpressure).
void stream_pause(hw_stream *s);
void stream_resume(hw_stream *s);

// egress.c: 0 when the policy lets a remote address through, -1 (with the class in *why) when not.
int egress_allowed(const hw_server_config *cfg, const struct sockaddr *sa, enum hw_addr_class *why);

#endif
