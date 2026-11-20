/*
 * server/internal.h - the server's private structures, shared by server.c, conn.c, stream.c,
 * proxy.c, twisp.c and egress.c. Not installed.
 *
 * Threads: hw_server is created and torn down by the controlling thread. Each hw_worker runs its
 * own loop thread and owns every hw_conn and hw_stream it accepted. The limiters, the reputation
 * table and the DNS cache are shared and lock internally; the _Atomic counters are the only other
 * thing touched from more than one thread.
 */
#ifndef HOLYWISP_SERVER_INTERNAL_H
#define HOLYWISP_SERVER_INTERNAL_H

#include "holywisp/buf.h"
#include "holywisp/cert.h"
#include "holywisp/filter.h"
#include "holywisp/limits.h"
#include "holywisp/loop.h"
#include "holywisp/map.h"
#include "holywisp/net.h"
#include "holywisp/reputation.h"
#include "holywisp/server.h"
#include "holywisp/smap.h"

#include <pthread.h>
#include <stdatomic.h>

#include <sys/types.h>
#include <sys/uio.h>

#ifndef HW_READ_CHUNK
#define HW_READ_CHUNK (64 * 1024) // one recv(2) from a remote or a client
#endif
#define HW_STREAM_MAX_ADDRS 8                   // addresses tried per CONNECT, in resolver order
#define HW_BATCH_MAX        64                  // DATA payloads written to one remote with a single sendmsg
#define HW_FRAME_MAX        (128 * 1024)        // the most payload one DATA packet toward a client carries (conn.c)
#define HW_WT_SCRATCH_LEN   (HW_FRAME_MAX + 64) // wt_conn_scratch: one such packet with its Wisp header

// A stream's relay pipe (conn.c). Remote bytes are spliced into it and from it into the client
// socket, never through user space. `pending` bytes of one DATA payload are still in it, waiting
// for their turn in the connection's queue; the stream may not refill it before that is zero. A
// pipe whose stream closed with bytes pending (`stream` NULL) lives until the queue reaches it.
typedef struct hw_spipe {
	int fd[2];
	size_t size;
	size_t pending;
	struct hw_stream *stream;
} hw_spipe;

// "After `at` bytes of the write queue have gone out, splice `n` bytes from pipe `p`."
typedef struct hw_pipe_mark {
	uint64_t at;
	size_t n;
	hw_spipe *p;
} hw_pipe_mark;

// wt_listener.c: the WebTransport listener. One wt_worker per worker (every worker has one, for
// its copy of the certificate hashes that GET /webtransport.json serves; only the ones with a UDP
// socket accept sessions), one wt_session per QUIC connection.
typedef struct wt_worker wt_worker;
typedef struct wt_session wt_session;
// A certificate as the workers get it: the chain and key new handshakes use (chain_len 0: none
// yet), and the SHA-256 of the current and previous self-signed leaf for /webtransport.json
// (nhashes 0 with an operator's certificate, which browsers verify by the Web PKI).
typedef struct wt_cert {
	hw_der chain[HW_CERT_CHAIN_MAX];
	size_t chain_len;
	uint8_t key[HW_P256_PRIV_LEN];
	uint8_t hashes[2][32];
	int nhashes;
} wt_cert;

// webtransport-cert-dir: one host's certificate, shared by every table that lists it, and the
// table itself, sorted by name. Both immutable once made and freed by their last reference, so
// the workers share one table instead of a copy each (a directory can hold thousands).
typedef struct wt_hosts wt_hosts;
void wt_hosts_unref(wt_hosts *t);

// What stat(2) says of an operator's certificate or key file. Any field that differs is another
// file, or the same file rewritten.
typedef struct {
	int ok; // stat succeeded; the rest is zero when it did not
	uint64_t dev, ino, size;
	int64_t mtime;
} wt_file_id;

// The lists an operator edits while the server runs: the config's own, plus policy-file's when
// there is one (server.c, "Policy"). Immutable once made, shared by reference between the
// workers and freed by its last one, so a new policy costs one copy however many workers read it,
// and the data path reads it without a lock: a worker swaps its pointer in a posted task, between
// two callbacks, and nothing keeps it across one.
typedef struct hw_policy {
	_Atomic int refs;
	hw_hostlist allow_hosts; // when non-empty, only these
	hw_hostlist block_hosts;
	hw_portset allow_ports; // when non-empty, only these
	hw_portset block_ports;
	hw_hostlist warp_bypass_hosts;
	char allow_origins[HW_MAX_ORIGINS][128];
	int allow_origin_count;
} hw_policy;

void policy_unref(hw_policy *p);

// auth.c: hashed-password checks on threads of their own.
typedef struct hw_auth hw_auth;
typedef struct hw_auth_req hw_auth_req;
typedef void (*hw_auth_cb)(hw_loop *loop, int ok, void *ud);

// A per-worker counter's add: only its worker's thread writes it (or the thread that frees the
// worker, after joining it), so a relaxed load and store do what a locked add would, without the
// lock. hw_server_stats_get reads and sums them from any thread.
#define HW_WSTAT_ADD(field, n)                                                                            \
	atomic_store_explicit(&(field), atomic_load_explicit(&(field), memory_order_relaxed) + (uint64_t)(n), \
	                      memory_order_relaxed)

// A timing histogram as a worker keeps it (hw_stats_hist without the count, which is the sum).
typedef struct hw_whist {
	_Atomic uint64_t n[HW_STATS_HIST_BUCKETS];
	_Atomic uint64_t sum_us;
} hw_whist;

// The counters a worker keeps for /stats. Bumped once per session or stream, never per packet.
typedef struct hw_worker_stats {
	// How its streams ended (hw_server_stats.streams_*), and how long they took.
	_Atomic uint64_t stream_ended[HW_STATS_REASONS];
	_Atomic uint64_t stream_failed[HW_STATS_REASONS];
	_Atomic uint64_t stream_refused[HW_STATS_REASONS];
	_Atomic uint64_t stream_client_closed[2];
	_Atomic uint64_t stream_conn_closed[2];
	hw_whist resolve, tcp_connect, tcp_first, proxied_connect, proxied_first, udp_first;
	// Per udp-warp-marks tunnel, by its index there.
	struct {
		_Atomic uint64_t tcp_streams, tcp_connect_failed, udp_streams;
		hw_whist tcp_connect, tcp_first, udp_first;
	} tun[HW_WARP_MAX_TUNNELS];
	// WebTransport sessions that have ended on this worker, and what QUIC counted over their lives
	// (folded in at the end, so a long session shows only once it is over). srtt_us is the sum of
	// each one's last smoothed RTT.
	_Atomic uint64_t quic_sessions;
	_Atomic uint64_t quic_packets_sent, quic_packets_received, quic_packets_lost, quic_spurious_lost;
	_Atomic uint64_t quic_bytes_sent, quic_bytes_received;
	_Atomic uint64_t quic_congestion_events, quic_ptos, quic_srtt_us;
} hw_worker_stats;

typedef struct hw_worker {
	hw_server *server;
	hw_loop *loop;
	int listen_fd;
	int index;
	pthread_t thread;
	int thread_started;
	uint8_t *scratch; // HW_READ_CHUNK bytes for remote reads
	// The WARP tunnels this worker marks UDP streams for (udp-warp-marks): its own copy of what
	// the maintenance thread last read, swapped in by a posted task, so the data path reads it
	// without a lock. NULL: no usable state, UDP goes out unmarked.
	struct hw_warp_state *warp;
	uint64_t warp_warned_ms; // last "no healthy tunnel" warning, at most one a minute per worker
	hw_policy *policy;       // this worker's reference to the policy in force (never NULL once running)
	struct hw_conn *conns;   // every live connection on this worker, for shutdown cleanup
	// Ingress batch (stream_on_data / stream_batch_flush): DATA payloads for one idle TCP stream,
	// still sitting in the connection's read buffer, waiting to go out in one vectored write. It
	// only ever exists inside a single pass over that buffer; conn.c flushes it before the buffer
	// can move.
	struct hw_stream *batch_stream;
	struct iovec batch_iov[HW_BATCH_MAX];
	// Payload bytes relayed by this worker. Per worker, not per server: they are bumped for every
	// DATA packet, and one shared counter would bounce its cache line between all the workers.
	// They sit between this worker's own fields so no other thread writes near them; the stats
	// reader sums them.
	_Atomic uint64_t bytes_in;
	_Atomic uint64_t bytes_out;
	int batch_n;
	int batch_pkts; // whole DATA packets completed inside the batch (a large one spans entries)
	// Connections holding small frames that have not been written yet (conn_kick). The loop's
	// batch-end hook writes them, so frames queued by several callbacks leave in one send.
	struct hw_conn *flush_head;
	uint64_t pipe_retry_ms; // a relay pipe could not be had: do not ask the kernel again before this
	// TCP streams that opened in the last two sweeps and have no keepalive yet, in two lists:
	// keepalive_new[keepalive_cur] takes the streams that open now, and each sweep arms the other
	// one and makes it the list that takes them (stream_keepalive_sweep).
	struct hw_stream *keepalive_new[2];
	int keepalive_cur;
	uint64_t accept_warn_ms; // when "out of file descriptors" was last logged
	// Placement of new connections (server.c, "Which worker gets a connection"). `load` is the
	// connections given to this worker and not yet freed: raised by whichever worker accepted,
	// lowered here, read by every worker that has one to place. The inbox holds connections
	// another worker accepted for this one until this loop takes them; nothing else of a worker
	// is touched from outside its thread.
	_Atomic int load;
	pthread_mutex_t inbox_lock;
	struct hw_handoff *inbox;
	wt_worker *wt; // NULL without webtransport
	hw_worker_stats st;
} hw_worker;

enum proxy_kind {
	PROXY_NONE = 0,
	PROXY_SOCKS5,
	PROXY_HTTP
};

typedef struct hw_proxy_config {
	enum proxy_kind kind;
	char host[256];
	uint16_t port;
	char user[128];
	char pass[128];
	struct sockaddr_storage addr; // resolved once at startup
	socklen_t addr_len;
} hw_proxy_config;

struct hw_server {
	hw_server_config cfg;
	hw_worker *workers;
	int nworkers;
	hw_resolver *resolver;
	hw_auth *auth; // NULL unless a password-user holds a crypt(3) hash
	hw_dns_cache *dns_cache;
	hw_proxy_config proxy;
	// The CONTINUE window actually advertised: buffer-remaining, capped so a full window of
	// maximum-size DATA packets fits in half of stream-queue-max (server_ingress_window).
	uint32_t window;
	// Upload credit's initial window (INFO 0xE4), 0 when it is not offered (server_upload_credit_window).
	uint32_t upload_credit_window;
	// SO_RCVBUF applied to accepted client sockets, 0 for none (server_client_rcvbuf decides).
	int client_rcvbuf;
	uint16_t port;
	// The embedded web client with webclient-wisp-url spliced in; NULL serves the page as built.
	uint8_t *webclient_page;
	size_t webclient_page_len;
	int started;
	_Atomic int stopped;
	uint64_t started_ms;

	// Shared limiters (NULL / max 0 when disabled).
	hw_window *conn_rate;    // new WebSockets per client IP
	hw_window *per_source;   // CONNECTs per client IP per second
	hw_window *per_dest_sec; // CONNECTs per destination per second
	hw_window *per_dest_min; // ... per minute
	hw_semaphore in_flight_syns;
	hw_semaphore connections;
	hw_gauge *syns_per_ip;   // TCP connects in progress per client IP
	hw_gauge *conns_per_ip;  // WebSocket clients per client IP
	hw_gauge *heads_per_ip;  // connections still in their HTTP head, per socket peer address
	hw_budget *queue_budget; // server-queue-max and its per-IP share (conn_budget_sync)
	hw_bandwidth *bandwidth;
	size_t bw_quantum; // bytes a connection buys from it at a time: 10 ms of the rate, 1 to 64 KiB
	hw_reputation *reputation;

	// Maintenance thread: evictions, reputation decay and saves, DNS cache expiry.
	pthread_t maint_thread;
	int maint_started;
	pthread_mutex_t maint_lock;
	pthread_cond_t maint_cond;
	int maint_stop;
	uint64_t maint_last_slow; // last eviction/decay pass (ms)
	uint64_t maint_last_save; // last reputation save (ms)
	// UDP on WARP. warp_on: udp-warp-marks is set and this process may mark sockets. The rest is
	// the maintenance thread's alone: the state file as last read (its identity, and what it held
	// or NULL when it was unusable), and what the workers were last given.
	int warp_on;
	int warp_seen;                   // the file existed at the last look
	int64_t warp_mtime;              // its identity at that look: rewritten atomically, it is a new
	uint64_t warp_ino, warp_size;    // inode each time, so a change within one second still shows
	struct hw_warp_state *warp_read; // its content, restricted to udp-warp-marks; NULL: unusable
	char warp_why[96];               // why it is unusable, for the log
	uint8_t client_key_secret[128];  // proxy-client-key's secret (the configured one, or random)
	size_t client_key_secret_len;
	struct hw_warp_state *warp_given; // what the workers were last given (NULL: unmarked)
	int warp_published;               // whether every worker has warp_given
	int warp_why_code;                // why warp_read is NULL, as an enum hw_warp_status
	// The same for /stats, written at every look and read from any thread (hw_server_stats_get):
	// an enum hw_warp_status, the file's mtime in wall-clock seconds (0: none), the tunnels given.
	_Atomic int64_t warp_stat_mtime;
	_Atomic int warp_stat_status;
	_Atomic int warp_stat_n4, warp_stat_n6;
	// WebTransport. The keys are drawn once and never change: Retry tokens are sealed with the
	// first and stateless reset tokens derived from the second, and any worker must be able to
	// answer for any other's connection IDs. The certificate is the maintenance thread's
	// (wt_cert_tick); workers have their copies.
	uint16_t wt_port; // bound UDP port, 0 when off
	uint8_t wt_token_key[32];
	uint8_t wt_reset_key[32];
	wt_cert *wt_cert_cur;  // maintenance thread only
	_Atomic int wt_renew;  // hw_server_wt_renew asked for a new certificate before its time
	uint64_t wt_cert_made; // wall-clock seconds the self-signed one was made, 0 for the operator's
	// webtransport-cert and -key (maintenance thread only): as the last look found them, and as
	// they were when the pair was last read, whether it loaded or not.
	wt_file_id wt_files_seen[2];
	wt_file_id wt_files_tried[2];
	// webtransport-cert-dir (maintenance thread only): the table the workers were last given, the
	// directory as the last look found it, when to look at every file again whatever it says, and
	// whether a worker missed the table (no memory) and gets it again at the next look.
	wt_hosts *wt_hosts_cur;
	wt_file_id wt_dir_seen;
	uint64_t wt_dir_rescan_ms;
	int wt_dir_failed;
	int wt_hosts_unpublished;
	// The policy (maintenance thread only, after hw_server_new): what the workers were last given,
	// policy-file as the last look found it and as it was when last read, when to read it again
	// whatever it says, whether that read failed, and whether a worker missed the last one.
	hw_policy *policy_cur;
	wt_file_id policy_seen;
	wt_file_id policy_tried;
	uint64_t policy_rescan_ms;
	int policy_failed;
	int policy_unpublished;

	_Atomic uint64_t connections_total;
	_Atomic uint64_t connections_active;
	_Atomic uint64_t ws_connections_total; // upgraded to a WebSocket (a 101 sent)
	_Atomic uint64_t ws_connections_active;
	_Atomic uint64_t http_replies; // answered with plain HTTP: polls, pages, refused upgrades
	_Atomic uint64_t streams_total;
	_Atomic uint64_t streams_active;
	_Atomic uint64_t refused_connection_rate;
	_Atomic uint64_t refused_connection_limit;
	_Atomic uint64_t refused_reputation;
	_Atomic uint64_t blocked_filter;
	_Atomic uint64_t blocked_egress;
	_Atomic uint64_t throttled_source;
	_Atomic uint64_t throttled_dest;
	_Atomic uint64_t throttled_syns;
	_Atomic uint64_t throttled_lookups;
	_Atomic uint64_t queue_budget_pauses;
	_Atomic uint64_t udp_warp_marked;
	_Atomic uint64_t udp_warp_direct;
	_Atomic uint64_t udp_warp_refused;
	_Atomic uint64_t tcp_warp_marked;
	_Atomic uint64_t tcp_warp_direct;
	_Atomic uint64_t tcp_warp_refused;
	_Atomic uint64_t udp_warp_bypassed;
	_Atomic uint64_t tcp_warp_bypassed;
	_Atomic uint64_t tcp_proxied;
	_Atomic uint64_t tcp_direct;
	_Atomic uint64_t syn_signatures;
	_Atomic uint64_t ws_closed_violations;
	_Atomic uint64_t auth_failures;
	_Atomic uint64_t wt_sessions_total;
	_Atomic uint64_t wt_sessions_active;
	_Atomic uint64_t wt_handshakes;
	_Atomic uint64_t wt_retries;
	_Atomic uint64_t wt_refused_handshakes;
	_Atomic uint64_t wt_dropped;
	_Atomic uint64_t relay_pipes; // open, whether a stream holds them or the queue still empties them
};

#define HW_STAT_INC(server, field) atomic_fetch_add(&(server)->field, 1)

enum conn_state {
	CONN_HTTP = 0,   // reading the request head
	CONN_HTTP_REPLY, // plain HTTP response queued; close once flushed
	CONN_WS,         // WebSocket established
	CONN_CLOSED
};

// One Wisp client: a WebSocket, or a WebTransport session (wt set, fd -1: its packets come from
// wt_listener.c and its frames go back there, and rbuf, wbuf and the pipes stay unused). Owned by
// its worker's loop thread.
typedef struct hw_conn {
	hw_worker *w;
	wt_session *wt;
	int fd;
	enum conn_state state;
	hw_buf rbuf; // bytes from the client not yet parsed
	hw_buf wbuf; // frames to the client not yet written
	// Payloads waiting in stream pipes, in queue order. The wire order is wbuf up to marks[0].at
	// (counted in bytes ever taken from wbuf, `wsent`), then that pipe's payload, then on.
	hw_pipe_mark *marks;
	size_t mark_head, mark_count, mark_cap;
	uint64_t wsent;
	// Frames the client is waiting on (a refill CONTINUE, a pong), sent at the next frame boundary
	// of wbuf instead of behind it (conn_send_ahead): fr_end is where the frame being sent ends its
	// part in wbuf, in wsent's count, and pri_mid says a frame of pri is half sent.
	hw_buf pri;
	uint64_t fr_end;
	int pri_mid;
	int pipes_held;    // streams of this connection that hold a relay pipe (conn_sweep looks at those)
	size_t pipe_bytes; // sum of the marks' n: what backpressure counts besides wbuf
	hw_buf frag;       // reassembly of a fragmented binary message
	int frag_active;
	hw_map streams;  // stream_id -> hw_stream
	hw_smap sigdets; // "ip:port" -> hw_sigdet (SYN-flood signature per destination)
	int is_v2;
	int handshake_done; // v2: client INFO received; v1: always
	int stream_confirm; // v2 extension: CONTINUE a stream once it connects
	int authenticated;
	hw_auth_req *auth_req; // a hashed password is being checked: the INFO exchange waits for it
	hw_timer *handshake_timer;
	hw_timer *throttle_timer; // bandwidth pause
	uint64_t throttle_until;  // hw_now_ms when the pause may end (the timer re-arms short of it)
	size_t bw_credit;         // bytes bought from the bandwidth limiter and not yet spent
	int throttled;            // reads suspended until throttle_timer fires
	int write_armed;          // HW_EV_WRITE requested
	int flush_queued;         // on the worker's flush list
	struct hw_conn *flush_next;
	int paused;        // remote reads suspended: bp_paused or throttled (conn_sync_streams)
	int bp_paused;     // the send queue passed the high-water mark and has not drained yet
	size_t queued_out; // bytes waiting in every stream's `out` toward its remote
	size_t pkt_avg;    // running average DATA payload from this client, 0 until the first
	// The streams that share the upload budget (conn_window): those that spent a window in the
	// current period of UPLOAD_ACTIVE_MS (up_cur) or the one before (up_prev), and those whose
	// refill is held behind a slow remote (up_held). Idle streams and UDP are in none of them.
	uint64_t up_epoch;
	uint32_t up_cur, up_prev, up_held;
	size_t read_chunk; // room offered to each recv: grows while reads fill it, decays when idle
	// A large DATA frame being forwarded as it arrives (ws_frames): its stream, the payload bytes
	// still to come, and the frame's mask with the position in its cycle.
	size_t pt_left;
	uint32_t pt_stream;
	uint8_t pt_mask[4];
	size_t pt_off;
	// server-queue-max: what this connection holds of the budget (whole BUDGET_CHUNKs), what was
	// queued toward the client at the last look (conn_backpressure), and whether a take was
	// refused, which stops the client's reads and the remotes' until it can take again.
	uint64_t budget_held;
	size_t q_client;
	int budget_paused;
	int wr_stalled;     // client reads suspended: its own send queue is far past the high-water mark
	int wrote;          // bytes left for the client since the worker's last sweep
	int read_paused;    // client reads suspended: queued_out past conn-queue-max
	uint64_t stall_ms;  // when a sweep first found the send queue not moving, 0 while it moves
	uint64_t active_ms; // last frame from the client, for idle-timeout-s
	int closing;
	int violations;
	int ws_counted;      // counted in server->ws_connections_active
	int conn_slot;       // holds one of server->connections
	int ip_slot;         // holds one of server->conns_per_ip for c->ip
	int head_slot;       // holds one of server->heads_per_ip for c->ip, the peer's until the head is read
	size_t head_scanned; // bytes of rbuf already searched for the end of the HTTP head
	uint32_t wt_code;    // WebTransport: the session close code conn_close sends (ws_fail's code)
	// WebTransport lanes: the lane of the packet being handled, which a stream it opens rides, and
	// the lanes whose streams' remotes are paused for their own queue (conn_backpressure).
	int rx_lane;
	uint32_t lane_paused;
	int wt_info_first; // the server opened lane 0: the client's next packet must be its INFO
	int continue_sent; // ... and the stream-0 CONTINUE went out with the server's INFO
	// Stream credit: whether the server's INFO offered it, and the initial window the client named
	// (at least HW_WISP_CREDIT_MIN), 0 while it is off. Every TCP and Twisp stream opened while it
	// is set starts with that window (stream_new).
	int credit_offered;
	uint32_t credit_window;
	// Upload credit: the initial window per stream once both INFOs named it, 0 while it is off. Every
	// TCP and Twisp stream opened while it is set counts its uploads in bytes (stream_new).
	int up_offered;
	uint32_t up_window;
	int heard;      // a read from the client since the worker's last sweep
	int stream_cap; // effective max streams (reputation THROTTLE tier lowers it)
	enum hw_rep_tier tier;
	char peer[HW_ADDR_STR_LEN];                  // socket peer, with port, for logs
	char ip[HW_IP_STR_LEN];                      // client IP after trusted-proxy headers, for policy
	char client_key[HW_WARP_CLIENT_KEY_LEN + 1]; // proxy-client-key: this client's, else ""
	struct sockaddr_storage peer_addr;
	struct hw_conn *lprev, *lnext; // worker->conns list
} hw_conn;

enum stream_state {
	STREAM_RESOLVING = 0,
	STREAM_CONNECTING,
	STREAM_PROXY, // TCP to the proxy is up; SOCKS5/CONNECT handshake in progress
	STREAM_OPEN,
	STREAM_CLOSED
};

enum proxy_phase {
	PROXY_PHASE_GREETING = 0, // SOCKS5: waiting for the method choice
	PROXY_PHASE_AUTH,         // SOCKS5: waiting for the username/password result
	PROXY_PHASE_CONNECT       // SOCKS5: waiting for the reply; HTTP: waiting for the status
};

// One relayed TCP, UDP or PTY stream. Owned by its connection's loop thread.
typedef struct hw_stream {
	hw_conn *conn;
	uint32_t id;
	uint8_t type; // HW_STREAM_TCP / HW_STREAM_UDP / HW_STREAM_TERM
	enum stream_state state;
	int fd;
	hw_buf out;         // toward the remote; UDP entries are [u32 len][datagram]
	uint32_t remaining; // DATA packets left before we owe the client a CONTINUE
	int continue_due;   // the window closed while `out` still had bytes queued
	uint64_t up_epoch;  // the period it last spent a window in (conn_window), 0 for never
	int up_held;        // counted in conn->up_held instead: its refill waits for `out` to drain
	size_t pkt_avg;     // running average DATA payload on this stream, 0 until the first
	int bulk;           // the remote delivers full reads: relay through the pipe (conn_splice_data)
	int bulk_miss;      // consecutive small splices; enough of them end bulk mode
	int parked;         // reads stopped until the stream's own pipe has drained into the client
	hw_spipe *pipe;     // opened when the stream goes bulk, given back when it leaves or idles
	int pipe_used;      // the pipe was filled since the last sweep (conn_sweep_pipes)
	int read_armed;
	int detached;    // hung up while reads were paused: off the loop until they resume
	int heard;       // the remote has sent something since the client last did
	int syn_held;    // holds one of server->in_flight_syns
	int syn_ip_held; // ... and one of server->syns_per_ip for the client's IP
	uint8_t denied;  // close reason of the last address policy refused (dest_policy), 0 for none
	hw_resolve_req *resolve;
	hw_timer *connect_timer;
	struct sockaddr_storage addrs[HW_STREAM_MAX_ADDRS];
	socklen_t addr_lens[HW_STREAM_MAX_ADDRS];
	int naddrs;
	int addr_idx;
	char dest[HW_IP_STR_LEN + 8]; // "ip:port" of the address being tried
	char host[256];
	int literal_host; // host is an IP literal: a proxy gets the address, not a name
	int via_proxy;    // TCP through the proxy (decided once the addresses are known, begin_dial)
	uint16_t port;
	// Upstream proxy handshake.
	enum proxy_phase proxy_phase;
	hw_buf pin;
	// Twisp.
	pid_t pid;
	int lane; // WebTransport: the lane its CONNECT came on, which every packet of it goes on
	// Stream credit: DATA payload bytes queued toward the client so far, and the most the client
	// lets it have (raised by CREDIT, never lowered). UINT64_MAX for a stream that is not counted
	// (UDP, or credit off), which therefore never reaches it.
	uint64_t credit_sent;
	uint64_t credit_limit;
	// Timing for /stats: when the phase being timed began (resolve, dial, open or the client's
	// first DATA, hw_now_us), which of the client's first DATA and the remote's first byte have been
	// seen (STREAM_TIMED_*), and the udp-warp-marks tunnel the socket is marked for, plus one (0:
	// none).
	uint64_t t_us;
	uint8_t timed;
	uint8_t warp_slot;
	uint8_t ka_list; // see ka_prev
	// Upload credit: DATA payload bytes the client has sent on the stream, and the most it may
	// have sent (raised by the server's UPLOAD_CREDIT, never lowered). up_limit 0: the stream is
	// paced by CONTINUE's packet window instead (UDP, or upload credit off).
	uint64_t up_recv;
	uint64_t up_limit;
	// On one of the worker's keepalive_new lists (ka_list - 1 says which, 0: none) until
	// the sweep gives its socket keepalive.
	struct hw_stream *ka_prev, *ka_next;
	// Where its last frame toward the client ends in the connection's wbuf, in wsent's count (the
	// mark's position for a spliced one): its refill CONTINUE goes ahead of the queue only once
	// that has been sent (conn_send_continue).
	uint64_t q_end;
} hw_stream;

#define STREAM_TIMED_DATA  1 // the client has sent DATA
#define STREAM_TIMED_FIRST 2 // the remote's first byte is counted (or never will be: a terminal)

// Stream credit spent: the stream may not read its remote until a CREDIT raises the limit.
static inline int stream_credit_held(const hw_stream *s) {
	return s->credit_sent >= s->credit_limit;
}

// The most one read from the remote may take for the client: cap, or what is left of the credit.
static inline size_t stream_credit_cap(const hw_stream *s, size_t cap) {
	uint64_t left = s->credit_limit - s->credit_sent;
	return left < cap ? (size_t)left : cap;
}

// Whether a stream reads from its remote: not while the connection's send queue or bandwidth
// holds every stream (c->paused), nor while its own lane's queue holds its lane (WebTransport),
// nor while its own credit is spent.
static inline int conn_stream_paused(const hw_conn *c, const hw_stream *s) {
	return c->paused || (c->lane_paused >> s->lane & 1u) || stream_credit_held(s);
}

// conn.c
void conn_accept(hw_worker *w, int fd, const struct sockaddr *peer);

// conn.c, for wt_listener.c: the WebTransport side of a connection.
// A connection for a WebTransport CONNECT from peer (the UDP address: no proxy header is ever
// read there). NULL on allocation failure.
hw_conn *conn_wt_new(hw_worker *w, wt_session *s, const struct sockaddr *peer);
// The connection-level checks of the WebSocket upgrade, in its order, for the CONNECT's origin
// and offered protocols. The HTTP status to answer: 200 admits the connection (it holds its slots,
// and is v2 when protocols was offered and enable-v2 is on); anything else refuses it, and the
// caller detaches and closes it.
int conn_wt_admit(hw_conn *c, const char *origin, const char *protocols);
// The session is open (the client's Wisp stream exists): the v1 or v2 opening, as after a 101.
void conn_wt_open(hw_conn *c);
// One whole Wisp packet from a lane (0 is the Wisp stream), or from a datagram (lane -1: only DATA
// for a UDP stream is acted on there). The bytes are only valid during the call. May close the
// connection.
void conn_wt_packet(hw_conn *c, const uint8_t *data, size_t len, int lane);
// Something may have left the send queue (an ACK, a flush): re-evaluate backpressure.
void conn_wt_progress(hw_conn *c);

// wt_listener.c
// The UDP sockets, one per worker where datagrams can be steered (else one, on worker 0), and the
// certificate. Called by hw_server_new after the workers exist. 0, or -1 (logged).
int wt_listener_init(hw_server *s);
// The server is stopping: every session of the worker is closed toward its client (the session's
// close capsule, then QUIC's CONNECTION_CLOSE), sent before this returns, waiting at most
// WT_STOP_FLUSH_MS for a full socket. On the worker's thread, after its loop has stopped; nothing
// is freed (wt_worker_free does that).
void wt_worker_stop(hw_worker *w);
// Every session of the worker, freed in place (shutdown, loops stopped), and the worker's state.
void wt_worker_free(hw_worker *w);
// What wt_listener_init would refuse before it binds: the operator's certificate and key not
// loading as a pair, webtransport-cert-dir not opening. 0, or -1 with the reason in why.
int wt_config_check(const hw_server_config *cfg, char *why, size_t why_cap);
// The maintenance thread's look at the certificate, once a second. Self-signed: a new one every 6
// days, or at once after hw_server_wt_renew. The operator's: read again once either file has
// changed and then stayed as it is for one look, and published only when it loads as at start.
void wt_cert_tick(hw_server *s, int running);
void wt_cert_free(wt_cert *c);
// The body of GET /webtransport.json from this worker's copy, into out. Its length, 0 when it
// does not fit.
size_t wt_json(const hw_worker *w, char *out, size_t cap);
// For conn.c on a WebTransport connection.
int wt_conn_send(wt_session *s, int lane, const uint8_t *pkt, size_t len, int unreliable);
size_t wt_conn_queued(const wt_session *s);
// One lane's share of that queue, and the lanes open now (a bit mask, lane 0 in bit 0).
size_t wt_conn_lane_queued(const wt_session *s, int lane);
uint32_t wt_conn_lanes(const wt_session *s);
// The lanes the server's INFO offers (0 for none), and whether the server opened lane 0.
int wt_conn_lanes_offered(const wt_session *s);
int wt_conn_server_stream(const wt_session *s);
// The client's INFO is done: let every lane's packets through (deferred to the session's settle).
void wt_conn_release(wt_session *s);
size_t wt_conn_datagram_max(const wt_session *s);
void wt_conn_pause(wt_session *s, int paused);
void wt_conn_flush(wt_session *s);
// The connection is closing (conn_close): end the session with code and forget the connection.
void wt_conn_detach(wt_session *s, uint32_t code);
// A per-worker buffer of one frame's payload plus a Wisp header, to lay out a packet in.
uint8_t *wt_conn_scratch(wt_session *s);

// stats.c: a time into a worker's histogram.
void stats_hist_add(hw_whist *h, uint64_t us);
// The enum hw_stats_reason of a CLOSE reason.
int stats_reason(uint8_t reason);
// The remote's first byte has reached the client: its time goes into the histograms (stream.c;
// proxy.c for what arrived with the proxy's answer). A no-op after the first.
void stream_time_first(hw_stream *s);
// stats.c: the body of GET /stats, appended to out, for a connection on worker w (whose own copy
// of the WARP state names the tunnels). 0, or -1 when out could not grow.
int stats_json(const hw_worker *w, hw_buf *out);
// Look at policy-file again, and when it holds another policy that loads, give it to the workers
// (server.c). The maintenance thread's, once a second.
void server_policy_tick(hw_server *s);

// Look at udp-warp-state again and give the workers what it now means (server.c). The maintenance
// thread does this every second; running 0 means the workers have not started, so their copies
// are set in place. Exposed for tests, which drive it by hand.
void server_warp_refresh(hw_server *s, int running);
// Queue one Wisp packet (already laid out) as a binary WebSocket frame.
int conn_send_packet(hw_conn *c, const uint8_t *packet, size_t len);
// Queue a DATA packet for stream s with `len` payload bytes copied from `data`.
int conn_send_data(hw_conn *c, hw_stream *s, const uint8_t *data, size_t len);
// Relay what the stream's remote has to read, at most max bytes (its credit; > 0), as one DATA
// packet without copying it through user space. Returns the bytes relayed (> 0), 0 on remote EOF,
// -1 with errno from the remote read (EAGAIN: nothing to read), -2 when the copying path (recv
// into scratch + conn_send_data) must be used instead, or -3 when the stream's previous payload is
// still in its pipe: the caller waits for it (stream_park). A failure toward the client closes the
// connection: check c->closing.
ssize_t conn_splice_data(hw_conn *c, hw_stream *s, size_t max);
// The stream is closing, or done with its pipe for now: free the pipe, or leave it to the queue
// when a payload is still in it.
void conn_pipe_drop(hw_stream *s);
int conn_send_continue(hw_conn *c, uint32_t stream_id, uint32_t remaining);
// A CLOSE for a CONNECT refused before it was a stream (counted so in the stats), or for stream 0.
// UPLOAD_CREDIT for a stream: written at once like a CONTINUE, for the same reason.
int conn_send_upload_credit(hw_conn *c, uint32_t stream_id, uint64_t limit);
// Upload credit's per-stream budget now: upload-window shared by the client's streams, at least
// UPLOAD_BUDGET_MIN, at most the initial window.
uint64_t conn_upload_budget(const hw_conn *c);
int conn_send_close(hw_conn *c, uint32_t stream_id, uint8_t reason);
// The same for a stream that is gone already, on the lane it rode (WebTransport; a WebSocket has
// one): stream_close's CLOSE.
int conn_send_close_lane(hw_conn *c, uint32_t stream_id, uint8_t reason, int lane);
// Flush what can be written now; arms HW_EV_WRITE for the rest. Closes the conn on error.
void conn_flush(hw_conn *c);
// The loop's batch-end hook (ud is the hw_worker): write every connection's deferred frames.
void conn_batch_end(hw_loop *loop, void *ud);
// Tear down the client and all its streams; the memory is released on the next loop iteration.
void conn_close(hw_conn *c);
// Shutdown only: tear down and free a connection synchronously (the loop is no longer running).
void conn_shutdown_free(hw_conn *c);
// Build s->webclient_page from the embedded client and cfg.webclient_wisp_url (no-op when the URL
// is empty). Returns 0, or -1 with errno on allocation failure.
int webclient_page_build(hw_server *s);
// Flood-protection violation: counts toward ws-close-after-violations. Returns 1 if that closed
// the connection.
int conn_violation(hw_conn *c, const char *reason);
// Bandwidth accounting for `bytes` in either direction; pauses the connection when over budget.
void conn_charge_bandwidth(hw_conn *c, size_t bytes);
// The window to hand TCP stream s on its next CONTINUE, called when s has just spent one: the
// connection's in-flight byte budget (upload-window) shared between the streams that are
// uploading now, in packets of the size s sends, never above the advertised maximum
// (server->window) and never below a few packets. Counts s as uploading from now on.
uint32_t conn_window(hw_conn *c, hw_stream *s);
// held 1: s has spent its window and its CONTINUE is held until its queue drains, and it keeps
// its share of the upload budget for as long as that takes. held 0: the CONTINUE has gone, and s
// counts as uploading from now on, as after conn_window.
void conn_upload_hold(hw_conn *c, hw_stream *s, int held);
// s is closing: it no longer shares the upload budget.
void conn_upload_forget(hw_conn *c, hw_stream *s);
// What one client may have in flight toward its remotes across its streams: upload-window, or
// ws-write-high-water when that is 0 (the budget the refill CONTINUE and QUIC's credit share out).
// Upload credit's smallest initial window and per-stream budget (docs/extensions.md).
#define UPLOAD_CREDIT_MIN (64 * 1024)
#define UPLOAD_BUDGET_MIN (256 * 1024)
static inline size_t cfg_upload_window(const hw_server_config *cfg) {
	return cfg->upload_window ? cfg->upload_window : cfg->ws_write_high_water;
}
// Bytes entered or left a stream's queue toward its remote. Past conn-queue-max the connection
// stops reading the client (never closes anything) and resumes at half the mark.
void conn_queue_add(hw_conn *c, size_t n);
void conn_queue_sub(hw_conn *c, size_t n);
// The worker's periodic pass over its connections: closes one whose send queue has not moved for
// client-write-timeout-s, or (idle-timeout-s) one with no streams that has sent nothing for that long.
void conn_sweep(hw_worker *w);
// Reputation shortcuts (no-ops when disabled).
void conn_rep_source(hw_conn *c, enum hw_rep_event e);
void conn_rep_dest(hw_conn *c, const char *dest, enum hw_rep_event e);

// auth.c
hw_auth *auth_new(void);
void auth_free(hw_auth *a);
// Hash `pass` the way `stored` (a crypt(3) hash) was made, on the pool, and run cb on `loop` with
// whether they match. With `known` zero the work is done and the answer is always no: a name that
// does not exist must cost what one that does costs. NULL when too many checks are waiting, or
// out of memory: nothing will be called. The result belongs to the pool; keep it only to cancel.
hw_auth_req *auth_check(hw_auth *a, hw_loop *loop, const char *pass, const char *stored, int known, hw_auth_cb cb,
                        void *ud);
// The caller is going away: cb will not run. Loop thread only.
void auth_cancel(hw_auth_req *req);

// stream.c
void stream_open(hw_conn *c, uint32_t id, uint8_t type, const char *host, size_t host_len, uint16_t port);
// DATA from the client. Takes care of flow control and queuing. For an idle TCP stream the bytes
// are not written yet: `data` joins the worker's batch and must stay valid until
// stream_batch_flush(), which the caller runs before the memory behind it can change.
void stream_on_data(hw_stream *s, const uint8_t *data, size_t len);
// The same for one piece of a DATA packet that is forwarded while it is still arriving; only the
// piece with `final` set counts against the flow-control window.
void stream_on_data_part(hw_stream *s, const uint8_t *data, size_t len, int final);
// Write the worker's pending batch to its stream (one sendmsg), queue what the socket did not
// take and settle flow control for the packets in it. May close the stream or the connection.
void stream_batch_flush(hw_worker *w);
// Close the remote side, tell the client when send_close, remove from the connection, free.
void stream_close(hw_stream *s, uint8_t reason, int send_close);
// Stop/resume reading from the remote (connection-level backpressure). A resume does nothing for a
// stream that is parked or whose credit is spent: those resume when their own hold ends.
void stream_pause(hw_stream *s);
void stream_resume(hw_stream *s);
// A bulk stream's pipe still holds its previous payload: stop reading the remote until the queue
// has written it (stream_unpark, from conn_flush).
void stream_park(hw_stream *s);
void stream_unpark(hw_stream *s);
// The remote (or proxy handshake) is up: finish opening the stream toward the client and send what
// it queued meanwhile. 0 when the stream is open, -1 when that closed it (or the connection): the
// stream is freed then, and a caller with more to do tests the result, never s->state.
int stream_connected(hw_stream *s);
// Give keepalive to the TCP streams that opened before the previous sweep and are still open, and
// start the next generation. From the worker's sweep timer; O(streams opened since).
void stream_keepalive_sweep(hw_worker *w);
// Adopt an already-connected fd (a PTY master for Twisp): register it on the loop and open the
// stream. Closes the stream on failure.
void stream_adopt(hw_stream *s, int fd);
// Allocate and register a stream in state RESOLVING with no fd. NULL when the connection refused
// it (a CLOSE has been sent).
hw_stream *stream_new(hw_conn *c, uint32_t id, uint8_t type, const char *host, size_t host_len, uint16_t port);

// How long a connect to sa may take: connect-timeout-ms, or family-fallback-ms while an address
// of the other family is still to be tried.
int stream_attempt_timeout_ms(const hw_stream *s, const struct sockaddr *sa);

// proxy.c
// Parse "socks5://[user:pass@]host[:port]" (socks5h:// is the same thing) / "http://..." into out.
// -1 with err on a bad URL.
int proxy_config_parse(const char *url, hw_proxy_config *out, char *err, size_t err_cap);
// Resolve the proxy host once. -1 with errno when it cannot be resolved.
int proxy_config_resolve(hw_proxy_config *p);
// The TCP connection to the proxy is up: send the first handshake bytes. -1 = stream closed.
int proxy_start(hw_stream *s);
// Bytes arrived from the proxy during the handshake. 1 = done (stream_connected was called),
// 0 = need more, -1 = failed (stream closed).
int proxy_on_data(hw_stream *s, const uint8_t *data, size_t len);

// twisp.c
// CONNECT with stream type TERM: fork a PTY running `command`. Sends CLOSE on failure.
void twisp_open(hw_conn *c, uint32_t id, const char *command, size_t len);
void twisp_resize(hw_stream *s, uint16_t rows, uint16_t cols);
// Called from stream_close for TERM streams: kill and forget the child.
void twisp_kill(hw_stream *s);

// egress.c: 0 when the policy lets a remote address through, -1 (with the class in *why) when not.
int egress_allowed(const hw_server_config *cfg, const struct sockaddr *sa, enum hw_addr_class *why);

// server.c
void server_tune_socket(const hw_server *s, int fd, int is_tcp);

#endif
