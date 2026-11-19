/*
 * holywisp/client.h - blocking Wisp client.
 *
 * One hw_client is one WebSocket connection to a Wisp server, multiplexing any number of streams.
 * It is single-threaded and blocking: the caller drives it with hw_client_poll(). Events for a
 * stream that arrive while another call is pumping the socket are queued and handed out in order.
 *
 * The server is not trusted. Every length it sends is checked against a limit the caller set
 * (max_message, max_queue_bytes, max_queue_events), every wait for it to send something runs
 * against one deadline per call that nothing it sends can restart, and credentials go to it only
 * when it asked for them. Writing is the exception: the socket is blocking, so a server that stops
 * reading it can hold a call that sends for as long as it keeps the connection open.
 * What the server says about itself (the MOTD, the text quoted in a connect error) is still its
 * own bytes: see hw_client_printable before writing any of it to a terminal or a log.
 *
 * There is no TLS on the WebSocket path. On a ws:// URL everything, the v2 password included,
 * travels in clear and anyone on the path can read it or answer in the server's place. Put a TLS
 * terminator in front (a local stunnel or proxy on the client side, a reverse proxy on the server
 * side) before giving a client credentials that matter.
 *
 * With opts.webtransport the same client speaks Wisp over WebTransport instead (QUIC over UDP to
 * the server's webtransport port, docs/webtransport.md). That path is encrypted, and it is
 * authenticated only by pin_sha256: the certificate's SHA-256, as the server's
 * /webtransport.json lists it. There is no certificate authority check; without a pin any
 * certificate is taken, which is for tests on loopback and nothing else.
 */
#ifndef HOLYWISP_CLIENT_H
#define HOLYWISP_CLIENT_H

#include <stddef.h>
#include <stdint.h>

typedef struct hw_client hw_client;

typedef struct hw_client_opts {
	const char *host; // server
	uint16_t port;
	const char *path; // "/" by default
	int v2;           // request wisp-v2
	// v2 password auth, optional; at most 255 and 127 bytes. Sent only when v2 is set and the
	// server's INFO advertises the password extension, and then in clear (see the top of this
	// file). hw_client_authenticated() tells whether they were sent.
	const char *user;
	const char *pass;
	int stream_confirm; // v2: ask the server to CONTINUE when a TCP stream connects
	// One bound for hw_client_connect as a whole (TCP connect, upgrade and Wisp handshake), and
	// the longest hw_client_send waits for a CONTINUE. Default 10000; negative waits without bound.
	int timeout_ms;
	size_t max_message; // largest incoming WebSocket message, default 1 MiB + header
	// The most the client holds in queued events: DATA bytes, and events of any kind. Events are
	// queued while a call waits for something else (hw_client_send for a CONTINUE,
	// hw_client_read_exact for one stream's bytes), so without a limit the server decides how much
	// memory that takes. Defaults 32 MiB and 65536; 0 means the default. A single event larger
	// than max_queue_bytes can never be queued.
	size_t max_queue_bytes;
	size_t max_queue_events;
	// WebTransport instead of a WebSocket: port is then the server's UDP webtransport port and
	// path the session's :path. A v2 request offers wt-available-protocols "wisp-v2". UDP stream
	// DATA goes out as QUIC datagrams.
	int webtransport;
	const uint8_t *pin_sha256; // 32 bytes the server's certificate must hash to; NULL takes any
	const char *origin;        // the origin header to send; NULL sends none
	// WebTransport: the name to send as SNI and as the :authority's host instead of host, which
	// is then only where to connect (an address, or another name), as curl's --connect-to.
	// NULL: host.
	const char *server_name;
	// WebTransport v2 (docs/webtransport.md): offer "wisp-v2-server-stream" after "wisp-v2", so a
	// server that knows it opens the Wisp stream itself and sends its CONTINUE without waiting for
	// the client's INFO. Off by default.
	int wt_server_stream;
	// WebTransport v2: ride up to this many lanes (QUIC streams), lane 0 included, when the
	// server's INFO offers lanes; at most 16. Each CONNECT goes on the lane with the fewest open
	// streams, the lowest first. 0 or 1 (the default): lane 0 alone.
	int wt_lanes;
	// Stream credit, v2 on either transport: name INFO extension 0xE2 with this initial window in
	// bytes when the server's INFO offers it (hw_client_credit_window then says so; a window under
	// 16384 is 16384, as the server takes it). The server then sends each TCP or terminal stream no
	// more than the client has granted: the window, and more as the caller takes the stream's data.
	// Taken means handed to the caller (hw_client_poll returning its DATA, hw_client_read_exact
	// copying it out); what waits in the client's queue is not taken. Once a stream's caller has
	// taken half a window since its last grant, the library sends CREDIT(taken + window) on the
	// stream's lane. A caller that takes nothing from a stream holds that stream alone. 0 (the
	// default): not named, and nothing changes.
	uint32_t credit_window;
	// With credit_window: the library grants nothing by itself, the caller does (hw_client_credit).
	int credit_manual;
	// Upload credit, v2 on either transport: name INFO extension 0xE4 when the server's INFO
	// offers it with a window (hw_client_upload_window then says which; docs/extensions.md). Each
	// TCP or terminal stream's sends are then counted in bytes against a limit that starts at that
	// window and that the server raises as its remote takes them, and hw_client_send waits for a
	// grant instead of a CONTINUE. 0 (the default): not named, and nothing changes.
	int upload_credit;
	// WebTransport: the UDP socket's receive and send buffers, in bytes as setsockopt takes them
	// (Linux grants double). 0: 4 MiB. A browser's is the system's cap, often 208 KiB on Linux
	// (net.core.rmem_max): this is how a test receives as a browser would.
	size_t wt_udp_buffer;
} hw_client_opts;

enum hw_client_event_type {
	HW_CEV_DATA = 1,
	HW_CEV_CLOSE = 2,
	HW_CEV_CONTINUE = 3
};

typedef struct hw_client_event {
	int type;
	uint32_t stream_id;
	uint8_t reason;            // CLOSE
	uint32_t buffer_remaining; // CONTINUE
	const uint8_t *data;       // DATA; valid until the next call on this client (a send can read too)
	size_t len;
} hw_client_event;

void hw_client_opts_defaults(hw_client_opts *o);

// Connect, upgrade, complete the Wisp handshake. NULL on failure with a message in err, which is
// printable ASCII even where it quotes the server. A server that answers with a subprotocol the
// client did not offer is refused (RFC 6455), so v2 is only ever spoken when opts.v2 asked for it.
hw_client *hw_client_connect(const hw_client_opts *o, char *err, size_t err_cap);
void hw_client_free(hw_client *c);

int hw_client_is_v2(const hw_client *c);
// 1 when opts.user and opts.pass were sent to the server and it completed the handshake (a server
// that rejects them closes instead, and hw_client_connect fails). 0 when nothing was sent: none
// were set, v2 was not requested, or the server did not advertise the password extension. In that
// last case the connection is up but unauthenticated, and a caller that requires authentication
// must check this and hang up.
int hw_client_authenticated(const hw_client *c);
// "" when none. The server's bytes, cut to 511: they can hold terminal escape sequences.
const char *hw_client_motd(const hw_client *c);
int hw_client_server_has_udp(const hw_client *c);
// 1 when the server's v2 INFO offers stream-open confirmation (0x05). opts.stream_confirm asks
// for it whatever this says (a server may confirm without offering it, as wispurr does); a
// confirmed TCP stream's first event is the CONTINUE, or its CLOSE. A UDP stream is never
// confirmed. 0 on v1.
int hw_client_server_has_stream_confirm(const hw_client *c);
// The most streams the server lets this connection have open at once, from its v2 INFO
// (extension 0xE3, docs/extensions.md), which the client names back. 0 when the server has no
// limit or did not say (v1, or a server without the extension). hw_client_open keeps to it.
uint32_t hw_client_max_streams(const hw_client *c);
// Upload credit as the session has it: the initial window per stream in bytes, 0 when it is off
// (not asked for, v1, or a server whose INFO does not offer it).
uint32_t hw_client_upload_window(const hw_client *c);
// WebTransport: the lanes open, lane 0 included (1 on a WebSocket), the lane a stream rides (-1
// for none), and whether the server opened lane 0 (opts.wt_server_stream answered).
int hw_client_lanes(const hw_client *c);
int hw_client_stream_lane(const hw_client *c, uint32_t stream_id);
int hw_client_server_stream(const hw_client *c);
uint32_t hw_client_buffer_size(const hw_client *c); // the server's initial CONTINUE
// Stream credit as the session has it: the initial window per stream in bytes, 0 when it is off
// (not asked for, v1, or a server whose INFO does not offer it).
uint32_t hw_client_credit_window(const hw_client *c);
int hw_client_fd(const hw_client *c); // for poll(2) alongside other fds
// The longest a caller that polls hw_client_fd may wait before it calls hw_client_poll, in
// milliseconds: QUIC's timers (retransmission, acknowledgements, keepalive) run only inside the
// client's calls. -1 on a WebSocket, which has none.
int hw_client_wait_ms(const hw_client *c);
// The same in microseconds, not rounded up (-1 on a WebSocket): what QUIC's pacer waits for is
// often well under a millisecond, and a caller that waits in milliseconds slows its uploads to a
// few datagrams per millisecond. hw_sys_poll_us waits for it.
int64_t hw_client_wait_us(const hw_client *c);

// Copy len bytes to out as printable ASCII for a terminal or a log line: every byte below 0x20 or
// above 0x7e becomes \xNN (four characters), so no escape sequence, line break or UTF-8 encoded
// control survives. out is always NUL-terminated when cap > 0; a byte whose rendering does not
// fit ends the copy, never half an escape. Returns the characters written, without the NUL; cap
// of 4 * len + 1 always fits.
size_t hw_client_printable(char *out, size_t cap, const void *data, size_t len);

// Open a stream; the id is chosen by the client and returned. 0 on success, HW_ERR_INVALID when
// host is empty or longer than 255 bytes, the most a CONNECT carries (it is never cut to fit),
// HW_ERR_TOOBIG with hw_client_max_streams streams open already (counting each until the client
// closed it or saw it closed): nothing is sent, and the server would have refused it 0x49. Over
// WebTransport lanes a CONNECT can still overtake the CLOSE that made room for it on another lane
// and be refused 0x49; on one lane, or a WebSocket, it never is.
int hw_client_open(hw_client *c, uint8_t stream_type, const char *host, uint16_t port, uint32_t *stream_id);
// Send one DATA packet. For TCP and terminal streams (every type but UDP, which the server never
// counts) this waits (pumping events into the queue) while the
// server's window is exhausted, for at most opts.timeout_ms: CONTINUE's packets, or with upload
// credit the stream's bytes (then for terminal streams too, and the CONTINUE named below is the
// grant). 0 on success, HW_ERR_CLOSED when the
// stream or socket is gone, HW_ERR_TIMEOUT when no CONTINUE came in time: nothing was sent and the
// client is intact, so the caller may poll and try again. HW_ERR_TOOBIG when what the server sent
// during the wait passed max_queue_bytes or max_queue_events: the client is then closed, events
// already queued can still be polled, and every later call returns HW_ERR_CLOSED. The timeout is
// for the CONTINUE only; the write that follows is a blocking send(2). Over WebTransport that
// write waits instead while the session's send queue is full, within the same timeout
// (HW_ERR_TIMEOUT, nothing sent), and a UDP stream's DATA is a datagram that may be lost, as UDP's
// would be.
int hw_client_send(hw_client *c, uint32_t stream_id, const void *data, size_t len);
int hw_client_close_stream(hw_client *c, uint32_t stream_id, uint8_t reason);
// Send CREDIT for stream_id: the server may have sent it `limit` DATA payload bytes in all,
// counted from its start. On the stream's lane (lane 0 for an id the client does not have open).
// The server only ever raises a limit, so a lower or repeated one changes nothing; it ignores one
// for stream 0, a stream it does not have open or a UDP stream. This is the only way to give a
// stream more than the window at once (a large download the caller is waiting on), and with
// opts.credit_manual the only grant there is. It does not change when the library grants next.
// 0, HW_ERR_INVALID when stream credit is off, HW_ERR_CLOSED.
int hw_client_credit(hw_client *c, uint32_t stream_id, uint64_t limit);

// Next event: 1 and ev filled, 0 on timeout, HW_ERR_CLOSED when the WebSocket is gone,
// HW_ERR_PROTOCOL on a framing error. timeout_ms -1 = forever. The timeout covers the whole call:
// packets and frames that are not events (PING, PONG, INFO) do not extend it. A zero timeout still
// reads the socket once, and 0 is only returned when no complete event is left in the client, so
// a caller may then wait on hw_client_fd().
int hw_client_poll(hw_client *c, int timeout_ms, hw_client_event *ev);

// Convenience for tests: wait for exactly `want` bytes of DATA on one stream (other events are
// queued). Returns bytes received (< want means the stream closed or the time ran out first) or a
// negative error when there are none: HW_ERR_TIMEOUT, HW_ERR_CLOSED, HW_ERR_PROTOCOL, or
// HW_ERR_TOOBIG when the events queued for other streams passed max_queue_bytes or
// max_queue_events (the client is then closed, as for hw_client_send). timeout_ms bounds the whole
// call. The count is a long long because a long is 32 bits on Windows and `want` may be 2 GiB or
// more.
long long hw_client_read_exact(hw_client *c, uint32_t stream_id, uint8_t *out, size_t want, int timeout_ms);

#endif
