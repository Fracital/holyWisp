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
 * There is no TLS here. On a ws:// URL everything, the v2 password included, travels in clear and
 * anyone on the path can read it or answer in the server's place. Put a TLS terminator in front
 * (a local stunnel or proxy on the client side, a reverse proxy on the server side) before giving
 * a client credentials that matter.
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
	int stream_confirm; // v2: ask the server to CONTINUE when a stream connects
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
uint32_t hw_client_buffer_size(const hw_client *c); // the server's initial CONTINUE
int hw_client_fd(const hw_client *c);               // for poll(2) alongside other fds

// Copy len bytes to out as printable ASCII for a terminal or a log line: every byte below 0x20 or
// above 0x7e becomes \xNN (four characters), so no escape sequence, line break or UTF-8 encoded
// control survives. out is always NUL-terminated when cap > 0; a byte whose rendering does not
// fit ends the copy, never half an escape. Returns the characters written, without the NUL; cap
// of 4 * len + 1 always fits.
size_t hw_client_printable(char *out, size_t cap, const void *data, size_t len);

// Open a stream; the id is chosen by the client and returned. 0 on success, HW_ERR_INVALID when
// host is empty or longer than 255 bytes, the most a CONNECT carries (it is never cut to fit).
int hw_client_open(hw_client *c, uint8_t stream_type, const char *host, uint16_t port, uint32_t *stream_id);
// Send one DATA packet. For TCP streams this waits (pumping events into the queue) while the
// server's window is exhausted, for at most opts.timeout_ms. 0 on success, HW_ERR_CLOSED when the
// stream or socket is gone, HW_ERR_TIMEOUT when no CONTINUE came in time: nothing was sent and the
// client is intact, so the caller may poll and try again. HW_ERR_TOOBIG when what the server sent
// during the wait passed max_queue_bytes or max_queue_events: the client is then closed, events
// already queued can still be polled, and every later call returns HW_ERR_CLOSED. The timeout is
// for the CONTINUE only; the write that follows is a blocking send(2).
int hw_client_send(hw_client *c, uint32_t stream_id, const void *data, size_t len);
int hw_client_close_stream(hw_client *c, uint32_t stream_id, uint8_t reason);

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
