/*
 * holywisp/client.h - blocking Wisp client.
 *
 * One hw_client is one WebSocket connection to a Wisp server, multiplexing any number of streams.
 * It is single-threaded and blocking: the caller drives it with hw_client_poll(). Events for a
 * stream that arrive while another call is pumping the socket are queued and handed out in order.
 */
#ifndef HOLYWISP_CLIENT_H
#define HOLYWISP_CLIENT_H

#include <stddef.h>
#include <stdint.h>

typedef struct hw_client hw_client;

typedef struct hw_client_opts {
	const char *host; // server
	uint16_t port;
	const char *path;   // "/" by default
	int v2;             // request wisp-v2
	const char *user;   // v2 password auth, optional
	const char *pass;   //
	int stream_confirm; // v2: ask the server to CONTINUE when a stream connects
	int timeout_ms;     // connect + handshake, default 10000
	size_t max_message; // largest incoming WebSocket message, default 1 MiB + header
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
	const uint8_t *data;       // DATA; valid until the next hw_client_poll
	size_t len;
} hw_client_event;

void hw_client_opts_defaults(hw_client_opts *o);

// Connect, upgrade, complete the Wisp handshake. NULL on failure with a message in err.
hw_client *hw_client_connect(const hw_client_opts *o, char *err, size_t err_cap);
void hw_client_free(hw_client *c);

int hw_client_is_v2(const hw_client *c);
const char *hw_client_motd(const hw_client *c); // "" when none
int hw_client_server_has_udp(const hw_client *c);
uint32_t hw_client_buffer_size(const hw_client *c); // the server's initial CONTINUE
int hw_client_fd(const hw_client *c);               // for poll(2) alongside other fds

// Open a stream; the id is chosen by the client and returned. 0 on success.
int hw_client_open(hw_client *c, uint8_t stream_type, const char *host, uint16_t port, uint32_t *stream_id);
// Send one DATA packet. For TCP streams this waits (pumping events into the queue) while the
// server's window is exhausted. 0 on success, HW_ERR_CLOSED when the stream or socket is gone.
int hw_client_send(hw_client *c, uint32_t stream_id, const void *data, size_t len);
int hw_client_close_stream(hw_client *c, uint32_t stream_id, uint8_t reason);

// Next event: 1 and ev filled, 0 on timeout, HW_ERR_CLOSED when the WebSocket is gone,
// HW_ERR_PROTOCOL on a framing error. timeout_ms -1 = forever.
int hw_client_poll(hw_client *c, int timeout_ms, hw_client_event *ev);

// Convenience for tests: wait for exactly `want` bytes of DATA on one stream (other events are
// queued). Returns bytes received (< want means the stream closed first) or a negative error.
long hw_client_read_exact(hw_client *c, uint32_t stream_id, uint8_t *out, size_t want, int timeout_ms);

#endif
