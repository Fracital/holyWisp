/*
 * client/wt_client.h - the WebTransport transport of the blocking client (holywisp/client.h): QUIC
 * over a connected UDP socket, an HTTP/3 extended CONNECT, and Wisp packets on the session
 * (docs/webtransport.md, "Wisp on the session"), driven by poll(2) and the deadlines the caller
 * passes. Internal to src/client; client.c calls it where it would read or write its WebSocket.
 *
 * Packets that arrive while the caller waits for something else are kept in order. Past
 * max_queue bytes of them the session stops granting the server credit (hw_wt_pause), so the
 * server is held back instead of the client's memory growing.
 */
#ifndef HOLYWISP_CLIENT_WT_CLIENT_H
#define HOLYWISP_CLIENT_WT_CLIENT_H

#include <stddef.h>
#include <stdint.h>

typedef struct hw_wtc hw_wtc;

typedef struct {
	const char *host;        // where to connect
	const char *server_name; // SNI and :authority; NULL: host
	uint16_t port;
	const char *path;
	const char *origin;        // NULL: none sent
	const char *protocols;     // wt-available-protocols as sent; NULL: none (Wisp v1)
	const uint8_t *pin_sha256; // the server's leaf must hash to this; NULL accepts any (tests)
	size_t max_packet;         // the largest Wisp packet accepted from the server
	size_t max_queue;          // bytes of packets held before the server is paused
} hw_wtc_opts;

// Connect and open the session by deadline (hw_now_ms clock, UINT64_MAX for none). NULL with a
// printable message in err; a refused session says the HTTP status, as "server answered 429".
hw_wtc *hw_wtc_connect(const hw_wtc_opts *o, uint64_t deadline, char *err, size_t err_cap);
void hw_wtc_free(hw_wtc *t);

// Send one whole Wisp packet on a lane (0, or one hw_wtc_open_lanes opened), as a datagram when
// unreliable and it fits one. Waits (receiving meanwhile) while that lane's send queue is full,
// until deadline. 0, HW_ERR_CLOSED, or HW_ERR_TIMEOUT with nothing sent.
int hw_wtc_send(hw_wtc *t, int lane, const uint8_t *pkt, size_t len, int unreliable, uint64_t deadline);

// Open lanes 1 to lanes - 1 (docs/webtransport.md, "Lanes"), each with its LANE packet, once the
// handshake is over. Returns the lanes open, lane 0 included: fewer than asked when the server's
// MAX_STREAMS stops them.
int hw_wtc_open_lanes(hw_wtc *t, int lanes);

// 1 when the server opened lane 0 itself (it answered "wisp-v2-server-stream").
int hw_wtc_server_stream(const hw_wtc *t);

// The next Wisp packet from the server: 1 with *pkt valid until the next hw_wtc_next or
// hw_wtc_send (both may receive, and receiving may move the queue it points into), 0 when the
// deadline has passed and *has_read is set (a call owes the socket one look even when its time is
// up, and sets it), HW_ERR_CLOSED when the session is over.
int hw_wtc_next(hw_wtc *t, uint64_t deadline, int *has_read, const uint8_t **pkt, size_t *len);

// The server's wt-protocol, unquoted; "" when it sent none.
const char *hw_wtc_protocol(const hw_wtc *t);

// The UDP socket, for poll(2), and how long a caller that polls it may wait before it has to call
// hw_wtc_next for QUIC's timers: milliseconds, -1 for no limit.
int hw_wtc_fd(const hw_wtc *t);
int hw_wtc_wait_ms(const hw_wtc *t);

#endif
