/*
 * holywisp/webtransport.h - HTTP/3 (RFC 9114) as far as WebTransport needs it, WebTransport over
 * HTTP/3 as Chrome speaks it (draft-ietf-webtrans-http3-02), and Wisp carried on top
 * (docs/webtransport.md, "Wisp over WebTransport").
 *
 * One hw_wt sits on one hw_quic_conn and is driven by the caller from the QUIC callbacks: the
 * caller forwards stream_data, stream_reset, stream_stop, stream_writable, datagram and
 * established to the hw_wt_on_* functions below. Single-threaded, sans-IO like holywisp/quic.h.
 *
 * What it does:
 * - Opens the HTTP/3 control stream with SETTINGS (QPACK table capacity 0, no blocked streams,
 *   SETTINGS_ENABLE_CONNECT_PROTOCOL = 1, H3_DATAGRAM = 1, ENABLE_WEBTRANSPORT = 1, and the
 *   draft's WEBTRANSPORT_MAX_SESSIONS = 1), and reads the peer's control, QPACK encoder and
 *   decoder streams (a dynamic table is never used, so their contents are ignored).
 * - Accepts exactly one extended CONNECT with :protocol webtransport per connection, decoded
 *   with the QPACK static table and literals only (Huffman included). The caller decides the
 *   answer (session_request); anything else (a plain GET, a second session) gets a 4xx response
 *   or H3_REQUEST_REJECTED, never a hang.
 * - On the session: the first client-opened WebTransport bidirectional stream (signal 0x41) is
 *   the Wisp stream. It carries Wisp packets, each preceded by its length as a u32 LE. Datagrams
 *   on the session (quarter stream id prefix) each carry one whole Wisp packet, which the server
 *   uses only for UDP stream DATA (hw_wt_send with unreliable = 1). Other WebTransport streams
 *   are refused with STOP_SENDING / RESET_STREAM (WEBTRANSPORT_BUFFERED_STREAM_REJECTED).
 * - The session ends with a CLOSE_WEBTRANSPORT_SESSION capsule (0x2843) or the CONNECT stream's
 *   FIN in either direction. The Wisp stream's end is not the session's (a reset may overtake the
 *   capsule): after the peer's FIN on it no more packets come, and after its STOP_SENDING
 *   hw_wt_send returns -1, which the caller takes as the end.
 *
 * Bounds: a header block over 16 KiB (the MAX_FIELD_SECTION_SIZE advertised), header blocks
 * buffered across streams over 64 KiB and a capsule over 64 KiB close the connection with
 * H3_EXCESSIVE_LOAD; a Wisp packet longer than max_packet closes it with H3_MESSAGE_ERROR (a
 * framing error leaves nothing to resynchronise on, so the session cannot go on); the reassembly
 * of one Wisp packet never holds more than max_packet bytes; at most 64 peer streams are tracked
 * at once. Received Wisp stream bytes are held only while paused, and then QUIC's stream window
 * bounds them. The send queue is reported (hw_wt_queued) for the caller's backpressure, which is
 * the same high-water rule as a WebSocket client's wbuf.
 *
 * Callbacks run synchronously from inside the hw_wt_* calls (and so from inside the QUIC
 * callbacks that forward to them). A callback may call any function here on the same hw_wt
 * except hw_wt_free. hw_wt_free is also not to be called from a QUIC callback that a hw_wt
 * function caused: hw_quic_close may report closed synchronously, so defer the free as for
 * hw_quic_free.
 */
#ifndef HOLYWISP_WEBTRANSPORT_H
#define HOLYWISP_WEBTRANSPORT_H

#include "holywisp/quic.h"

#include <stddef.h>
#include <stdint.h>

#define HW_WT_ALPN "h3"

// HTTP/3 and WebTransport error codes the module sends.
#define HW_H3_NO_ERROR                 0x100
#define HW_H3_GENERAL_PROTOCOL_ERROR   0x101
#define HW_H3_INTERNAL_ERROR           0x102
#define HW_H3_STREAM_CREATION_ERROR    0x103
#define HW_H3_CLOSED_CRITICAL_STREAM   0x104
#define HW_H3_FRAME_UNEXPECTED         0x105
#define HW_H3_FRAME_ERROR              0x106
#define HW_H3_EXCESSIVE_LOAD           0x107
#define HW_H3_ID_ERROR                 0x108
#define HW_H3_SETTINGS_ERROR           0x109
#define HW_H3_MISSING_SETTINGS         0x10a
#define HW_H3_REQUEST_REJECTED         0x10b
#define HW_H3_MESSAGE_ERROR            0x10e
#define HW_H3_DATAGRAM_ERROR           0x33
#define HW_WT_BUFFERED_STREAM_REJECTED 0x3994bd84
#define HW_WT_SESSION_GONE             0x170d7b68 // our Wisp stream reset after the client closed
#define HW_QPACK_DECOMPRESSION_FAILED  0x200      // a header block that is malformed or uses a dynamic table

typedef struct {
	const char *authority; // :authority
	const char *path;      // :path, with its query
	const char *origin;    // the origin header, NULL when absent (not a browser)
	// The wt-available-protocols header (draft-02 has none; Chrome sends the protocols passed to
	// new WebTransport(url, {protocols}) here), NULL when absent. Its presence is the Wisp v2
	// opt-in, as a WebSocket client's Sec-WebSocket-Protocol is.
	const char *protocols;
} hw_wt_request;

typedef struct {
	void *ud;
	// The extended CONNECT arrived. Return the HTTP status to answer: 200 opens the session,
	// anything else is sent as the response and the CONNECT stream is closed. protocol_out may
	// be set (to a string that lives as long as the hw_wt) to answer with
	// wt-protocol: <value>, as the WebSocket path echoes the subprotocol it was offered.
	int (*session_request)(void *ud, const hw_wt_request *req, const char **protocol_out);
	// One whole Wisp packet from the client, from the Wisp stream (datagram = 0) or a datagram.
	// The bytes are valid only during the call.
	void (*packet)(void *ud, const uint8_t *data, size_t len, int datagram);
	// The send queue has drained below what hw_wt_send would refuse (see hw_wt_send). Also called
	// once when the session becomes ready (hw_wt_ready), which is when the caller may send its
	// opening (the stream-0 CONTINUE, or INFO).
	void (*writable)(void *ud);
	// The session ended: code and reason from the peer's CLOSE_WEBTRANSPORT_SESSION, or 0 and ""
	// for a FIN, reset or STOP_SENDING of the CONNECT stream, or the connection's end (hw_wt_on_closed, or an HTTP/3
	// error hw_wt closed it for). Called at most once: on the server only for a session it answered 200, on the client
	// for every request it sent (a refused one too: hw_wt_status says why). Never called after hw_wt_close.
	// When the peer ended the session, hw_wt has answered with the CONNECT stream's FIN and reset
	// the Wisp stream, and leaves the connection open for those to go out: a server connection
	// carries one session, and Chrome sends no CONNECTION_CLOSE after it and goes silent, so the
	// caller closes the connection itself once its queue has drained (as wt_listener.c does).
	void (*session_closed)(void *ud, uint32_t code, const char *reason);
} hw_wt_callbacks;

typedef struct {
	size_t max_packet; // the largest Wisp packet accepted, header included (max-message-size)
	size_t send_max;   // bytes hw_wt_send may hold queued before it refuses (0 = no limit)
	int is_client;     // the client role, for holyWisp's tests and client
	// Client role only: the request it makes (copied). authority and path are required; origin
	// and protocols (the wt-available-protocols value as sent, a structured-field list such as
	// "\"wisp-v2\"") may be NULL, and the field is then not sent.
	const char *authority, *path, *origin, *protocols;
} hw_wt_config;

typedef struct hw_wt hw_wt;

// A WebTransport endpoint on q. It does nothing until hw_wt_on_established.
hw_wt *hw_wt_new(hw_quic_conn *q, const hw_wt_config *cfg, const hw_wt_callbacks *cb);
void hw_wt_free(hw_wt *w);

// The QUIC events, forwarded by the caller.
void hw_wt_on_established(hw_wt *w);
void hw_wt_on_stream_data(hw_wt *w, uint64_t id, const uint8_t *data, size_t len, int fin);
void hw_wt_on_stream_reset(hw_wt *w, uint64_t id, uint64_t app_error);
void hw_wt_on_stream_stop(hw_wt *w, uint64_t id, uint64_t app_error);
void hw_wt_on_stream_writable(hw_wt *w, uint64_t id);
void hw_wt_on_datagram(hw_wt *w, const uint8_t *data, size_t len);
// The connection closed (QUIC's closed): reports session_closed if it is still owed, and makes
// every later call a no-op that touches the connection no more.
void hw_wt_on_closed(hw_wt *w);

// 1 once the session is open (server: answered 200 and saw the Wisp stream; client: got 200
// and opened it).
int hw_wt_ready(const hw_wt *w);

// Send one whole Wisp packet. unreliable = 1 sends it as a datagram when it fits
// (hw_wt_datagram_max) and on the Wisp stream otherwise (a datagram QUIC drops for a full queue
// is lost, as UDP would lose it, and still returns 0). Returns 0 when it was sent or queued
// whole, 1 when this module's own queue (the bytes QUIC has not taken yet) holds send_max or
// more (nothing taken: wait for writable), -1 when the session is not open or has ended.
int hw_wt_send(hw_wt *w, const uint8_t *pkt, size_t len, int unreliable);

// Bytes of Wisp stream data queued and not yet acknowledged, here and in QUIC (hw_quic_queued).
// The QUIC part falls as acknowledgements arrive, with no callback: re-check it after
// hw_quic_input.
size_t hw_wt_queued(const hw_wt *w);

// The largest Wisp packet that fits one datagram on the session now, 0 when there are none.
size_t hw_wt_datagram_max(const hw_wt *w);

// Stop (1) or resume (0) delivering packets and granting the client stream credit: the
// backpressure a WebSocket connection gets by not reading its socket. Datagrams that arrive
// while paused are dropped, as a full UDP socket would.
void hw_wt_pause(hw_wt *w, int paused);

// End the session with a CLOSE_WEBTRANSPORT_SESSION capsule and FIN (the Wisp stream gets a FIN
// after what is queued on it), then the connection: it is closed (H3_NO_ERROR) once the peer
// answers with its own FIN or capsule, as draft-02 has it, so the capsule is not lost to the
// CONNECTION_CLOSE; the caller's idle timeout bounds a peer that never answers. No stream is
// stopped or reset here: one that overtook the capsule would make Chrome drop the session as
// lost and never answer (it resets its own streams once the capsule is in). Without an open
// session it closes the connection at once.
void hw_wt_close(hw_wt *w, uint32_t code, const char *reason);

// Client role: the response's :status, 0 until it arrives.
int hw_wt_status(const hw_wt *w);

// The session's subprotocol, unquoted: on the client the server's wt-protocol, on the server the
// one session_request chose. "" when there is none.
const char *hw_wt_protocol(const hw_wt *w);

// The first member of a structured-field list of strings or tokens (RFC 8941), such as the
// wt-available-protocols value hw_wt_request.protocols carries, unquoted into out (cap bytes,
// NUL-terminated). Returns 0, or -1 when the list does not start with a string or token or the
// member does not fit. session_request may hand back that member as protocol_out, quoted or not:
// it is sent as a structured-field string.
int hw_wt_protocol_first(const char *list, char *out, size_t cap);

// Whether a session request's :authority and :path are what a webtransport-path rule names. The
// rule's host (NULL, "" or "*" for any) is compared with the authority's host whole and without
// case, its port, an IPv6 literal's brackets and a trailing dot left aside. The rule's path is the
// request's path (the query and fragment left aside) exactly, or a prefix of it ending where a
// "/" follows: "/pipe/k" names "/pipe/k" and "/pipe/k/x", never "/pipe/kx", and a rule ending
// in "/" ("/" itself) names that path alone. Both paths must start with "/". 1 or 0.
int hw_wt_route_match(const char *rule_host, const char *rule_path, const char *authority, const char *path);

#endif
