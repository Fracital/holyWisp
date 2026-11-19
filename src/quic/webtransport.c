/*
 * src/quic/webtransport.c - HTTP/3 as far as WebTransport needs it, WebTransport draft-02 as
 * Chrome speaks it, and Wisp on the session (holywisp/webtransport.h). The bytes are h3.c's and
 * qpack.c's; this file is the state: which stream is what, the one session, the Wisp stream and
 * its queues.
 *
 * Streams. Every stream the peer opens gets a wt_stream until it has ended in both directions;
 * the client's CONNECT stream and the Wisp stream keep theirs until hw_wt_free. A stream starts
 * PENDING until its prefix says what it is (h3.c, hw_h3_stream_kind_parse), then it is read as
 * that kind. Streams refused or not wanted are DRAIN: their bytes are credited and dropped.
 *
 * Credit. Every byte received is handed back to QUIC (hw_quic_stream_consumed) when it has been
 * read, except Wisp stream bytes while paused: those wait in rx_hold, uncredited, so the client
 * runs out of stream credit, which is the backpressure (docs/webtransport.md).
 *
 * Re-entrancy. Callbacks may call back into hw_wt (send, pause, close). After any call that can
 * reach a callback or close the connection, code here checks w->dead and the session state
 * before going on; stream entries are only removed at the end of the hw_wt_on_* entry points.
 */
#include "holywisp/webtransport.h"

#include "holywisp/buf.h"
#include "holywisp/hw.h"
#include "holywisp/wisp.h"

#include "h3.h"
#include "quic_wire.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define WT_STREAMS_MAX       64                            // peer streams tracked at once
#define WT_HEADERS_TOTAL_MAX (4 * HW_H3_FIELD_SECTION_MAX) // header block bytes buffered across streams
#define WT_SETTINGS_MAX      4096                          // a SETTINGS frame's payload
#define WT_CAPSULE_MAX       65536                         // a capsule's value
#define WT_FIELDS_MAX        64                            // fields in one header block
#define WT_PROTOCOL_MAX      512                           // a subprotocol name (Chrome's limit)
#define WT_BLOCK_MAX         2048                          // a header block we encode
// The GREASE capsule the client sends after its request, as Chrome does: 0x29 * n + 0x17.
#define WT_GREASE_CAPSULE (0x29 * 0x2full + 0x17)

enum {
	SK_PENDING,
	SK_CONTROL,
	SK_QPACK,
	SK_REQUEST,
	SK_CONNECT,
	SK_WISP,
	SK_DRAIN
};
enum {
	SESSION_NONE,
	SESSION_PENDING,
	SESSION_OPEN,
	SESSION_CLOSING,
	SESSION_DONE
};
enum {
	KEEP_SKIP,
	KEEP_BODY,
	KEEP_CAPSULES
};

// Our sending side of a stream: what QUIC has not taken yet, and the FIN behind it.
typedef struct {
	int64_t id; // -1: none (a peer's unidirectional stream)
	hw_buf tx;
	int fin;      // a FIN is queued behind tx
	int fin_sent; // QUIC took the FIN
	int dead;     // reset by us or stopped by the peer: nothing more is written
} wt_out;

typedef struct {
	uint64_t id;
	int kind; // SK_*
	uint8_t pre[16];
	size_t pre_len;
	hw_h3_tlv rd; // frames (control, request and CONNECT streams)
	int framed;   // a frame has started (a flag, not a count: a peer sends as many as it likes)
	int headers;  // HEADERS frames completed
	int keep;     // KEEP_*: what the current frame's body is for
	hw_buf body;  // a SETTINGS or HEADERS payload being collected
	size_t body_charged;
	int deferred;  // a request waiting for the peer's SETTINGS (its HEADERS are in body)
	hw_h3_tlv cap; // capsules inside the CONNECT stream's DATA frames
	int cap_keep;
	hw_buf capbody;
	int rx_done; // the peer's sending side has ended (FIN or reset)
	wt_out out;
} wt_stream;

struct hw_wt {
	hw_quic_conn *q;
	hw_wt_callbacks cb;
	size_t max_packet, send_max;
	int is_client;
	char *authority, *path, *origin, *protocols;
	int established, dead;
	wt_out ctrl, enc, dec; // our unidirectional streams
	wt_stream *streams[WT_STREAMS_MAX];
	size_t n_streams;
	size_t hdr_bytes; // header block bytes buffered across streams
	int peer_ctrl, peer_enc, peer_dec;
	int settings_seen;
	hw_h3_settings peer;
	int session; // SESSION_*
	uint64_t session_id;
	wt_stream *conn_s; // the session's CONNECT stream
	wt_stream *wisp_s; // the Wisp stream
	int ready;
	int owes_closed;
	int status;
	char protocol[WT_PROTOCOL_MAX];
	hw_h3_lp rx;
	hw_buf rx_hold; // Wisp stream bytes received while paused, not yet credited
	int paused, in_rx;
	int send_refused; // hw_wt_send returned 1: writable is owed
};

static const uint8_t EMPTY[1];

static char *dup_str(const char *s) {
	if (!s) return NULL;
	size_t n = strlen(s) + 1;
	char *d = malloc(n);
	if (d) memcpy(d, s, n);
	return d;
}

// ---- Ending things ------------------------------------------------------------------------------

static void wt_report_closed(hw_wt *w, uint32_t code, const char *reason) {
	if (!w->owes_closed) return;
	w->owes_closed = 0;
	if (w->cb.session_closed) w->cb.session_closed(w->cb.ud, code, reason);
}

// Close the connection (an HTTP/3 error, or H3_NO_ERROR for a finished session).
static void wt_fail(hw_wt *w, uint64_t code, const char *reason) {
	if (w->dead) return;
	w->dead = 1;
	w->ready = 0;
	if (w->session != SESSION_CLOSING) w->session = SESSION_DONE;
	hw_quic_close(w->q, code, reason);
	wt_report_closed(w, 0, "");
}

// ---- Our sending sides ----------------------------------------------------------------------------

static void out_init(wt_out *o, int64_t id) {
	memset(o, 0, sizeof(*o));
	o->id = id;
	hw_buf_init(&o->tx);
}

static int out_idle(const wt_out *o) {
	return o->id < 0 || o->fin_sent || o->dead;
}

// Write what QUIC takes now and queue the rest (and the FIN) behind it.
static void out_write(hw_wt *w, wt_out *o, const uint8_t *d, size_t n, int fin) {
	if (w->dead || o->id < 0 || o->dead || o->fin || o->fin_sent) return;
	if (!d) d = EMPTY;
	if (hw_buf_avail(&o->tx) == 0) {
		int64_t t = hw_quic_stream_write(w->q, (uint64_t)o->id, d, n, fin);
		if (t < 0) {
			o->dead = 1;
			return;
		}
		if ((size_t)t == n) {
			if (fin) o->fin_sent = 1;
			return;
		}
		d += t;
		n -= (size_t)t;
	}
	if (hw_buf_append(&o->tx, d, n) < 0) {
		wt_fail(w, HW_H3_INTERNAL_ERROR, "out of memory");
		return;
	}
	if (fin) o->fin = 1;
}

static void out_flush(hw_wt *w, wt_out *o) {
	if (w->dead || out_idle(o)) return;
	size_t n = hw_buf_avail(&o->tx);
	if (n == 0 && !o->fin) return;
	const uint8_t *d = n ? hw_buf_head(&o->tx) : EMPTY;
	int64_t t = hw_quic_stream_write(w->q, (uint64_t)o->id, d, n, o->fin);
	if (t < 0) {
		o->dead = 1;
		hw_buf_free(&o->tx);
		return;
	}
	hw_buf_consume(&o->tx, (size_t)t);
	if ((size_t)t == n && o->fin) o->fin_sent = 1;
	if (hw_buf_avail(&o->tx) == 0) hw_buf_shrink(&o->tx, 0);
}

static void out_reset(hw_wt *w, wt_out *o, uint64_t code) {
	if (w->dead || out_idle(o)) return;
	hw_quic_stream_reset(w->q, (uint64_t)o->id, code);
	o->dead = 1;
	hw_buf_free(&o->tx);
}

// ---- Streams ----------------------------------------------------------------------------------

static int stream_is_peer(const hw_wt *w, uint64_t id) {
	return (int)(id & 1) == (w->is_client ? 1 : 0);
}

static int stream_is_bidi(uint64_t id) {
	return (id & 2) == 0;
}

static wt_stream *stream_find(hw_wt *w, uint64_t id) {
	for (size_t i = 0; i < w->n_streams; i++) {
		if (w->streams[i]->id == id) return w->streams[i];
	}
	return NULL;
}

static wt_stream *stream_new(hw_wt *w, uint64_t id, int kind) {
	if (w->n_streams == WT_STREAMS_MAX) {
		wt_fail(w, HW_H3_EXCESSIVE_LOAD, "too many streams");
		return NULL;
	}
	wt_stream *s = calloc(1, sizeof(*s));
	if (!s) {
		wt_fail(w, HW_H3_INTERNAL_ERROR, "out of memory");
		return NULL;
	}
	s->id = id;
	s->kind = kind;
	hw_h3_tlv_init(&s->rd);
	hw_h3_tlv_init(&s->cap);
	hw_buf_init(&s->body);
	hw_buf_init(&s->capbody);
	out_init(&s->out, stream_is_bidi(id) ? (int64_t)id : -1);
	w->streams[w->n_streams++] = s;
	return s;
}

static void stream_body_release(hw_wt *w, wt_stream *s) {
	w->hdr_bytes -= s->body_charged;
	s->body_charged = 0;
	hw_buf_free(&s->body);
}

static void stream_free(hw_wt *w, wt_stream *s) {
	stream_body_release(w, s);
	hw_buf_free(&s->capbody);
	hw_buf_free(&s->out.tx);
	free(s);
}

// Forget the streams that have ended both ways (the session's two are kept).
static void streams_sweep(hw_wt *w) {
	size_t j = 0;
	for (size_t i = 0; i < w->n_streams; i++) {
		wt_stream *s = w->streams[i];
		if (s != w->conn_s && s != w->wisp_s && s->rx_done && !s->deferred && out_idle(&s->out)) {
			stream_free(w, s);
		} else {
			w->streams[j++] = s;
		}
	}
	w->n_streams = j;
}

// Refuse a stream: STOP_SENDING, and RESET_STREAM for a bidirectional one; its bytes are dropped.
static void stream_refuse(hw_wt *w, wt_stream *s, uint64_t code) {
	s->kind = SK_DRAIN;
	stream_body_release(w, s);
	s->deferred = 0;
	if (w->dead) return;
	if (!s->rx_done) hw_quic_stream_stop(w->q, s->id, code);
	out_reset(w, &s->out, code);
}

// ---- The session ending ---------------------------------------------------------------------------

// The peer ended the session (its capsule, a FIN, a reset or STOP_SENDING of the CONNECT or the
// Wisp stream).
static void peer_closed(hw_wt *w, uint32_t code, const char *reason) {
	if (w->dead) return;
	if (w->session == SESSION_CLOSING) {
		// The answer to our close: the connection has nothing left to carry.
		w->session = SESSION_DONE;
		wt_fail(w, HW_H3_NO_ERROR, "");
		return;
	}
	if (w->session != SESSION_OPEN) return;
	w->session = SESSION_DONE;
	w->ready = 0;
	out_write(w, &w->conn_s->out, NULL, 0, 1);
	if (w->wisp_s) {
		out_reset(w, &w->wisp_s->out, HW_WT_SESSION_GONE);
		if (!w->dead && !w->wisp_s->rx_done) hw_quic_stream_stop(w->q, w->wisp_s->id, HW_WT_SESSION_GONE);
		hw_buf_free(&w->rx_hold);
	}
	wt_report_closed(w, code, reason);
}

// ---- Responses and requests ---------------------------------------------------------------------

static size_t block_put(uint8_t *out, size_t cap, const char *name, const char *value) {
	return hw_qpack_field_put(out, cap, name, strlen(name), value, strlen(value));
}

// Quote a subprotocol as a structured-field string; 0 for one that cannot be one.
static int sf_quote(const char *in, char *out, size_t cap) {
	char bare[WT_PROTOCOL_MAX];
	if (in[0] == '"') {
		if (hw_wt_protocol_first(in, bare, sizeof(bare)) < 0) return 0;
		in = bare;
	}
	size_t o = 0;
	if (cap < 3) return 0;
	out[o++] = '"';
	for (const char *p = in; *p; p++) {
		unsigned char c = (unsigned char)*p;
		if (c < 0x20 || c > 0x7e) return 0;
		if (o + 3 >= cap) return 0;
		if (c == '"' || c == '\\') out[o++] = '\\';
		out[o++] = (char)c;
	}
	out[o++] = '"';
	out[o] = '\0';
	return 1;
}

// HEADERS with :status (and, for a 200, the draft-02 marker and wt-protocol) on s.
static void respond(hw_wt *w, wt_stream *s, int status, const char *protocol, int fin) {
	uint8_t block[WT_BLOCK_MAX];
	char st[4] = {(char)('0' + status / 100 % 10), (char)('0' + status / 10 % 10), (char)('0' + status % 10), 0};
	size_t n = hw_qpack_prefix_put(block, sizeof(block));
	n += block_put(block + n, sizeof(block) - n, ":status", st);
	// A request for a page lands here when a browser holds an h3 alternative service for this
	// host from somewhere else (a CDN that was in front of it). 421 makes Chrome and Firefox send
	// it again over TCP without the alternative, and the clear drops what they hold.
	if (status == 421) n += block_put(block + n, sizeof(block) - n, "alt-svc", "clear");
	if (status == 200) {
		n += block_put(block + n, sizeof(block) - n, "sec-webtransport-http3-draft", "draft02");
		char quoted[2 * WT_PROTOCOL_MAX + 3];
		if (protocol && *protocol && sf_quote(protocol, quoted, sizeof(quoted))) {
			n += block_put(block + n, sizeof(block) - n, "wt-protocol", quoted);
			if (hw_wt_protocol_first(quoted, w->protocol, sizeof(w->protocol)) < 0) w->protocol[0] = '\0';
		}
	}
	uint8_t frame[WT_BLOCK_MAX + 16];
	size_t h = hw_h3_frame_header_put(frame, sizeof(frame), HW_H3_FRAME_HEADERS, n);
	memcpy(frame + h, block, n);
	out_write(w, &s->out, frame, h + n, fin);
}

// Answer a request that does not open a session, and stop reading it (RFC 9114 section 4.1.1:
// a complete response before the request is complete, then STOP_SENDING with H3_NO_ERROR).
static void respond_refuse(hw_wt *w, wt_stream *s, int status) {
	respond(w, s, status, NULL, 1);
	s->kind = SK_DRAIN;
	if (!w->dead && !s->rx_done) hw_quic_stream_stop(w->q, s->id, HW_H3_NO_ERROR);
}

typedef struct {
	char arena[HW_H3_FIELD_SECTION_MAX];
	char join[HW_H3_FIELD_SECTION_MAX];
	hw_qpack_field fields[WT_FIELDS_MAX];
} wt_scratch;

// Decode s->body; returns the field count, or -1 when the connection was closed for it.
static int headers_decode(hw_wt *w, wt_stream *s, wt_scratch *sc) {
	int n = hw_qpack_decode(hw_buf_head(&s->body) ? hw_buf_head(&s->body) : EMPTY, hw_buf_avail(&s->body), sc->arena,
	                        sizeof(sc->arena), sc->fields, WT_FIELDS_MAX);
	stream_body_release(w, s);
	if (n == HW_ERR_TOOBIG) {
		wt_fail(w, HW_H3_EXCESSIVE_LOAD, "header block too large");
		return -1;
	}
	if (n < 0) {
		wt_fail(w, HW_QPACK_DECOMPRESSION_FAILED, "header block");
		return -1;
	}
	return n;
}

static void server_request(hw_wt *w, wt_stream *s) {
	if (!w->settings_seen) {
		s->deferred = 1; // the answer depends on the peer's SETTINGS (H3_DATAGRAM)
		return;
	}
	s->deferred = 0;
	wt_scratch *sc = malloc(sizeof(*sc));
	if (!sc) {
		wt_fail(w, HW_H3_INTERNAL_ERROR, "out of memory");
		return;
	}
	int n = headers_decode(w, s, sc);
	if (n < 0) goto done;
	hw_h3_request r;
	if (hw_h3_request_parse(sc->fields, (size_t)n, sc->join, sizeof(sc->join), &r) < 0) {
		stream_refuse(w, s, HW_H3_MESSAGE_ERROR);
		goto done;
	}
	if (strcmp(r.method, "CONNECT") != 0) {
		respond_refuse(w, s, 421); // not a server of pages: misdirected
		goto done;
	}
	if (!r.protocol || (strcmp(r.protocol, "webtransport") != 0 && strcmp(r.protocol, "webtransport-h3") != 0)) {
		respond_refuse(w, s, 405);
		goto done;
	}
	if (w->session != SESSION_NONE) {
		respond_refuse(w, s, 429); // one session per connection
		goto done;
	}
	hw_wt_request req = {r.authority, r.path, r.origin, r.protocols};
	const char *protocol = NULL;
	w->session = SESSION_PENDING;
	int status = w->cb.session_request ? w->cb.session_request(w->cb.ud, &req, &protocol) : 404;
	if (w->dead || w->session != SESSION_PENDING) goto done;
	if (status != 200) {
		w->session = SESSION_DONE;
		respond_refuse(w, s, status >= 200 && status <= 599 ? status : 500);
		goto done;
	}
	w->session = SESSION_OPEN;
	w->session_id = s->id;
	w->conn_s = s;
	w->owes_closed = 1;
	s->kind = SK_CONNECT;
	respond(w, s, 200, protocol, 0);
	// A request that waited for SETTINGS may have seen its stream end meanwhile.
	if (!w->dead && s->rx_done) peer_closed(w, 0, "");
done:
	free(sc);
}

static void client_start(hw_wt *w) {
	if (w->dead || w->session != SESSION_NONE || !w->established || !w->settings_seen) return;
	w->owes_closed = 1;
	// Chrome sends no request to a server without both (stomp-rewrite docs/webtransport.md).
	if (!w->peer.h3_datagram || !w->peer.enable_webtransport) {
		wt_fail(w, HW_H3_NO_ERROR, "server does not offer WebTransport");
		return;
	}
	int64_t id = hw_quic_stream_open(w->q, 1);
	if (id < 0) {
		wt_fail(w, HW_H3_GENERAL_PROTOCOL_ERROR, "no request stream");
		return;
	}
	wt_stream *s = stream_new(w, (uint64_t)id, SK_CONNECT);
	if (!s) return;
	w->conn_s = s;
	w->session = SESSION_PENDING;
	// Chrome's fields in Chrome's order.
	static const char *const names[] = {":scheme",    ":method",
	                                    ":authority", ":path",
	                                    ":protocol",  "sec-webtransport-http3-draft02",
	                                    "origin",     "wt-available-protocols"};
	const char *values[] = {"https", "CONNECT", w->authority, w->path, "webtransport", "1", w->origin, w->protocols};
	uint8_t block[WT_BLOCK_MAX];
	size_t n = hw_qpack_prefix_put(block, sizeof(block));
	for (size_t i = 0; i < HW_ARRAY_LEN(names); i++) {
		if (!values[i]) continue; // origin and protocols are optional
		size_t f = block_put(block + n, sizeof(block) - n, names[i], values[i]);
		if (!f) {
			wt_fail(w, HW_H3_INTERNAL_ERROR, "request too large");
			return;
		}
		n += f;
	}
	uint8_t frame[WT_BLOCK_MAX + 32];
	size_t h = hw_h3_frame_header_put(frame, sizeof(frame), HW_H3_FRAME_HEADERS, n);
	memcpy(frame + h, block, n);
	size_t len = h + n;
	// Then a DATA frame with one empty GREASE capsule.
	uint8_t capsule[16];
	size_t c = hw_h3_frame_header_put(capsule, sizeof(capsule), WT_GREASE_CAPSULE, 0);
	len += hw_h3_frame_header_put(frame + len, sizeof(frame) - len, HW_H3_FRAME_DATA, c);
	memcpy(frame + len, capsule, c);
	len += c;
	out_write(w, &s->out, frame, len, 0);
}

static void client_response(hw_wt *w, wt_stream *s) {
	wt_scratch *sc = malloc(sizeof(*sc));
	if (!sc) {
		wt_fail(w, HW_H3_INTERNAL_ERROR, "out of memory");
		return;
	}
	int n = headers_decode(w, s, sc);
	if (n < 0) goto done;
	int status;
	const char *protocol;
	if (hw_h3_response_parse(sc->fields, (size_t)n, &status, &protocol) < 0) {
		wt_fail(w, HW_H3_MESSAGE_ERROR, "malformed response");
		goto done;
	}
	if (status < 200) goto done; // informational: the final response follows
	s->headers = 1;
	w->status = status;
	if (status != 200) {
		w->session = SESSION_DONE;
		out_write(w, &s->out, NULL, 0, 1);
		if (!w->dead && !s->rx_done) hw_quic_stream_stop(w->q, s->id, HW_H3_NO_ERROR);
		wt_report_closed(w, 0, "");
		goto done;
	}
	w->session = SESSION_OPEN;
	w->session_id = s->id;
	if (!protocol || hw_wt_protocol_first(protocol, w->protocol, sizeof(w->protocol)) < 0) w->protocol[0] = '\0';
	int64_t id = hw_quic_stream_open(w->q, 1);
	if (id < 0) {
		wt_fail(w, HW_H3_GENERAL_PROTOCOL_ERROR, "no stream for Wisp");
		goto done;
	}
	wt_stream *ws = stream_new(w, (uint64_t)id, SK_WISP);
	if (!ws) goto done;
	w->wisp_s = ws;
	uint8_t pre[16];
	size_t p = hw_qw_varint_put(pre, sizeof(pre), HW_H3_WT_BIDI_SIGNAL);
	p += hw_qw_varint_put(pre + p, sizeof(pre) - p, w->session_id);
	out_write(w, &ws->out, pre, p, 0);
	if (w->dead) goto done;
	w->ready = 1;
	if (w->cb.writable) w->cb.writable(w->cb.ud);
done:
	free(sc);
}

// ---- The Wisp stream ------------------------------------------------------------------------------

static int wisp_live(const hw_wt *w) {
	return !w->dead && w->session == SESSION_OPEN && !w->paused;
}

// Hand whole packets to the callback until the input ends, a pause or the session's end. Returns
// the bytes read.
static size_t wisp_feed(hw_wt *w, const uint8_t *p, size_t len) {
	size_t off = 0;
	while (off < len && wisp_live(w)) {
		size_t used;
		const uint8_t *pkt;
		size_t pkt_len;
		int r = hw_h3_lp_next(&w->rx, p + off, len - off, &used, &pkt, &pkt_len);
		off += used;
		if (r < 0) {
			wt_fail(w, r == HW_ERR_TOOBIG ? HW_H3_MESSAGE_ERROR : HW_H3_INTERNAL_ERROR, "Wisp packet too large");
			return off;
		}
		if (r == 0) break;
		if (w->cb.packet) w->cb.packet(w->cb.ud, pkt, pkt_len, 0);
	}
	return off;
}

// After a resume: what was held, then the FIN behind it.
static void wisp_drain(hw_wt *w) {
	if (!w->wisp_s) return;
	while (hw_buf_avail(&w->rx_hold) && wisp_live(w)) {
		w->in_rx = 1;
		size_t used = wisp_feed(w, hw_buf_head(&w->rx_hold), hw_buf_avail(&w->rx_hold));
		w->in_rx = 0;
		if (w->dead || w->session != SESSION_OPEN) return;
		hw_buf_consume(&w->rx_hold, used);
		if (used) hw_quic_stream_consumed(w->q, w->wisp_s->id, used);
		if (!used) break;
	}
	if (hw_buf_avail(&w->rx_hold) == 0) hw_buf_shrink(&w->rx_hold, 0);
}

// The Wisp stream's end (FIN, reset, STOP_SENDING) is not the session's: only the CONNECT stream
// ends a session (draft-02), and Chrome resets its streams as it closes, so a reset may overtake
// the close capsule that carries the code and reason.
static void wisp_input(hw_wt *w, wt_stream *s, const uint8_t *d, size_t n) {
	if (w->session != SESSION_OPEN) {
		if (n) hw_quic_stream_consumed(w->q, s->id, n);
		return;
	}
	if (w->paused || hw_buf_avail(&w->rx_hold)) {
		if (n && hw_buf_append(&w->rx_hold, d, n) < 0) {
			wt_fail(w, HW_H3_INTERNAL_ERROR, "out of memory");
			return;
		}
		if (!w->paused) wisp_drain(w); // behind what is held, in order
		return;
	}
	w->in_rx = 1;
	size_t used = wisp_feed(w, d, n);
	w->in_rx = 0;
	if (w->dead) return;
	if (used) hw_quic_stream_consumed(w->q, s->id, used);
	if (w->session != SESSION_OPEN) return;
	if (used < n && hw_buf_append(&w->rx_hold, d + used, n - used) < 0) {
		wt_fail(w, HW_H3_INTERNAL_ERROR, "out of memory");
	}
}

// ---- Frames ---------------------------------------------------------------------------------------

static void capsules_input(hw_wt *w, wt_stream *s, const uint8_t *d, size_t n) {
	while (!w->dead) {
		hw_h3_tlv_ev ev;
		size_t used = hw_h3_tlv_step(&s->cap, d, n, &ev);
		d += used;
		n -= used;
		if (ev.kind == HW_H3_TLV_NEED) return;
		if (ev.kind == HW_H3_TLV_START) {
			if (ev.len > WT_CAPSULE_MAX) {
				wt_fail(w, HW_H3_EXCESSIVE_LOAD, "capsule too large");
				return;
			}
			s->cap_keep = ev.type == HW_H3_CAPSULE_CLOSE_SESSION;
			if (s->cap_keep && (ev.len < 4 || ev.len > 4 + HW_H3_CLOSE_REASON_MAX)) {
				wt_fail(w, HW_H3_MESSAGE_ERROR, "malformed close capsule");
				return;
			}
			continue;
		}
		if (!s->cap_keep) continue; // GREASE, DRAIN and unknown capsules are skipped
		if (ev.n && hw_buf_append(&s->capbody, ev.data, ev.n) < 0) {
			wt_fail(w, HW_H3_INTERNAL_ERROR, "out of memory");
			return;
		}
		if (!ev.end) continue;
		uint32_t code;
		char reason[HW_H3_CLOSE_REASON_MAX + 1];
		const uint8_t *v = hw_buf_head(&s->capbody) ? hw_buf_head(&s->capbody) : EMPTY;
		int bad = hw_h3_close_capsule_parse(v, hw_buf_avail(&s->capbody), &code, reason, sizeof(reason));
		hw_buf_free(&s->capbody);
		s->cap_keep = 0;
		if (bad) {
			wt_fail(w, HW_H3_MESSAGE_ERROR, "malformed close capsule");
			return;
		}
		peer_closed(w, code, reason);
	}
}

static void settings_done(hw_wt *w) {
	if (w->is_client) {
		client_start(w);
		return;
	}
	for (size_t i = 0; i < w->n_streams && !w->dead; i++) {
		if (w->streams[i]->deferred) server_request(w, w->streams[i]);
	}
}

// A frame header on a control, request or CONNECT stream. Returns -1 when the connection closed.
static int frame_start(hw_wt *w, wt_stream *s, const hw_h3_tlv_ev *ev) {
	uint64_t t = ev->type;
	s->keep = KEEP_SKIP;
	int first = !s->framed;
	s->framed = 1;
	int forbidden = hw_h3_frame_reserved(t) || t == HW_H3_FRAME_PUSH_PROMISE;
	int control_only = t == HW_H3_FRAME_SETTINGS || t == HW_H3_FRAME_GOAWAY || t == HW_H3_FRAME_MAX_PUSH_ID ||
	                   t == HW_H3_FRAME_CANCEL_PUSH;
	if (s->kind == SK_CONTROL) {
		if (first && t != HW_H3_FRAME_SETTINGS) {
			wt_fail(w, HW_H3_MISSING_SETTINGS, "first frame is not SETTINGS");
			return -1;
		}
		if ((!first && t == HW_H3_FRAME_SETTINGS) || forbidden || t == HW_H3_FRAME_DATA || t == HW_H3_FRAME_HEADERS) {
			wt_fail(w, HW_H3_FRAME_UNEXPECTED, "frame on the control stream");
			return -1;
		}
		if (t == HW_H3_FRAME_SETTINGS) {
			if (ev->len > WT_SETTINGS_MAX) {
				wt_fail(w, HW_H3_EXCESSIVE_LOAD, "SETTINGS too large");
				return -1;
			}
			s->keep = KEEP_BODY;
		}
		return 0; // GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, GREASE and unknown frames are skipped
	}
	if (forbidden || control_only) {
		wt_fail(w, HW_H3_FRAME_UNEXPECTED, "frame on a request stream");
		return -1;
	}
	// The request (server) or the response (client) comes first; unknown frames may precede it.
	int awaiting = s->kind == SK_REQUEST ? !s->headers && !s->deferred : !s->headers && w->is_client;
	if (t == HW_H3_FRAME_DATA && awaiting) {
		wt_fail(w, HW_H3_FRAME_UNEXPECTED, "DATA before HEADERS");
		return -1;
	}
	if (t == HW_H3_FRAME_HEADERS && awaiting) {
		if (ev->len > HW_H3_FIELD_SECTION_MAX || w->hdr_bytes + ev->len > WT_HEADERS_TOTAL_MAX) {
			wt_fail(w, HW_H3_EXCESSIVE_LOAD, "header block too large");
			return -1;
		}
		w->hdr_bytes += ev->len;
		s->body_charged += ev->len;
		s->keep = KEEP_BODY;
		return 0;
	}
	// DATA on the session's CONNECT stream carries capsules; anything else (trailers, a request
	// body, unknown frames) is skipped.
	if (t == HW_H3_FRAME_DATA && s->kind == SK_CONNECT && s == w->conn_s) s->keep = KEEP_CAPSULES;
	return 0;
}

static void frame_done(hw_wt *w, wt_stream *s, uint64_t type) {
	if (s->kind == SK_CONTROL) {
		hw_h3_settings set;
		uint64_t err = hw_h3_settings_parse(hw_buf_head(&s->body) ? hw_buf_head(&s->body) : EMPTY,
		                                    hw_buf_avail(&s->body), &set);
		hw_buf_free(&s->body);
		if (err) {
			wt_fail(w, err, "SETTINGS");
			return;
		}
		w->peer = set;
		w->settings_seen = 1;
		settings_done(w);
		return;
	}
	if (type != HW_H3_FRAME_HEADERS) return;
	if (s->kind == SK_REQUEST) {
		s->headers = 1;
		server_request(w, s);
	} else if (s->kind == SK_CONNECT) {
		client_response(w, s);
	}
}

static int stream_reads_frames(const wt_stream *s) {
	return s->kind == SK_CONTROL || s->kind == SK_REQUEST || s->kind == SK_CONNECT;
}

static void frames_input(hw_wt *w, wt_stream *s, const uint8_t *d, size_t n) {
	while (!w->dead && stream_reads_frames(s)) {
		hw_h3_tlv_ev ev;
		size_t used = hw_h3_tlv_step(&s->rd, d, n, &ev);
		d += used;
		n -= used;
		if (ev.kind == HW_H3_TLV_NEED) return;
		if (ev.kind == HW_H3_TLV_START) {
			if (frame_start(w, s, &ev) < 0) return;
			continue;
		}
		if (s->keep == KEEP_CAPSULES) {
			capsules_input(w, s, ev.n ? ev.data : EMPTY, ev.n);
			continue;
		}
		if (s->keep != KEEP_BODY) continue;
		if (ev.n && hw_buf_append(&s->body, ev.data, ev.n) < 0) {
			wt_fail(w, HW_H3_INTERNAL_ERROR, "out of memory");
			return;
		}
		if (ev.end) {
			s->keep = KEEP_SKIP;
			frame_done(w, s, ev.type);
		}
	}
}

// The peer's FIN on a stream that reads frames.
static void frames_fin(hw_wt *w, wt_stream *s) {
	if (s->kind == SK_CONTROL) {
		wt_fail(w, HW_H3_CLOSED_CRITICAL_STREAM, "control stream closed");
		return;
	}
	if (hw_h3_tlv_mid(&s->rd)) {
		wt_fail(w, HW_H3_FRAME_ERROR, "stream ends inside a frame");
		return;
	}
	if (s->kind == SK_CONNECT && s == w->conn_s) {
		if (hw_h3_tlv_mid(&s->cap)) {
			wt_fail(w, HW_H3_MESSAGE_ERROR, "stream ends inside a capsule");
			return;
		}
		peer_closed(w, 0, "");
		return;
	}
	// A request that ended without its HEADERS is malformed.
	if (s->kind == SK_REQUEST && !s->headers && !s->deferred) stream_refuse(w, s, HW_H3_MESSAGE_ERROR);
}

// ---- Stream data dispatch -------------------------------------------------------------------------

// The stream's prefix is complete: decide what it is. Returns -1 when the connection closed.
static int stream_classify(hw_wt *w, wt_stream *s, const hw_h3_stream_kind *k) {
	switch (k->kind) {
	case HW_H3_SK_REQUEST:
		if (w->is_client) {
			wt_fail(w, HW_H3_STREAM_CREATION_ERROR, "server opened a request stream");
			return -1;
		}
		s->kind = SK_REQUEST;
		return 0;
	case HW_H3_SK_WT_BIDI:
		if (!w->is_client && w->session == SESSION_OPEN && k->session == w->session_id && !w->wisp_s) {
			s->kind = SK_WISP;
			w->wisp_s = s;
			w->ready = 1;
			if (w->cb.writable) w->cb.writable(w->cb.ud);
			return w->dead ? -1 : 0;
		}
		stream_refuse(w, s, HW_WT_BUFFERED_STREAM_REJECTED);
		return 0;
	case HW_H3_SK_CONTROL:
	case HW_H3_SK_QPACK_ENC:
	case HW_H3_SK_QPACK_DEC: {
		int *seen = k->kind == HW_H3_SK_CONTROL     ? &w->peer_ctrl
		            : k->kind == HW_H3_SK_QPACK_ENC ? &w->peer_enc
		                                            : &w->peer_dec;
		if (*seen) {
			wt_fail(w, HW_H3_STREAM_CREATION_ERROR, "second critical stream");
			return -1;
		}
		*seen = 1;
		s->kind = k->kind == HW_H3_SK_CONTROL ? SK_CONTROL : SK_QPACK;
		return 0;
	}
	case HW_H3_SK_PUSH:
		// A client may not push; a server may not without a MAX_PUSH_ID, which we never send.
		wt_fail(w, w->is_client ? HW_H3_ID_ERROR : HW_H3_STREAM_CREATION_ERROR, "push stream");
		return -1;
	case HW_H3_SK_WT_UNI:
		stream_refuse(w, s, HW_WT_BUFFERED_STREAM_REJECTED);
		return 0;
	default:
		stream_refuse(w, s, HW_H3_STREAM_CREATION_ERROR); // GREASE and unknown types
		return 0;
	}
}

// Bytes after a stream's prefix, by its kind.
static void stream_input(hw_wt *w, wt_stream *s, const uint8_t *d, size_t n, int fin) {
	if (!d) d = EMPTY;
	switch (s->kind) {
	case SK_CONTROL:
	case SK_REQUEST:
	case SK_CONNECT:
		frames_input(w, s, d, n);
		if (!w->dead && n) hw_quic_stream_consumed(w->q, s->id, n);
		if (fin) s->rx_done = 1;
		// The kind may have changed under the frames (a request accepted, or refused).
		if (!w->dead && fin && stream_reads_frames(s)) frames_fin(w, s);
		return;
	case SK_QPACK:
		// No dynamic table: the peer's encoder and decoder instructions are skipped.
		if (n) hw_quic_stream_consumed(w->q, s->id, n);
		if (fin) {
			s->rx_done = 1;
			wt_fail(w, HW_H3_CLOSED_CRITICAL_STREAM, "QPACK stream closed");
		}
		return;
	case SK_WISP:
		if (fin) s->rx_done = 1;
		wisp_input(w, s, d, n);
		return;
	default:
		if (n) hw_quic_stream_consumed(w->q, s->id, n);
		if (fin) s->rx_done = 1;
		return;
	}
}

// ---- The QUIC events --------------------------------------------------------------------------

hw_wt *hw_wt_new(hw_quic_conn *q, const hw_wt_config *cfg, const hw_wt_callbacks *cb) {
	hw_wt *w = calloc(1, sizeof(*w));
	if (!w) return NULL;
	w->q = q;
	w->cb = *cb;
	w->max_packet = cfg->max_packet ? cfg->max_packet : 65536;
	w->send_max = cfg->send_max;
	w->is_client = cfg->is_client;
	if (w->is_client) {
		w->authority = dup_str(cfg->authority ? cfg->authority : "localhost");
		w->path = dup_str(cfg->path ? cfg->path : "/");
		w->origin = dup_str(cfg->origin);
		w->protocols = dup_str(cfg->protocols);
		if (!w->authority || !w->path || (cfg->origin && !w->origin) || (cfg->protocols && !w->protocols)) {
			hw_wt_free(w);
			return NULL;
		}
	}
	out_init(&w->ctrl, -1);
	out_init(&w->enc, -1);
	out_init(&w->dec, -1);
	hw_h3_lp_init(&w->rx, w->max_packet);
	hw_buf_init(&w->rx_hold);
	return w;
}

void hw_wt_free(hw_wt *w) {
	if (!w) return;
	for (size_t i = 0; i < w->n_streams; i++) stream_free(w, w->streams[i]);
	hw_buf_free(&w->ctrl.tx);
	hw_buf_free(&w->enc.tx);
	hw_buf_free(&w->dec.tx);
	hw_buf_free(&w->rx_hold);
	hw_h3_lp_clear(&w->rx);
	free(w->authority);
	free(w->path);
	free(w->origin);
	free(w->protocols);
	free(w);
}

static int uni_open(hw_wt *w, wt_out *o, uint8_t type, const uint8_t *rest, size_t rest_len) {
	int64_t id = hw_quic_stream_open(w->q, 0);
	if (id < 0) {
		wt_fail(w, HW_H3_GENERAL_PROTOCOL_ERROR, "peer allows too few unidirectional streams");
		return -1;
	}
	out_init(o, id);
	uint8_t buf[256];
	buf[0] = type; // the three types are one-byte varints
	if (rest_len) memcpy(buf + 1, rest, rest_len);
	out_write(w, o, buf, 1 + rest_len, 0);
	return w->dead ? -1 : 0;
}

void hw_wt_on_established(hw_wt *w) {
	if (w->dead || w->established) return;
	w->established = 1;
	uint8_t settings[128];
	size_t n = hw_h3_settings_frame(settings, sizeof(settings), w->is_client);
	if (uni_open(w, &w->ctrl, HW_H3_STREAM_CONTROL, settings, n) < 0) return;
	// Chrome opens the decoder stream before the encoder stream; servers usually the other way.
	if (w->is_client) {
		if (uni_open(w, &w->dec, HW_H3_STREAM_QPACK_DEC, NULL, 0) < 0) return;
		if (uni_open(w, &w->enc, HW_H3_STREAM_QPACK_ENC, NULL, 0) < 0) return;
		client_start(w);
	} else {
		if (uni_open(w, &w->enc, HW_H3_STREAM_QPACK_ENC, NULL, 0) < 0) return;
		if (uni_open(w, &w->dec, HW_H3_STREAM_QPACK_DEC, NULL, 0) < 0) return;
	}
}

void hw_wt_on_stream_data(hw_wt *w, uint64_t id, const uint8_t *data, size_t len, int fin) {
	if (w->dead) return;
	if (!data) data = EMPTY;
	wt_stream *s = stream_find(w, id);
	if (!s) {
		if (!stream_is_peer(w, id)) return; // ours, unidirectional: the peer cannot send on it
		s = stream_new(w, id, SK_PENDING);
		if (!s) return;
	}
	if (s->rx_done) return;
	if (s->kind == SK_PENDING) {
		size_t take = HW_MIN(len, sizeof(s->pre) - s->pre_len);
		memcpy(s->pre + s->pre_len, data, take);
		s->pre_len += take;
		hw_h3_stream_kind k;
		if (!hw_h3_stream_kind_parse(s->pre, s->pre_len, stream_is_bidi(id), &k)) {
			// take == len here: 16 bytes always hold a prefix.
			if (fin) {
				s->rx_done = 1;
				hw_quic_stream_consumed(w->q, id, s->pre_len);
				// A request stream that ends before its first frame has no HEADERS: malformed. A
				// unidirectional one that ends inside its type is nothing.
				if (stream_is_bidi(id)) stream_refuse(w, s, HW_H3_MESSAGE_ERROR);
			}
			goto sweep;
		}
		hw_quic_stream_consumed(w->q, id, k.prefix);
		if (stream_classify(w, s, &k) < 0) return;
		int last = take == len;
		stream_input(w, s, s->pre + k.prefix, s->pre_len - k.prefix, fin && last);
		if (w->dead) return;
		if (!last) stream_input(w, s, data + take, len - take, fin);
	} else {
		stream_input(w, s, data, len, fin);
	}
	if (w->dead) return;
sweep:
	streams_sweep(w);
}

void hw_wt_on_stream_reset(hw_wt *w, uint64_t id, uint64_t app_error) {
	(void)app_error;
	if (w->dead) return;
	wt_stream *s = stream_find(w, id);
	if (!s || s->rx_done) return;
	s->rx_done = 1;
	switch (s->kind) {
	case SK_CONTROL:
	case SK_QPACK:
		wt_fail(w, HW_H3_CLOSED_CRITICAL_STREAM, "critical stream reset");
		return;
	case SK_CONNECT:
		if (s == w->conn_s) peer_closed(w, 0, "");
		break;
	case SK_WISP:
		break; // the session goes on until its CONNECT stream ends
	default:
		stream_body_release(w, s);
		s->deferred = 0;
		break;
	}
	if (!w->dead) streams_sweep(w);
}

void hw_wt_on_stream_stop(hw_wt *w, uint64_t id, uint64_t app_error) {
	(void)app_error;
	if (w->dead) return;
	if ((int64_t)id == w->ctrl.id || (int64_t)id == w->enc.id || (int64_t)id == w->dec.id) {
		wt_fail(w, HW_H3_CLOSED_CRITICAL_STREAM, "critical stream stopped");
		return;
	}
	wt_stream *s = stream_find(w, id);
	if (!s) return;
	s->out.dead = 1; // QUIC has reset our side already
	hw_buf_free(&s->out.tx);
	if (s == w->conn_s) peer_closed(w, 0, ""); // the Wisp stream's: hw_wt_send now returns -1
	if (!w->dead) streams_sweep(w);
}

void hw_wt_on_stream_writable(hw_wt *w, uint64_t id) {
	if (w->dead) return;
	wt_out *mine[] = {&w->ctrl, &w->enc, &w->dec};
	for (size_t i = 0; i < HW_ARRAY_LEN(mine); i++) {
		if (mine[i]->id == (int64_t)id) {
			out_flush(w, mine[i]);
			return;
		}
	}
	wt_stream *s = stream_find(w, id);
	if (!s) return;
	out_flush(w, &s->out);
	if (w->dead) return;
	if (s == w->wisp_s && w->send_refused && (!w->send_max || hw_buf_avail(&s->out.tx) < w->send_max)) {
		w->send_refused = 0;
		if (w->cb.writable) w->cb.writable(w->cb.ud);
		if (w->dead) return;
	}
	streams_sweep(w);
}

void hw_wt_on_datagram(hw_wt *w, const uint8_t *data, size_t len) {
	if (w->dead) return;
	uint64_t qsid;
	size_t p = hw_qw_varint_get(data, len, &qsid);
	// A quarter stream id past the largest stream id / 4 is an error (RFC 9297 section 2.1).
	if (!p || qsid > HW_QW_VARINT_MAX / 4) {
		wt_fail(w, HW_H3_DATAGRAM_ERROR, "datagram without a quarter stream id");
		return;
	}
	// Only the session's, only once the Wisp stream is there, only while reading. Any other is
	// dropped unread, at the cost of a varint (RFC 9297 lets a receiver drop what it cannot
	// place), however many a peer sends.
	if (!w->ready || w->session != SESSION_OPEN || qsid != w->session_id / 4 || w->paused) return;
	if (len - p > w->max_packet) return;
	if (w->cb.packet) w->cb.packet(w->cb.ud, data + p, len - p, 1);
}

void hw_wt_on_closed(hw_wt *w) {
	if (w->dead) {
		wt_report_closed(w, 0, "");
		return;
	}
	w->dead = 1;
	w->ready = 0;
	w->session = SESSION_DONE;
	wt_report_closed(w, 0, "");
}

// ---- The caller's side ----------------------------------------------------------------------------

int hw_wt_ready(const hw_wt *w) {
	return !w->dead && w->ready && w->session == SESSION_OPEN;
}

size_t hw_wt_datagram_max(const hw_wt *w) {
	if (!hw_wt_ready(w) || !w->peer.h3_datagram) return 0;
	size_t m = hw_quic_datagram_max(w->q);
	size_t pre = hw_qw_varint_len(w->session_id / 4);
	if (m <= pre) return 0;
	m -= pre;
	if (m > HW_QUIC_MAX_DGRAM) m = HW_QUIC_MAX_DGRAM;
	return HW_MIN(m, w->max_packet);
}

int hw_wt_send(hw_wt *w, const uint8_t *pkt, size_t len, int unreliable) {
	if (!hw_wt_ready(w) || len > UINT32_MAX) return -1;
	if (unreliable && len <= hw_wt_datagram_max(w)) {
		uint8_t dgram[HW_QUIC_MAX_DGRAM + 8];
		size_t p = hw_qw_varint_put(dgram, sizeof(dgram), w->session_id / 4);
		if (len) memcpy(dgram + p, pkt, len);
		(void)hw_quic_datagram_send(w->q, dgram, p + len); // a drop is a lost datagram
		return 0;
	}
	wt_out *o = &w->wisp_s->out;
	if (o->dead || o->fin || o->fin_sent) return -1;
	if (w->send_max && hw_buf_avail(&o->tx) >= w->send_max) {
		w->send_refused = 1;
		return 1;
	}
	uint8_t hdr[4];
	hw_put_le32(hdr, (uint32_t)len);
	out_write(w, o, hdr, sizeof(hdr), 0);
	if (len) out_write(w, o, pkt, len, 0);
	return w->dead ? -1 : 0;
}

size_t hw_wt_queued(const hw_wt *w) {
	size_t mine = w->wisp_s ? hw_buf_avail(&w->wisp_s->out.tx) : 0;
	return mine + (w->dead ? 0 : hw_quic_queued(w->q));
}

void hw_wt_pause(hw_wt *w, int paused) {
	if (paused) {
		w->paused = 1;
		return;
	}
	if (!w->paused) return;
	w->paused = 0;
	if (!w->in_rx && !w->dead) {
		wisp_drain(w);
		if (!w->dead) streams_sweep(w);
	}
}

void hw_wt_close(hw_wt *w, uint32_t code, const char *reason) {
	if (w->dead) return;
	w->owes_closed = 0; // the caller knows
	if (w->session != SESSION_OPEN) {
		wt_fail(w, HW_H3_NO_ERROR, reason ? reason : "");
		return;
	}
	w->session = SESSION_CLOSING;
	w->ready = 0;
	uint8_t frame[HW_H3_CLOSE_REASON_MAX + 32];
	size_t n = hw_h3_close_capsule_frame(frame, sizeof(frame), code, reason);
	out_write(w, &w->conn_s->out, frame, n, 1);
	// Only a FIN on the Wisp stream, never STOP_SENDING or RESET_STREAM: QUIC may put those ahead
	// of the capsule, and Chrome, seeing its streams cut before the capsule, reports "Connection
	// lost" and never answers it. It resets its own streams once the capsule is in, and whatever
	// still arrives on the Wisp stream meanwhile is credited and dropped (wisp_input).
	if (w->wisp_s && !w->dead) out_write(w, &w->wisp_s->out, NULL, 0, 1);
	hw_buf_free(&w->rx_hold);
	// The peer may already have closed its side; then nothing more will come to wait for.
	if (!w->dead && w->conn_s->rx_done) wt_fail(w, HW_H3_NO_ERROR, "");
}

int hw_wt_status(const hw_wt *w) {
	return w->status;
}

const char *hw_wt_protocol(const hw_wt *w) {
	return w->protocol;
}

static int sf_tchar(char c) {
	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) return 1;
	return c && strchr("!#$%&'*+-.^_`|~:/", c) != NULL;
}

int hw_wt_protocol_first(const char *list, char *out, size_t cap) {
	if (!list || cap == 0) return -1;
	const char *p = list;
	while (*p == ' ' || *p == '\t') p++;
	size_t o = 0;
	if (*p == '"') {
		for (p++;; p++) {
			char c = *p;
			if (c == '\0') return -1;
			if (c == '"') break;
			if (c == '\\') {
				c = *++p;
				if (c != '"' && c != '\\') return -1;
			} else if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7e) {
				return -1;
			}
			if (o + 1 >= cap) return -1;
			out[o++] = c;
		}
	} else if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || *p == '*') {
		for (; sf_tchar(*p); p++) {
			if (o + 1 >= cap) return -1;
			out[o++] = *p;
		}
	} else {
		return -1;
	}
	out[o] = '\0';
	return 0;
}

// The host of an :authority: what is before the port, without an IPv6 literal's brackets and a
// trailing dot. 0, or -1 when it does not fit cap or is empty.
static int authority_host(const char *authority, char *out, size_t cap) {
	const char *p = authority, *end;
	if (*p == '[') {
		p++;
		end = strchr(p, ']');
		if (!end) return -1;
	} else {
		end = strchr(p, ':');
		if (!end) end = p + strlen(p);
	}
	size_t n = (size_t)(end - p);
	if (n > 0 && p[n - 1] == '.') n--;
	if (n == 0 || n >= cap) return -1;
	for (size_t i = 0; i < n; i++) out[i] = (char)tolower((unsigned char)p[i]);
	out[n] = '\0';
	return 0;
}

int hw_wt_route_match(const char *rule_host, const char *rule_path, const char *authority, const char *path) {
	if (!rule_path || !path || rule_path[0] != '/' || path[0] != '/') return 0;
	if (rule_host && rule_host[0] && strcmp(rule_host, "*") != 0) {
		char want[256], got[256];
		// The rule names a host alone (no port), an IPv6 literal with or without its brackets.
		size_t rn = strlen(rule_host);
		const char *rh = rule_host;
		if (rn >= 2 && rh[0] == '[' && rh[rn - 1] == ']') {
			rh++;
			rn -= 2;
		}
		if (rn > 0 && rh[rn - 1] == '.') rn--;
		if (rn == 0 || rn >= sizeof(want)) return 0;
		for (size_t i = 0; i < rn; i++) want[i] = (char)tolower((unsigned char)rh[i]);
		want[rn] = '\0';
		if (!authority || authority_host(authority, got, sizeof(got)) != 0 || strcmp(want, got) != 0) {
			return 0;
		}
	}
	size_t plen = strcspn(path, "?#");
	size_t rlen = strlen(rule_path);
	if (plen == rlen) return memcmp(path, rule_path, rlen) == 0;
	// Under the rule's path, never beside it: /pipe/key covers /pipe/key/x, not /pipe/keyx. A rule
	// that ends in a slash (/ itself) is that path alone.
	return plen > rlen && rule_path[rlen - 1] != '/' && memcmp(path, rule_path, rlen) == 0 && path[rlen] == '/';
}
