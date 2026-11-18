/*
 * src/quic/h3.h - the stateless half of holywisp/webtransport.h: HTTP/3 frames (RFC 9114
 * section 7), SETTINGS, the stream-type prefixes of HTTP/3 and of WebTransport draft-02, request
 * and response field validation (RFC 9114 section 4.3, RFC 9220), capsules (RFC 9297), QPACK
 * with the static table and literals only (RFC 9204, Huffman per RFC 7541 appendix B), and the
 * u32 LE length-delimited framing of Wisp packets on the Wisp stream. Varints are quic_wire.h's
 * (hw_qw_varint_*).
 *
 * Internal to src/quic: webtransport.c is built on it and tests/test_webtransport.c tests it.
 * Pure functions on caller-owned memory, every length checked against the buffer it reads; the
 * only allocation is hw_h3_lp's reassembly buffer, which grows with the bytes of a packet that
 * have arrived and never exceeds max_packet bytes.
 */
#ifndef HOLYWISP_H3_H
#define HOLYWISP_H3_H

#include <stddef.h>
#include <stdint.h>

// ---- Frames, stream types, settings, capsules -----------------------------------------------
#define HW_H3_FRAME_DATA         0x00
#define HW_H3_FRAME_HEADERS      0x01
#define HW_H3_FRAME_CANCEL_PUSH  0x03
#define HW_H3_FRAME_SETTINGS     0x04
#define HW_H3_FRAME_PUSH_PROMISE 0x05
#define HW_H3_FRAME_GOAWAY       0x07
#define HW_H3_FRAME_MAX_PUSH_ID  0x0d
// Draft-02: the first varint of a bidirectional WebTransport stream, where a frame type would be.
#define HW_H3_WT_BIDI_SIGNAL 0x41

#define HW_H3_STREAM_CONTROL   0x00
#define HW_H3_STREAM_PUSH      0x01
#define HW_H3_STREAM_QPACK_ENC 0x02
#define HW_H3_STREAM_QPACK_DEC 0x03
#define HW_H3_STREAM_WT_UNI    0x54

#define HW_H3_SETTING_QPACK_MAX_TABLE_CAPACITY 0x01
#define HW_H3_SETTING_MAX_FIELD_SECTION_SIZE   0x06
#define HW_H3_SETTING_QPACK_BLOCKED_STREAMS    0x07
#define HW_H3_SETTING_ENABLE_CONNECT_PROTOCOL  0x08
#define HW_H3_SETTING_H3_DATAGRAM              0x33
#define HW_H3_SETTING_H3_DATAGRAM_DRAFT04      0xffd277
#define HW_H3_SETTING_ENABLE_WEBTRANSPORT      0x2b603742
#define HW_H3_SETTING_WT_MAX_SESSIONS          0xc671706a

#define HW_H3_CAPSULE_CLOSE_SESSION 0x2843
#define HW_H3_CAPSULE_DRAIN_SESSION 0x78ae
#define HW_H3_CLOSE_REASON_MAX      1024 // draft-02: a close reason is at most this many bytes

// What we advertise as MAX_FIELD_SECTION_SIZE, and the bound on a header block we buffer.
#define HW_H3_FIELD_SECTION_MAX 16384

// A reserved ("GREASE") identifier: 0x1f * n + 0x21 for frame types, settings and stream types;
// capsule types are 0x29 * n + 0x17.
static inline int hw_h3_is_grease(uint64_t v) {
	return v >= 0x21 && (v - 0x21) % 0x1f == 0;
}

// The frame types HTTP/2 had and HTTP/3 reserves (0x02, 0x06, 0x08, 0x09): receiving one is
// H3_FRAME_UNEXPECTED (RFC 9114 section 7.2.8).
static inline int hw_h3_frame_reserved(uint64_t type) {
	return type == 0x02 || type == 0x06 || type == 0x08 || type == 0x09;
}

// A frame or capsule header (type, length), and an incremental reader for a stream of them:
// frames and capsules share the layout Type(i) Length(i) Value. hw_h3_tlv_step consumes input
// and reports one event at a time:
// - HW_H3_TLV_START: a header completed (ev->type, ev->len).
// - HW_H3_TLV_BODY: the next piece of the body (ev->data, ev->n), ev->end on its last piece. A
//   body of length 0 still gives one BODY with n = 0 and end = 1.
// - HW_H3_TLV_NEED: the input is used up with no event.
// It returns the bytes consumed. The reader holds at most a partial header (16 bytes); bodies are
// handed out in place.
enum {
	HW_H3_TLV_NEED,
	HW_H3_TLV_START,
	HW_H3_TLV_BODY
};

typedef struct {
	uint8_t hdr[16];
	size_t hdr_len;
	int in_body;
	uint64_t type, len, left;
} hw_h3_tlv;

typedef struct {
	int kind;
	uint64_t type, len;
	const uint8_t *data;
	size_t n;
	int end;
} hw_h3_tlv_ev;

void hw_h3_tlv_init(hw_h3_tlv *r);
size_t hw_h3_tlv_step(hw_h3_tlv *r, const uint8_t *p, size_t len, hw_h3_tlv_ev *ev);
// 1 while the reader is inside a header or a body: a FIN there truncates a frame.
int hw_h3_tlv_mid(const hw_h3_tlv *r);

// Writes a frame header (type, len) at out. Returns its length, 0 when cap is too small.
size_t hw_h3_frame_header_put(uint8_t *out, size_t cap, uint64_t type, uint64_t len);

typedef struct {
	uint64_t qpack_max_table_capacity;
	uint64_t max_field_section_size; // UINT64_MAX when absent
	uint64_t qpack_blocked_streams;
	uint64_t enable_connect_protocol;
	uint64_t h3_datagram; // 1 when either H3_DATAGRAM (0x33) or the draft-04 0xffd277 is 1
	uint64_t enable_webtransport;
	uint64_t wt_max_sessions;
} hw_h3_settings;

// Parses a SETTINGS frame's payload. Unknown and GREASE settings are skipped. Returns 0, or the
// HTTP/3 error to close with: H3_SETTINGS_ERROR for an HTTP/2 setting (0x02 to 0x05), a known
// setting given twice or a boolean setting above 1; H3_FRAME_ERROR for a truncated payload.
uint64_t hw_h3_settings_parse(const uint8_t *p, size_t len, hw_h3_settings *s);

// Our whole SETTINGS frame. Server: QPACK_MAX_TABLE_CAPACITY 0, MAX_FIELD_SECTION_SIZE,
// QPACK_BLOCKED_STREAMS 0, ENABLE_CONNECT_PROTOCOL 1, H3_DATAGRAM 1, the draft-04 H3_DATAGRAM
// 1, ENABLE_WEBTRANSPORT 1, WEBTRANSPORT_MAX_SESSIONS 1. Client, in Chrome's order:
// QPACK_MAX_TABLE_CAPACITY 0 (Chrome says 65536; this decoder has no dynamic table),
// MAX_FIELD_SECTION_SIZE, QPACK_BLOCKED_STREAMS 0, H3_DATAGRAM 1, the draft-04 one 1,
// ENABLE_WEBTRANSPORT 1 and a GREASE setting, followed by an empty GREASE frame as Chrome sends.
// Returns the bytes written, 0 when cap is too small.
size_t hw_h3_settings_frame(uint8_t *out, size_t cap, int is_client);

// What a peer's stream is, from its first bytes. A unidirectional stream starts with its type
// (and a WebTransport one with the session id after it); a bidirectional one is a request
// stream (its bytes are frames, nothing is consumed) unless it starts with
// HW_H3_WT_BIDI_SIGNAL and a session id.
enum {
	HW_H3_SK_REQUEST,
	HW_H3_SK_WT_BIDI,
	HW_H3_SK_CONTROL,
	HW_H3_SK_PUSH,
	HW_H3_SK_QPACK_ENC,
	HW_H3_SK_QPACK_DEC,
	HW_H3_SK_WT_UNI,
	HW_H3_SK_UNKNOWN, // a GREASE or unknown unidirectional type: ignored with STOP_SENDING
};

typedef struct {
	int kind;         // HW_H3_SK_*
	uint64_t type;    // the stream type read (unidirectional), or the first varint (bidirectional)
	uint64_t session; // WebTransport streams: the session id
	size_t prefix;    // bytes the prefix took
} hw_h3_stream_kind;

// Returns 1 when the prefix is complete (k filled), 0 when more bytes are needed. A prefix never
// takes more than 16 bytes.
int hw_h3_stream_kind_parse(const uint8_t *p, size_t len, int bidi, hw_h3_stream_kind *k);

// A DATA frame holding one CLOSE_WEBTRANSPORT_SESSION capsule (code as a u32 big-endian, then
// the reason, cut to HW_H3_CLOSE_REASON_MAX bytes). Returns its length, 0 when cap is too small.
size_t hw_h3_close_capsule_frame(uint8_t *out, size_t cap, uint32_t code, const char *reason);
// The value of a CLOSE_WEBTRANSPORT_SESSION capsule. reason receives the reason NUL-terminated
// (cap must be at least HW_H3_CLOSE_REASON_MAX + 1). Returns 0, or -1 when it is shorter than
// the code or its reason is longer than HW_H3_CLOSE_REASON_MAX.
int hw_h3_close_capsule_parse(const uint8_t *v, size_t n, uint32_t *code, char *reason, size_t cap);

// ---- QPACK (static table and literals only) -------------------------------------------------
#define HW_QPACK_STATIC_COUNT 99

typedef struct {
	const char *name, *value; // NUL-terminated (a field holding a NUL in the wire is refused)
	size_t name_len, value_len;
} hw_qpack_field;

// Entry i of the static table (RFC 9204 appendix A), NULL past its end.
const char *hw_qpack_static_name(size_t i);
const char *hw_qpack_static_value(size_t i);

// Decodes a field section (a HEADERS frame's payload) into at most max_fields fields, copying the
// strings NUL-terminated into arena. Returns the number of fields, HW_ERR_INVALID for a
// malformed section, one that refers to the dynamic table or holds a NUL (all
// QPACK_DECOMPRESSION_FAILED), or HW_ERR_TOOBIG when the fields or their bytes do not fit.
int hw_qpack_decode(const uint8_t *p, size_t len, char *arena, size_t arena_cap, hw_qpack_field *fields,
                    size_t max_fields);

// The two-byte field section prefix of a section that uses no dynamic table (Required Insert
// Count 0, Delta Base 0). Returns 2, 0 when cap is too small.
size_t hw_qpack_prefix_put(uint8_t *out, size_t cap);
// One field line, encoded as Chrome's encoder does with no dynamic table: an exact static match
// is an indexed line, a static name match a literal with that name reference, anything else a
// literal with a literal name; a string goes Huffman-coded when that is shorter. Returns the
// bytes written, 0 when cap is too small.
size_t hw_qpack_field_put(uint8_t *out, size_t cap, const char *name, size_t name_len, const char *value,
                          size_t value_len);

// Huffman coding of RFC 7541 appendix B. hw_huffman_len is the encoded length of s;
// hw_huffman_encode writes it (returns its length, 0 when cap is too small). hw_huffman_decode
// returns the decoded length, -1 for an invalid string (EOS, padding over 7 bits or not all
// ones), or -2 when it does not fit cap.
size_t hw_huffman_len(const uint8_t *s, size_t n);
size_t hw_huffman_encode(const uint8_t *s, size_t n, uint8_t *out, size_t cap);
long long hw_huffman_decode(const uint8_t *p, size_t n, uint8_t *out, size_t cap);

// ---- Requests and responses -----------------------------------------------------------------
typedef struct {
	const char *method, *scheme, *authority, *path, *protocol; // NULL when absent
	const char *origin;                                        // the first origin field
	const char *protocols; // wt-available-protocols, its field lines joined with ", "
	const char *draft02;   // sec-webtransport-http3-draft02
} hw_h3_request;

// Validates a request's fields (RFC 9114 section 4.3.1, RFC 9220): each pseudo-header known, at
// most once and before every regular field; names lower case tokens; no connection-specific
// field; a te other than "trailers" refused; values without NUL, CR or LF; :method present; a
// CONNECT with :protocol (extended CONNECT) needs :scheme, :path and :authority; a plain
// CONNECT needs :authority and has neither :scheme nor :path; any other method needs :scheme and
// a non-empty :path, and may not carry :protocol. Repeated wt-available-protocols lines are
// joined into join (join_cap bytes). Returns 0, or -1 for a malformed request (H3_MESSAGE_ERROR).
int hw_h3_request_parse(const hw_qpack_field *f, size_t n, char *join, size_t join_cap, hw_h3_request *r);

// The :status of a response (exactly one, three digits, the only pseudo-header, first), and
// wt-protocol when there is one (else NULL). Returns 0, or -1 for a malformed response.
int hw_h3_response_parse(const hw_qpack_field *f, size_t n, int *status, const char **wt_protocol);

// ---- Wisp packets on the Wisp stream ----------------------------------------------------------
// Each packet is preceded by its length as a u32 LE (epoxy-server's LengthDelimitedLe framing).
typedef struct {
	size_t max_packet;
	uint8_t hdr[4];
	size_t hdr_len;
	int in_packet;
	uint8_t *buf; // the packet being reassembled, when it did not arrive in one piece
	size_t buf_cap, need, have;
} hw_h3_lp;

void hw_h3_lp_init(hw_h3_lp *r, size_t max_packet);
void hw_h3_lp_clear(hw_h3_lp *r);
// 1 while a packet (or its length) is partly read.
int hw_h3_lp_mid(const hw_h3_lp *r);
// Reads from p. Returns 1 with *pkt and *pkt_len a whole packet (pointing into p, or into the
// reader's buffer, valid until the next call), 0 when the input was used up without one, or
// HW_ERR_TOOBIG for a length past max_packet (or HW_ERR_NOMEM). *used is the bytes consumed in
// every case. The buffer grows with the bytes of a packet that have arrived (never past the
// packet's length), and one over 64 KiB is freed before the next packet.
int hw_h3_lp_next(hw_h3_lp *r, const uint8_t *p, size_t len, size_t *used, const uint8_t **pkt, size_t *pkt_len);

#endif
