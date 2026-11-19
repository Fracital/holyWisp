/*
 * holywisp/quic.h - a QUIC version 1 endpoint (RFC 9000, 9001, 9002), with the DATAGRAM
 * extension (RFC 9221), for holyWisp's WebTransport listener (holywisp/webtransport.h) and for
 * its own client and tests.
 *
 * Sans-IO and single-threaded, like boringtun's Tunn: the caller owns the sockets and the clock.
 * It hands every datagram for this connection to hw_quic_input, asks hw_quic_output for the
 * datagrams to send until it returns 0, and calls hw_quic_on_timeout when hw_quic_timeout says.
 * Application events come back through callbacks, synchronously, from inside hw_quic_input and
 * hw_quic_on_timeout. A callback may call any function here on the same connection except
 * hw_quic_free.
 *
 * Scope (docs/webtransport.md, "QUIC"):
 * - Version 1 only; Version Negotiation for anything else. TLS through holywisp/tls13.h.
 * - Loss detection and NewReno congestion control per RFC 9002, with pacing; ACK ranges;
 *   persistent congestion; PTO probes; anti-amplification (3x) before address validation.
 * - Streams (bidirectional and unidirectional, both directions of flow control), DATAGRAM
 *   frames, connection IDs issued with a server-chosen first byte (the listener steers by it),
 *   path validation on a peer address change, stateless reset, idle timeout, key update.
 * - Not: 0-RTT, active migration by the server, ECN, multipath, QUIC v2.
 *
 * Memory is bounded by the config: a stream's send buffer, the connection's receive
 * reassembly, the datagram queue and the CRYPTO buffers each have a cap, and a peer that would
 * exceed one is closed with FLOW_CONTROL_ERROR or CRYPTO_BUFFER_EXCEEDED, never buffered.
 */
#ifndef HOLYWISP_QUIC_H
#define HOLYWISP_QUIC_H

#include "holywisp/tls13.h"

#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>

#define HW_QUIC_VERSION_1 0x00000001u
#define HW_QUIC_CID_LEN   8    // length of every connection ID this endpoint issues
#define HW_QUIC_MIN_DGRAM 1200 // a client's Initial datagram is padded to at least this
#define HW_QUIC_MAX_DGRAM 1452 // the largest datagram this endpoint sends, once a probe shows the path takes it
#define HW_QUIC_RESET_LEN 16   // stateless reset token
#define HW_QUIC_KEY_LEN   32   // the listener's token and reset keys

// Transport error codes (RFC 9000 section 20.1) the endpoint sends.
#define HW_QUIC_NO_ERROR                  0x0
#define HW_QUIC_INTERNAL_ERROR            0x1
#define HW_QUIC_CONNECTION_REFUSED        0x2
#define HW_QUIC_FLOW_CONTROL_ERROR        0x3
#define HW_QUIC_STREAM_LIMIT_ERROR        0x4
#define HW_QUIC_STREAM_STATE_ERROR        0x5
#define HW_QUIC_FINAL_SIZE_ERROR          0x6
#define HW_QUIC_FRAME_ENCODING_ERROR      0x7
#define HW_QUIC_TRANSPORT_PARAMETER_ERROR 0x8
#define HW_QUIC_PROTOCOL_VIOLATION        0xa
#define HW_QUIC_INVALID_TOKEN             0xb
#define HW_QUIC_CRYPTO_BUFFER_EXCEEDED    0xd
#define HW_QUIC_AEAD_LIMIT_REACHED        0xf
#define HW_QUIC_CRYPTO_ERROR(alert)       (0x100 + (alert))

// Congestion control: BBR, which a random loss does not slow, or RFC 9002's NewReno, which halves
// its window at each.
#define HW_QUIC_CC_BBR     0
#define HW_QUIC_CC_NEWRENO 1

typedef struct {
	int is_server;
	hw_tls_config tls; // certificate, key, ALPN; transport_params is filled in by hw_quic
	// Our transport parameters (RFC 9000 section 18.2).
	uint64_t max_idle_ms;              // 0 = none; the effective timeout is the smaller of both sides'
	uint64_t initial_max_data;         // connection receive window
	uint64_t initial_max_stream_data;  // per-stream receive window, every stream type
	uint64_t initial_max_streams_bidi; // streams the peer may open
	uint64_t initial_max_streams_uni;
	uint64_t max_datagram_frame_size; // 0 = DATAGRAM frames not accepted
	// Local limits.
	size_t stream_send_max;    // bytes a stream may hold unacknowledged plus unsent
	size_t conn_send_max;      // the same, across all streams of the connection
	size_t datagram_queue_max; // datagrams queued for sending before the newest is dropped
	uint64_t keepalive_ms;     // 0 = none: send a PING after this long without sending anything
	int congestion;            // HW_QUIC_CC_BBR (the default) or HW_QUIC_CC_NEWRENO
	// Server: the first byte of every connection ID issued (the owning worker's index), the
	// listener's stateless reset key (reset tokens are HMAC-SHA-256(key, cid) truncated), and
	// the original DCID and Retry SCID when the client went through a Retry.
	uint8_t cid_prefix;
	const uint8_t *reset_key; // HW_QUIC_KEY_LEN bytes
} hw_quic_config;

typedef struct {
	void *ud;
	// The handshake completed (server: HANDSHAKE_DONE sent; client: received). ALPN is known.
	void (*established)(void *ud);
	// In-order bytes of a stream the peer sends on, and whether its FIN is now reached. The
	// connection does not grant the peer more credit for them until hw_quic_stream_consumed.
	void (*stream_data)(void *ud, uint64_t id, const uint8_t *data, size_t len, int fin);
	// RESET_STREAM from the peer (its sending side ended abruptly) and STOP_SENDING (it wants
	// ours to stop: the endpoint has already answered with RESET_STREAM).
	void (*stream_reset)(void *ud, uint64_t id, uint64_t app_error);
	void (*stream_stop)(void *ud, uint64_t id, uint64_t app_error);
	// A stream that was blocked by flow control or its send buffer can take more bytes.
	void (*stream_writable)(void *ud, uint64_t id);
	// A DATAGRAM frame's payload.
	void (*datagram)(void *ud, const uint8_t *data, size_t len);
	// A connection ID was issued (retire = 0) or retired (1): the listener maps it to this
	// connection so the datagrams that carry it find it. Called for the initial one too.
	void (*cid)(void *ud, const uint8_t cid[HW_QUIC_CID_LEN], int retire);
	// The connection closed: error and whether it is an application error, and the reason.
	// Called once; afterwards hw_quic_is_drained says when the connection can be freed.
	void (*closed)(void *ud, uint64_t error, int app, const char *reason);
} hw_quic_callbacks;

typedef struct hw_quic_conn hw_quic_conn;

// ---- Stateless processing (the listener, before a connection exists) ---------------------

typedef struct {
	int long_header;
	uint8_t type;     // long header: 0 Initial, 1 0-RTT, 2 Handshake, 3 Retry
	uint32_t version; // long header only
	uint8_t dcid[20];
	uint8_t dcid_len;
	uint8_t scid[20]; // long header only
	uint8_t scid_len;
	const uint8_t *token; // Initial (and Retry) only, pointing into the datagram
	size_t token_len;
	size_t dgram_len; // the whole datagram's length, as passed to hw_quic_parse_header
} hw_quic_header;

// The unprotected parts of the first packet of a datagram. Short headers are read with
// HW_QUIC_CID_LEN-byte DCIDs. A long header of a version other than 1 is read to its invariant
// fields only (version, CIDs), which is enough to answer it with Version Negotiation. Returns 0,
// or -1 when it is not a QUIC packet.
int hw_quic_parse_header(const uint8_t *dgram, size_t len, hw_quic_header *h);

// Amplification: Version Negotiation and Retry are only ever sent for a datagram of at least
// HW_QUIC_MIN_DGRAM bytes (RFC 9000 sections 5.2.2, 8.1, 14.1). The check is here, not the
// listener's: both functions answer nothing (0) when h->dgram_len is below it, so h must come
// from hw_quic_parse_header (or carry the datagram's real length).

// A Version Negotiation packet answering h (listing version 1 and a GREASE version, RFC 9000
// 6.3; the CIDs swapped, random unused bits with 0x40 set), into out. Returns its length, or 0
// when cap is too small, h is a short header or itself a Version Negotiation (version 0), or the
// datagram was under HW_QUIC_MIN_DGRAM.
size_t hw_quic_version_negotiation(const hw_quic_header *h, uint8_t *out, size_t cap);

// A Retry answering the Initial h from peer, with a new SCID and an address-validation token
// sealed under key (it names peer's address, the time and h's DCID), into out. Returns its
// length, or 0: cap too small, h not a version 1 Initial, the datagram under
// HW_QUIC_MIN_DGRAM, new_scid equal to h's DCID (RFC 9000 17.2.5.1), peer neither IPv4 nor
// IPv6, or no randomness. Tokens are sealed with ChaCha20-Poly1305 under key with a random
// nonce; the address and port (an IPv4-mapped IPv6 peer counts as the IPv4 it maps) are bound as
// associated data, not carried, and the token expires: see hw_quic_token_valid.
size_t hw_quic_retry(const hw_quic_header *h, const struct sockaddr *peer, const uint8_t key[HW_QUIC_KEY_LEN],
                     uint64_t now_ms, const uint8_t new_scid[HW_QUIC_CID_LEN], uint8_t *out, size_t cap);

// Whether token (from an Initial) was made by hw_quic_retry under key for this peer address
// and port within max_age_ms (now_ms - issued <= max_age_ms; a token dated after now_ms is
// refused). On 1, odcid receives the DCID of the Initial the Retry answered; on 0, *odcid_len
// is 0. The Retry SCID is the DCID of the Initial that carries the token.
int hw_quic_token_valid(const uint8_t *token, size_t len, const struct sockaddr *peer,
                        const uint8_t key[HW_QUIC_KEY_LEN], uint64_t now_ms, uint64_t max_age_ms, uint8_t odcid[20],
                        uint8_t *odcid_len);

// A stateless reset for a short-header datagram of length in_len that carried cid, into out
// (shorter than in_len, so it never amplifies). Random bytes with the short header's fixed bit
// (0x40) set and the form bit clear, ending in hw_qw_reset_token(key, cid). Its length is
// in_len - 1 when that is 43 or less (RFC 9000 10.3), otherwise random from 42 to the smaller of
// 73 and in_len - 1, and never more than cap. Returns its length, or 0 when in_len is too short to answer (under 22),
// cap is under 21 or there is no randomness.
size_t hw_quic_stateless_reset(const uint8_t cid[HW_QUIC_CID_LEN], const uint8_t key[HW_QUIC_KEY_LEN], size_t in_len,
                               uint8_t *out, size_t cap);

// ---- Connections ----------------------------------------------------------------------------

// Server: a connection for the Initial h from peer. validated = 1 when h carried a valid Retry
// token (odcid is the DCID it names), so the path is validated and the 3x limit does not apply.
// The caller then passes the same datagram to hw_quic_input.
hw_quic_conn *hw_quic_accept(const hw_quic_config *cfg, const hw_quic_callbacks *cb, const hw_quic_header *h,
                             const struct sockaddr *peer, socklen_t peer_len, int validated, const uint8_t *odcid,
                             uint8_t odcid_len, uint64_t now_ms);

// Client: a connection to peer; hw_quic_output then produces its Initial.
hw_quic_conn *hw_quic_connect(const hw_quic_config *cfg, const hw_quic_callbacks *cb, const struct sockaddr *peer,
                              socklen_t peer_len, uint64_t now_ms);

void hw_quic_free(hw_quic_conn *q);

// A received datagram for this connection (it may hold several coalesced packets). dgram is
// decrypted in place. Returns 0; a packet that fails to decrypt or parse is dropped silently, a
// protocol violation closes the connection (closed callback) and still returns 0.
int hw_quic_input(hw_quic_conn *q, uint8_t *dgram, size_t len, const struct sockaddr *from, socklen_t from_len,
                  uint64_t now_ms);

// The next datagram to send, at most cap bytes (cap >= HW_QUIC_MAX_DGRAM), and its destination.
// Returns its length, or 0 when there is nothing to send now: the congestion window, the pacer
// or the amplification limit may be what holds it back, and hw_quic_timeout says when to try.
size_t hw_quic_output(hw_quic_conn *q, uint8_t *out, size_t cap, struct sockaddr_storage *to, socklen_t *to_len,
                      uint64_t now_ms);

// Whether the datagram hw_quic_output returned last must be sent by itself (hw_sys_dgram.alone):
// a PMTU probe, which a hop narrower than it drops whole, with whatever shared its write.
int hw_quic_output_alone(const hw_quic_conn *q);

// The absolute time (ms, the caller's clock) of the next timer: loss detection, PTO, ACK delay,
// pacing, idle, keepalive, draining. UINT64_MAX when there is none.
uint64_t hw_quic_timeout(const hw_quic_conn *q);
void hw_quic_on_timeout(hw_quic_conn *q, uint64_t now_ms);

// Open a stream of ours. Returns its id, or -1 while the peer's MAX_STREAMS forbids it.
int64_t hw_quic_stream_open(hw_quic_conn *q, int bidi);

// Queue bytes on a stream (copied). Returns how many were taken: fewer than len when the
// stream's send buffer, the connection's, or the peer's flow control is full (stream_writable
// then says when to retry). fin ends the stream once every queued byte is sent; it is taken
// only together with the last byte of data (or with len 0 when everything was taken).
// Returns -1 on a stream that is not ours to write.
int64_t hw_quic_stream_write(hw_quic_conn *q, uint64_t id, const uint8_t *data, size_t len, int fin);

// The application consumed n bytes of a stream's received data: grant the peer that much more
// stream (and connection) credit. Withholding this is how the caller pushes back on a peer.
void hw_quic_stream_consumed(hw_quic_conn *q, uint64_t id, size_t n);

// End our sending side abruptly (RESET_STREAM), or ask the peer to stop sending (STOP_SENDING).
void hw_quic_stream_reset(hw_quic_conn *q, uint64_t id, uint64_t app_error);
void hw_quic_stream_stop(hw_quic_conn *q, uint64_t id, uint64_t app_error);

// Queue a DATAGRAM frame. Returns 0, or -1 when it is larger than the peer allows or the
// queue is full (it is dropped, as UDP would).
int hw_quic_datagram_send(hw_quic_conn *q, const uint8_t *data, size_t len);

// The largest DATAGRAM payload that fits one packet on the current path, 0 when the peer
// accepts none.
size_t hw_quic_datagram_max(const hw_quic_conn *q);

// Close with an application error (CONNECTION_CLOSE type 0x1d) and a reason.
void hw_quic_close(hw_quic_conn *q, uint64_t app_error, const char *reason);

// Bytes queued for sending and sent but not yet acknowledged, across streams: the
// connection's backpressure figure.
size_t hw_quic_queued(const hw_quic_conn *q);
// Of those, the bytes never sent yet: what is waiting for the window, the pacer or the peer's
// credit. What is in flight is not counted, as a TCP socket's is not in a WebSocket's queue.
size_t hw_quic_unsent(const hw_quic_conn *q);

// 1 once the connection has closed and its draining period has passed: free it then.
int hw_quic_is_drained(const hw_quic_conn *q);

// The negotiated ALPN, the SNI the client sent, and the peer's current (validated) address.
const char *hw_quic_alpn(const hw_quic_conn *q);
const char *hw_quic_server_name(const hw_quic_conn *q);
const struct sockaddr *hw_quic_peer(const hw_quic_conn *q, socklen_t *len);

// Counters for tests and the server's stats.
typedef struct {
	uint64_t packets_sent, packets_received, packets_lost, bytes_sent, bytes_received;
	uint64_t srtt_us, cwnd;
	uint64_t mds;               // the datagram size in use: HW_QUIC_MIN_DGRAM until a larger one is probed
	uint64_t ssthresh;          // UINT64_MAX while still in slow start
	uint64_t congestion_events; // recovery periods entered (mod 2^16)
	uint64_t spurious_lost;     // packets declared lost and acknowledged after all
	uint64_t acked_limited;     // bytes acknowledged that the window did not grow by (sent app-limited)
	uint64_t ptos;              // probe timeouts
	uint64_t bandwidth;         // BBR's estimate of the path, bytes per second (0: NewReno, or none yet)
} hw_quic_stats;
void hw_quic_get_stats(const hw_quic_conn *q, hw_quic_stats *out);

#endif
