# Wisp over WebTransport

holyWisp listens for WebTransport (HTTP/3 over QUIC, UDP) beside its WebSocket listener. A
browser opens `new WebTransport("https://host:port/")`, and Wisp runs over the session exactly
as it runs over a WebSocket: same packets, same streams, same egress policy, limits and
reputation. What changes is the transport under it: no TCP head-of-line blocking between Wisp
streams, and Wisp UDP streams (QUIC, WebRTC) ride QUIC datagrams instead of a reliable byte
stream, so a lost datagram is lost instead of stalling every other stream on the connection.

The owner decided (2026-11-18) to implement QUIC, TLS 1.3 and the HTTP/3 needed for
WebTransport in-tree. This reverses AGENTS.md's "TLS does not exist in-tree" for this listener
only: the WebSocket path still expects a reverse proxy for TLS. No third-party code.

## Layers

Each layer is one static library that links only the ones below it (`CMakeLists.txt`), so a
layer's unit tests build and run whatever state the layers above are in.

| Library | Files | Contract |
| --- | --- | --- |
| `hw_crypto_sym` | `src/common/sha256.c`, `aead.c` | `holywisp/sha256.h`, `holywisp/aead.h` |
| `hw_crypto_asym` | `src/common/x25519.c`, `p256.c`, `cert.c` | `holywisp/ecc.h`, `holywisp/cert.h` |
| `hw_tls` | `src/quic/tls13.c` | `holywisp/tls13.h` |
| `hw_quic_wire` | `src/quic/quic_wire.c` | `src/quic/quic_wire.h` and the stateless half of `holywisp/quic.h` |
| `hw_quic` | `src/quic/quic.c` (+ more files of its own) | `holywisp/quic.h` |
| `hw_wt` | `src/quic/webtransport.c` (+ `h3.c`, `qpack.c` if split) | `holywisp/webtransport.h` |
| server | `src/server/wt_listener.c` (new), changes in `conn.c`, `server.c`, `config.c`, `sys*.c` | `src/server/internal.h` |

Everything below the server is sans-IO and single-threaded: no sockets, no clock reads (the
caller passes `now_ms`), no threads, no global state except constant tables. Randomness comes
from `hw_sys_random` (key generation, connection IDs, the Retry token key).

## Cryptography

- **TLS 1.3 only**, server and (for tests and holyWisp's own client) client. Key exchange
  X25519 only: a ClientHello that lists X25519 in supported_groups without a key share for it gets
  a HelloRetryRequest. Signatures ecdsa_secp256r1_sha256 only. No PSK, no tickets, no 0-RTT,
  no client certificates. ALPN `h3` required.
- **Cipher suites.** The server selects TLS_CHACHA20_POLY1305_SHA256 for the Handshake and
  1-RTT keys. Chrome offers it. It is constant-time in portable C, and AES-GCM is not without
  hardware support, which no-dependency C cannot reach portably. AES-128-GCM exists only because
  RFC 9001 mandates it for Initial packets, whose keys derive from a connection ID on the wire
  and protect nothing secret. A client that does not offer ChaCha20 is refused
  (handshake_failure).
- **Constant time** for everything keyed by a secret: X25519 (Montgomery ladder, constant-time
  field arithmetic), P-256 signing (constant-time scalar multiplication, RFC 6979 nonces),
  ChaCha20-Poly1305, and tag comparisons (`hw_ct_equal`). Verification of public data
  (`hw_p256_verify`) may be variable-time.
- **Vectors.** Every primitive is pinned by its RFC/NIST vectors (RFC 8439, RFC 7748 including
  the iterated vectors, RFC 6979 A.2.5, NIST GCM test cases, RFC 9001 appendix A for the
  whole Initial packet, RFC 8448 where it applies), plus cross-checks against `openssl` and Python
  `cryptography` where those are on the machine. Tests may shell out to them only to generate
  vectors once, which are then checked in; CI has neither.

## Certificates

Chrome's `serverCertificateHashes` accepts a certificate only if it is X.509 v3 with an ECDSA
P-256 key and a validity of at most 14 days. So by default the server makes its own:

- At start and then every 6 days, the maintenance thread makes a P-256 key and a self-signed
  certificate valid from one hour ago for 13 days (`hw_cert_selfsigned`), and publishes it to
  the WebTransport listener the way `warp_publish` publishes WARP state (each worker gets its own
  copy by a posted task; no lock on the data path). The previous certificate stays valid in
  browsers that already pinned it. New handshakes use the new certificate.
- `GET /webtransport.json` on the TCP listener (the same port as `/health`) answers
  `{"url": <webtransport-url or "">, "hashes": [{"algorithm": "sha-256", "value": "<base64>"}, ...]}`
  with the current and previous certificate, `Access-Control-Allow-Origin: *` and
  `Cache-Control: no-store`. A page fetches it and passes `hashes` (decoded) as
  `serverCertificateHashes`.
- With `webtransport-cert` and `webtransport-key` (PEM files, ECDSA P-256 only: the TLS layer
  signs with P-256 only), that chain is used instead, nothing rotates, and `/webtransport.json`
  lists no hashes. The browser then verifies it through the Web PKI.
- With `webtransport-cert-dir`, a server that answers for many names (the edge's TCP vhosts
  each have their own certificate) picks one by the ClientHello's SNI: the TLS layer asks
  (`hw_tls_config.cert_for`) once the ClientHello is read, and the listener looks the name up,
  in lower case and without the root's dot, in a table of `<host>.pem` files. Any other name,
  and no name, gets the certificate above. The table is immutable and shared: the maintenance
  thread makes a new one when the directory changes, reusing every certificate whose file is
  the same file, and posts each worker a reference (an atomic count; a directory can hold
  thousands, which would be thousands of copies per worker). A file younger than a second is
  left for the next look, for a writer that writes in place.
- `webtransport-path` rules admit a session only on the paths the WebSocket side reaches the
  relay on (a keyed path behind nginx, say). A request no rule names is answered 404 before a
  connection is made for it or anything is counted. Any HTTP/3 request that is not a CONNECT
  is answered 421 with `alt-svc: clear`: a browser that holds an h3 alternative service for
  the host from a CDN once in front of it sends it again over TCP and forgets the alternative.
- Those files are renewed in place (certbot, lego) without a restart. The maintenance thread
  stats both once a second (device, inode, size, mtime; `stat` follows certbot's symlinks).
  When either has changed it waits until neither changes for one more look, because a renewer
  writes the certificate and then the key and the new certificate must not be tried with the
  old key. Then it reads the pair with exactly the checks made at start (a chain of at most
  `HW_CERT_CHAIN_MAX` blocks, a P-256 key, the key of the leaf) and, only if they pass, posts
  each worker its copy as the self-signed rotation does, and logs the leaf's notAfter and
  SHA-256 at INFO. New handshakes take the new certificate; a connection under way keeps the
  one it started with, because `hw_tls_new` copies the chain and the key. A pair that does not
  load is one ERROR (paths and the reason, never the key) and changes nothing: the current
  certificate stays until the files change again. There is no SIGHUP; the unit has no
  `ExecReload` on purpose.

## QUIC

RFC 9000/9001/9002 version 1, plus RFC 9221 datagrams. Implemented: Initial/Handshake/1-RTT
spaces; coalesced packets; ACK ranges and ACK delay; loss detection by packet and time
threshold, both adapting to the reordering seen, with a window cut undone when every loss it
answered proves spurious; PTO with probes; BBR or NewReno, with pacing; persistent congestion; anti-amplification (3x
the bytes received before the address is validated); flow control at stream and connection
level, with receive credit granted only when the application consumes (`hw_quic_stream_consumed`),
which is how backpressure reaches a client; stream limits (MAX_STREAMS); NEW_CONNECTION_ID and
RETIRE_CONNECTION_ID; path validation on a peer address change (NAT rebinding: the client's
port changes, and the connection survives); key update; idle timeout; stateless reset;
Retry; datagram packetization layer PMTU discovery (RFC 8899). Not implemented: 0-RTT, server
migration, preferred_address, ECN, QUIC v2, and noticing a path MTU that shrinks later.

Datagram size: a connection starts at 1200 bytes, which every QUIC path must carry, and once the
handshake is confirmed it probes for more: a PING padded to the size, alone in a datagram, first
at the ceiling (1452, or the peer's `max_udp_payload_size` if smaller), then halfway between what
passed and what failed, three tries per size. An acknowledged probe raises the size; the probes
are never counted in flight, so a lost one is not a congestion signal and arms no PTO. A new path
starts at 1200 again. Until 2026-11-18 every connection started at 1452, and a path under 1480
bytes that drops instead of answering with ICMP (a VPN, PPPoE, some mobile links) lost every
full-size packet: the handshake went through and the session then carried nothing
(`test_pmtu` in `test_quic`). Every datagram carries DF and is never fragmented on this host
(`hw_sys_udp_no_fragment`: Linux `IP_PMTUDISC_PROBE`), so a probe the path cannot carry is lost.
Until 2026-11-19 the sockets kept Linux's default: once an ICMP "fragmentation needed" had put a
1360 MTU in the route cache, the edge sent every 1452-byte probe, and then every packet, as two
fragments, and a lost fragment lost the packet.

**Congestion control** is BBR by default (`webtransport-congestion-control`), version 1 as Linux's
`tcp_bbr` has it, in `quic_recovery.c`. Every packet in flight records the delivery state when it
was sent (draft-cheng-iccrg-delivery-rate-estimation), each ACK makes a delivery rate sample, and
the model is the highest rate of the last 10 rounds and the lowest RTT of the last 10 s. The
pacer sends at a gain over that rate (2.89 in startup, then a cycle of 1.25, 0.75 and six of 1),
the window is twice the estimated BDP, and a loss changes neither. Samples taken while the sender
had nothing to send (`hw_qc_cc_app_limited`) only ever raise the estimate. The RTT the model sees
is never under 1 ms, the clock's tick: below it a loopback path measured 0 and the window was 4
packets. NewReno (RFC 9002 7, appendix B) remains selectable, and is what the window was until
2026-11-19: on the edge path, 45 ms and about 0.3% random loss, it halved its window 13 times in
an 8 s download and ran at 4 Mbit/s where the same path's TCP (BBR) did 30. On a 40 Mbit/s netem
link with that loss and RTT, NewReno moved 0.8 MiB/s and BBR 4.5.

Every buffer is bounded (`hw_quic_config`). A peer that would push a buffer past its bound is
closed with the matching transport error, never buffered: CRYPTO data beyond 64 KiB per
level is CRYPTO_BUFFER_EXCEEDED, out-of-order stream data beyond the credit granted is
FLOW_CONTROL_ERROR, and more than 32 ACK ranges kept per space drops the oldest.

**Connection IDs and steering.** Every CID the server issues is 8 bytes: byte 0 is the owning
worker's index and the rest is random. Each worker has its own `SO_REUSEPORT` UDP socket on the
WebTransport port, and a classic BPF program on the group (`SO_ATTACH_REUSEPORT_CBPF`, no
capability needed) returns the byte that holds the worker index: offset 1 for a short header,
offset 6 for a long header whose DCID is 8 bytes. For a client's first Initial (a DCID of the
client's choosing, so the program cannot use it) it returns an index past the group's end, and
the kernel falls back to its 4-tuple hash. Whichever worker gets the Initial then issues CIDs
with its own index, and every later packet of the connection lands on it. No connection state
ever crosses threads, as with TCP. That is a `sys.h` function (`hw_sys_udp_steer`)
implemented three times: on macOS and Windows only one worker opens the UDP socket and it owns
every WebTransport connection, as only one listener exists there. A datagram for a CID a worker
does not know (its owner index is another worker after a reuseport group change, or unknown) gets
a stateless reset if it is a short header of at least 21 bytes, and is dropped otherwise.

**Datagram I/O.** On Linux, `recvmmsg` and `sendmmsg` batches with UDP GSO and GRO (in `sys.h`:
`hw_sys_recv_batch`, `hw_sys_send_batch`, `hw_sys_udp_gro`; a one-datagram loop on the other
platforms). `hw_sys_send_batch` hands a run of datagrams to the same address and of the same
length to the kernel as one write (`UDP_SEGMENT`), and a worker reads into 16 slots of 64 KiB that
GRO fills with several datagrams each. The UDP sockets ask for 4 MiB buffers (or
`socket-buffer-size`): at the kernel's default 208 KiB a single session lost hundreds of packets
per 256 MiB on loopback, and NewReno then held its window near 270 KB. Set `net.core.rmem_max`
and `wmem_max` to at least 4 MiB; the server warns at start when it is granted less. Measured
2026-11-18, one session on loopback, 256 MiB echoed: 174 MiB/s each way with plain batches,
416 MiB/s with GSO and GRO, at half the CPU on each end; ChaCha20-Poly1305 is then 55 to 60% of it.

## HTTP/3 and WebTransport

Chrome speaks draft-ietf-webtrans-http3-02. `~/src/stomp-rewrite/docs/webtransport.md` ("On
the wire") has the bytes as Chrome 152 to 157 send them, measured. In summary: the server's
SETTINGS must carry H3_DATAGRAM (0x33) = 1 and ENABLE_WEBTRANSPORT (0x2b603742) = 1, or Chrome
sends no request. The request is HEADERS on stream 0 (`:method CONNECT`, `:protocol webtransport`,
`:scheme https`, `:authority`, `:path`, `sec-webtransport-http3-draft02: 1`, `origin`,
`wt-available-protocols`), static QPACK table and literals only. A DATA frame with a GREASE
capsule follows. The answer `:status 200` opens the session. Datagrams are prefixed with the
quarter stream id of the session (`00`). Client bidi streams start `40 41 <session id>`, uni
streams `40 54 <session id>`. A close is capsule 0x2843 (code u32, reason) then FIN. The server
advertises a QPACK dynamic table of 0 and never reads the encoder stream's instructions beyond
skipping them. A header block that refers to the dynamic table is a QPACK_DECOMPRESSION_FAILED.

## Wisp on the session

- The client opens one bidirectional WebTransport stream: the **Wisp stream**. It carries Wisp
  packets back to back, each preceded by its length as a u32 LE, as epoxy-server's
  LengthDelimitedLe codec frames them. Packets on it are exactly the packets a WebSocket message
  would carry, and the server treats them so: one `hw_conn` per session, the same
  `handle_packet` dispatch, the same v1/v2 opening (CONTINUE on stream 0, or INFO first for v2).
- **v2** iff the CONNECT carried `wt-available-protocols` and `enable-v2` is on, mirroring the
  WebSocket rule (presence of the header). The server answers with `wt-protocol` echoing the
  first offered token, as the WebSocket path echoes the subprotocol.
- **Datagrams.** A Wisp packet that fits one datagram (`hw_wt_datagram_max`) may be sent as one
  QUIC datagram on the session, whole, with no length prefix. Only DATA for a **UDP** Wisp
  stream is ever sent that way, in both directions. The server accepts any Wisp packet in a
  datagram but acts only on DATA for UDP streams (anything else is dropped and counted). A UDP
  DATA packet too large for a datagram goes on the Wisp stream. TCP stream DATA, CONTINUE,
  CONNECT and CLOSE are only ever on the stream: they must not be lost or reordered.
- **Flow control** is Wisp's, unchanged (CONTINUE per stream, counted in packets), on top of
  QUIC's. Backpressure toward the client is the WebSocket rule with `hw_wt_queued` in place of
  `wbuf`: past `ws-write-high-water` the remotes pause. Toward the server, a connection whose reads
  would pause (`conn_queue_add`, `wr_stalled`, the bandwidth limit) calls `hw_wt_pause`, which
  stops granting the client QUIC credit, which is what not reading a TCP socket does.
- **No zero copy.** Bytes toward a WebTransport client are copied into QUIC packets and
  encrypted; the splice path is the WebSocket listener's alone. A WebTransport `hw_conn` never
  opens a relay pipe.
- **Phase 2 (not now):** one WebTransport stream per Wisp TCP stream, so that a loss on one
  stream does not stall the others. It needs a Wisp extension to negotiate. It comes after
  phase 1 has been measured.

## Security

Everything AGENTS.md's "Security suite" says holds for a WebTransport client, at the same
places in the code. On top of it:

- **Address validation before cost.** A client's address is not trusted until its handshake
  completes or it returns a Retry token. Before that, the server sends at most 3x what it
  received (QUIC's rule) and charges nothing to the per-IP limiters, because the source address
  of a UDP datagram is forgeable. Past `webtransport-retry-threshold` handshakes in progress on a
  worker (default 64) every new Initial gets a Retry. Tokens are sealed with
  ChaCha20-Poly1305 under a per-process key, name the address and port, and expire after 30 s.
- **The connection-level checks** (per-IP connect rate, reputation tier, per-IP gauge, the
  concurrent-connection semaphore, `allow-origin` against the CONNECT's `origin`) run when the
  CONNECT arrives, the WebTransport equivalent of the upgrade. A refusal is answered with the
  HTTP status the TCP listener would use (429, 403) and the connection is closed. The client's
  address is the UDP peer address. **Proxy headers are never read on this listener**: there is
  no proxy in front of UDP.
- **Handshakes in progress** are capped per worker (`webtransport-max-handshakes`, default 1024)
  and per source address, and expire after 10 s. Allocation per Initial is bounded and made
  only after the Initial decrypts.
- **Idle timeout** is mandatory (`webtransport-idle-timeout-s`, default 30). The server sends a
  keepalive PING after 20 s without sending: divide's conntrack keeps a UDP flow for 30 s, and
  past that a reply would leave from the other uplink (infra `docs/divide-host.md`).
- **Amplification.** A Version Negotiation and a Retry are only sent in answer to a datagram
  of at least 1200 bytes, and a stateless reset is shorter than the datagram it answers.

## Configuration

| Key | Default | Meaning |
| --- | --- | --- |
| `webtransport` | off | Listen for WebTransport. |
| `webtransport-host` | `host` | UDP address to bind. |
| `webtransport-port` | `port` | UDP port to bind (the same number as the TCP port by default). |
| `webtransport-url` | empty | The URL `/webtransport.json` names, for when the client should not derive it from the page's origin. |
| `webtransport-cert`, `webtransport-key` | empty | PEM files (ECDSA P-256) to use instead of the rotating self-signed certificate. Read again when they change, for new sessions. |
| `webtransport-cert-dir` | empty | `<host>.pem` files (chain and P-256 key in one) picked by the client's SNI; any other name gets the certificate above. Read again when it changes. |
| `webtransport-path` | every path | `[host] /path`, repeatable: the paths (and hosts) a session is admitted on; any other is a 404. |
| `webtransport-idle-timeout-s` | 30 | QUIC idle timeout. |
| `webtransport-max-handshakes` | 1024 | Handshakes in progress per worker. |
| `webtransport-retry-threshold` | 64 | Handshakes in progress per worker past which every Initial gets a Retry. |
| `webtransport-congestion-control` | `bbr` | `bbr` or `newreno` (see "Congestion control"). |

Like every key: `config.c` (parser, `--help`), `README.md`, `holywisp.conf.example`,
`deploy/holywisp.conf`, the npm wrapper (`node/src/config.ts`, its README, its tests).

## Tests

- Each layer: unit tests with vectors (`tests/test_aead.c`, `test_ecc.c`, `test_cert.c`,
  `test_tls13.c`, `test_quic_wire.c`, `test_quic.c`, `test_webtransport.c`).
- `test_quic.c` runs a client and a server connection against each other in memory, through a
  simulated path that drops, reorders, duplicates and delays datagrams, and changes the
  client's address mid-connection. Every transfer must arrive intact, and the run must be
  repeatable from a seed.
- `test_e2e_wt.c`: the real server on an ephemeral UDP port, driven by holyWisp's own
  WebTransport client (the client role of the same layers) over loopback, doing what
  `test_e2e.c` does for WebSocket: TCP echo, UDP echo by datagram, v1 and v2, egress refusals,
  limits.
- Interop, when the tools are on the machine (skipped otherwise, never in CI): `curl --http3-only`
  against the TLS and QUIC layers, and headless Chrome against `GET /webtransport.json` plus a
  WebTransport session with the pinned hash.
