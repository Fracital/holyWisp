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
caller passes `now_ms`, or `now_us` to the calls that BBR's samples are timed by), no threads, no global state except constant tables. Randomness comes
from `hw_sys_random` (key generation, connection IDs, the Retry token key).

## Cryptography

- **TLS 1.3 only**, server and (for tests and holyWisp's own client) client. Key exchange
  X25519 only: a ClientHello that lists X25519 in supported_groups without a key share for it gets
  a HelloRetryRequest. Signatures ecdsa_secp256r1_sha256 only. No PSK, no tickets, no 0-RTT,
  no client certificates. ALPN `h3` required.
- **Cipher suites.** For the Handshake and 1-RTT keys the server selects TLS_AES_128_GCM_SHA256
  when its CPU has AES-NI and PCLMULQDQ (`hw_aes128gcm_hw`) and the client offers it without
  listing ChaCha20 before it (BoringSSL and NSS put ChaCha20 first on a CPU without AES
  instructions, where AES costs the client too), and TLS_CHACHA20_POLY1305_SHA256 otherwise.
  Chrome offers both. The AES-NI kernel is in `aead.c`, compiled for those instructions and
  picked at the first call by `cpuid`, as the AVX2 ChaCha20 kernels are; elsewhere AES-128-GCM
  is the portable bitsliced code, constant-time but several times slower than ChaCha20, and is
  never chosen for secret keys (it still protects Initial packets, which RFC 9001 mandates and
  whose keys derive from a connection ID on the wire). A client that offers neither suite the
  server may choose is refused (handshake_failure). holyWisp's own client offers AES-128-GCM,
  first, only on AES instructions. Under AES-128-GCM a sender updates its 1-RTT key after 2^22
  packets of a phase and sends nothing under a key past 2^23 (RFC 9001 6.6's confidentiality
  limit; `key_update_at` in `quic.c`).
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
migration, preferred_address, ECN and QUIC v2.

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

A path whose MTU shrinks after the search (a route change, a tunnel set up under the session) is
noticed (black hole detection, RFC 8899 4.3): three packets above 1200 bytes lost with none at
least as large acknowledged since, a smaller packet sent after them acknowledged, and then larger
packets sent after that one lost too. The size falls back to 1200 and the search starts again
below the smallest size that was lost. From the second PTO in a row on, the probes go at 1200
bytes, or a session whose every full-size packet is lost would never send the small packet that
tells a black hole from a dead path. One small packet through is not enough on its own: after an
outage the first packet through is often such a probe, and what follows it then arrives too.
Random loss never takes three large packets with no large one acknowledged between. Until
2026-11-19 the size only ever rose, and a session on such a path stalled for good while the ACKs
and keepalives, all small, kept it from timing out (`test_pmtu_black_hole`).

**Congestion control** is BBR by default (`webtransport-congestion-control`), version 1 as Linux's
`tcp_bbr` has it, in `quic_recovery.c`. Every packet in flight records the delivery state when it
was sent (draft-cheng-iccrg-delivery-rate-estimation), each ACK makes a delivery rate sample, and
the model is the highest rate of the last 10 rounds and the lowest RTT of the last 10 s. The
pacer sends at a gain over that rate (2.89 in startup, then a cycle of 1.25, 0.75 and six of 1),
the window is twice the estimated BDP, and a loss changes neither. Samples taken while the sender
had nothing to send (`hw_qc_cc_app_limited`) only ever raise the estimate. A sender whose
stream waits for room in the send buffer or for the peer's credit has something to send, and its
samples count: marked app-limited, a bulk download behind a full buffer stayed in startup,
pacing at 2.89 times the path. PROBE_RTT counts as app-limited until what was in flight is
delivered (as Linux does), so its four-packet samples cannot replace an estimate that an
app-limited stretch left stale: one did, on the edge, and the rate fell to 1 Mbit/s for seconds
about 10 s into every download. The min RTT of the model
is never under 1 ms, the timers' tick: below it a loopback path measured 0 and the window was 4
packets. The clock under it is finer: the listener and the client pass microseconds
(`hw_quic_input_us`, `_output_us`, `_on_timeout_us`), because a rate sample over a round trip of
30 ms is known only to 3% on a clock of milliseconds, the max filter kept the samples the clock
made high, and the sender paced 3% over the path. Behind a buffer of 5 ms that was a standing
queue and 5 to 8% of the packets lost, at 440 Mbit/s and 30 ms, one download or two (netns,
2026-11-19); on microseconds the estimate is the path's and the loss 3.5 to 5%, most of
it startup's overshoot and the 1.25 probes. A rate sample is judged against the RTT as measured,
never the floored one: against the floor, a loopback path kept only the samples that spanned a
stall and ran at a fifth of its speed. NewReno (RFC 9002 7, appendix B) remains selectable, and is what the window was until
2026-11-19: on the edge path, 45 ms and about 0.3% random loss, it halved its window 13 times in
an 8 s download and ran at 4 Mbit/s where the same path's TCP (BBR) did 30. On a 40 Mbit/s netem
link with that loss and RTT, NewReno moved 0.8 MiB/s and BBR 4.5.

`bbr2` is the same model with version 3's answer to loss (draft-cardwell-ccwg-bbr), for paths
where version 1's indifference to loss is the problem: behind a shallow buffer it keeps pacing at
the path's rate, so its 1.25 probes and startup's overshoot are lost. A round whose losses pass
2% of what was in flight when it began (and are 3 packets at least) is too much: it ends startup
and a probe and sets `inflight_hi`, the flight at which the loss began, which caps the window.
PROBE_BW is the draft's DOWN, CRUISE (under `inflight_hi` less 15%), REFILL and UP, a probe every
2 to 3 s at random (or sooner, on a short path, as Reno would have); UP raises `inflight_hi`
slowly until the loss comes back, and a probe that ends on loss cuts it by 0.7. Two rounds in a
row of too much loss outside a probe cut the short-term bounds (`bw_lo`, `inflight_lo`) by 0.7,
and the next probe starts from `bw_lo`, not from the rate before the drop. PROBE_RTT comes every
5 s and keeps half the BDP. Where this is not the draft: loss is judged once per round, by the
round's sum, where the draft judges at each loss the loss since that packet was sent (a judgment
made at a loss always counts one, so random loss well under 2% crossed it every few rounds on a
small window); and the short-term bounds answer two rounds of too much loss, where the draft's
answer any loss and the edge's random 0.3% would cut them every round. In the simulator, 40
Mbit/s, 40 ms and 1% random loss: the draft's judgment kept 79% of the path, one round 81%, two
95%. On netns (2026-11-19), 440 Mbit/s, 30 ms, a 5 ms queue: one download lost 3.4 to 3.7% under
`bbr` and 0.46 to 0.50% under `bbr2`, at 401 to 406 Mbit/s against 405 to 407, and its longest
gap was 37 to 67 ms against 66 to 106; two downloads on one session the same; two sessions lost
7 to 12% against 0.5 to 0.6%. At 1 Gbit/s, 138 ms and 0.3% random loss both made 640 to 670
Mbit/s (both made 910 without the loss, so that limit is not the congestion control), and on
loopback both are the same within the noise.

Two `bbr2` sessions on one path converged slowly as the draft has it. A newcomer's startup ends on
the queue the first session keeps full, at a sixth of the path, and that bound holds until its
next probe 2 to 3 s later. The first session cruises at about the BDP and gives up room only
when it probes: each probe moves about 15% of the difference, PROBE_RTT restarted the wait, and
the draft's short-term bounds (floored at what the round delivered) moved it by 3%. The second
session held 0.13 to 0.26 of the path for 10 to 30 s. Three changes, each of which
`test_bbr2_fairness` needs:
- a probe that raised `inflight_hi` by more than 5%, and startup's bound, are followed by
  another probe 4 to 7 rounds later;
- PROBE_RTT no longer restarts the wait for the next probe;
- another flow's overflow cuts this one's flight. That is two rounds in a row of too much loss
  (2%) among packets sent since this flow's own last probe, with a queue standing (the round's
  largest RTT more than 5% over the minimum). The cut sets `inflight_lo` to 0.8 of the flight
  until the next probe, so the larger flow gives up more. Without the queue test the
  simulator's 1% random-loss path kept 84% instead of 95%.

In the simulator, the newcomer started at 24 different times. Its share in the fifth second
after it started was within 0.4 to 0.6 of the path in 15 and 14 of them on 440 Mbit/s and
30 ms, and on 100 Mbit/s and 40 ms (each behind a 5 ms queue). Before the changes it was in
none of them. In the tenth second it was within the range in 21 and 12 (before: 5 and 1).

On netns (2026-11-19) the second session started 3 s after the first, three runs of each:

| Path, ACK jitter | Newcomer's share in seconds 1 to 12, before | After | Loss before / after |
| --- | --- | --- | --- |
| 440 Mbit/s, 30 ms, 5 ms queue, 500 µs | 0.12 to 0.21 in the first second, 0.30 to 0.36 in the tenth | 0.24 to 0.26, then 0.28 to 0.59 from the second on | 0.44 to 0.54% / 0.46 to 0.61% |
| Same path, 100 µs | 0.28 to 0.43 in the tenth | 0.43 to 0.55 in the tenth | 0.48 to 0.55% / 0.55 to 0.67% |
| 100 Mbit/s, 40 ms, 500 µs | 0.29 to 0.33 in the tenth | 0.38 to 0.51 in the tenth | 0.63 to 0.78% / 0.77 to 1.09% |

The newcomer first reached 0.4 of the path 2 to 5 s after it started at 500 µs, and 4 to 7 s at 100 µs.

All of this depends on drops being shared between the flows in proportion to their sending.
With a tail-drop queue and ACKs that come back exactly on time (netem with no jitter), the
flow clocked by its ACKs takes each slot the moment it frees, so the paced newcomer takes the
drops. There, on both paths, the newcomer still had only 0.13 to 0.42 in the fifth second and 0.38 to 0.57 in
the twelfth (before: 0.13 to 0.26 and 0.26 to 0.39). The simulator showed the same with no ACK jitter,
which is why its paths carry 100 µs.

Across the change:
- the 1 Gbit/s, 138 ms, 0.3% random-loss path made 646 to 684 Mbit/s against 666 to 685 before;
- loopback stayed the same within the noise.

`bbr` stays the default until `bbr2` has run on the edges.

**Pacing** is a token bucket at the congestion controller's rate, and what it may let go at once
is set by how late the caller's timers fire. Until 2026-11-19 the listener's timers were
milliseconds, and a burst was two milliseconds of the rate: 250 KB back to back at a gigabit.
A browser receives into what Linux's `net.core.rmem_max` allows, 208 KiB by default (twice that
counted by the kernel), and on a fast path Chrome's receive buffer errors matched the server's
losses almost exactly, in runs of 50 to 340 packets. So the loop has microsecond timers (`hw_loop_add_timer_us`, `epoll_pwait2`
on Linux, falling back to milliseconds where the kernel or a seccomp filter refuses it), QUIC
reports its deadline in microseconds (`hw_quic_timeout_us`), and the listener and the client tell
the pacer how late their timers may be (`timer_tick_us`, 100 us). On that tick a burst is two
ticks of the rate, 2 to 32 datagrams (`HW_QC_PACER_BURST_MAX`), and a sender held back wakes when
the bucket is a tick short of full, so that a timer a tick late finds a full burst and loses none
of the rate: at most 9 datagrams of 1200 bytes at once at 440 Mbit/s, 20 at a gigabit, and never
more than 38 KB in any 100 us at a gigabit (`test_pacer_fine_tick`, which the millisecond pacer
fails). Where a tick of the rate is a whole burst or more, past about 1.5 Gbit/s, it is a burst
per wakeup, which caps one session at about 5 Gbit/s with timers 50 us late on average. A session's timer is rounded up to a 50 us grid so that the sessions of a worker share
their wakeups, and a GSO write never holds two releases (`run_start` in `hw_sys_dgram`,
`test_udp_run_start`): one write leaves the NIC back to back. Before the first RTT sample there
is no rate, and the initial window goes as one burst. Applies to `newreno`, `bbr` and `bbr2`.

`SO_TXTIME` with the `fq` qdisc (earliest departure time) was considered and is not used. It
needs `fq` on the egress device, which is not the default (`fq_codel`), and the edges' UDP leaves
through WireGuard (WARP) devices that have no queue and build a new packet, which carries no
departure time onward; a GSO write has one time for all its segments, so spacing within a release
would take a write per datagram; and the pacer in user space has to be right anyway, on macOS,
Windows and any host without `fq`. Nothing depends on it.

Measured 2026-11-19 on netns (server, a router with netem's rate and queue toward the client,
30 ms; one download of 400 MB; the same client both times). At a gigabit the server's most
datagrams in any 100 us went from 64 to 41 to 47, in any millisecond from 265 to 269 to 132 to 154,
its longest back-to-back train from 32 to 23 (99th percentile 32 to 15 to 18), and what the
receiver saw in 100 us behind the router from 37 to 44 to 17 to 21; at 440 Mbit/s 64 to 24 to 28,
trains 32 to 10. A receiver with a 208 KiB buffer at a gigabit counted fewer receive buffer errors
(median of four runs, `bbr` 9,450 to 6,470, `bbr2` 4,050 to 1,410, both noisy); at 440 Mbit/s
there were none either way, and with 2 MiB none either way. What remains is the receiver's own
pace: a client that stalls 3 ms in every 20 misses 375 KB at a gigabit each time, which no pacing
can help (its errors were the same before and after). Throughput was the same within the noise
(400 Mbit/s at 440; 870 to 890 at a gigabit; at 138 ms with 0.3% loss 420 to 490 either way). The
cost is wakeups: the server's CPU for a download was 4 to 8% more at 440 Mbit/s and within the noise
at a gigabit, and on loopback, where one session runs a core flat out and the pacer, not the
window, sets each write, a WebTransport echo moves 4 to 6% fewer bytes per server CPU second
(WebSocket unchanged).

Every buffer is bounded (`hw_quic_config`). A peer that would push a buffer past its bound is
closed with the matching transport error, never buffered: CRYPTO data beyond 64 KiB per
level is CRYPTO_BUFFER_EXCEEDED, out-of-order stream data beyond the credit granted is
FLOW_CONTROL_ERROR, and more than 32 ACK ranges kept per space drops the oldest. The gaps in a
stream's out-of-order data are bounded too (1024 per stream), but by the path's loss, not by
what the peer is allowed: a packet that would open one more is left unacknowledged, as if lost,
and its frames come again (`rx_info.refused`). It used to close the connection with
INTERNAL_ERROR, which heavy loss on a long path reached (a gigabit at 138 ms and 5% loss is
about that many gaps).

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

**Stop and restart.** A stop closes every session before the process goes (`wt_worker_stop`, on
each worker once its loop has stopped): an open session gets its close capsule (code 0, "server
stopping") and FIN, then 50 ms later QUIC's CONNECTION_CLOSE (`H3_NO_ERROR`), a handshake the
CONNECTION_CLOSE alone; nothing waits for an answer, and a full socket gets at most 200 ms.
Headless Chrome resolves `closed` with the capsule's code and reason within a few milliseconds;
with the two arriving together it reported "Connection lost." (one stop in three with 1 ms
between them, none in five with 50; `tests/wt_interop.mjs` stops the server under an open
session). Until 2026-11-19 nothing was sent, and every client of a restarted edge waited out its
idle timeout (30 s) before it reconnected. A process that dies without a stop sends nothing, and its clients
are then told by the next one: their next datagram carries a CID the new process does not know,
and its stateless reset ends the session at the client if it carries the token the old one gave
for that CID. That token is made from the reset key, which is new at each start unless
`webtransport-reset-key-file` keeps it (`test_reset_key_file`).

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
streams `40 54 <session id>`. A close is capsule 0x2843 (code u32, reason) then FIN. The server's
capsule waits until what it queued before it is acknowledged (2 s at most), because Chrome drops
unread stream data once it has the capsule; a session ended by a stream-0 CLOSE carries that
Wisp reason as its code (0x04 incompatible, 0x06 auth required, ...). The server
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
  first offered token, as the WebSocket path echoes the subprotocol, except that a v2 session
  whose list holds `wisp-v2-server-stream` gets that token (see "Lanes and the server-opened
  stream").
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
- **Windows are sized for a gigabit at 138 ms** (17 MB), because a TCP socket's buffers grow to
  the path and nothing grows these. QUIC may hold `ws-write-high-water` unsent plus
  `WT_INFLIGHT_MAX` (32 MiB, twice that BDP: BBR's window) in flight; with the mark alone, 2 MiB on
  the edge, a session never had more than 2 MiB in flight, 120 Mbit/s at 138 ms. The client's
  credit toward the server is `ws-write-high-water` within [16, 32] MiB. Only bytes the client
  acknowledges can fill the allowance, at the rate BBR measured, so a client that does not read
  costs the unsent mark and the window it has, as before.
- **No zero copy.** Bytes toward a WebTransport client are copied into QUIC packets and
  encrypted; the splice path is the WebSocket listener's alone. A WebTransport `hw_conn` never
  opens a relay pipe.

## Lanes and the server-opened stream

Two opt-in extensions, specified in STomp's `wisp-lanes` draft 2; a client that asks for neither
sees the protocol above, byte for byte.

- **The server-opened Wisp stream.** A v2 client that offers `"wisp-v2", "wisp-v2-server-stream"`
  is answered `wt-protocol: "wisp-v2-server-stream"` (whatever `webtransport-lanes` says), and
  the server opens a bidirectional stream right behind the 200 (`server_stream_open` in
  `webtransport.c`). That stream is lane 0, the Wisp stream; the server writes its INFO on it
  and, unless `password-required` is on, the stream-0 CONTINUE at once (`conn_wt_open`), so the
  client can send its first CONNECT with no round trip after `ready`. The client's first packet
  on it must be its INFO: anything else is CLOSE(0, `0x04`) and the session ends
  (`wt_info_first` in `conn_wt_packet`). An older server echoes `"wisp-v2"` and the client opens
  the stream as before. Once the server's stream exists, every client bidi stream must start
  with LANE; one that does not is reset `STREAM_UNWANTED`.
- **Lanes.** The server's INFO carries extension `0xE1` (one byte: the most lanes a session may
  have, lane 0 included) when `webtransport-lanes` is 2 or more and the session is v2. After the
  stream-0 CONTINUE, a client opens further bidirectional streams, each beginning with a LANE
  packet (`type 0xE1, stream 0, index u8`, framed like any other); index 1 to lanes - 1, each
  once. A LANE the server did not advertise, out of range or repeated is reset `LANE_REFUSED`;
  a stream that has not finished its first packet holds at most 64 bytes
  (`WT_LANE_FIRST_MAX`). Application codes are mapped as WebTransport's
  (`hw_wt_error_code`): `LANE_REFUSED` 0x01, `STREAM_UNWANTED` 0x02.
- **A Wisp stream belongs to the lane its CONNECT came on** (`s->lane`, from `c->rx_lane`), and
  everything the server sends for it goes there: DATA, CONTINUE, CLOSE, the CLOSE that refuses
  the CONNECT. Stream 0 is lane 0's. UDP DATA still goes as a datagram when it fits. Lanes never
  move a stream, so the order of a stream's packets is its lane's.
- **Nothing is acted on before the INFO, and nothing is dropped.** `hw_wt` gates delivery: a
  client-opened session delivers lane 0 alone until the handshake is done, a server-opened one
  delivers exactly one packet of lane 0 (the INFO) and then nothing until `hw_wt_release`
  (from `handshake_done`, deferred through the session's settle). A lane's bytes meanwhile wait
  in its own hold buffer, which is never credited, so QUIC's stream window bounds it as it bounds
  a socket nobody reads.
- **Any lane ending ends the connection** (FIN, RESET_STREAM or STOP_SENDING, through the
  `lane_ended` callback), as the Wisp stream's end does.
- **Backpressure per lane, under a session cap** (`conn_wt_lane_marks`). A lane whose unsent
  bytes (`hw_wt_lane_queued`: hw_wt's queue plus QUIC's unsent part of that stream) pass
  `ws-write-high-water` pauses the remotes of its own streams (`c->lane_paused`,
  `conn_stream_paused`) and resumes them under a quarter of it, so a lane waiting on Chrome's
  fixed 6 MiB window or a lost packet holds up only its streams. Past lanes x the mark across the
  session, every remote pauses as before. In flight stays session-wide: QUIC's allowance is
  lanes x the mark (one mark with no lanes) plus `WT_INFLIGHT_MAX`. Reads from the client pause
  for the session, never per lane (`hw_wt_pause`).
- **Room for the lanes.** The server's `initial_max_streams_bidi` is 16 plus the lane count.
- **The client library** (`hw_client_opts.wt_server_stream`, `.wt_lanes`; the CLI's
  `--server-stream`, `--lanes N`, and `--streams N` to split a bench over several streams)
  opens the server's number of lanes within its own and 16, and puts each new stream on the lane
  with the fewest open streams, the lowest index of those.
- **What lanes do not fix.** One Wisp stream is still one lane. Spreading one stream over lanes
  would need sequence numbers; it is not part of this.

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
| `webtransport-reset-key-file` | empty | A file that keeps the stateless-reset key across restarts (64 hex digits, made 0600 when missing); empty: a new key each start. |
| `webtransport-idle-timeout-s` | 30 | QUIC idle timeout. |
| `webtransport-max-handshakes` | 1024 | Handshakes in progress per worker. |
| `webtransport-retry-threshold` | 64 | Handshakes in progress per worker past which every Initial gets a Retry. |
| `webtransport-congestion-control` | `bbr` | `bbr`, `bbr2` or `newreno` (see "Congestion control"). |
| `webtransport-lanes` | 8 | Lanes a v2 session may have, lane 0 included (INFO extension `0xE1`); 0 or 1: none; at most 16. |

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
  limits; the server-opened stream (INFO and CONTINUE before the client sends, the password
  case, INFO first, a lane before the INFO), lanes echo, a stalled lane beside a moving one,
  and old clients unchanged.
- Interop, when the tools are on the machine (skipped otherwise, never in CI): `curl --http3-only`
  against the TLS and QUIC layers, and headless Chrome against `GET /webtransport.json` plus a
  WebTransport session with the pinned hash.
