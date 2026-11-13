# AGENTS.md: holyWisp

Guidance for AI coding agents working in this repository. Read this fully before making changes.
When a section conflicts with a habit, follow the section. `STYLE.md` is the companion document
for how the C is written; this one is about how the repository is worked on.

## What this project is

holyWisp is a [Wisp](https://github.com/MercuryWorkshop/wisp-protocol) server written in C11 with
no dependencies beyond libc and pthreads. It accepts WebSocket connections, speaks Wisp v1 and v2,
and relays TCP and UDP streams to the hosts its clients ask for. It is built for throughput: one
epoll loop per worker thread, `SO_REUSEPORT` listeners so every worker accepts (and each new
connection then goes to the worker with the fewest), at most
one copy per direction on the data path (none toward the client for a bulk TCP stream, which goes
remote socket to its own pipe to client socket with `splice`), and flow control that is tied to whether the
remote is actually draining.

It ships three things from one tree:

- `holywisp`, the server binary (`src/server/`, public API in `include/holywisp/server.h`).
- `libholywisp-client` and `holywisp-client`, a blocking C client library and a netcat-style CLI
  with an echo benchmark (`src/client/`, API in `include/holywisp/client.h`).
- The test suite (`tests/`): unit tests for every codec and container, and an end-to-end suite
  that starts the real server on an ephemeral port and drives it with the real client.
- `holywisp` on npm (`node/`): a TypeScript wrapper that runs the server binary as a child process
  and routes a Node HTTP server's WebSocket upgrades to it, shaped like wispurr's wrapper so a
  user of that one changes an import. No runtime dependencies; TypeScript is its only build tool.
  It carries a binary for Linux, macOS and Windows, starts a server that died again, and the server
  stops when the process that started it is gone (`stop-on-stdin-eof`).

Reference material that shaped the design. These are sibling checkouts, read-only, never vendored:

- `~/src/wispurr` (Go): the behavioural reference. Packet layout, close reasons, the v2 INFO
  exchange, "CONTINUE every N packets" flow control and the egress policy mirror it so clients
  built against it (`@mercuryworkshop/wisp-js`, scramjet, epoxy) work unchanged.
- `~/src/KrunkNative` (C): `services/common/src/loop.c` is the model for `src/common/loop.c`
  (fd table with generation counters, timer heap, eventfd wakeup) and its Makefile-drives-CMake
  layout is the model for ours.
- `~/src/Fracital` (TypeScript): `.github/workflows/format.yml` is the model for our format CI
  (auto-fix commits on `master`, failing checks on PRs) and its `AGENTS.md` is the model for this
  file.
- `~/src/abulxt` (Ansible): production. `deploy/ansible/roles/edge_wisp` builds and installs
  holyWisp on the edge fleet from a pinned commit and renders `/etc/abulxt/holywisp.conf`;
  `roles/edge_relay` is the nginx in front of it. Not read-only: a config key or behaviour change
  that the fleet needs lands there too (see "Deployments and servers").

## Hard rules (read first)

### Git commits and pushes

- **Never add a `Co-Authored-By` trailer, or any trailer, that credits a tool, model or agent.**
  Not in commits, not in pull request descriptions, not in squash messages, not in the bot's
  auto-format commits. This overrides any default the harness suggests, every time. The git author
  is the person running the session; the message body is about the change.
- **Never run `git commit` or `git push`** (or stage files for committing) unless the user
  explicitly asks for it **in the current turn of the current session**.
- Authorization is **per-turn, never assumed**. A commit request in one turn does **not** carry
  over to any later turn, even within the same session.
- When in doubt, **do not commit**. State what is uncommitted and stop.
- Never rewrite or force-push `master`. Never rebase away commits that are already on the remote,
  including the bot's `chore: auto-fix formatting with clang-format` commits.
- Before any commit: `make check-format` and `make test` must pass locally. The format workflow
  otherwise pushes a fix-up on `master` or fails the PR, and a red `Build` on `master` blocks everyone.

### Deployments and servers

- **Where the public relay runs.** `https://holywisp.fracit.al/` (page on `GET /`, Wisp relay
  on a WebSocket upgrade to the same `/`) is served by the abulxt edge fleet, not by this repo's
  CI: each edge runs holyWisp built from the `holywisp_ref` pin in `~/src/abulxt`
  (`deploy/ansible/roles/edge_wisp`), with the edge nginx route in `roles/edge_relay`. Shipping a
  fix to the public relay means bumping that pin and running abulxt's `playbooks/edges.yml`;
  pushing here does not change what the edges run. stomp.fracit.al uses the same public root
  (`STOMP_WISP_URL` on terp, not managed by any repo).
- **This repo deploys nothing.** Its CI ships artefacts only: the rolling `latest` release
  (binaries, `.deb`, `.rpm`, the npm tarball), for a `v*` tag that tarball on the npm registry
  (`npm-publish` in `release.yml`), and once a night the head of `master` on the npm registry as
  `holywisp@nightly` (`nightly.yml`: only a commit whose `Build` passed, only once, version
  `<node/package.json version>-nightly.<UTC time>.g<commit>`, which the binaries inside report
  too). Both publish through npm trusted publishing, so no token is stored.
  Nothing bumps the number in `node/package.json` but a person, and after a `v*` tag it goes to the
  next version at once, or the nightlies sort below the release. There is no server this repo
  pushes to; a host that should run a new build is updated by whoever operates it (the edges:
  abulxt's ansible pin).
- Do not start, stop or reconfigure a `holywisp` process on a machine that is not the one you are
  developing on. Running `make run` locally against loopback is development; touching a host that
  serves users is deployment.
- Never point a test or a benchmark at a server you do not own. The e2e tests bind their own
  echo services on loopback for exactly this reason.

### Dependencies and the build

- **No third-party code.** No vendored libraries, no `FetchContent`, no `pkg-config` lookups.
  SHA-1 and Base64 exist in-tree only because the WebSocket handshake needs them; TLS does not
  exist in-tree because a reverse proxy does it better. If a change seems to need a library, it
  needs a design conversation first.
- Linux is the platform, by design: epoll, `accept4`, `eventfd`, `SO_REUSEPORT`, `splice`. macOS
  and Windows are ports for development machines (they are what lets the npm package run on a Mac
  or a PC), not production targets and not tuned: both copy where Linux splices and have their
  workers share one listener, and Windows has neither Twisp nor hashed passwords (the server
  refuses a config that asks for either). A platform is two files: a loop backend behind
  `src/common/loop_backend.h` (`loop_epoll.c`, `loop_kqueue.c`, `loop_select.c`) and a half of
  `include/holywisp/sys.h` (`sys_linux.c`, `sys_darwin.c`, `sys_win32.c`), chosen in
  `CMakeLists.txt`. Windows alone has a third part, because it lacks the POSIX socket calls
  themselves: `src/compat/win32/` supplies them over Winsock under their POSIX names (headers in
  `include/`, all of the code in `posix.c`), so no other file knows it is not on POSIX. The one
  platform `#if` in the tree is the pair of `send` flags in `sys.h` (the one architecture `#if` is
  `__x86_64__` around the AVX2 unmask in `ws.c`, which is about the CPU, not the OS; see "The
  unmask"). Do not add another, do not
  write `_WIN32` or a Winsock call outside the three Windows files, and do not call a
  kernel-specific function (`accept4`, `splice`, `pipe2`, `crypt_r`, `forkpty`, `MSG_NOSIGNAL`,
  ...) outside the platform files: add it to `sys.h`, implement it three times, and test the
  promise, not the mechanism, in `tests/test_sys.c`. What is plain POSIX but missing on Windows (a
  libc call, a socket option) goes into the compat directory as what POSIX says it is, never into
  an `#if`. `long` is 32 bits there: anything that can pass 2^31 is a `size_t`, a `uint64_t` or a
  `long long`. Never make the Linux path slower to make another one simpler.
- `-Werror` stays on. Do not weaken a warning flag in `CMakeLists.txt`, disable a sanitizer in the
  Debug preset, or add `// NOLINT` without a comment that says why the checker is wrong there.
- Clang and GCC both build the tree in CI. Code that only one of them accepts is not done.

## Protocol surface (do not regress)

Clients in the wild are not ours. Anything below that changes is a compatibility break even if
every test still passes, so each item has a test and a change to it needs a reason in the commit.

- **Wire format.** 1 byte type, 4 bytes little-endian stream id, payload. CONNECT is
  `type(u8) port(u16 LE) hostname`; CONTINUE is `buffer_remaining(u32 LE)`; CLOSE is `reason(u8)`;
  INFO is `major(u8) minor(u8)` then `id(u8) len(u32 LE) meta` extensions. Codec in
  `src/common/wisp.c`, pinned by `tests/test_wisp.c`.
- **v1 opening.** Right after the 101 the server sends `CONTINUE(stream 0, buffer_remaining)`.
  Nothing else precedes it.
- **v2 negotiation.** Only when the client offered *any* `Sec-WebSocket-Protocol` token *and*
  `enable-v2` is on. The spec names no subprotocol; wispurr treats a non-empty header as the v2
  opt-in and epoxy (scramjet, STomp) sends a random UUID, so the rule is presence, not the string
  `wisp-v2`. The server echoes the offered token *verbatim* (a browser fails the handshake if the
  token it asked for does not come back), sends INFO first, waits for the client's INFO, then
  sends the stream-0 CONTINUE. Until that CONTINUE, the only packets honoured are
  INFO and CLOSE on stream 0. Major version mismatch closes with `0x04`.
- **Extensions advertised.** `0x01` UDP when `allow-udp`, `0x02` password (meta = required byte)
  when any `password-user` exists, `0x04` MOTD when set. Stream-confirm (`0x05`) is honoured when
  the client asks for it: a connected TCP stream gets `CONTINUE(id, buffer_remaining)`. Unknown
  extension ids are skipped, never rejected.
- **Flow control.** The window is counted in DATA packets, not bytes, per TCP stream, reset to
  the advertised window each time it hits zero. That window is `buffer-remaining` capped so a full
  window of `max-message-size` packets fits in `stream-queue-max` (`server_ingress_window` in
  `src/server/server.c`): a client at full window speed into a stalled remote is slowed, never
  closed `0x49`. The CONTINUE for a spent window is *held* while bytes toward the remote are still
  queued (`continue_due` in `src/server/stream.c`), which is why the whole queue, not half of it,
  is the budget: it never holds more than one window. Across a connection, `conn-queue-max` bounds
  the sum of those queues; past it the client's reads pause (`conn_queue_add`) and resume at half
  the mark. Nothing is closed for staying inside its window. The value a *refill* CONTINUE carries
  is dynamic (`conn_window`): the connection's in-flight budget (`ws-write-high-water`) shared by
  its live streams in packets of the size that client actually sends, clamped to [4, the advertised
  maximum], so one stream gets the whole window and ten streams do not make the server buffer ten
  windows. The stream-0 CONTINUE and stream-confirm always carry the maximum. UDP streams are
  never counted. Toward the
  client, one remote read is split into as many DATA packets as it takes (`conn_send_data`), each
  within the negotiated size and within `CONN_FRAME_MAX` (128 KiB of payload, `frame_payload_max`
  in `conn.c`) whatever that size allows: a client holds a whole message before it can use any of
  it, and megabyte frames cost the client and the echo behind it 20 to 40% more per byte while
  saving the server nothing (`test_egress_frames_capped`).
- **Close reasons** are the spec's: `0x02` remote EOF, `0x03` network error, `0x41` invalid
  CONNECT, `0x42` unresolvable/unreachable, `0x43` connect timeout, `0x44` refused, `0x48` blocked
  by egress policy, `0x49` throttled. A client's CLOSE for a stream gets no CLOSE back. A CONNECT
  on stream 0 gets no reply at all (a CLOSE on stream 0 would end the whole connection). A CONNECT
  for an id that is already open closes that stream with `0x41` and opens nothing: the id is the
  only name the two ends share for it, and two streams under one name is two ends that disagree.
- **Closing toward the remote.** A stream's socket is closed in the ordinary way (FIN) except in
  one case, where it is reset: the stream ended from the *client's* side (its CLOSE, or the end
  of its connection), the stream is TCP and not through an upstream proxy, the remote has sent something since
  the client last did (`s->heard`), nothing is queued toward the remote, and the kernel reports
  every written byte acknowledged (`stream_may_reset` in `src/server/stream.c`,
  `hw_sys_close_reset`). A reset leaves no connection in TIME_WAIT and frees the local port at
  once, which on the churn row is 15% more streams per second; an ordinary close of a stream the
  client aborted mid-download was already a reset, because Linux resets on close with unread
  data. Every condition is there so that a reset can never cost the remote bytes the client sent:
  do not widen it (a stream the remote ended, or one the server closes for its own reasons, is
  never reset), and where the kernel cannot tell what is acknowledged (macOS, Windows) it is a
  plain close. `test_close_toward_remote` and `test_close_reset` hold both halves.
- **WebSocket strictness.** Client frames must be masked; unmasked, reserved bits, text frames and
  oversize messages close the socket with the RFC 6455 codes `1002` / `1003` / `1009`. Pings get
  pongs; a CLOSE is echoed. Server frames are never masked.
- **Plain HTTP on the same port.** `GET /health` is `{"status":"ok"}`, `GET /stats` is the
  counters, any other non-upgrade request gets `non-ws-response` (or 426 when it is empty), and a
  malformed head gets 400. Malformed is everything that would make the header table differ from
  what was sent (`hw_http_parse_request` in `ws.c`): too many headers, a name that is not a token,
  a continuation line, a NUL or bare CR in a value. An upgrade refused by
  `connections-limit-per-ip` or by `max-concurrent-connections-per-ip` is 429 with
  `Retry-After: <connection-window-s>`; one whose `Origin` is not on a non-empty `allow-origin`
  list is 403 (a request with no `Origin` is never refused for it: that header is a browser's);
  one from a trusted proxy whose forwarding header was too long to keep whole is 400. All with
  `Connection: close`, and once a reply is queued the connection is not read from again
  (`CONN_HTTP_REPLY` in `conn_reads_stopped`). With `serve-webclient`, `GET /` is the
  embedded client; `webclient-wisp-url` is spliced into it as `window.HOLYWISP_CONFIG.wisp`
  (validated: `ws(s)://`, nothing that can escape a script string) for when the relay is not
  the origin that served the page.

## Egress policy (do not regress)

A Wisp server is an open relay by nature. The policy in `src/server/egress.c` plus
`hw_addr_classify()` in `src/common/net.c` is what keeps it from being a door into the network it
runs on. The defaults deny everything that is not public unicast and every change here needs a
`tests/test_net.c` case.

- Loopback, RFC 1918, CGNAT (`100.64/10`), link-local, unspecified, multicast, broadcast and
  reserved ranges are denied unless the matching `allow-*` is on. There is no `allow-*` for
  multicast, unspecified or reserved: those are never valid stream targets.
- IPv4 wrapped in IPv6 (`::ffff:a.b.c.d`, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, the deprecated
  `::a.b.c.d`) is classified as the IPv4 it wraps. Never add a path that looks at the IPv6 bytes
  alone.
- The check runs on the *resolved* addresses, after DNS, address by address. A hostname that
  resolves to one public and one private address connects to the public one only. A literal IP in
  CONNECT additionally needs `allow-direct-ip`. With an upstream `proxy`, the check still runs
  here first, but the proxy is then handed the *hostname* (SOCKS5 ATYP 3, CONNECT `host:port`) so
  a classifying router can resolve it itself; only a literal IP is sent as an address.
- Hostnames are passed to the resolver as given, but a NUL inside the host, an empty host, a port
  of 0 or a host over 255 bytes is `0x41` before anything is looked up. So is a host with a byte
  outside `[A-Za-z0-9._:\[\]-]` and `_` (`host_chars_ok` in `conn.c`), and a name whose last
  label is a number (`0x7f.1`, `2130706433`, `1.2.3`): a resolver's `inet_aton` turns those into
  an address without asking the DNS, so only the canonical dotted quad is an IPv4 literal
  (`hw_addr_parse` in `net.c`) and nothing else numeric reaches a resolver. That function does not
  take `inet_pton`'s word for it: macOS's accepts `0177.0.0.1` and `fe80::1%eth0`, glibc's
  neither, so an IPv4 literal must be what `inet_ntop` writes back and an IPv6 one holds only hex
  digits, colons and dots. Never trust a libc parser to be as strict as Linux's.
- IPv6 is public only inside `2000::/3`. The translation and tunnel forms that wrap a *public*
  IPv4 address (NAT64, 6to4, IPv4-compatible, IPv4-translated, an ISATAP interface id) are
  reserved, not public: this host has no business being someone's translator. Only IPv4-mapped
  is classified as exactly the IPv4 it wraps.
- The host filters compare a host whole or not at all (`hw_hostlist_allows`,
  `hw_hostlist_blocks`): a host too long to compare is not on an allow list and is on a non-empty
  block list. Never match the part that fits.
- The upstream proxy resolves the hostname again, so this check and that dial can see different
  addresses (DNS rebinding). The server cannot close that gap alone; a proxy that reaches private
  networks has to check what *it* resolved. abulxt's `edge-router.py` does (it resolves once,
  refuses anything not public, and dials or forwards the address it checked).

## UDP on WARP (do not regress)

On the abulxt edges, TCP streams leave through the edge router (a SOCKS5 `proxy`), which sends
each one out through one of several kernel WARP tunnels, chosen by rendezvous hashing of the
stream's site. UDP never goes through the router (`proxy-udp = direct`), so with
`udp-warp-marks` and `udp-warp-state` holyWisp marks each UDP socket (`SO_MARK`,
`hw_sys_set_mark`) for the tunnel the router would have chosen. Then a site's QUIC and WebRTC
leave from the same exit address as its TCP.

- **The choice is the router's, to the bit.** `holywisp/warp.h` repeats `edge-router.py`'s
  `site_key` (the last two labels, or three under a two-letter TLD whose second level is on its
  suffix list), `rendezvous_score` (BLAKE2b-64 of `key "\0" name`, big-endian; `blake2b.c` is
  in-tree for this alone) and `WarpTunnels.pick` (the highest score, ties to the greater name,
  over the tunnels healthy for the address family). An IP literal's key is the address as
  `inet_ntop` writes it, which is what the router is handed. `tests/warp_vectors.h` is
  generated from the router itself (`tests/gen_warp_vectors.py`). A change to either side
  without the other moves sites' UDP to another exit than their TCP: regenerate the vectors and
  change both.
- **The state file only chooses among configured marks.** The router publishes its healthy
  tunnels as `{"v4": [{"name", "mark"}], "v6": [...]}`, replaced atomically. Entries whose mark
  is not in `udp-warp-marks` are dropped (`hw_warp_state_restrict`), so whoever can write that
  file still cannot give a socket an arbitrary mark. The reader is strict and all-or-nothing.
- **Unusable state is today's behaviour, never an outage.** A file that is missing, unreadable,
  malformed or older than `udp-warp-state-max-age-s` means unmarked UDP. The router rewrites
  the file every probe round (15 s), so an old file means a dead router. A process without
  `CAP_NET_ADMIN` starts anyway, with marking off and an ERROR in the log (`warp_init`):
  refusing to start would take the whole relay down over its UDP's exit address. Only a state
  that lists no tunnel for the family, with `udp-warp-fallback refuse`, refuses a stream (`0x42`,
  what the router answers a TCP stream then).
- **No lock on the data path.** The maintenance thread stats the file once a second, reads it
  only when it is another file (inode, size or mtime), and posts each worker its own copy
  (`warp_publish`, `warp_swap_task`). A stream reads only its worker's copy (`w->warp`).
- **What stays unmarked:** TCP (the router marks it), DNS (`dns.c`, the resolver threads) and
  everything holyWisp opens for itself. The egress policy runs before the mark, as it always does.
  `test_warp` holds the vectors and the reader. `test_udp_warp` holds the state tracking and the
  streams: run it also as `unshare -Urn sh -c 'ip link set lo up && build/debug/test_udp_warp'`,
  where the process has the capability and the marks take.

## Security suite (do not regress)

The limiters, reputation and filters are the point of this server. They are process-wide, created
in `hw_server_new` (`build_limiters`), lock internally, and are evicted and persisted by the one
maintenance thread in `server.c`. Each has a unit test (`test_limits`, `test_reputation`,
`test_filter`) and the whole path has `test_security`. Keep these invariants:

- **Where each check runs.** Connection-level checks (the origin allowlist, real-IP resolution,
  per-IP connect rate, reputation tier, the per-IP connection gauge, the concurrent-connection
  semaphore) are in `http_process` at upgrade time, in that order.
  Per-CONNECT checks (per-source connect rate, the Twisp gate) are in `handle_connect`.
  Per-destination checks (host/port filters, per-dest rate, destination reputation, the in-flight
  SYN caps, the SYN-flood signature) are in `stream.c` around the dial. Do not move a check to a
  cheaper-but-wrong place; the per-destination ones must see the resolved address, and they see
  *each* one: `stream_connect_next` applies `dest_policy` to every address it is about to dial,
  not to the first of the list (a name whose first address is a decoy used to carry the rest
  past the per-destination limits).
- **A shared limit is shared by its users, not by one of them.** Every server-wide cap that one
  client could fill has a per-client share next to it (`hw_gauge`, keyed by client address):
  `max-in-flight-syns-per-ip` beside `max-in-flight-syns`, `max-concurrent-connections-per-ip`
  beside `max-concurrent-connections`. A new server-wide cap needs one too. The SYN-signature
  records a connection keeps are bounded (`SIGDET_MAX_PER_CONN`, oldest reused), and the
  resolver and the password pool have bounded queues that fail the newcomer (`EAI_AGAIN`,
  CLOSE `0x49`) instead of growing.
- **What is held against a client.** Only what it did on its own account. Running into a limit
  all clients share (the per-destination windows, the server-wide SYN cap) closes the stream
  `0x49` and is not a violation and not a reputation event, for the client or the destination:
  it used to be, and one client could get a destination refused for everyone, or the others
  closed for its flood. Its own cap (`max-in-flight-syns-per-ip`) is a violation.
  `privateEgress` weighs 0 by default and Twisp-when-off is not scored at all, because any web
  page can make its visitor's browser send either; both are refused (`0x48`) and counted. The
  same reasoning is why `allow-origin` exists: without it, a page's rate-limit events land on
  its visitor's address.
- **A client that will not read.** Backpressure stops the *remotes*; frames the server makes
  itself (pongs, CLOSE for a refused CONNECT, CONTINUE) are answers to what the client sends, so
  past twice `ws-write-high-water` the client is not read from either (`wr_stalled` in
  `conn_backpressure`, cleared at the mark). `conn_sweep` (a per-worker timer) closes a
  connection whose queue has not moved for `client-write-timeout-s`, and with `idle-timeout-s`
  one that has been silent both ways (1001). Nothing a client can send may grow `wbuf` without
  bound; a new server-made frame type has to be covered by this, not exempt from it.
- **The client's address.** `hw_real_ip` reads every instance of the first trusted header the
  request carries, as one list, from the right, and stops at the first entry that is not a
  trusted proxy; an entry that is not an address ends the walk with the peer as the answer. The
  default trusted header is `X-Forwarded-For` alone: a header the proxy in front does not
  overwrite is the client's to choose. `trusted-proxy-secret` makes the headers count only with
  `X-HolyWisp-Proxy-Secret`, for a proxy that shares 127.0.0.1 with other processes (the npm
  wrapper sets one per start). Per-client keys are the full address, IPv6 included.
- **The tables are keyed by what clients choose** (addresses, destinations), so `hw_smap` hashes
  with SipHash under a key drawn once per process from `hw_sys_random`. Do not hash client data
  with anything unkeyed, and do not persist or send a hash.
- **Logs.** `hw_log` writes every control byte of the tag and message as `\xNN`; callers pass
  client strings as they are. A failed login is logged without the user name it tried, and a
  config error never echoes the value of `proxy`, `trusted-proxy-secret` or a `password-user`.
- **Reputation tiers.** STRICT refuses a client at upgrade (or a destination at dial); THROTTLE
  lowers the per-connection stream cap. Events and weights live in `reputation.h`/`.c`; the JSON
  store format is parsed by a hand-rolled reader that must round-trip what the writer emits
  (`test_reputation` covers it). The store is written atomically (temp + rename), mode 0600.
- **Flow control vs. flood control are different things.** `buffer-remaining` is the Wisp CONTINUE
  window (correctness); the `flood-*` limits are abuse control. Don't conflate them.
- **Fail open on allocation failure, fail closed on policy.** A limiter that cannot allocate lets
  the request through (`hw_window_allow` returns 1); a policy that denies always denies. Keep that
  asymmetry: a transient OOM must not lock out every client, but a blocked address stays blocked.
- **Passwords** are compared in constant time, and a `$`-prefixed stored value goes through
  `hw_sys_crypt` (`crypt_r` on Linux), never a plain `strcmp`. That call takes tens of
  milliseconds on purpose, so it never runs on a loop: `auth.c` has two threads of its own and
  posts the answer back (`auth_check`, `auth_done` in `conn.c`), with the resolver's ownership
  rules, a queue of 64 past which a login is turned away with `0x49`, and the same hash computed
  for a user that does not exist. An empty password is refused in the config
  (`hw_server_config_add_user`): the password extension cannot tell it from none. Where there is
  no crypt(3) at all
  (`hw_sys_has_crypt`: Windows) a config holding a hashed password is refused when the server is
  made, not left to never match. The config that holds them is never logged and is installed
  `0640 root:wisp`.
- **Bandwidth throttling pauses, never drops.** `conn_charge_bandwidth` suspends reads and arms a
  timer; it must never discard stream data. It charges both directions: a throttled connection's
  streams stop reading from their remotes too (`conn_sync_streams`), or the limit would only
  ever have applied to uploads. The upstream proxy and DNS client are in `proxy.c` and
  `dns.c`; the destination is resolved and policy-checked before the proxy is dialled, so egress
  still applies through a proxy, and the proxy then receives the hostname (see "Egress policy").
  UDP through a proxy is refused unless the operator sets `proxy-udp = direct`, which relays UDP
  around the proxy on purpose; it is never leaked by accident.

## Twisp / terminal streams (do not regress)

`enable-twisp` runs a command on a PTY and relays it (`twisp.c`). The command line is the
*client's*: the CONNECT payload is split like a shell would and executed as the server's user,
with nothing in the config narrowing what it may be. It is a remote shell by design, so the gate in `handle_connect` is the whole access-control story and must stay
intact: **`enable-twisp` on, the client on Wisp v2, and the client authenticated** with a
configured password. Probing it unauthenticated while it is on is a reputation event; while it is off the CONNECT is
closed `0x48` and nothing is scored (see "What is held against a client"). The config validator refuses
`enable-twisp` without `enable-v2` and at least one `password-user`, and on a platform with no
pseudo-terminal (`hw_sys_has_pty`: Windows) refuses it outright. The terminal and its process are
the platform's (`hw_sys_pty_spawn`, `_resize`, `_end`); `twisp.c` holds the gate and the command
line. The systemd sandbox
(`NoNewPrivileges`, capability drop, read-only FS, syscall filter) is the backstop that keeps a
spawned shell from escalating; do not weaken it to make Twisp "more useful". The child gets the
PTY and nothing else: on Linux every descriptor is made close-on-exec in the call that creates
it, and on macOS, where that takes a second call, the child closes everything above 2 itself.

## Concurrency model (do not regress)

- One `hw_loop` per worker thread. Every `hw_conn` and `hw_stream` belongs to the loop it was
  created on and is only ever touched from that thread. The only cross-thread paths are
  `hw_loop_post()` (resolver completions, eventfd-woken), a worker's inbox of accepted
  descriptors (below) and the `_Atomic` counters in
  `hw_server` and `hw_worker` (the per-packet byte counters live in the worker so no cache line
  is written by two threads; `hw_server_stats_get` sums them). Do not add a mutex to the data path; if a design needs one, it is the wrong design.
- **Placement.** The kernel deals connections to the workers' listeners by a hash, which is even
  over thousands and lumpy over a handful: 8 connections on 16 workers usually put two on one
  worker, and those two share a core for as long as they live (on the bench VM the churn row
  ran on 6 saturated workers instead of 8). So `accept_cb` keeps a connection only if no worker
  has fewer (`least_loaded`, by `hw_worker.load`); otherwise `hand_off` puts the untouched
  descriptor and peer address in the target's inbox and posts `inbox_task`, and the `hw_conn` is
  created on the loop that receives it. `load` is raised by the accepting thread before the
  hand-off, so a burst accepted in one pass is spread, and lowered in `conn_release`. Only a
  descriptor ever crosses threads; never hand over a connection that exists, and never read
  another worker's fields besides `load`. `test_connections_spread` holds it.
- **Deferred free.** `conn_close()` tears the socket and streams down immediately but frees the
  `hw_conn` on the next loop iteration via `hw_loop_post`. Streams are freed immediately by
  `stream_close()`. The re-entrancy rules at the top of `src/server/conn.c` and
  `src/server/stream.c` follow from this: after any call that can write to the client, check
  `c->closing` and return; never touch the stream after `stream_close()` or after a call that may
  have closed the connection. `c->closing` does not show a stream that was closed alone: a function
  that can do that (`stream_flush`, `stream_connected`, `signature_record`) reports it in its result,
  and the caller tests that result, never `s->state` (both use-after-frees found so far read it).
- **fd generations.** The loop delivers an event only when the fd's generation matches the one it
  was registered with, so a close-and-reuse inside a dispatch batch is safe. Do not cache fds
  across callbacks.
- **An fd that is not being read must not be able to spin the loop.** Readiness is
  level-triggered, and a kernel reports error and hang-up whatever the interest. So: a backend
  asks for the half-close (`EPOLLRDHUP`) only together with `HW_EV_READ`
  (`test_half_close_needs_read_interest`); a paused stream that gets an error or hang-up it will
  not act on takes its fd off the loop (`s->detached`, re-added by `stream_update_events`); a
  connection whose reads are stopped (`conn_reads_stopped`) closes on HUP or ERROR; and a
  listener that fails with EMFILE or ENFILE is disarmed for `ACCEPT_RETRY_MS` instead of being
  retried in a loop (`accept_resume_cb`). Each of these was a worker at 100% CPU that any client
  could cause. A new "ignore this event for now" has to say which of the four it is.
- **Every wait has an end.** A stream has a timer from CONNECT to connected, not only around
  `connect()`: resolving (`0x42`) and the upstream proxy's handshake (`0x43`) are covered by
  `open_timeout_cb` on the same `connect_timer`.
- **Relay pipes.** A TCP stream whose remote delivers full reads (`s->bulk`) gets its own pipe
  (`hw_spipe`, opened on first use) and relays remote to client through it without a copy
  (`conn_splice_data`): the frame header is appended to `wbuf`, the payload is spliced into the
  pipe, and a mark (`hw_pipe_mark`) records "after this many queue bytes, splice n from this
  pipe". `conn_flush` sends `wbuf` up to the head mark (with `MSG_MORE`), empties that pipe into
  the socket, and goes on, so frames never interleave and any number of streams can have a
  payload queued at once. One splice takes at most a frame's payload (`CONN_FRAME_MAX`), however
  large the pipe, and one read event on the stream relays up to `STREAM_MAX_READS_PER_EVENT`
  pipes' worth of bytes in as many frames as that is (the byte budget in `stream_read`), so a
  smaller frame does not mean less work per wakeup. A stream may not refill its pipe while its previous payload is still in
  it: it parks (`stream_park`) and `mark_pop` unparks it; it never copies behind its own pipe. A
  stream that closes with a payload queued leaves its pipe to the queue (`conn_pipe_drop`), which
  frees it when the payload is out or the connection closes (`marks_free`). The kernel charges
  pipe memory per user and, past `fs.pipe-user-pages-soft`, hands out 8 KiB pipes that make
  every splice tiny: a pipe under 256 KiB is refused and that stream copies, and the worker waits
  before asking again. A pipe costs two descriptors per bulk stream. A bulk stream stays bulk
  through isolated small splices (`bulk_miss`); it takes a run of them to leave. Small reads, UDP
  and PTY streams never use a pipe: three syscalls for a tiny frame cost more than one copy.
- **The ingress batch.** DATA for an idle TCP stream is not written packet by packet.
  `stream_on_data` records a pointer into the connection's read buffer in the worker's batch
  (`batch_iov`, one stream at a time) and `stream_batch_flush` sends up to `HW_BATCH_MAX` payloads
  with one `sendmsg`, queues what the socket did not take and then counts the packets against the
  window. The pointers are only valid while the read buffer does not move, so `conn.c` flushes
  before `hw_buf_reserve`, before any non-DATA packet (a CLOSE must not overtake its stream's
  data), before reusing the fragment buffer and before `ws_process` returns; `hw_buf_consume`
  never moves or reallocates. `stream_close` drops a batch that belongs to the stream it frees.
  A DATA frame of 128 KiB or more that is still arriving is not reassembled: `ws_frames` reads its
  Wisp header, then unmasks and forwards each piece as it comes (`pt_left`, `stream_on_data_part`),
  and only the last piece counts as a packet against the window. If the stream closes mid-frame
  the rest of the frame is read and dropped.
- **Busy polling.** `busy-poll-us` (0 by default) makes a worker poll that long before it sleeps,
  but only after an iteration that delivered events, so an idle server never spins
  (`hw_loop_set_busy_poll`). It trades CPU for round-trip latency and changes nothing else.
- **The flush batch.** Small frames toward a client are not written one by one. `conn_kick` writes
  at once when the queue holds a pipe payload or has reached `CONN_DEFER_MAX` (16 KiB); otherwise
  the connection goes on its worker's flush list and `conn_batch_end`, the loop's batch-end hook
  (`hw_loop_set_batch_end`), writes it after the posted tasks of an iteration and again after its
  events and timers, always before the loop can sleep. So the CLOSE and small DATA frames that
  several streams produce in one pass leave in one send. Two things do not wait: a CONTINUE
  (`conn_send_continue` flushes; the client is stalled until it arrives, and deferring it
  measurably slowed a connection with ten busy streams) and anything sent right before `conn_close` (flush first, as
  `handle_info` does, or the frame is lost with the socket). The list is emptied before any
  `conn_free_task` can run, which is what makes it safe to hold `hw_conn` pointers in it. The
  retries after a short write in `conn_flush` and `conn_splice_data` are deliberate: removing them
  saved 11% of the syscalls and lost 3 to 4% of throughput.
- **The unmask.** `hw_ws_mask` is the server's only per-byte work in user space (every uploaded
  byte, a tenth of its CPU under load). It goes 32 bytes a step with the compiler's generic
  vectors, compiled twice on x86-64 and picked at the first call by asking the CPU (`cpuid` and
  `xgetbv`, never `__builtin_cpu_supports` or an ifunc, which musl and Mach-O lack): AVX2 was 4.8%
  more bytes per CPU second at 16x4 on the bench VM, SSE2 half that. Elsewhere it is two NEON or
  SSE2 registers.
- **Measured and not kept** (bench VM, 2026-11-12, alternating A/B, 6 to 8 rounds). None of these
  moved throughput or bytes per CPU second outside the noise, so do not redo them without a new
  reason: reading a copied remote read straight into `wbuf` behind a header gap (it saves one
  `memcpy`, which is not where the time goes); entering splice mode at 16 KiB or 4 KiB, or always
  splicing (under load streams are already bulk); deferring frames past 16 KiB to the batch end;
  and splicing up to 1 MiB into a pipe per fill, framed as several 128 KiB packets. That one
  cut the syscalls per frame by 16% and still changed nothing: past about 2 GiB/s a stream costs
  per byte (the kernel's copies and TCP), not per syscall, and a bigger fill only coarsens how
  streams share a connection.
- **Backpressure.** When a client's send queue (`wbuf` plus the payloads queued in pipes) passes
  `ws-write-high-water`, every stream on that connection stops reading from its remote
  (`stream_pause`), and resumes at a quarter of the mark.
  Toward a slow remote, bytes queue in `s->out` up to `stream-queue-max` (and `conn-queue-max`
  across the connection, which pauses the client's reads instead), then the stream closes
  `0x49`. Both limits are configuration; neither may become unbounded.
- The resolver owns `hw_resolve_req` from `hw_resolve()` until its delivery task runs or
  `hw_resolver_free` drops it. Cancellation is a flag read on the loop thread. Do not free a
  request from stream code. `auth.c` is the same pattern for `hw_auth_req` (`auth_check`,
  `auth_cancel` from `conn_close`, `auth_free`), and a third thing that leaves the loop for a
  thread should be a third copy of it, not a new idea.

## Verification before you hand work off

- `make test` (Debug, ASan + UBSan) and `make test-release` both pass. If your machine's GCC has
  no sanitizer runtime, `make build CC=clang` after `rm -rf build/debug`; CI runs both compilers.
- `make check-format` is clean. Run `make format` first; do not hand-indent.
- `make tidy` adds no warnings. It needs the Debug compile database (`make build` creates it).
- If you touched the protocol path (`conn.c`, `stream.c`, `wisp.c`, `ws.c`, `client.c`), run the
  e2e binary several times in a row (`for i in 1 2 3 4 5; do build/debug/test_e2e; done`): the
  suite is deterministic but timing-sensitive bugs show up as flakes, not failures.
- If you touched the data path, run the real binaries against each other once:
  `build/release/holywisp --port 6001 --allow-loopback --allow-direct-ip` and
  `build/release/holywisp-client --bench 268435456 127.0.0.1 <echo port>` against any TCP echo
  service. Throughput on loopback should be hundreds of MiB/s; a drop to tens is a regression.
- If you touched a limiter, a timeout, backpressure or anything else a hostile client leans on,
  run `test_abuse` several times (`for i in 1 2 3 4 5; do build/debug/test_abuse || break; done`).
  It holds the cases that were found by attacking the server: a client that never reads, a remote
  that resets while paused (it measures the server's CPU time), the per-IP caps, the origin
  list, bandwidth on downloads, hostile host bytes, raw CONNECTs, passwords on and off the loop.
  A fix for an abuse case is not done until this file fails without it.
- If you touched the proxy path, run `test_security` several times (it starts real SOCKS5 and HTTP
  CONNECT proxies in-process): `for i in $(seq 1 20); do build/debug/test_security || break; done`.
  A service a test runs on a thread of its own closes its listener on that thread (`accept_loop`):
  closed from the case, the descriptor's number went to the next case's server while the thread
  was still between two accepts, and it took that case's connections, about one run in 260.
- If you added or renamed a config key or CLI flag: `src/server/config.c` (parser and `--help`
  text), `README.md` (the table), `holywisp.conf.example`, `deploy/holywisp.conf` and this file's
  relevant section if it changes behaviour.
- If you added a public function: it is declared in exactly one `include/holywisp/*.h`, has a
  contract comment, and a unit test exercises it.
- If you touched `node/`, or added, renamed or changed the meaning of a config key: `make npm-test`.
  The wrapper turns its options into `holywisp` flags (`node/src/config.ts`) and passes its own
  values for the real-IP keys, so a key that changes here changes there, in `node/README.md`'s
  table and in `tests/config.test.mjs`. The wrapper's rule for client addresses is a security
  invariant: `route()` drops every trusted header that arrives from a peer outside
  `trustedProxies` and writes the socket's peer address itself. Do not forward them unfiltered.
  Its own headers go first in the head it writes, with the secret of this start
  (`trusted-proxy-secret`, generated per start, passed in the 0600 file, never in argv), and a
  copy of the secret header from the client is dropped: the server believes proxy headers from
  127.0.0.1 only with that secret, so another local process cannot name a client. A socket with
  no peer address at all (a front on a Unix socket) counts as 127.0.0.1 and says so once in the
  log; one whose address does not parse is refused. The binary and the wrapper change together
  here: after touching either side of that exchange, `make npm` before `make npm-test`.
- If you touched `loop.c`, a loop backend, `sys.h` or any of its halves, or `src/compat/win32`:
  nothing here runs macOS, so `make npm` is the local check that both macOS targets still compile
  with `-Werror` (zig cross-builds them); the `macOS` job in `build.yml` is where that code
  executes, under the sanitizers. Windows can be run here: `make test-windows` cross-builds the tree
  with zig and runs every test under Wine (a real Winsock, but not Windows; the `Windows / tests`
  job runs the same binaries on the real thing). The compat layer makes Winsock keep POSIX's
  promises where the server's correctness rests on them, and those must stay: a non-blocking send
  takes at most one send buffer and reports the rest unsent (Winsock would take all of it, and
  the CONTINUE that is held while bytes are queued would never be held), a blocking send returns
  when the peer has taken all but a send buffer (Winsock returns at once with the whole write
  buffered, and nothing that waits for its peer would wait), a non-blocking accept never waits
  (workers woken for one connection race inside Winsock's, and the loser sat there deaf; they go
  one at a time), a failed connect is an
  error event (`select`'s third set; `WSAPoll` loses it on older Windows), and a descriptor is a
  small int that `close` accepts. A backend must keep what `loop_backend.h` promises (level-triggered readiness,
  the generation carried with every event) and report a failed connect as an error event:
  `stream_io_cb` treats `HW_EV_ERROR` as failure even when `SO_ERROR` reads clean, because kqueue
  carries the error in the event.
- If you touched the release build flags or added a platform: `make npm` (needs zig) and run the
  wrapper's tests with the packaged binary (`cd node && node --test tests/*.test.mjs`).
- The wrapper's hold on its server is two things, and both are tested in `node/tests`: it starts a
  server that exited unasked again (`autoRestart`, backing off from 100 ms to 5 s, cancelled by
  `stop()` and `kill()`), and it gives the server a pipe as stdin with `stop-on-stdin-eof`, which
  is what ends the server when Node is killed outright and what `stop()` uses on Windows, where
  there is no SIGTERM. Never spawn it with an inherited or ignored stdin: `/dev/null` is at end of
  file from the start, and the server would stop as soon as it was up.
- Release builds carry `HW_HARDEN` (stack protector everywhere but Windows; FORTIFY, PIE and
  full RELRO on Linux). It is off under the sanitizers and must not cost the data path: if a
  bench row moves, find the flag, do not drop the option. The unit has no `ExecReload` on
  purpose: the server has no SIGHUP handler, so a reload would stop it.
- If you touched packaging or the unit: `bash deploy/package.sh all` builds all four packages, and
  `systemd-analyze security --offline=true deploy/systemd/holywisp.service` must still rate "OK"
  (~1.3). Never lower the sandbox to work around a bug; fix the bug. `holywisp-client` is the
  client and nothing else: no maintainer scripts, no user, no unit, no config (the release
  workflow installs it alone on a clean system and fails if any of those appear). Until 0.5.3-2
  the client's binary was in `holywisp`, and the client package takes it over with `Replaces`
  (rpm: `Conflicts`). The .deb has no `Breaks`, because apt satisfies one by removing the older
  server, and installing a client must never remove a server. A packaging-only change raises
  `pkg_release` in `package.sh`.

## Repository layout

| Path | What it is |
| --- | --- |
| `include/holywisp/hw.h` | Project macros, `HW_ERR_*`, `hw_now_ms`. Included by everything. |
| `include/holywisp/buf.h`, `src/common/buf.c` | Growable byte buffer with a read cursor; every queue in the server is one. |
| `include/holywisp/loop.h`, `src/common/loop.c` | The event loop: fds with generations, timer heap, thread-safe post. |
| `src/common/loop_backend.h`, `loop_epoll.c`, `loop_kqueue.c`, `loop_select.c` | The kernel half of the loop: readiness for a set of fds, on epoll (Linux), kqueue (macOS) and Winsock's select (Windows). |
| `include/holywisp/sys.h`, `src/common/sys_linux.c`, `sys_darwin.c`, `sys_win32.c` | Every call the kernels disagree on: sockets that never raise SIGPIPE, the extra listeners, relay pipes and splice, keepalive, the reset close, socket marks, crypt, the pseudo-terminal, random bytes fit for keys. |
| `src/compat/win32/` | Windows only. `include/`: the POSIX headers Windows lacks or falls short of (`sys/socket.h`, `poll.h`, `unistd.h`, `fcntl.h`, `signal.h`, ...). `posix.c`: what they declare, over Winsock, with a descriptor table and errno. `hw_w32.h`: what the three Windows files share. |
| `include/holywisp/net.h`, `src/common/net.c`, `src/common/resolver.c` | Sockets, address parsing and classification, the getaddrinfo thread pool. |
| `include/holywisp/ws.h`, `src/common/ws.c` | WebSocket framing, masking, HTTP upgrade request/response parsing. |
| `include/holywisp/wisp.h`, `src/common/wisp.c` | Wisp packet codec and constants. The wire format lives here and nowhere else. |
| `include/holywisp/map.h`, `src/common/map.c` | `uint32_t -> void *` open-addressing map (stream id to stream). |
| `include/holywisp/sha1.h`, `base64.h` | Only for `Sec-WebSocket-Accept`. |
| `include/holywisp/warp.h`, `src/common/warp.c`, `blake2b.h`, `blake2b.c` | UDP on WARP: the edge router's site key, score and tunnel choice, the state file's reader, the mark list. |
| `include/holywisp/log.h`, `src/common/log.c` | Levelled logging, one `write(2)` per line. |
| `include/holywisp/server.h` | Public server API: config struct, new/start/stop/free, stats. |
| `src/server/internal.h` | `hw_server`, `hw_worker`, `hw_conn`, `hw_stream` and the functions conn.c/stream.c share. |
| `src/server/server.c` | Config defaults, listeners, worker threads, lifecycle, stats. |
| `src/server/conn.c` | One client: HTTP upgrade, WebSocket frames, Wisp dispatch, write queue, backpressure. |
| `src/server/stream.c` | One relayed TCP/UDP stream: resolve, connect with fallback, both data directions. |
| `src/server/egress.c` | The allow/deny decision for a remote address (address class only). |
| `src/server/proxy.c` | Upstream SOCKS5 / HTTP CONNECT handshake, driven on the stream socket. |
| `src/server/auth.c` | Hashed-password checks on two threads of their own, answered on the loop that asked. |
| `src/server/twisp.c` | PTY terminal streams: shell-split the command, `hw_sys_pty_spawn`, relay the master. |
| `src/server/config.c`, `config.h` | `key = value` file and `--flag` parsing, `--help`, validation. |
| `src/server/main.c` | The `holywisp` binary: parse, run, stop on SIGINT/SIGTERM, or (`stop-on-stdin-eof`) when stdin closes. |
| `include/holywisp/limits.h`, `src/common/limits.c` | Fixed-window rate counter, semaphore, per-key gauge, token-bucket bandwidth, SYN-signature ring. |
| `include/holywisp/reputation.h`, `src/common/reputation.c` | Per-IP / per-dest scoring, tiers, decay, JSON persistence. |
| `include/holywisp/filter.h`, `src/common/filter.c` | Host/port allow-block lists, CIDR match, real-client-IP from proxy headers. |
| `include/holywisp/dns.h`, `src/common/dns.c` | Built-in A/AAAA DNS client and the shared result cache. |
| `include/holywisp/smap.h`, `src/common/smap.c` | String-keyed open-addressing map used by the limiters, reputation and DNS cache; SipHash under a per-process random key. |
| `include/holywisp/client.h`, `src/client/client.c` | Blocking client library: connect, open, send, poll, read_exact. |
| `src/client/main.c` | `holywisp-client`: stdin/stdout relay and `--bench`. |
| `tests/test.h` | `CHECK`, `CHECK_EQ`, `CHECK_STR`, `RUN`. The entire test framework. |
| `tests/test_e2e.c`, `tests/test_security.c` | End-to-end: real server + real services + real client. The reference for the APIs. |
| `tests/test_warp.c`, `tests/warp_vectors.h`, `tests/gen_warp_vectors.py` | The WARP tunnel choice against vectors generated from `edge-router.py`. |
| `tests/test_udp_warp.c` | The state file as the server tracks it, and UDP streams marked, unmarked and refused. |
| `tests/test_abuse.c` | End-to-end from the attacker's side: each case is something a hostile client or remote did to the server before it was fixed. |
| `tests/test_client.c`, `tests/test_log.c` | The client library against servers that misbehave; log lines that hold client bytes. |
| `node/src/index.ts` | The npm package's `holyWisp` class: spawn, readiness, `route()`, stop, orphan cleanup. |
| `node/src/config.ts` | wispurr-shaped options to `holywisp` flags; secrets go to a 0600 file, not argv. |
| `node/src/vite.ts`, `logger.ts`, `path.ts` | Vite plugin, log relay, where the platform's binary lives. |
| `node/scripts/build.mjs` | `make npm`: static binaries per platform via zig, `tsc`, licence copy. A prerelease in `package.json`'s version becomes the suffix `holywisp --version` prints. |
| `node/scripts/nightly-version.mjs` | The version a nightly of HEAD publishes as. |
| `node/tests/` | `node --test` suites: option mapping, and the wrapper against the real server. |
| `cmake/zig-toolchain.cmake` | CMake toolchain for `zig cc` cross builds (Linux musl static, macOS, Windows). |
| `deploy/systemd/holywisp.service` | The hardened unit (the sandbox is load-bearing; see "Security suite"). |
| `deploy/holywisp.conf` | The installed default config (loopback bind, reputation store under /var/lib). |
| `deploy/debian/`, `deploy/rpm/holywisp.spec` | Debian maintainer scripts and the RPM spec. |
| `deploy/package.sh` | Builds two `.deb`s (dpkg-deb) and two `.rpm`s (rpmbuild) into `build/packages/`: `holywisp`, the server as a service, and `holywisp-client`, the client alone. |
| `CMakeLists.txt`, `CMakePresets.json`, `Makefile` | CMake compiles; the Makefile is the one entry point (`make help`). |
| `.clang-format`, `.clang-tidy`, `.editorconfig` | Enforcement of `STYLE.md`. |
| `.github/workflows/build.yml` | GCC + Clang, Debug + Release, ctest, clang-tidy, binary smoke; macOS; the Windows cross build and its tests on Windows; the npm package installed and tested on every platform it carries. |
| `.github/workflows/format.yml` | clang-format drift: auto-fix commit on `master`, failing check on PRs. |
| `.github/workflows/release.yml` | Rolling `latest` release: prebuilt binaries plus the `.deb`, the `.rpm` and the npm tarball, one build per push; `npm publish` for a `v*` tag. |
| `.github/workflows/nightly.yml` | `holywisp@nightly` on npm, nightly and on dispatch: waits for `Build` on the commit, builds the tarball once, runs it on every platform it carries, publishes that file. Only its `publish` job holds the OIDC identity, and it runs nothing from the tree. |

## Hand-off

End every piece of work with: what changed (files and behaviour), what you ran and its result
(the tail of `make test`, the bench number if you touched the data path), and anything left undone
or deliberately out of scope. If anything is uncommitted, say so; do not commit to tidy up.
