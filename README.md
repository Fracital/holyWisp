# holyWisp

A [Wisp](https://github.com/MercuryWorkshop/wisp-protocol) server in C11 with no dependencies
beyond libc and pthreads, plus a C client library and CLI that drive it in the tests.

- Wisp v1 and v2 (`wisp-v2` subprotocol): UDP, password auth, MOTD and stream-confirm extensions
- TCP and UDP streams, IPv4 and IPv6, asynchronous DNS with address fallback
- One epoll loop per worker thread, `SO_REUSEPORT` listeners, no locks on the data path
- Flow control that waits for the remote to drain before handing the client another window
- Default-deny egress to loopback, private, link-local and reserved address space
- `/health` and `/stats` over plain HTTP on the same port

## Build

Requires CMake 3.20+, a C11 compiler and Linux (epoll). Ninja is used when present.

```sh
make            # debug build with ASan/UBSan -> build/debug
make test       # unit + end-to-end tests
make release    # optimised build -> build/release
make help
```

## Run

```sh
build/release/holywisp --port 6001
build/release/holywisp --config holywisp.conf --log-level debug
```

Every option is a `--flag value` (or `--flag=value`) and a `flag = value` line in the config
file; flags override the file. Boolean flags may stand alone (`--allow-loopback`).

| Key | Default | What it does |
| --- | --- | --- |
| `host`, `port` | `""`, `6001` | Bind address (all interfaces, dual-stack) and port |
| `workers` | `0` | Worker threads; `0` means one per CPU |
| `allow-tcp`, `allow-udp` | on | Stream types clients may open |
| `allow-direct-ip` | off | Accept literal IP addresses in CONNECT |
| `allow-private`, `allow-loopback`, `allow-link-local` | off | Egress to RFC 1918 / CGNAT, `127/8` + `::1`, `169.254/16` + `fe80::/10` |
| `enable-v2` | on | Offer the Wisp v2 handshake to clients that ask for `wisp-v2` |
| `motd` | `""` | Message of the day sent in the v2 INFO packet |
| `password-user` | none | `USER:PASS`, repeatable; enables the password-auth extension |
| `password-required` | off | Refuse clients that do not authenticate (also refuses v1) |
| `buffer-remaining` | `128` | CONTINUE window, in DATA packets per stream |
| `max-message-size` | 1 MiB + 5 | Largest WebSocket message accepted |
| `ws-write-high-water` | 8 MiB | Pause remote reads when a client's send queue passes this |
| `stream-queue-max` | 16 MiB | Bytes queued toward a slow remote before the stream is throttled |
| `max-streams-per-conn` | `2048` | `0` = unlimited |
| `connect-timeout-ms` | `15000` | Remote TCP connect, per address |
| `handshake-timeout-ms` | `10000` | HTTP upgrade plus v2 INFO exchange |
| `resolver-threads` | `4` | getaddrinfo threads shared by all workers |
| `tcp-nodelay` | on | `TCP_NODELAY` on client and remote sockets |
| `non-ws-response` | a short banner | Body returned to plain HTTP GETs (empty = 426) |
| `log-level` | `info` | `debug`, `info`, `warn`, `error`, `none` |

TLS is not built in: put the server behind nginx, Caddy or Cloudflare and let them terminate
`wss://`. Rate limiting, IP reputation and upstream proxies are likewise left to the reverse proxy.

## Client

`holywisp-client` is netcat through a Wisp server:

```sh
# stdin/stdout <-> example.org:80 via the server on localhost
printf 'GET / HTTP/1.0\r\nHost: example.org\r\n\r\n' | build/release/holywisp-client example.org 80

# UDP, wisp-v2 with a password
build/release/holywisp-client -s ws://wisp.example:6001/ --udp --user me --pass secret 1.1.1.1 53

# throughput against a TCP echo service
build/release/holywisp-client --bench 268435456 echo.example 7
```

The library behind it is `include/holywisp/client.h`: connect, open streams, send, poll events.
`tests/test_e2e.c` is the reference for using it.

## Layout

```
include/holywisp/   public headers
src/common/         buffers, logging, epoll loop, resolver, WebSocket + Wisp codecs
src/server/         holywisp: config, workers, connections, streams, egress policy
src/client/         libholywisp-client and the holywisp-client CLI
tests/              one binary per module plus the end-to-end suite, run by ctest
```

`STYLE.md` has the coding rules, `AGENTS.md` the rules for anyone (human or agent) changing the
repository, and `.github/workflows/` the CI that enforces both.
