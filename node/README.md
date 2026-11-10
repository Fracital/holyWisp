# holyWisp for Node.js

[holyWisp](https://github.com/Fracital/holyWisp) is a Wisp v1/v2 server written in C. This package
embeds it in a Node.js application: it carries a prebuilt server binary, starts it as a child
process and hands it the WebSocket upgrades your HTTP server receives. It powers
[STomp](https://github.com/Fracital/powerMouse)'s demo server.

```sh
npm install holywisp
```

That is the newest release. `npm install holywisp@nightly` is the newest commit of `master` that
passed its tests, published once a night as a version like `0.5.2-nightly.202611110643.g1a2b3c4`
(the UTC time, then the commit); pin the exact one you tested with.

```ts
import { createServer } from "node:http";
import { holyWisp } from "holywisp";

const wisp = new holyWisp({ logLevel: "info" });
await wisp.start(4); // four worker threads; 0 = one per CPU

const server = createServer();
server.on("upgrade", (req, socket, head) => {
	if (req.url?.startsWith("/wisp/")) wisp.route(req, socket, head);
	else socket.destroy();
});
server.listen(8080);
```

No dependencies, no install script, nothing compiled on your machine. Node 20 or newer.

## API

- `new holyWisp(options?)`: validates the options; nothing is started yet.
- `start(workers = 1)`: start the server with that many worker threads (`0` = one per CPU) and
  resolve once it answers. Rejects with the server's own message if it refuses the config.
- `route(req, socket, head)`: the handler for an HTTP server's `upgrade` event.
- `stop(timeoutMs = 10000)`: ask it to shut down (SIGTERM; on Windows, by closing its stdin), then
  kill it if it has not exited in time.
- `kill()`: kill it now.
- `stats()`: the server's counters (connections, streams, bytes, refusals by cause).
- `isRunning`, `port`, `ports`, `pid`, `restarts`, `config`.

**It comes back.** A server that exits without `stop()` or `kill()` having been called (a crash,
the OOM killer, someone's `kill`) is started again on the port it had, with the worker count it
had. The first attempt is 100 ms after the exit; while it keeps dying the wait doubles up to 5 s,
and it is back to 100 ms once a server has stayed up for 10 s. In the gap `isRunning` is false and
`route()` answers 503; connections that were open are gone, as they would be with any restart.
`restarts` counts how often this has happened since `start()`. `autoRestart: false` turns it off:
the instance is then simply stopped, and `start()` can be called again.

**It does not outlive your process.** The server is stopped when Node exits or is ended by SIGINT,
SIGTERM or SIGHUP, whether or not `stop()` was called; if you handle those signals yourself, your
handler is left in charge. And when Node is killed outright (`kill -9`, the OOM killer, Task
Manager), where no handler runs, the server notices on its own: the wrapper holds a pipe to its
stdin, the kernel closes it with the process, and the server shuts down (`stop-on-stdin-eof`).

### Coming from wispurr

The class, its methods and the option names are wispurr's, so the change is the import and the
class name. What differs:

| | wispurr | holyWisp |
| --- | --- | --- |
| `start(n)` | n processes on n ports, upgrades dealt round-robin | one process, n threads, one port; the kernel balances accepts |
| Limits and reputation | per process, so n workers allow n times the configured rate | one set for the whole server |
| `ports` | n entries | one entry |
| Default `host` | all interfaces | `127.0.0.1`: `route()` is the way in. Set `host: "0.0.0.0"` to expose the port too |
| Client address behind `route()` | every client is `127.0.0.1` unless a proxy header says otherwise, and a client can send that header itself | the peer of the socket `route()` was given; see below |
| Passwords | in the process arguments | in a `0600` file that is deleted once the server is up |
| Defaults | a bundled JSON file | the server's own (`holywisp --help`); an option you leave out is not passed |
| `tcpBufferSize`, `pendingQueueSize`, `dnsMethod`, `websocketPermessageDeflate`, `staticDir` | used | accepted and ignored, with a warning |

### Who the client is

Every limit holyWisp enforces per client (connection rate, bandwidth, reputation) depends on
knowing the client's address, and behind `route()` the server only ever sees a connection from
this process. So `route()` tells it: the address of the socket it was handed is written into the
first of `trustedHeaders`, and any such header that arrived with the request is dropped, because
from an arbitrary client it is just a claim.

If your Node server is itself behind a reverse proxy (nginx, a CDN), list that proxy in
`trustedProxies`. Requests arriving from it keep their forwarding headers, and the server walks
them as usual to the right-most address that is not a trusted hop.

```ts
new holyWisp({ trustedProxies: ["127.0.0.1", "10.0.0.0/8"] });
```

`parseRealIP: false` ignores `trustedProxies`: the client is always the socket's peer.

## Options

All optional. Names follow wispurr; the right-hand column is the `holywisp` flag each becomes, and
`holywisp --help` has the defaults.

| Option | Flag |
| --- | --- |
| `port` (default 6001; the next free port is used if taken; `0` = any) | `port` |
| `host` (default `127.0.0.1`) | `host` |
| `binary` (or the `HOLYWISP_BIN` environment variable) | path of the server to run |
| `autoRestart` (default `true`) | none: whether the wrapper starts a server that died again |
| `allowTCP`, `allowUDP`, `allowDirectIP` | `allow-tcp`, `allow-udp`, `allow-direct-ip` |
| `allowPrivateIPs`, `allowLoopbackIPs`, `allowLinkLocalIPs` | `allow-private`, `allow-loopback`, `allow-link-local` |
| `blacklist.hostnames`, `blacklist.ports` | `block-host`, `block-port` |
| `whitelist.hostnames`, `whitelist.ports` | `allow-host`, `allow-port` |
| `enableV2`, `enableTwisp`, `motd` | `enable-v2`, `enable-twisp`, `motd` |
| `passwordUsers`, `passwordAuth`, `passwordAuthRequired` | `password-user`, `password-required` |
| `parseRealIP`, `trustedProxies`, `trustedHeaders` | `trusted-proxy`, `trusted-header` |
| `connectionsLimitPerIP`, `connectionWindowSeconds`, `bandwidthLimitKbps` | `connections-limit-per-ip`, `connection-window-s`, `bandwidth-limit-kbps` |
| `floodProtection.*` | `flood-protection`, `max-connects-per-*`, `max-in-flight-syns`, `max-streams-per-conn`, `max-concurrent-connections`, `syn-signature*`, `ws-close-after-violations`, `log-blocked-dials` |
| `reputation.*` | `reputation`, `reputation-store`, `reputation-save-interval-s`, `reputation-decay-per-hour`, `reputation-evict-after-days`, `reputation-{warn,throttle,strict}`, `reputation-weight`, `reputation-dest-weight` |
| `proxy`, `proxyUDP` | `proxy`, `proxy-udp` |
| `dnsServers`, `dnsResultOrder`, `dnsTtlSeconds`, `dnsNegativeTtlSeconds`, `dnsTimeoutMs` | `dns-server`, `dns-order`, `dns-ttl-s`, `dns-negative-ttl-s`, `dns-timeout-ms` |
| `bufferRemainingLength`, `maxMessageSize` | `buffer-remaining`, `max-message-size` |
| `wsWriteHighWater`, `streamQueueMax`, `connQueueMax` | `ws-write-high-water`, `stream-queue-max`, `conn-queue-max` |
| `socketBufferSize`, `clientRecvBuffer`, `listenBacklog` | `socket-buffer-size`, `client-recv-buffer`, `listen-backlog` |
| `connectTimeoutMs`, `handshakeTimeoutSeconds` | `connect-timeout-ms`, `handshake-timeout-ms` |
| `resolverThreads`, `busyPollUs`, `tcpNoDelay`, `tcpQuickAck` | `resolver-threads`, `busy-poll-us`, `tcp-nodelay`, `tcp-quickack` |
| `nonWSResponse`, `serveWebclient`, `webclientWispUrl` | `non-ws-response`, `serve-webclient`, `webclient-wisp-url` |
| `logLevel` (default `warn`) | `log-level` |

The egress defaults deny everything that is not a public address. `allowLoopbackIPs` and
`allowPrivateIPs` open the machine and the network this runs on to every client: leave them off
unless that is the point.

## Vite

```ts
import { holyWispVite } from "holywisp/vite";

export default {
	plugins: [holyWispVite({ path: "/wisp/", config: { logLevel: "info" } })],
};
```

Starts a server with the dev and preview servers (`apply: "serve" | "preview" | "both"`), routes
upgrades whose path starts with `path` (or a predicate over the request), and stops it when Vite
closes.

## Platforms

| Platform | Binary |
| --- | --- |
| `linux-x64`, `linux-arm64` | included. Statically linked, so it runs on glibc and musl (Alpine) systems alike |
| `darwin-x64`, `darwin-arm64` | included, for macOS 13 and newer. A port for development: correct, not tuned |
| `win32-x64`, `win32-arm64` | included, for Windows 10 and newer; needs nothing installed. A port for development too |

holyWisp is a Linux server (epoll, `splice`, `SO_REUSEPORT`). The macOS and Windows builds are
there so the package works on the machine you develop on: they run the same code on kqueue and on
Winsock's `select`, copy payloads where Linux moves them without a copy, and have their workers
share one listening socket. Deploy on Linux.

On Windows two options are refused by `start()`, with the server's own message: `enableTwisp`
(there is no pseudo-terminal the server could watch) and a hashed password in `passwordUsers`
(there is no `crypt`). The file passwords travel in is protected by your temporary directory's
access list rather than by a mode. Under WSL 2 the Linux binaries work as they are, with neither
limit.

To run a build of your own, or on a system with no binary here, point `binary` (or
`HOLYWISP_BIN`) at a `holywisp` executable.

Password hashes (a `passwordUsers` value starting with `$`) are checked by the C library's
`crypt`. The Linux binaries carry musl's, which knows `$1$`, `$2a$`/`$2b$`, `$5$` and `$6$` but not
yescrypt (`$y$`); macOS's knows none of those, and Windows has no `crypt` at all. A hash the
library does not know never matches, so on macOS and Windows use plain passwords while developing.

## Building the package

From the repository root:

```sh
make npm        # cross-compiles the six binaries with zig, compiles the wrapper -> node/bin, node/dist
make npm-test   # the wrapper's tests against the tree's release build
cd node && npm pack
```

A `v<version>` tag publishes the tarball to the npm registry from CI (`release.yml`), after the
same tarball has been installed and tested on every platform it carries a binary for. `nightly.yml`
does the same for `master` once a night, under the dist-tag `nightly`:
`scripts/nightly-version.mjs` prints the version, and `scripts/build.mjs` gives the binaries
whatever follows the number in `package.json`'s version, so `holywisp --version` names the nightly.

`make npm` needs [zig](https://ziglang.org) on the PATH (`pip install ziglang` provides it as
`python-zig`). `scripts/smoke-package.mjs` checks an installed tarball.

## License

ISC, like holyWisp.
