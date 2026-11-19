# Wisp extensions in holyWisp

The Wisp v2 INFO packet lists extensions as `id(u8) length(u32 LE) meta`, and a peer skips every
id it does not know (the spec: "If an extension is missing from this packet, it is assumed to not
be supported"). holyWisp offers the spec's extensions and a few of its own in the `0xE_` range.
Each private one is opt-in twice over: the server's INFO offers it, and it changes what either side
does only once the client's INFO names it back. A client that does not know an id sees the
protocol of the spec, byte for byte, beside one more entry it skips.

The server's INFO comes first on both transports, so a client always knows what is offered before
it names anything. A client names only what the server offered.

| Id | Name | Server's meta | Client's meta | Packets | Where |
| --- | --- | --- | --- | --- | --- |
| `0x01` | UDP | empty | empty | | spec |
| `0x02` | password | `required(u8)` | `user_len(u8) user pass` | | spec |
| `0x04` | MOTD | the text | | | spec |
| `0x05` | stream-open confirmation | empty | empty | `CONTINUE` | spec, below |
| `0xE1` | lanes (WebTransport only) | `lanes(u8)` | | `LANE 0xE1` | docs/webtransport.md |
| `0xE2` | stream credit | empty | `initial_window(u32 LE)` | `CREDIT 0xE2`, client to server | below |
| `0xE3` | stream limit | `max_streams(u32 LE)` | empty | none | below |
| `0xE4` | upload credit | `initial_window(u32 LE)` | empty | `UPLOAD_CREDIT 0xE4`, server to client | below |

Every meta may grow: bytes past the fields named here are reserved, and a receiver ignores them.
A meta shorter than its fields is as if the extension were absent.

## `0x05` stream-open confirmation

Always offered, since it is always honoured. When the client names it, a TCP stream gets
`CONTINUE(id, buffer_remaining)` once its socket is connected (through the upstream proxy, once
the proxy has answered), and before any DATA for it. A stream that fails to open gets its CLOSE
instead. A UDP stream is never confirmed: the spec confirms a connected TCP socket, wispurr
confirms TCP alone, and a UDP stream has no CONTINUE window. Clients that know this (moonbeam,
the bundled web client) open a UDP stream at once.

## `0xE2` stream credit

Flow control toward the client, per TCP and Twisp stream, in bytes: the receive window a native
socket has. The server offers it with `stream-credit` (on by default); the client names it with
its initial window (under 16384 is 16384). Each stream then sends the client no more DATA payload
than its limit, which starts at the window. `CREDIT` (`type 0xE2, stream, limit(u64 LE)`) is the
total the stream may have sent from its start, and only ever raises the limit, so a repeated or
reordered grant changes nothing. One that is lower, for stream 0, for a stream not open or UDP,
on a session without credit or under 8 bytes is ignored; one in a WebTransport datagram is
dropped. UDP is never counted. AGENTS.md ("Stream credit") has the server's rules in full.

## `0xE3` stream limit

How many streams the connection may have open at once, so a client keeps under it instead of
finding it by being refused `0x49` and backing off. The meta is `max_streams(u32 LE)`: the
connection's cap as admission left it, which is `max-streams-per-conn` (2048 by default), or 16 at
most for a client whose reputation is THROTTLE; 0 means no limit. It is always offered on v2, and
it does not change during the connection.

- **What counts.** Every stream the server has open for the connection, of any type (TCP, UDP,
  Twisp). A stream stops counting when the server reads the client's CLOSE for it, or when the
  server sends its own CLOSE. A CONNECT that finds the limit reached is closed `0x49` and opens
  nothing, as without the extension; it is not a violation and not a reputation event.
- **The client's count is never under the server's** if it counts every stream it opened until
  it sent a CLOSE for it or received one: a CLOSE the server sent may still be on its way, and a
  CLOSE the client sent reaches the server before anything the client sends after it. So a
  client that keeps that count under the limit is never refused for it on a WebSocket, or on one
  WebTransport lane. Packets on different lanes have no order between them: a CONNECT on one
  lane can overtake the CLOSE on another that made room for it, and be refused.
- **Naming it.** The client's meta is empty. Naming it says the client keeps count; it changes
  nothing on the server in this version, and is what a later one that can change the limit during
  the connection would require before sending a new limit. A CONNECT inside the limit can still
  be refused for other reasons (the per-source connect rate, `0x49`; the egress policy, `0x48`).
- **The client library** names it whenever the server offers it, reports the limit
  (`hw_client_max_streams`), and refuses a stream past it in `hw_client_open` with `HW_ERR_TOOBIG`,
  sending nothing.

`tests/ext_cases.h` holds it over both transports, run by `test_e2e` and `test_e2e_wt`.

## `0xE4` upload credit

Flow control toward the server, per TCP and Twisp stream, in bytes: `0xE2` the other way round.
Wisp's own CONTINUE counts a window of DATA packets and is absolute, so it can only be sent once
the window is spent (a CONTINUE sent early lets the client spend the old window and the new one,
and the server cannot tell how much of the old was left). Every window then costs the upload a
round trip with nothing in flight. A limit that counts bytes from the stream's start and only
rises can be sent at any time, as often as wanted, in any order: a repeated or overtaken grant
changes nothing. So the server grants early, and a stream whose remote keeps up is never out of
credit.

- **Negotiation.** The server offers it with `upload-credit` (on by default), its meta
  `initial_window(u32 LE)`: `upload-window` (by default `ws-write-high-water`), at least 64 KiB,
  and at most `stream-queue-max` less one packet of `max-message-size` and 4 bytes. With no such
  room it is not offered (an INFO line in the log says so). The client names it with an empty
  meta. From then on every TCP and Twisp stream opened in the session is paced by it; UDP never
  is. Without both INFOs naming it nothing changes, and v1 never has it.
- **The client** counts the DATA payload bytes it sends on the stream (`sent`) against a limit
  that starts at the initial window. It may begin a DATA packet while `sent` is under the limit,
  and that packet may run past the limit by its own length (at most `max-message-size`), so a
  client never has to split a packet to fit and never waits with credit left. It waits only once
  `sent` has reached the limit. The CONTINUE of a spent packet window is not sent for such a
  stream and a client does not wait for one; the stream-0 CONTINUE and stream-open confirmation
  are sent as always (the confirmation's value is then meaningless).
- **UPLOAD_CREDIT** is `type 0xE4, stream, limit(u64 LE)`: the total the client may have sent on
  the stream from its start. It only ever raises the limit; one that is lower or repeated, for a
  stream the client does not have open, or under 8 bytes is ignored. Over WebTransport it goes on
  the stream's lane, as everything for the stream does.
- **When the server grants.** The server counts what the client sent (`up_recv`, counted where
  the packet window counts packets, every piece of a large frame included) and what is still
  queued toward the remote (`s->out`). Once a stream's bytes have reached the remote's socket
  (after the ingress batch's write, a direct send, or the queue draining), it may grant what has
  reached the socket plus a budget, and does when that raises the limit by half a budget or more:
  one grant per half budget uploaded, and none while the remote does not take anything. The
  budget is `upload-window` shared by the connection's open streams, at least 256 KiB and at
  most the initial window, as the refill CONTINUE shares it (`conn_upload_budget`); a budget that
  shrinks as streams open only delays the next grant, it never lowers a limit.
- **The bound.** At any time the queue toward the remote holds at most a budget plus the one
  packet the client may start inside its credit, which fits `stream-queue-max` with 4 bytes to
  spare: a client inside its credit is slowed by a remote that does not drain, and never closed
  `0x49`. A client past its credit is not closed for that either; it meets the `stream-queue-max`
  backstop (`0x49`) and the `conn-queue-max` pause as any client does. A grant is an answer to
  bytes the client sent that reached their remote, so a client that does not read cannot make
  the server queue more of them than it uploads (and past twice `ws-write-high-water` it is not
  read from at all).
- **The client library** names it with `opts.upload_credit` (`holywisp-client --upload-credit`),
  reports the window (`hw_client_upload_window`), and waits in `hw_client_send` for a grant
  where it would wait for a CONTINUE, within the same timeout.

`tests/ext_cases.h` holds it over both transports: an echo of four windows without a CONTINUE, a
remote that reads nothing behind a 2 MiB `stream-queue-max` (the client is held, never closed,
and everything arrives once the remote reads), and the three ways it is not negotiated.
