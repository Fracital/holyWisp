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
