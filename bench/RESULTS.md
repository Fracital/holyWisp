# Benchmark results

Run on 2026-11-16 (UTC). Charts for every table below are in `charts/`, light and dark.
The method, the exact server and client command lines, and the install notes for each server are in
[README.md](README.md). Regenerate with `python3 -I bench/run.py` and `python3 -I bench/charts.py`.

The host was a 16-vCPU KVM guest (Xeon Gold 6348, Debian 13) that ran nothing else. Servers,
clients and the echo service shared its 16 cores, so the two rows with many connections are bounded
by the whole box, not by the server alone. With 16 connections the box had no idle time left under
holyWisp and about one idle core under finalwisp, and how many cores a server's threads take from
the 16 clients and the echo service decides that row as much as what the server costs per byte.
finalwisp's default placement leaves five or six of its sixteen threads without a connection; with
`--balance`, which spreads the connections over all sixteen as holyWisp does, it relayed 7,572 and
7,672 MiB/s there instead of 9,243 and 9,478 (two runs each, on the same host after this one), and
holyWisp with `--workers=12` relayed 9,747 to 9,781 against 8,690 to 8,823 with its default of one
worker per core (three runs each).

Each scenario ran twelve times with the server order rotated, so every one of the six servers held
every position in the order twice. The position matters on this host (see "Running it" in the
README), and the latency table shows it most: a 64 B round trip measured 45 to 52 us for the four
fastest servers when they ran first after the saturating 16-connection scenario, and 76 to 87 us in
the later positions (holyWisp twice measured 57 to 58 us there). The medians in that table are from
the later mode. They are 24 to 38 us longer than in the run of 2026-11-12 for every server, the
Python one included, with the same kernel and the same server builds apart from holyWisp's: the
host's round trip changed between the two days, and the table compares servers, not days.

Read differences of a few percent as noise. The rows with one connection are the noisiest:
holyWisp's native one-stream runs range from 2,293 to 2,792 MiB/s, finalwisp's from 2,022 to 2,708
and the C++23 wispurr's from 1,925 to 3,169; with 10 streams on one connection holyWisp ranges from
1,667 to 2,242 and finalwisp from 1,545 to 2,277. holyWisp's medians in those rows are lower than on
2026-11-12, but eight alternating runs of this build and that one (`09b75bd`) afterwards gave
overlapping ranges and medians within that noise in all four one-connection rows. The rows with 16
connections repeat within 6%, except wisp-server-python's. With 8 connections holyWisp's and
finalwisp's runs span 10% (9,537 to 10,596 and 9,446 to 10,303), and holyWisp's lowest run there,
like its lowest with five wisp-js connections (2,270 against 2,728 to 3,444 for the rest), was one
in the first position. In the churn row the two runs in the first position fall well below the rest
for holyWisp (219,186 and 226,669 against 258,778 to 266,910), the C++23 wispurr and epoxy-server;
the medians are not moved by them. Compare servers within a row, not numbers across hosts.

The churn scenario dials eight echo ports, one per connection; the README explains why.

epoxy-server runs with its own defaults except for three settings in
`configs/epoxy-server-bench.toml`: the bind address, error-level logging, and a `max_message_size`
of 1 MiB plus the Wisp header. Its default of 64 KiB is smaller than one 64 KiB packet from the
native client with its 5-byte header, and it closes the connection on the first one.

holyWisp was a release build of `978e1d1` (0.5.3).

| | version |
| --- | --- |
| holyWisp | holywisp 0.5.3, `978e1d1`, release build |
| finalwisp | 341dcf7a, rustc 1.100.0-nightly (f248f4038 2026-09-05), x86_64-unknown-linux-gnu +crt-static, pool allocator |
| epoxy-server | epoxy-tls 9cde724 (`server/`), rustc 1.100.0-nightly, `cargo build --release` |
| wispurr (C++23) | g++ (Debian 14.2.0-19) 14.2.0 |
| wispurr (Go) | 36de32e, go1.26.4 linux/amd64 |
| wisp-server-python | deeb390, Python 3.13.5, websockets 13.1 |
| wisp-js client | 0.4.1 on Node v20.19.2 |
| kernel | 6.12.116+deb13-cloud-amd64 |

```
CPU: Intel(R) Xeon(R) Gold 6348 CPU @ 2.60GHz (x16)
Test duration: 10s x 12 (median)
```

### Throughput (MiB/s through the echo port)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 647 | 3,345 | 2,591 | 1,936 | 1,942 | 10,475 | 8,744 |
| finalwisp (Rust) | 704 | 3,351 | 2,330 | 1,963 | 2,202 | 9,972 | 9,413 |
| epoxy-server (Rust) | 361 | 2,229 | 484 | 505 | 598 | 5,990 | 6,608 |
| wispurr (C++23) | 625 | 2,794 | 2,914 | 2,210 | 2,314 | 9,098 | 7,143 |
| wispurr (Go) | 639 | 3,236 | 1,678 | 1,067 | 1,081 | 5,395 | 4,886 |
| wisp-server-python | 391 | 1,676 | 443 | 302 | DNF | 2,969 | 3,317 |

### Server CPU cores busy during the throughput tests

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 0.42 | 1.88 | 0.99 | 1.00 | 0.92 | 4.91 | 4.65 |
| finalwisp (Rust) | 0.53 | 2.49 | 0.99 | 1.00 | 1.00 | 4.81 | 5.26 |
| epoxy-server (Rust) | 1.44 | 4.03 | 1.12 | 1.84 | 1.73 | 7.79 | 8.60 |
| wispurr (C++23) | 0.40 | 1.67 | 0.97 | 0.99 | 0.92 | 4.58 | 6.01 |
| wispurr (Go) | 1.68 | 4.10 | 1.80 | 2.41 | 2.24 | 8.54 | 8.78 |
| wisp-server-python | 1.00 | 4.99 | 1.00 | 1.00 | DNF | 6.99 | 9.39 |

### MiB relayed per server CPU-second (efficiency)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 1,552 | 1,768 | 2,628 | 1,940 | 2,094 | 2,140 | 1,878 |
| finalwisp (Rust) | 1,321 | 1,362 | 2,361 | 1,958 | 2,206 | 2,070 | 1,824 |
| epoxy-server (Rust) | 250 | 553 | 432 | 273 | 345 | 770 | 765 |
| wispurr (C++23) | 1,579 | 1,684 | 2,983 | 2,233 | 2,523 | 1,984 | 1,186 |
| wispurr (Go) | 380 | 792 | 930 | 442 | 482 | 633 | 555 |
| wisp-server-python | 391 | 371 | 443 | 302 | DNF | 421 | 354 |

### Round-trip latency, 64 B echo, one stream (us)

| server | p50 | p90 | p99 | p99.9 | mean | round trips/s |
|---|---|---|---|---|---|---|
| holyWisp (C11) | 78.50 | 98.00 | 136 | 311 | 83.33 | 11,909 |
| finalwisp (Rust) | 81.00 | 100 | 143 | 332 | 85.82 | 11,559 |
| epoxy-server (Rust) | 85.00 | 106 | 152 | 351 | 89.96 | 11,028 |
| wispurr (C++23) | 80.00 | 99.50 | 142 | 328 | 85.24 | 11,638 |
| wispurr (Go) | 118 | 144 | 314 | 612 | 123 | 8,060 |
| wisp-server-python | 180 | 292 | 554 | 1,010 | 208 | 4,772 |

### Stream churn (open + 1 B echo + close, lifecycles/s)

| server | stream churn, 8 conns x 32 in flight | server cores | peak RSS MiB |
|---|---|---|---|
| holyWisp (C11) | 262,431 | 7.03 | 3.96 |
| finalwisp (Rust) | 229,821 | 6.13 | 3.38 |
| epoxy-server (Rust) | 60,258 | 6.28 | 2,208 |
| wispurr (C++23) | 239,041 | 6.78 | 54.96 |
| wispurr (Go) | 131,966 | 9.60 | 888 |
| wisp-server-python | 37,884 | 5.98 | 506 |
