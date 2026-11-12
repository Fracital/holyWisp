# Benchmark results

Run on 2026-11-12 (UTC). Charts for every table below are in `charts/`, light and dark.
The method, the exact server and client command lines, and the install notes for each server are in
[README.md](README.md). Regenerate with `python3 -I bench/run.py` and `python3 -I bench/charts.py`.

The host was a 16-vCPU KVM guest (Xeon Gold 6348, Debian 13) that ran nothing else. Servers,
clients and the echo service shared its 16 cores, so the two rows with many connections are bounded
by the whole box, not by the server alone.

Each scenario ran twelve times with the server order rotated, so every one of the six servers held
every position in the order twice. The position matters on this host (see "Running it" in the
README), and the latency table shows it most: a 64 B round trip measured 45 to 49 us for the four
fastest servers when they ran first after the saturating 16-connection scenario, and 52 to 59 us in
the later positions. The medians in that table are from the later mode.

Read differences of a few percent as noise. The rows with one connection are the noisiest: holyWisp's
native one-stream runs range from 2,422 to 2,776 MiB/s, finalwisp's from 2,511 to 2,721 and the C++23
wispurr's from 2,642 to 2,993. The rows with 8 and 16 connections repeat within about 5%, except
finalwisp's 8-connection runs (9,051 to 10,196). In the churn row one of finalwisp's twelve runs
measured 153,219 lifecycles/s against 236,000 to 279,000 for the rest; the median is not moved by
it. Compare servers within a row, not numbers across hosts.

The churn scenario dials eight echo ports, one per connection; the README explains why.

epoxy-server runs with its own defaults except for three settings in
`configs/epoxy-server-bench.toml`: the bind address, error-level logging, and a `max_message_size`
of 1 MiB plus the Wisp header. Its default of 64 KiB is smaller than one 64 KiB packet from the
native client with its 5-byte header, and it closes the connection on the first one.

holyWisp was a release build of `09b75bd` (0.5.3).

| | version |
| --- | --- |
| holyWisp | holywisp 0.5.3, `09b75bd`, release build |
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
| holyWisp (C11) | 794 | 3,217 | 2,588 | 2,204 | 2,125 | 9,746 | 8,378 |
| finalwisp (Rust) | 781 | 3,248 | 2,583 | 2,105 | 2,133 | 9,533 | 9,055 |
| epoxy-server (Rust) | 474 | 2,153 | 581 | 615 | 739 | 5,773 | 6,289 |
| wispurr (C++23) | 690 | 2,715 | 2,856 | 2,142 | 2,171 | 8,534 | 6,844 |
| wispurr (Go) | 752 | 3,098 | 1,843 | 1,510 | 1,263 | 5,178 | 4,693 |
| wisp-server-python | 427 | 1,634 | 420 | 389 | DNF | 2,715 | 3,137 |

### Server CPU cores busy during the throughput tests

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 0.45 | 1.90 | 0.99 | 1.00 | 0.90 | 4.93 | 4.77 |
| finalwisp (Rust) | 0.53 | 2.42 | 0.99 | 1.00 | 1.00 | 4.72 | 5.21 |
| epoxy-server (Rust) | 1.48 | 4.03 | 1.14 | 1.85 | 1.75 | 7.75 | 8.56 |
| wispurr (C++23) | 0.39 | 1.65 | 0.99 | 0.97 | 0.87 | 4.53 | 5.91 |
| wispurr (Go) | 1.74 | 4.06 | 1.83 | 2.42 | 2.31 | 8.49 | 8.75 |
| wisp-server-python | 1.00 | 4.99 | 1.00 | 1.00 | DNF | 6.45 | 8.79 |

### MiB relayed per server CPU-second (efficiency)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 1,786 | 1,701 | 2,620 | 2,203 | 2,414 | 2,010 | 1,748 |
| finalwisp (Rust) | 1,489 | 1,350 | 2,633 | 2,106 | 2,161 | 2,020 | 1,744 |
| epoxy-server (Rust) | 319 | 534 | 514 | 332 | 422 | 745 | 736 |
| wispurr (C++23) | 1,810 | 1,655 | 2,878 | 2,189 | 2,466 | 1,903 | 1,158 |
| wispurr (Go) | 433 | 765 | 1,008 | 624 | 547 | 612 | 539 |
| wisp-server-python | 427 | 342 | 420 | 390 | DNF | 405 | 355 |

### Round-trip latency, 64 B echo, one stream (us)

| server | p50 | p90 | p99 | p99.9 | mean | round trips/s |
|---|---|---|---|---|---|---|
| holyWisp (C11) | 53.00 | 61.00 | 89.00 | 128 | 55.86 | 17,739 |
| finalwisp (Rust) | 54.00 | 64.00 | 90.50 | 136 | 55.89 | 17,728 |
| epoxy-server (Rust) | 58.00 | 67.50 | 92.00 | 136 | 60.05 | 16,505 |
| wispurr (C++23) | 53.00 | 62.50 | 90.00 | 133 | 55.60 | 17,824 |
| wispurr (Go) | 80.00 | 102 | 162 | 318 | 84.01 | 11,794 |
| wisp-server-python | 156 | 174 | 219 | 360 | 154 | 6,434 |

### Stream churn (open + 1 B echo + close, lifecycles/s)

| server | stream churn, 8 conns x 32 in flight | server cores | peak RSS MiB |
|---|---|---|---|
| holyWisp (C11) | 257,594 | 7.04 | 3.77 |
| finalwisp (Rust) | 251,411 | 6.46 | 3.38 |
| epoxy-server (Rust) | 56,915 | 6.10 | 2,085 |
| wispurr (C++23) | 236,038 | 6.80 | 53.07 |
| wispurr (Go) | 137,431 | 9.62 | 878 |
| wisp-server-python | 37,283 | 5.98 | 506 |
