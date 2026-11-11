# Benchmark results

Run on 2026-11-11 (UTC). Charts for every table below are in `charts/`, light and dark.
The method, the exact server and client command lines, and the install notes for each server are in
[README.md](README.md). Regenerate with `python3 -I bench/run.py` and `python3 -I bench/charts.py`.

The host was a 16-vCPU KVM guest (Xeon Gold 6348, Debian 13.7) that ran nothing else. Servers,
clients and the echo service shared its 16 cores, so the two rows with many connections are bounded
by the whole box, not by the server alone.

Each scenario ran ten times with the server order rotated, so every one of the five servers held
every position in the order twice. The position matters on this host (see "Running it" in the
README), and the latency table shows it most: a 64 B round trip measured 45 to 50 us for holyWisp,
finalwisp and the C++23 wispurr when they ran first after the saturating 16-connection scenario,
and 54 to 91 us in the later positions. The medians in that table sit between those two modes.

Read differences of a few percent as noise. The repeats of one cell spread widely in some rows: the
wisp-js 10-stream runs of holyWisp range from 422 to 763 MiB/s and those of the C++23 wispurr from
441 to 709, and holyWisp's native 10-stream runs from 1,418 to 2,359. The rows with one connection
are the noisiest on this host; the rows with 8 and 16 connections and the churn row repeat within a
few percent. Compare servers within a row, not numbers across hosts.

The churn scenario dials eight echo ports, one per connection; the README explains why.

holyWisp was a release build of the working tree on top of `5d01e8f` (0.5.3, with DATA frames
toward the client capped at 128 KiB and new connections placed on the least loaded worker), not of
a commit.

| | version |
| --- | --- |
| holyWisp | holywisp 0.5.3, release build |
| finalwisp | 341dcf7a, rustc 1.100.0-nightly (f248f4038 2026-09-05), x86_64-unknown-linux-gnu +crt-static, pool allocator |
| wispurr (C++23) | g++ (Debian 14.2.0-19) 14.2.0 |
| wispurr (Go) | 36de32e, go1.26.4 linux/amd64 |
| wisp-server-python | deeb390, Python 3.13.5, websockets 13.1 |
| wisp-js client | 0.4.1 on Node v20.19.2 |
| kernel | 6.12.116+deb13-cloud-amd64 |

```
CPU: Intel(R) Xeon(R) Gold 6348 CPU @ 2.60GHz (x16)
Test duration: 10s x 10 (median)
```

### Throughput (MiB/s through the echo port)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 525 | 3,141 | 2,281 | 1,476 | 1,831 | 9,592 | 8,200 |
| wispurr (Go) | 649 | 3,045 | 1,611 | 1,047 | 995 | 5,035 | 4,635 |
| wisp-server-python | 321 | 1,443 | 398 | 281 | DNF | 2,962 | 3,133 |
| finalwisp (Rust) | 587 | 3,102 | 2,418 | 1,719 | 1,809 | 9,155 | 8,876 |
| wispurr (C++23) | 579 | 2,592 | 2,763 | 1,796 | 1,933 | 8,399 | 6,689 |

### Server CPU cores busy during the throughput tests

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 0.42 | 1.92 | 0.99 | 0.99 | 0.90 | 4.87 | 4.77 |
| wispurr (Go) | 1.66 | 4.15 | 1.83 | 2.41 | 2.22 | 8.41 | 8.73 |
| wisp-server-python | 1.00 | 4.49 | 1.00 | 1.00 | DNF | 6.98 | 9.40 |
| finalwisp (Rust) | 0.51 | 2.46 | 0.99 | 1.00 | 0.99 | 4.71 | 5.22 |
| wispurr (C++23) | 0.40 | 1.66 | 0.98 | 0.97 | 0.86 | 4.56 | 5.98 |

### MiB relayed per server CPU-second (efficiency)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 1,249 | 1,601 | 2,312 | 1,482 | 2,019 | 1,990 | 1,722 |
| wispurr (Go) | 390 | 735 | 874 | 432 | 449 | 598 | 529 |
| wisp-server-python | 321 | 344 | 398 | 281 | DNF | 393 | 334 |
| finalwisp (Rust) | 1,199 | 1,268 | 2,457 | 1,715 | 1,822 | 1,977 | 1,694 |
| wispurr (C++23) | 1,527 | 1,571 | 2,795 | 1,861 | 2,283 | 1,854 | 1,119 |

### Round-trip latency, 64 B echo, one stream (us)

| server | p50 | p90 | p99 | p99.9 | mean | round trips/s |
|---|---|---|---|---|---|---|
| holyWisp (C11) | 70.00 | 91.00 | 125 | 266 | 73.02 | 13,812 |
| wispurr (Go) | 122 | 161 | 356 | 652 | 128 | 7,740 |
| wisp-server-python | 170 | 209 | 432 | 810 | 178 | 5,563 |
| finalwisp (Rust) | 69.50 | 90.00 | 123 | 270 | 72.31 | 13,738 |
| wispurr (C++23) | 79.00 | 96.50 | 132 | 280 | 76.97 | 12,886 |

### Stream churn (open + 1 B echo + close, lifecycles/s)

| server | stream churn, 8 conns x 32 in flight | server cores | peak RSS MiB |
|---|---|---|---|
| holyWisp (C11) | 253,298 | 6.94 | 3.76 |
| wispurr (Go) | 127,003 | 9.49 | 916 |
| wisp-server-python | 36,568 | 5.98 | 503 |
| finalwisp (Rust) | 216,112 | 5.76 | 3.42 |
| wispurr (C++23) | 228,157 | 6.69 | 46.21 |
