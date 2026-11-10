# Benchmark results

Run on 2026-11-10 (UTC). Charts for every table below are in `charts/`, light and dark.
The method, the exact server and client command lines, and the install notes for each server are in
[README.md](README.md). Regenerate with `python3 -I bench/run.py` and `python3 -I bench/charts.py`.

The host was a 16-vCPU KVM guest (Xeon Gold 6348, Debian 13.7) that ran nothing else. Servers,
clients and the echo service shared its 16 cores, so the two rows with many connections are bounded
by the whole box, not by the server alone: with 16 connections 14.9 to 15.9 of the 16 cores were
busy for every server, and with 8 connections 13.3 to 13.9.

Each scenario ran eight times with the server order rotated, so every server held every position
in the order twice. The position matters on this host (see "Running it" in the README), and one
table shows it more than the others: a 64 B round trip measured 45 to 49 us for holyWisp and the
C++23 wispurr when they ran first after the saturating 16-connection scenario and 73 to 87 us when
they ran third or fourth. The medians in the latency table sit between those two modes. Slot by
slot the two servers are within a few microseconds of each other except in the second slot, where
holyWisp measured 53 to 56 us and wispurr 66 to 87.

Read differences of a few percent as noise. The repeats of one cell spread widely in some rows: the
wisp-js 10-stream runs of holyWisp range from 438 to 804 MiB/s and those of the C++23 wispurr from
378 to 726. Compare servers within a row, not numbers across hosts: the previous run of this
table, on a desktop Ryzen 9 7950X, ranked the servers differently in several rows.

The churn scenario dials eight echo ports, one per connection. Against a single port all four
servers measured between 16,500 and 18,300 lifecycles a second in this same run, because the
kernel's search for a free local port dominated; the README explains why.

holyWisp was built from `ca1f69b`, whose server code is that of `fc9cd24`.

| | version |
| --- | --- |
| holyWisp | holywisp 0.1.0 (ca1f69b), release build |
| wispurr (C++23) | g++ (Debian 14.2.0-19) 14.2.0 |
| wispurr (Go) | 36de32e, go1.26.4 linux/amd64 |
| wisp-server-python | deeb390, Python 3.13.5, websockets 13.1 |
| wisp-js client | 0.4.1 on Node v20.19.2 |
| kernel | 6.12.116+deb13-cloud-amd64 |

```
CPU: Intel(R) Xeon(R) Gold 6348 CPU @ 2.60GHz (x16)
Test duration: 10s x 8 (median)
```

### Throughput (MiB/s through the echo port)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 480 | 2,702 | 2,329 | 1,522 | 1,712 | 8,354 | 8,173 |
| wispurr (C++23) | 529 | 2,438 | 2,590 | 1,519 | 1,946 | 8,402 | 6,829 |
| wispurr (Go) | 523 | 2,682 | 1,583 | 984 | 939 | 5,095 | 4,627 |
| wisp-server-python | 315 | 1,272 | 438 | 248 | DNF | 2,555 | 3,104 |

### Server CPU cores busy during the throughput tests

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 0.41 | 1.87 | 0.96 | 1.00 | 0.74 | 4.41 | 4.69 |
| wispurr (C++23) | 0.37 | 1.68 | 0.98 | 0.96 | 0.84 | 4.53 | 5.88 |
| wispurr (Go) | 1.58 | 4.25 | 1.84 | 2.42 | 2.21 | 8.43 | 8.73 |
| wisp-server-python | 1.00 | 4.50 | 1.00 | 1.00 | DNF | 6.98 | 9.21 |

### MiB relayed per server CPU-second (efficiency)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 1,187 | 1,461 | 2,435 | 1,522 | 2,220 | 1,902 | 1,734 |
| wispurr (C++23) | 1,406 | 1,460 | 2,660 | 1,559 | 2,306 | 1,889 | 1,156 |
| wispurr (Go) | 334 | 631 | 858 | 406 | 425 | 608 | 534 |
| wisp-server-python | 315 | 298 | 438 | 248 | DNF | 403 | 328 |

### Round-trip latency, 64 B echo, one stream (us)

| server | p50 | p90 | p99 | p99.9 | mean | round trips/s |
|---|---|---|---|---|---|---|
| holyWisp (C11) | 68.50 | 89.00 | 124 | 252 | 73.31 | 13,916 |
| wispurr (C++23) | 79.00 | 101 | 138 | 322 | 81.75 | 12,251 |
| wispurr (Go) | 127 | 164 | 377 | 654 | 135 | 7,352 |
| wisp-server-python | 181 | 247 | 520 | 904 | 202 | 4,925 |

### Stream churn (open + 1 B echo + close, lifecycles/s)

| server | stream churn, 8 conns x 32 in flight | server cores | peak RSS MiB |
|---|---|---|---|
| holyWisp (C11) | 100,404 | 3.15 | 3.46 |
| wispurr (C++23) | 92,965 | 2.98 | 32.48 |
| wispurr (Go) | 73,278 | 5.52 | 894 |
| wisp-server-python | 38,531 | 5.77 | 505 |
