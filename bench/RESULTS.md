# Benchmark results

Run on 2026-11-09. Charts for every table below are in `charts/`, light and dark.
The method, the exact server and client command lines, and the install notes for each server are in
[README.md](README.md). Regenerate with `python3 -I bench/run.py` and `python3 -I bench/charts.py`.

The host was a desktop that was not idle during the run (a browser was using several cores), so
absolute numbers are lower than on a quiet machine and vary by several percent between runs.
Servers were measured interleaved, so compare them within a row; differences of a few percent are
within the noise.

| | version |
| --- | --- |
| holyWisp | holywisp 0.1.0 (fc9cd24), release build |
| wispurr (C++23) | g++ (GCC) 16.2.1 20260819 (Red Hat 16.2.1-2) |
| wispurr (Go) | 36de32e, go1.26.4 linux/amd64 |
| wisp-server-python | deeb390, Python 3.13.15, websockets 13.1 |
| wisp-js client | 0.4.1 on Node v24.16.0 |
| kernel | 7.0.10-201.fc44.x86_64 |

```
CPU: AMD Ryzen 9 7950X 16-Core Processor (x32)
Test duration: 10s x 5 (median)
```

### Throughput (MiB/s through the echo port)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 872 | 1,553 | 2,465 | 2,078 | 2,109 | 3,621 | 3,693 |
| wispurr (C++23) | 749 | 1,143 | 2,461 | 2,170 | 2,170 | 2,993 | 2,720 |
| wispurr (Go) | 799 | 1,202 | 1,540 | 1,528 | 1,422 | 1,879 | 1,922 |
| wisp-server-python | 525 | 878 | 566 | 568 | DNF | 2,025 | 1,767 |

### Server CPU cores busy during the throughput tests

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 0.30 | 1.74 | 0.69 | 0.74 | 0.72 | 3.84 | 5.28 |
| wispurr (C++23) | 0.40 | 1.96 | 0.69 | 0.66 | 0.62 | 3.49 | 5.59 |
| wispurr (Go) | 0.97 | 3.26 | 1.62 | 2.32 | 1.89 | 6.68 | 7.37 |
| wisp-server-python | 0.85 | 3.32 | 0.85 | 0.82 | DNF | 5.17 | 8.46 |

### MiB relayed per server CPU-second (efficiency)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 2,831 | 894 | 3,581 | 2,772 | 2,883 | 948 | 716 |
| wispurr (C++23) | 1,883 | 601 | 3,565 | 3,260 | 3,503 | 859 | 491 |
| wispurr (Go) | 800 | 345 | 952 | 672 | 756 | 287 | 271 |
| wisp-server-python | 616 | 260 | 679 | 697 | DNF | 358 | 204 |

### Round-trip latency, 64 B echo, one stream (us)

| server | p50 | p90 | p99 | p99.9 | mean | round trips/s |
|---|---|---|---|---|---|---|
| holyWisp (C11) | 33 | 46 | 70 | 386 | 36.23 | 27,179 |
| wispurr (C++23) | 33 | 44 | 66 | 269 | 35.91 | 27,426 |
| wispurr (Go) | 40 | 56 | 92 | 309 | 44.20 | 22,324 |
| wisp-server-python | 55 | 83 | 155 | 778 | 64.02 | 15,471 |

### Stream churn (open + 1 B echo + close, lifecycles/s)

| server | stream churn, 8 conns x 32 in flight | server cores | peak RSS MiB |
|---|---|---|---|
| holyWisp (C11) | 15,386 | 6.02 | 3.97 |
| wispurr (C++23) | 15,518 | 6.81 | 10.88 |
| wispurr (Go) | 18,328 | 18.10 | 411 |
| wisp-server-python | 14,985 | 6.40 | 972 |
