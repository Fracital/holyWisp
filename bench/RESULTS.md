# Benchmark results

Run on 2026-11-06. Charts for every table below are in `charts/`, light and dark.
The method, the exact server and client command lines, and the install notes for each server are in
[README.md](README.md). Regenerate with `python3 -I bench/run.py` and `python3 -I bench/charts.py`.

| | version |
| --- | --- |
| holyWisp | holywisp 0.1.0 (cb2510a), release build |
| wispurr (Go) | 36de32e, go1.26.4 linux/amd64 |
| wispurr (C++23) | g++ (GCC) 16.2.1 20260819 (Red Hat 16.2.1-2) |
| wisp-server-python | deeb390, Python 3.13.15, websockets 13.1 |
| wisp-js client | 0.4.1 on Node v24.16.0 |
| kernel | 7.0.10-201.fc44.x86_64 |

```
CPU: AMD Ryzen 9 7950X 16-Core Processor (x32)
Test duration: 10s x 3 (median)
```

### Throughput (MiB/s through the echo port)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 1,156 | 2,551 | 1,554 | 1,689 | 1,663 | 5,884 | 4,958 |
| holyWisp (C11, 32 MiB socket buffers) | 1,166 | 2,667 | 1,745 | 1,682 | 1,855 | 5,872 | 5,381 |
| wispurr (Go) | 929 | 1,538 | 2,108 | 2,189 | 1,915 | 3,029 | 2,414 |
| wispurr (C++23) | 1,065 | 1,829 | 2,889 | 2,859 | 2,636 | 5,154 | 3,314 |
| wisp-server-python | 685 | 1,080 | 609 | 686 | DNF | 3,229 | 2,031 |

### Server CPU cores busy during the throughput tests

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 0.43 | 1.83 | 0.71 | 0.66 | 0.77 | 5.49 | 8.17 |
| holyWisp (C11, 32 MiB socket buffers) | 0.42 | 1.76 | 0.76 | 0.71 | 0.83 | 5.46 | 8.38 |
| wispurr (Go) | 0.90 | 4.90 | 1.66 | 2.35 | 1.92 | 8.88 | 10.41 |
| wispurr (C++23) | 0.40 | 2.24 | 0.72 | 0.62 | 0.61 | 5.21 | 8.02 |
| wisp-server-python | 0.85 | 4.33 | 0.87 | 0.80 | DNF | 5.77 | 10.08 |

### MiB relayed per server CPU-second (efficiency)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams | native, 16 conns x 4 streams |
|---|---|---|---|---|---|---|---|
| holyWisp (C11) | 2,662 | 1,409 | 2,157 | 2,545 | 2,169 | 1,129 | 607 |
| holyWisp (C11, 32 MiB socket buffers) | 2,719 | 1,516 | 2,304 | 2,384 | 2,223 | 1,004 | 642 |
| wispurr (Go) | 1,027 | 321 | 1,266 | 944 | 1,000 | 341 | 234 |
| wispurr (C++23) | 2,633 | 818 | 4,027 | 4,608 | 4,332 | 912 | 415 |
| wisp-server-python | 815 | 249 | 697 | 857 | DNF | 532 | 210 |

### Round-trip latency, 64 B echo, one stream (us)

| server | p50 | p90 | p99 | p99.9 | mean | round trips/s |
|---|---|---|---|---|---|---|
| holyWisp (C11) | 28 | 35 | 49 | 77 | 30.07 | 32,682 |
| holyWisp (C11, 32 MiB socket buffers) | 29 | 38 | 54 | 86 | 31.28 | 31,440 |
| wispurr (Go) | 35 | 47 | 70 | 170 | 38.56 | 25,580 |
| wispurr (C++23) | 29 | 37 | 53 | 89 | 31.09 | 31,637 |
| wisp-server-python | 46 | 60 | 96 | 236 | 49.99 | 19,794 |

### Stream churn (open + 1 B echo + close, lifecycles/s)

| server | stream churn, 8 conns x 32 in flight | server cores | peak RSS MiB |
|---|---|---|---|
| holyWisp (C11) | 16,295 | 7.14 | 4.00 |
| holyWisp (C11, 32 MiB socket buffers) | 16,260 | 6.30 | 3.95 |
| wispurr (Go) | 19,831 | 21.79 | 404 |
| wispurr (C++23) | 16,556 | 7.09 | 10.99 |
| wisp-server-python | 15,902 | 7.46 | 976 |
