# Benchmark results

Run on 2026-11-18 (UTC), from 19:14 to 21:18. Charts for every table below are in `charts/`, light
and dark. The method, the exact server and client command lines, and the install notes for each
server are in [README.md](README.md). Regenerate with `python3 -I bench/run.py` and
`python3 -I bench/charts.py`.

The bench host was a Debian 13 container on a Proxmox host with an AMD Ryzen 9 7950X, pinned to
CPUs 12-15 and 28-31, which are four cores with both of their hardware threads, with 16 GiB of
memory. Servers, clients and the echo service shared those eight threads. The Proxmox host is not
a dedicated machine: it also runs other guests, production services among them, some of them on
the same CCD. The scenarios are sized for eight CPUs (see "Running it" in the README), so the 16-connection
row of the earlier runs is gone. The widest row is 8 connections, and it fills the container: the
server's threads share four cores with eight load generators and the echo service, and a CPU-second
buys less when the other hardware thread of its core is busy. The four fastest servers relay 39 to
48% as many bytes per CPU-second there as with 10 streams on one connection (holyWisp 1,418 MiB
against 3,495), and wisp-server-python 45%; only epoxy-server, slow on one connection, does better
with eight. On the 16-vCPU VM of 2026-11-16 the two rows cost about the same. The 8-connection row
measures how a server shares a full box as much as what it costs.

Each scenario ran twelve times with the server order rotated, so every one of the six servers held
every position in the order twice. All 576 runs completed. The only failures are wisp-server-python's
twelve with 1 MiB packets (the pump reports `send failed` ten times and `connection lost` twice; it
did not finish in the previous run either), no pump reported a stall, and no run was stopped by the
memory or timing guards. The run watched the container's own cgroup (inside the container its
`memory.max` reads `max`; `results.json` does not record whether `--memory-limit-mib` was given).
Its memory-pressure stall time grew by 3 us over the whole run and it had no `high` events. The
container's memory peaked at 8.3 GiB, under the C++23 wispurr behind five wisp-js connections, and
6.7 to 7.3 GiB of that was socket memory in every one of its twelve runs there (the next highest
row peaked at 3.0 GiB). That is half the container, well below the guard's 85%, but it is the
profile the guard is for: an earlier full run the same day was discarded because the host ran out
of socket memory part-way through, and none of its numbers are used here.

The position in the order did not matter on this host. Averaged over the rows, the run in each
position is within 2% of the server's median (the one-stream row 4%), and every server's 64 B round
trips measured within 1 us of its median in all twelve runs; on the Xeon VM the first position was
6 to 10% slower with 8 connections and 30 us faster on round trips. The host did drift during the
run: for about a third of the servers and rows the last six repeats were 4 to 6% faster than the
first six, and none was slower by as much. It went the same way for every server, and the rotation
keeps it out of the comparisons. The rows are also much tighter than on the Xeon VM, whose
one-connection rows were bimodal: holyWisp's native one-stream runs range from 3,597 to 3,874 MiB/s,
the C++23 wispurr's from 3,667 to 4,014 and finalwisp's from 3,469 to 3,703, and every row of the
three fastest servers spans at most 15% (most under 12%). wisp-server-python is the noisy one (676
to 1,002 MiB/s with one native stream). Read differences of a few percent as noise all the same,
and compare servers within a row, not numbers across hosts.

## Against the run of 2026-11-16

The absolute numbers do not compare: that run was on a 16-vCPU Xeon Gold 6348 VM, with sixteen
workers per server and a 16-connection row. Round trips are 3 times shorter here (holyWisp 24.5 us
against 78.5) and one native stream relays 47% more, while 8 connections relay 57% less, because
the eight connections now share four cores with their own clients. What moved is the order within
the rows:

- **8 connections.** finalwisp leads by 5% (4,705 against 4,466 MiB/s; holyWisp's runs span 4,355
  to 4,590, finalwisp's 4,458 to 4,978), where holyWisp led by 5% on the Xeon VM. The two cost the
  same per byte here (1,418 and 1,393 MiB per CPU-second); finalwisp kept 3.35 cores busy to
  holyWisp's 3.15, 6% more, which is its lead. On a full box the server that takes more of it
  relays more. The C++23 wispurr is 21% behind holyWisp.
- **Five wisp-js connections.** holyWisp leads by 10% over finalwisp and 24% over the C++23
  wispurr, where it was level with finalwisp. holyWisp needed 1.32 cores for its 2,225 MiB/s
  against finalwisp's 1.89 for 2,029: its 1,687 MiB per CPU-second is the best in the row by 38%.
  The five Node clients that drive this row share the same eight threads, so what the server does
  not use is probably what lets them go faster.
- **One native connection.** The C++23 wispurr no longer leads clearly: it is 1% ahead of holyWisp
  with one stream, inside the noise, and holyWisp leads with 10 streams by 6% over both it and
  finalwisp. On the Xeon VM, where those rows were bimodal, the C++23 wispurr led both by 12 to
  13%.
- **1 MiB packets.** finalwisp leads by 18% over holyWisp and the C++23 wispurr; on the Xeon VM it
  was 13% ahead of holyWisp and the C++23 wispurr led. It is not cheaper per byte: the three relay
  3,571 to 3,627 MiB per CPU-second. holyWisp and the C++23 wispurr keep 0.84 and 0.83 cores busy
  and finalwisp 0.97, so the gap is time the other two spend waiting, not work, and the Xeon VM
  showed the same pattern (0.92 against 1.00). No pump reported a stall in this row.
- **Churn.** holyWisp leads by 3% over finalwisp (114,439 against 111,342 lifecycles a second;
  finalwisp's runs span 100,827 to 117,012) and by 19% over the C++23 wispurr. epoxy-server now
  opens and closes more streams than the Go wispurr, which was rebuilt at a newer commit for this
  run (below). holyWisp and finalwisp again stay under 4 MiB under churn; epoxy-server's memory
  passed 2 GiB again (2,502 MiB).
- **Latency.** holyWisp has the shortest round trip at every percentile (24.5 us median, 35 at p99,
  64.5 at p99.9), finalwisp and epoxy-server 26 us, the C++23 wispurr 27.

holyWisp moved from `978e1d1` to `394dec9`. Of the commits between, one is on the data path:
`2ffb7c7` starts a busy client's receive buffer at 256 KiB instead of 128 KiB (measured on this
host beforehand as 5% cheaper with one busy stream and 3.5 to 4% with ten). A new host and a new
build at once cannot be separated in one run, so the deltas above are not attributed to it.
`394dec9` changes only `proxy-only-to` routing, which the benchmark does not use. Among the other
servers, finalwisp moved from `341dcf7a` to `18cccabe` (1.3.3, whose new `--auto-balance` is opt-in
and was off), the Go wispurr from `36de32e` to `0e0fdb1` and was built with Go 1.25.0 instead of
1.26.4, and epoxy-server is the same commit built with a newer nightly compiler. The C++23 wispurr
and wisp-server-python are unchanged.

The churn scenario dials eight echo ports, one per connection; the README explains why.

epoxy-server runs with its own defaults except for three settings in
`configs/epoxy-server-bench.toml`: the bind address, error-level logging, and a `max_message_size`
of 1 MiB plus the Wisp header. Its default of 64 KiB is smaller than one 64 KiB packet from the
native client with its 5-byte header, and it closes the connection on the first one.

holyWisp was a release build of `394dec9` (0.5.4), pulled and built on the host before the run;
the checkout differed from that commit only in the harness (`bench/run.py`, and three untracked
scripts beside it).

| | version |
| --- | --- |
| holyWisp | holywisp 0.5.4, `394dec9`, release build |
| finalwisp | 1.3.3, 18cccabe, rustc 1.100.0-nightly (f248f4038 2026-09-05), x86_64-unknown-linux-gnu +crt-static, pool allocator |
| epoxy-server | epoxy-tls 9cde724 (`server/`), rustc 1.102.0-nightly (59cbdee2e 2026-11-17), `cargo build --release` |
| wispurr (C++23) | g++ (Debian 14.2.0-19) 14.2.0 |
| wispurr (Go) | 0e0fdb1, go1.25.0 linux/amd64 |
| wisp-server-python | deeb390, Python 3.13.5, websockets 13.1 |
| wisp-js client | 0.4.1 on Node v20.19.2 |
| kernel | 7.0.14-29-pve |

```
CPU: AMD Ryzen 9 7950X 16-Core Processor (x8)
Test duration: 10s x 12 (median)
```

### Throughput (MiB/s through the echo port)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams |
|---|---|---|---|---|---|---|
| holyWisp (C11) | 1,325 | 2,225 | 3,813 | 3,462 | 3,005 | 4,466 |
| finalwisp (Rust) | 1,380 | 2,029 | 3,532 | 3,256 | 3,537 | 4,705 |
| wispurr (C++23) | 1,091 | 1,792 | 3,861 | 3,274 | 2,985 | 3,700 |
| wispurr (Go) | 1,192 | 1,460 | 2,603 | 2,427 | 2,545 | 2,002 |
| epoxy-server (Rust) | 732 | 1,265 | 994 | 1,003 | 1,127 | 3,073 |
| wisp-server-python | 800 | 1,132 | 767 | 839 | DNF | 2,024 |

### Server CPU cores busy during the throughput tests

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams |
|---|---|---|---|---|---|---|
| holyWisp (C11) | 0.45 | 1.32 | 0.99 | 1.00 | 0.84 | 3.15 |
| finalwisp (Rust) | 0.64 | 1.89 | 0.99 | 1.00 | 0.97 | 3.35 |
| wispurr (C++23) | 0.48 | 1.47 | 0.99 | 0.99 | 0.83 | 2.91 |
| wispurr (Go) | 1.21 | 2.85 | 1.90 | 2.83 | 2.41 | 4.82 |
| epoxy-server (Rust) | 1.29 | 2.68 | 1.23 | 2.23 | 2.00 | 4.90 |
| wisp-server-python | 1.00 | 3.64 | 1.00 | 1.00 | DNF | 5.36 |

### MiB relayed per server CPU-second (efficiency)

| server | wisp-js, 10 streams | wisp-js, 5 conns x 10 streams | native, 1 stream | native, 10 streams | native, 10 streams, 1 MiB packets | native, 8 conns x 4 streams |
|---|---|---|---|---|---|---|
| holyWisp (C11) | 2,906 | 1,687 | 3,837 | 3,495 | 3,571 | 1,418 |
| finalwisp (Rust) | 2,128 | 1,070 | 3,564 | 3,255 | 3,616 | 1,393 |
| wispurr (C++23) | 2,289 | 1,226 | 3,913 | 3,296 | 3,627 | 1,273 |
| wispurr (Go) | 984 | 510 | 1,367 | 861 | 1,052 | 416 |
| epoxy-server (Rust) | 567 | 474 | 816 | 451 | 562 | 626 |
| wisp-server-python | 801 | 314 | 768 | 840 | DNF | 379 |

### Round-trip latency, 64 B echo, one stream (us)

| server | p50 | p90 | p99 | p99.9 | mean | round trips/s |
|---|---|---|---|---|---|---|
| holyWisp (C11) | 24.50 | 26.00 | 35.00 | 64.50 | 24.95 | 39,528 |
| finalwisp (Rust) | 26.00 | 28.00 | 38.00 | 70.00 | 26.74 | 36,917 |
| wispurr (C++23) | 27.00 | 29.00 | 38.50 | 77.00 | 27.88 | 35,432 |
| wispurr (Go) | 33.00 | 35.50 | 50.00 | 126 | 33.68 | 29,379 |
| epoxy-server (Rust) | 26.00 | 28.00 | 38.50 | 68.50 | 26.29 | 37,536 |
| wisp-server-python | 42.00 | 46.50 | 65.00 | 116 | 43.32 | 22,893 |

### Stream churn (open + 1 B echo + close, lifecycles/s)

| server | stream churn, 8 conns x 32 in flight | server cores | peak RSS MiB |
|---|---|---|---|
| holyWisp (C11) | 114,439 | 4.49 | 3.72 |
| finalwisp (Rust) | 111,342 | 4.24 | 3.54 |
| wispurr (C++23) | 95,897 | 4.34 | 22.03 |
| wispurr (Go) | 63,738 | 5.16 | 494 |
| epoxy-server (Rust) | 70,918 | 4.55 | 2,502 |
| wisp-server-python | 36,816 | 4.94 | 298 |
