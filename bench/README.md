# Benchmarks

This directory compares holyWisp with other Wisp servers using the same method as
[wispmark](https://github.com/MercuryWorkshop/wispmark): a TCP echo service listens on loopback,
one Wisp server at a time sits in front of it, and clients push data through Wisp streams to the
echo port. The number that matters is how many bytes per second cross the echo port in one
direction. Our echo service counts those bytes itself (wispmark reads the same figure from iftop),
so the result does not depend on which client generated the traffic.

On top of throughput, the harness records how much CPU time and memory the server process used
during each run, and it has two extra scenarios that the native client drives: round-trip latency
for small messages, and how quickly a server can open and close streams.

None of this runs as part of `make test`. It is a tool for development.

The last full run's tables are in [RESULTS.md](RESULTS.md) and its charts (PNG) in `charts/`, in light
and dark variants; the root README embeds three of them. Fresh runs land in `results/`, which git
ignores. To refresh the committed copies after a run:

```sh
cp bench/results/full/charts/*.png bench/charts/
```

and rebuild `RESULTS.md` from `results/full/results.md` plus the version table at its top.

## What is here

| File | Purpose |
| --- | --- |
| `echo.c` | The counting echo service. One thread per connection; prints `ns bytes conns` every 100 ms. It listens on eight consecutive ports, which only the churn scenario uses (see below). |
| `pump.c` | The native load generator, built on `libholywisp-client`. `tp` keeps N streams full while respecting CONTINUE, `rtt` measures latency with one message in flight, `churn` opens a stream, echoes one byte and closes it, over and over. Prints one JSON line when it finishes. |
| `run.py` | Starts servers and clients, takes the measurements, and writes `results.json`, `runs.jsonl`, `results.csv` and `results.md`. |
| `charts.py` | Reads a results directory and produces `charts/*.svg` (add `--png` for PNGs too) and `report.html`. |
| `configs/` | The wispurr configs. Flood protection, reputation and connection limits are off; loopback and literal IPs are allowed. There are two files because the Go build rejects the `frameObfuscation` key, and the Go file also sets `bufferRemainingLength` to 128, since the Go server deadlocks within seconds at the 32768 its shipped speed config uses. |

## The servers

- `holywisp` is `build/release/holywisp` with the stock config plus the flags that allow loopback targets.
- `holywisp-sockbuf` is the same with `--socket-buffer-size=33554432`, which matches wispurr's `socketBufferSize`. It is an optional profile (`--only`), not part of the published run.
- `wispurr-go` is `~/src/wispurr/wispurr`, built with `go build -o wispurr main.go`.
- `wispurr-cpp` is `~/src/wispurr-cpp23/wispurr`, built with `make -C cpp -j LDFLAGS="-flto=auto -O3 -s"`.
  GCC 16 also needs `#include <cstdint>` added to `cpp/src/json.cpp`.
- `wisp-python` is [wisp-server-python](https://github.com/MercuryWorkshop/wisp-server-python) cloned to
  `~/src/wisp-server-python` and run as `python -m wisp.server --allow-loopback`. Two things about
  its install differ from a plain `pip install -e .`. Its venv is on Python 3.13 (`uv python install
  3.13`, `uv venv --python 3.13 .venv`, `uv pip install -e .`) because on 3.14 it tries to use
  subinterpreters and fails to start. And `websockets` is pinned below 14 (`uv pip install
  'websockets<14'`): with the current release its WebSocket reader blocks on a full per-stream queue
  and the connection deadlocks as soon as more than a couple of streams are busy, which drops it to
  a few MiB/s. With 13.1 it behaves the way wispmark's published results show.
- `finalwisp` is [finalwisp](https://github.com/theogbob/finalwisp) cloned to `~/src/finalwisp` and
  built with its own `bench/release.sh` (a static release build with its pinned nightly toolchain),
  run as `finalwisp --allow-loopback --allow-private --log-level error`, the way its own harness
  starts it. Its limits are off by default.

The wisp-js client is wispmark's own `client/js/client.mjs`. Clone wispmark to `~/src/wispmark`
and run `npm install` in `client/js`.

## Running it

```sh
make bench                                  # release build plus build/bench/{echo,pump}
python3 -I bench/run.py --duration 10 --repeats 8 --out bench/results/full
python3 -I bench/charts.py bench/results/full --png
```

Within a scenario the servers run one after another, and the order rotates by one each repeat
(reversing after every full rotation). That matters more than it sounds: the first run of a
scenario inherits the state the previous scenario left the host in. On the 16-vCPU VM the
published numbers come from, the server that ran first after a light scenario was 6 to 10% slower
with 8 connections for most of its window, and the one that ran first after the saturating
16-connection scenario measured a 47 us median round trip against 75 to 87 us for the same server
one slot later. So use a repeat count that is a multiple of the number of servers (4 gives every
server every slot once, 8 also balances which server it follows); with any other count the
medians favour or penalise whoever held the first slot more often.

Use `--only holywisp,wispurr-cpp` or `--scenarios native-10,rtt-64` to run part of the matrix,
and `--replace` with `--only` to re-measure one server and splice it into an existing results
directory. The exact command line for every server and scenario is stored in `results.json`
under `meta`.

The churn scenario gives each of its eight connections its own echo port. Against a single port
every server measured the same 15 to 18 thousand streams a second, Python included, with nearly
all of the server's CPU time inside `connect()`: a server that dials one address and port that
often leaves the kernel hunting for a free local port to that destination, and the row measured
the hunt. On the desktop the same holyWisp binary did 15,600 streams/s at 380 us of CPU per
stream against one port and 80,300 at 49 us against eight.

## Reading the results

Throughput cells are MiB/s in one direction, the median of the repeats; the whiskers in the charts
show the spread. "MiB per CPU-second" is the bytes relayed divided by the CPU time the server spent
in the same window, which tells you what each server costs per byte.

A `DNF` means either that no byte reached the echo port during the measurement window or that a
client exited with an error. The reason is in `runs.jsonl` and in the per-run logs under `logs/`.
The pump also reports `stalls`: the number of times every stream had used up its CONTINUE window
and the server sent nothing for two seconds. The harness carries that through as `client_stalls`.
