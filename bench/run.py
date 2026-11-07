#!/usr/bin/env python3
"""
bench/run.py - drive every Wisp server through the same scenarios and record the numbers.

Methodology follows wispmark: one TCP echo service on loopback, a Wisp server in front of it,
clients pumping data through streams to the echo port; the metric is bytes that crossed the echo
port per second (one direction), measured by the echo service itself so it is independent of the
client. On top of that the harness samples the server process's CPU time and peak RSS over the
measurement window, and runs latency and stream-churn scenarios with the native pump client.

    python3 -I bench/run.py [--duration 10] [--repeats 3] [--only SERVER,...] [--scenarios NAME,...]
                            [--out bench/results/<timestamp>]
"""
import argparse
import json
import os
import pathlib
import re
import shlex
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT.parent
BENCH_BIN = ROOT / "build" / "bench"
WISP_PORT = 16401
ECHO_PORT = 16402

# ------------------------------------------------------------------------------------- servers
# Every server gets its "speed" profile: loopback + literal-IP egress allowed (the echo is at
# 127.0.0.1), flood protection, reputation and per-IP connection limits off, error-level logging,
# default worker count (= CPUs for all three).

HW_COMMON = ["--port", str(WISP_PORT), "--allow-loopback=on", "--allow-direct-ip=on", "--flood-protection=off",
             "--reputation=off", "--connections-limit-per-ip=0", "--connection-window-s=0",
             "--serve-webclient=off", "--log-level=error"]

SERVERS = {
    "holywisp": {
        # The shipped defaults (16 MiB per-stream queue, so an 8-packet CONTINUE window for 1 MiB
        # packets; kernel socket buffers), only the permission flags added.
        "label": "holyWisp (C11)",
        "cmd": [str(ROOT / "build/release/holywisp")] + HW_COMMON,
        "version": [str(ROOT / "build/release/holywisp"), "--version"],
    },
    "holywisp-sockbuf": {
        # Same, plus the 32 MiB socket buffers wispurr's bench config asks for (socketBufferSize).
        "label": "holyWisp (C11, 32 MiB socket buffers)",
        "cmd": [str(ROOT / "build/release/holywisp")] + HW_COMMON + ["--socket-buffer-size=33554432"],
    },
    "wispurr-go": {
        "label": "wispurr (Go)",
        "cmd": [str(SRC / "wispurr/wispurr"), "-config", str(ROOT / "bench/configs/wispurr-go-bench.json"),
                "-port", str(WISP_PORT)],
        "cwd": str(SRC / "wispurr"),
    },
    "wisp-python": {
        # wispmark's install: a venv with `pip install -e .`; run the way wispmark runs it.
        "label": "wisp-server-python",
        "cmd": [str(SRC / "wisp-server-python/.venv/bin/python"), "-m", "wisp.server", "--port", str(WISP_PORT),
                "--allow-loopback", "--log-level", "error"],
        "cwd": str(SRC / "wisp-server-python"),
    },
    "wispurr-cpp": {
        "label": "wispurr (C++23)",
        "cmd": [str(SRC / "wispurr-cpp23/wispurr"), "-config", str(ROOT / "bench/configs/wispurr-bench.json"),
                "-port", str(WISP_PORT)],
        "cwd": str(SRC / "wispurr-cpp23"),
    },
}

# ----------------------------------------------------------------------------------- scenarios
# kind=tp: throughput measured at the echo port. kind=rtt / churn: the pump reports the metric.

PUMP = str(BENCH_BIN / "pump")
WISPJS = SRC / "wispmark/client/js"


def pump(mode, procs, **kw):
    args = [PUMP, "-s", f"ws://127.0.0.1:{WISP_PORT}/", "--mode", mode, "--settle-ms", "200"]
    for k, v in kw.items():
        args += [f"--{k}", str(v)]
    args += ["127.0.0.1", str(ECHO_PORT)]
    return {"procs": procs, "cmd": args}


SCENARIOS = {
    "wispjs-10": {
        "label": "wisp-js, 10 streams", "kind": "tp", "group": "wispmark",
        "client": {"procs": 1, "cmd": ["node", str(WISPJS / "client.mjs"), str(WISP_PORT), str(ECHO_PORT), "10"]},
    },
    "wispjs-5x10": {
        "label": "wisp-js, 5 conns x 10 streams", "kind": "tp", "group": "wispmark",
        "client": {"procs": 5, "cmd": ["node", str(WISPJS / "client.mjs"), str(WISP_PORT), str(ECHO_PORT), "10"]},
    },
    "native-1": {"label": "native, 1 stream", "kind": "tp", "group": "native", "client": pump("tp", 1, streams=1)},
    "native-10": {"label": "native, 10 streams", "kind": "tp", "group": "native", "client": pump("tp", 1, streams=10)},
    "native-10-1m": {"label": "native, 10 streams, 1 MiB packets", "kind": "tp", "group": "native",
                     "client": pump("tp", 1, streams=10, chunk=1048576)},
    "native-8x4": {"label": "native, 8 conns x 4 streams", "kind": "tp", "group": "native",
                   "client": pump("tp", 8, streams=4)},
    "native-16x4": {"label": "native, 16 conns x 4 streams", "kind": "tp", "group": "native",
                    "client": pump("tp", 16, streams=4)},
    "rtt-64": {"label": "round trip, 64 B", "kind": "rtt", "group": "latency", "client": pump("rtt", 1, chunk=64)},
    "churn-8x32": {"label": "stream churn, 8 conns x 32 in flight", "kind": "churn", "group": "churn",
                   "client": pump("churn", 8, inflight=32)},
}


# -------------------------------------------------------------------------------------- helpers
def wait_http(port, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5) as s:
                s.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                if s.recv(64).startswith(b"HTTP/1.1"):
                    return True
        except OSError:
            time.sleep(0.05)
    return False


def wait_port_free(port, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                time.sleep(0.1)
        except OSError:
            return True
    return False


def session_pids(leader):
    """The leader plus every process in its session (wisp-server-python forks workers)."""
    pids = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            if int(fields[3]) == leader:  # session id
                pids.append(int(d))
        except (OSError, IndexError, ValueError):
            continue
    return pids or [leader]


def proc_cpu_seconds(pid):
    """utime + stime of every thread of every process in the server's session, in seconds."""
    tck = os.sysconf("SC_CLK_TCK")
    total = 0
    for p in session_pids(pid):
        try:
            with open(f"/proc/{p}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            total += int(fields[11]) + int(fields[12])
        except OSError:
            continue
    return total / tck


def proc_peak_rss_kib(pid):
    """Peak RSS summed over the server's session (one process for most servers)."""
    total = 0
    for p in session_pids(pid):
        try:
            with open(f"/proc/{p}/status") as f:
                m = re.search(r"VmHWM:\s+(\d+)", f.read())
            total += int(m.group(1)) if m else 0
        except OSError:
            continue
    return total


def kill(p):
    """Terminate a process and everything in its session: wisp-server-python forks one worker per
    CPU, and an orphaned worker would keep the SO_REUSEPORT port and steal the next server's
    connections."""
    if p is None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(p.pid, sig)
        except ProcessLookupError:
            pass
        try:
            p.wait(3)
            break
        except subprocess.TimeoutExpired:
            continue


class Echo:
    """The counting echo service; keeps the latest (ts_ns, bytes, conns) line it printed."""

    def __init__(self):
        self.p = subprocess.Popen([str(BENCH_BIN / "echo"), str(ECHO_PORT)], stdout=subprocess.PIPE, text=True,
                                  start_new_session=True)
        self.latest = (0, 0, 0)
        self.lock = threading.Lock()
        t = threading.Thread(target=self._reader, daemon=True)
        t.start()
        if not wait_port_open(ECHO_PORT):
            raise RuntimeError("echo did not start")

    def _reader(self):
        for line in self.p.stdout:
            ns, b, c = (int(x) for x in line.split())
            with self.lock:
                self.latest = (ns, b, c)

    def sample(self):
        with self.lock:
            return self.latest

    def close(self):
        kill(self.p)


def wait_port_open(port, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


# ------------------------------------------------------------------------------------- one run
def run_once(server_key, scen_key, duration, echo, log_dir):
    srv = SERVERS[server_key]
    scen = SCENARIOS[scen_key]
    slog = open(log_dir / f"server-{server_key}-{scen_key}.log", "a")
    sp = subprocess.Popen(srv["cmd"], cwd=srv.get("cwd"), stdout=slog, stderr=subprocess.STDOUT,
                          start_new_session=True)
    result = {"server": server_key, "scenario": scen_key, "kind": scen["kind"], "ok": False}
    clients = []
    try:
        if not wait_http(WISP_PORT):
            result["error"] = "server did not come up"
            return result
        time.sleep(0.3)
        client = scen["client"]
        if scen["kind"] == "tp":
            cmd = list(client["cmd"])
            if cmd[0] == PUMP:
                cmd += ["--duration", str(duration + 4)]
            for i in range(client["procs"]):
                clog = open(log_dir / f"client-{server_key}-{scen_key}-{i}.log", "a")
                clients.append(subprocess.Popen(cmd, stdout=clog, stderr=subprocess.STDOUT, start_new_session=True))
            time.sleep(1.5)  # warm up: connections open, windows fill, JIT settles
            ns0, b0, _ = echo.sample()
            cpu0 = proc_cpu_seconds(sp.pid)
            # Sample the echo counter every 250 ms so the result carries a throughput-over-time
            # series (and so a mid-run stall is visible, not just averaged in).
            timeline = []
            t_end = time.monotonic() + duration
            while True:
                time.sleep(0.25)
                ns, b, _ = echo.sample()
                timeline.append([round((ns - ns0) / 1e9, 3), b - b0])
                if time.monotonic() >= t_end:
                    break
            ns1, b1, _ = echo.sample()
            cpu1 = proc_cpu_seconds(sp.pid)
            el = (ns1 - ns0) / 1e9
            result["timeline"] = timeline
            if el <= 0 or b1 == b0:
                tails = []
                for i in range(client["procs"]):
                    lines = (log_dir / f"client-{server_key}-{scen_key}-{i}.log").read_text().strip().splitlines()
                    if lines and lines[-1] not in tails:
                        tails.append(lines[-1][-160:])
                result["error"] = ("no traffic reached the echo port during the window"
                                   + (f"; client said: {' | '.join(tails)}" if tails else ""))
                return result
            result.update({
                "elapsed_s": el,
                "bytes": b1 - b0,
                "mib_s": (b1 - b0) / 1048576 / el,
                "server_cpu_s": cpu1 - cpu0,
                "server_cpu_cores": (cpu1 - cpu0) / el,
                "mib_per_cpu_s": (b1 - b0) / 1048576 / max(cpu1 - cpu0, 1e-9),
                "server_peak_rss_mib": proc_peak_rss_kib(sp.pid) / 1024,
                "ok": True,
            })
            for c in clients:
                kill(c)
            if cmd[0] == PUMP:
                stalls = 0
                for i in range(client["procs"]):
                    for line in (log_dir / f"client-{server_key}-{scen_key}-{i}.log").read_text().splitlines():
                        if line.startswith("{"):
                            stalls += json.loads(line).get("stalls", 0)
                result["client_stalls"] = stalls
        else:
            cmd = list(client["cmd"]) + ["--duration", str(duration)]
            cpu0 = proc_cpu_seconds(sp.pid)
            t0 = time.monotonic()
            for i in range(client["procs"]):
                clients.append(subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                                start_new_session=True))
            outs = [c.communicate(timeout=duration + 30) for c in clients]
            el = time.monotonic() - t0
            cpu1 = proc_cpu_seconds(sp.pid)
            reports = []
            for c, (out, err) in zip(clients, outs):
                if c.returncode != 0:
                    result["error"] = f"client exit {c.returncode}: {err.strip()[-300:]}"
                    return result
                reports.append(json.loads(out.strip().splitlines()[-1]))
            result["server_cpu_s"] = cpu1 - cpu0
            result["server_cpu_cores"] = (cpu1 - cpu0) / el
            result["server_peak_rss_mib"] = proc_peak_rss_kib(sp.pid) / 1024
            if scen["kind"] == "rtt":
                r = reports[0]
                result.update({k: r[k] for k in ("count", "mean_us", "p50_us", "p90_us", "p99_us", "p999_us",
                                                  "max_us", "rps", "stalls")})
            else:
                result["completed"] = sum(r["completed"] for r in reports)
                result["failed"] = sum(r["failed"] for r in reports)
                result["per_s"] = sum(r["per_s"] for r in reports)
            result["ok"] = True
        return result
    finally:
        for c in clients:
            kill(c)
        kill(sp)
        slog.close()
        wait_port_free(WISP_PORT)


# ----------------------------------------------------------------------------------- aggregate
def median_of(runs, key):
    vals = [r[key] for r in runs if r.get("ok") and key in r]
    return statistics.median(vals) if vals else None


def aggregate(runs):
    out = {}
    for r in runs:
        out.setdefault(r["scenario"], {}).setdefault(r["server"], []).append(r)
    summary = {}
    for scen, by_server in out.items():
        summary[scen] = {}
        for server, rs in by_server.items():
            kind = rs[0]["kind"]
            keys = {"tp": ["mib_s", "server_cpu_cores", "mib_per_cpu_s", "server_peak_rss_mib", "client_stalls"],
                    "rtt": ["p50_us", "p90_us", "p99_us", "p999_us", "mean_us", "rps", "stalls", "server_cpu_cores"],
                    "churn": ["per_s", "failed", "server_cpu_cores", "server_peak_rss_mib"]}[kind]
            agg = {k: median_of(rs, k) for k in keys}
            agg["runs"] = len(rs)
            agg["ok_runs"] = sum(1 for r in rs if r.get("ok"))
            agg["errors"] = [r.get("error") for r in rs if not r.get("ok")]
            if kind == "tp":
                agg["mib_s_all"] = [r["mib_s"] for r in rs if r.get("ok")]
            summary[scen][server] = agg
    return summary


def fmt(v, unit=""):
    if v is None:
        return "DNF"
    if isinstance(v, float):
        return (f"{v:,.0f}" if v >= 100 else f"{v:,.2f}") + unit
    return f"{v}{unit}"


def markdown(summary, servers, meta):
    lines = [f"```\nCPU: {meta['cpu']}\nTest duration: {meta['duration']}s x {meta['repeats']} (median)\n```", ""]
    tp = [s for s in SCENARIOS if SCENARIOS[s]["kind"] == "tp" and s in summary]
    head = "| server | " + " | ".join(SCENARIOS[s]["label"] for s in tp) + " |"
    lines += ["### Throughput (MiB/s through the echo port)", "", head, "|" + "---|" * (len(tp) + 1)]
    for sv in servers:
        lines.append(f"| {SERVERS[sv]['label']} | " + " | ".join(
            fmt(summary[s].get(sv, {}).get("mib_s")) for s in tp) + " |")
    lines += ["", "### Server CPU cores busy during the throughput tests", "", head, "|" + "---|" * (len(tp) + 1)]
    for sv in servers:
        lines.append(f"| {SERVERS[sv]['label']} | " + " | ".join(
            fmt(summary[s].get(sv, {}).get("server_cpu_cores")) for s in tp) + " |")
    lines += ["", "### MiB relayed per server CPU-second (efficiency)", "", head, "|" + "---|" * (len(tp) + 1)]
    for sv in servers:
        lines.append(f"| {SERVERS[sv]['label']} | " + " | ".join(
            fmt(summary[s].get(sv, {}).get("mib_per_cpu_s")) for s in tp) + " |")
    if "rtt-64" in summary:
        lines += ["", "### Round-trip latency, 64 B echo, one stream (us)", "",
                  "| server | p50 | p90 | p99 | p99.9 | mean | round trips/s |", "|---|---|---|---|---|---|---|"]
        for sv in servers:
            a = summary["rtt-64"].get(sv, {})
            lines.append(f"| {SERVERS[sv]['label']} | " + " | ".join(
                fmt(a.get(k)) for k in ("p50_us", "p90_us", "p99_us", "p999_us", "mean_us", "rps")) + " |")
    churn = [s for s in SCENARIOS if SCENARIOS[s]["kind"] == "churn" and s in summary]
    if churn:
        lines += ["", "### Stream churn (open + 1 B echo + close, lifecycles/s)", "",
                  "| server | " + " | ".join(SCENARIOS[s]["label"] for s in churn) + " | server cores | peak RSS MiB |",
                  "|" + "---|" * (len(churn) + 3)]
        for sv in servers:
            a = [summary[s].get(sv, {}) for s in churn]
            lines.append(f"| {SERVERS[sv]['label']} | " + " | ".join(fmt(x.get("per_s")) for x in a) +
                         f" | {fmt(a[0].get('server_cpu_cores'))} | {fmt(a[0].get('server_peak_rss_mib'))} |")
    return "\n".join(lines) + "\n"


def cpu_name():
    with open("/proc/cpuinfo") as f:
        txt = f.read()
    m = re.search(r"model name\s*:\s*(.+)", txt)
    return f"{m.group(1).strip() if m else 'unknown'} (x{txt.count('processor')})"


def versions():
    v = {}
    try:
        v["holywisp"] = subprocess.run(SERVERS["holywisp"]["version"], capture_output=True, text=True).stdout.strip()
        v["holywisp_git"] = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                                           capture_output=True, text=True).stdout.strip()
        v["wispurr_go_git"] = subprocess.run(["git", "-C", str(SRC / "wispurr"), "rev-parse", "--short", "HEAD"],
                                             capture_output=True, text=True).stdout.strip()
        v["wispurr_cpp_git"] = subprocess.run(["git", "-C", str(SRC / "wispurr-cpp23"), "rev-parse", "--short", "HEAD"],
                                              capture_output=True, text=True).stdout.strip() or "not a git checkout"
        v["wisp_python_git"] = subprocess.run(["git", "-C", str(SRC / "wisp-server-python"), "rev-parse", "--short", "HEAD"],
                                              capture_output=True, text=True).stdout.strip()
        v["python"] = subprocess.run([str(SRC / "wisp-server-python/.venv/bin/python"), "--version"],
                                     capture_output=True, text=True).stdout.strip()
        v["node"] = subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip()
        v["wisp-js"] = json.load(open(WISPJS / "node_modules/@mercuryworkshop/wisp-js/package.json"))["version"]
        v["go"] = subprocess.run(["go", "version"], capture_output=True, text=True).stdout.strip()
        v["gcc"] = subprocess.run(["g++", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
        v["kernel"] = os.uname().release
    except Exception as e:  # noqa: BLE001 - versions are informational
        v["error"] = str(e)
    return v


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--duration", type=int, default=10)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--only", default=",".join(SERVERS))
    ap.add_argument("--scenarios", default=",".join(SCENARIOS))
    ap.add_argument("--out", default=None)
    ap.add_argument("--replace", action="store_true",
                    help="re-run only the servers in --only and splice them into an existing --out directory")
    a = ap.parse_args()
    servers = [s for s in a.only.split(",") if s]
    scenarios = [s for s in a.scenarios.split(",") if s]
    out = pathlib.Path(a.out) if a.out else ROOT / "bench/results" / time.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    log_dir = out / "logs"
    log_dir.mkdir(exist_ok=True)
    meta = {"cpu": cpu_name(), "duration": a.duration, "repeats": a.repeats, "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "versions": versions(), "servers": {k: {"label": v["label"], "cmd": shlex.join(v["cmd"])} for k, v in SERVERS.items() if k in servers},
            "scenarios": {k: {"label": v["label"], "kind": v["kind"], "group": v["group"], "procs": v["client"]["procs"],
                              "cmd": shlex.join(v["client"]["cmd"])} for k, v in SCENARIOS.items() if k in scenarios}}
    echo = Echo()
    runs = []
    if a.replace:
        prev = json.load(open(out / "results.json"))
        runs = [r for r in prev["runs"] if r["server"] not in servers or r["scenario"] not in scenarios]
        for k in ("servers", "scenarios"):
            meta[k] = {**prev["meta"][k], **meta[k]}
        meta["replaced"] = prev["meta"].get("replaced", []) + [{"servers": servers, "scenarios": scenarios,
                                                                 "at": meta["started"]}]
        (out / "runs.jsonl").unlink(missing_ok=True)
        for r in runs:
            with open(out / "runs.jsonl", "a") as f:
                f.write(json.dumps(r) + "\n")
        servers_all = list(meta["servers"])
    else:
        servers_all = servers
    try:
        for rep in range(a.repeats):
            order = servers if rep % 2 == 0 else list(reversed(servers))  # alternate to spread drift
            for scen in scenarios:
                for sv in order:
                    r = run_once(sv, scen, a.duration, echo, log_dir)
                    r["repeat"] = rep
                    runs.append(r)
                    msg = (f"{r['mib_s']:8.0f} MiB/s  {r['server_cpu_cores']:.2f} cores" if r["ok"] and r["kind"] == "tp"
                           else f"p50 {r['p50_us']} us p99 {r['p99_us']} us" if r["ok"] and r["kind"] == "rtt"
                           else f"{r['per_s']:.0f} streams/s" if r["ok"] else f"FAILED: {r.get('error')}")
                    print(f"[{rep + 1}/{a.repeats}] {sv:12s} {scen:12s} {msg}", flush=True)
                    with open(out / "runs.jsonl", "a") as f:
                        f.write(json.dumps(r) + "\n")
    finally:
        echo.close()
    summary = aggregate(runs)
    json.dump({"meta": meta, "summary": summary, "runs": runs}, open(out / "results.json", "w"), indent=1)
    md = markdown(summary, servers_all, meta)
    (out / "results.md").write_text(md)
    with open(out / "results.csv", "w") as f:
        keys = ["repeat", "server", "scenario", "kind", "ok", "mib_s", "server_cpu_cores", "mib_per_cpu_s",
                "server_peak_rss_mib", "client_stalls", "stalls", "p50_us", "p90_us", "p99_us", "p999_us", "mean_us", "rps", "per_s", "failed"]
        f.write(",".join(keys) + "\n")
        for r in runs:
            f.write(",".join("" if r.get(k) is None else str(r[k]) for k in keys) + "\n")
    print(md)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
