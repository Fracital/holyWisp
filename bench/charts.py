#!/usr/bin/env python3
"""
bench/charts.py - turn a results directory from run.py into SVG charts and an HTML report.

    python3 -I bench/charts.py bench/results/<run> [--png]

Writes <run>/charts/*.svg (light theme, self-contained) and <run>/report.html (both themes,
hover tooltips, table views). --png also rasterises each SVG with headless Chromium.
No dependencies beyond the standard library.
"""
import html
import json
import math
import pathlib
import subprocess
import sys

# ------------------------------------------------------------------------------ palette (dataviz)
# Categorical slots in fixed order; the two primary rivals and the Go port take the three
# all-pairs-safe slots, the holyWisp variant takes slot 4.
SERVER_ORDER = ["holywisp", "wispurr-cpp", "wispurr-go", "holywisp-sockbuf", "wisp-python"]
LIGHT = {"s1": "#2a78d6", "s2": "#eb6834", "s3": "#1baf7a", "s4": "#eda100", "s5": "#e87ba4", "surface": "#fcfcfb",
         "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781", "grid": "#e1e0d9", "axis": "#c3c2b7"}
DARK = {"s1": "#3987e5", "s2": "#d95926", "s3": "#199e70", "s4": "#c98500", "s5": "#d55181", "surface": "#1a1a19",
        "ink": "#f0efec", "ink2": "#c3c2b7", "muted": "#898781", "grid": "#2c2c2a", "axis": "#383835"}
FONT = 'system-ui, -apple-system, "Segoe UI", sans-serif'

THEMES = {"light": LIGHT, "dark": DARK}
SVG_STYLE = "".join(f"--{k}:{v};" for k, v in LIGHT.items())
_style = {"current": SVG_STYLE}


def esc(s):
    return html.escape(str(s), quote=True)


def fmt(v, digits=0):
    if v is None:
        return "DNF"
    if abs(v) >= 1000 or digits == 0:
        return f"{v:,.0f}"
    return f"{v:,.{digits}f}"


def nice_ticks(vmax, n=5):
    if vmax <= 0:
        return [0, 1]
    raw = vmax / n
    mag = 10 ** math.floor(math.log10(raw))
    for m in (1, 2, 2.5, 5, 10):
        step = m * mag
        if vmax / step <= n:
            break
    ticks = []
    t = 0
    while t <= vmax + 1e-9:
        ticks.append(round(t, 6))
        t += step
    if ticks[-1] < vmax:
        ticks.append(round(t, 6))
    return ticks


def tick_label(v, ticks):
    if max(ticks) >= 10000:
        return f"{v / 1000:g}K" if v else "0"
    return f"{v:,.0f}" if float(v).is_integer() else f"{v:g}"


class SVG:
    """Tiny SVG builder. Marks get data-tip attributes; the report's JS turns them into tooltips,
    and a <title> child gives standalone files a native hover text."""

    def __init__(self, w, h, title):
        self.w, self.h = w, h
        self.parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
                      f'role="img" aria-label="{esc(title)}" font-family=\'{FONT}\' style="{_style["current"]}">'
                      f'<rect width="{w}" height="{h}" fill="var(--surface)"/>']

    def add(self, s):
        self.parts.append(s)

    def text(self, x, y, s, size=12, fill="var(--ink2)", anchor="start", weight="normal", extra=""):
        self.add(f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" text-anchor="{anchor}" '
                 f'font-weight="{weight}" {extra}>{esc(s)}</text>')

    def line(self, x1, y1, x2, y2, stroke="var(--grid)", width=1, extra=""):
        self.add(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{stroke}" '
                 f'stroke-width="{width}" {extra}/>')

    def bar_h(self, x, y, w, h, fill, tip):
        # 4px rounded data end, square at the baseline.
        r = min(4, w / 2, h / 2)
        if w <= 0:
            return
        d = (f"M{x:.1f},{y:.1f} H{x + w - r:.1f} Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} "
             f"V{y + h - r:.1f} Q{x + w:.1f},{y + h:.1f} {x + w - r:.1f},{y + h:.1f} H{x:.1f} Z")
        self.add(f'<path class="mark" d="{d}" fill="{fill}" data-tip="{esc(tip)}"><title>{esc(tip)}</title></path>')

    def dot(self, x, y, fill, tip, r=4.5):
        self.add(f'<circle class="mark" cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{fill}" stroke="var(--surface)" '
                 f'stroke-width="2" data-tip="{esc(tip)}"><title>{esc(tip)}</title></circle>')

    def legend(self, x, y, items):
        cx = x
        for color, label in items:
            self.add(f'<rect x="{cx}" y="{y - 9}" width="10" height="10" rx="2" fill="{color}"/>')
            self.text(cx + 15, y, label, 12)
            cx += 15 + 7 * len(label) + 22

    def done(self):
        self.add("</svg>")
        return "\n".join(self.parts)


def color_of(server_key):
    return f"var(--s{SERVER_ORDER.index(server_key) + 1})"


# -------------------------------------------------------------------------------------- charts
def grouped_bars_h(title, subtitle, groups, servers, labels, values, unit, ranges=None, higher_better=True):
    """groups: [(key, label)], values[g][s] -> number|None, ranges[g][s] -> (lo, hi)|None."""
    bar, gap, group_pad = 14, 2, 22
    left, right, top = 230, 90, 74
    gh = len(servers) * (bar + gap) + group_pad
    w = 960
    h = top + len(groups) * gh + 70
    svg = SVG(w, h, title)
    svg.text(24, 30, title, 17, "var(--ink)", weight="600")
    svg.text(24, 50, subtitle, 12, "var(--muted)")
    plot_x0, plot_x1 = left, w - right
    vmax = max([v for g in values for v in g.values() if v is not None] +
               [r[1] for g in (ranges or []) for r in g.values() if r]) if any(values) else 1
    ticks = nice_ticks(vmax)
    scale = (plot_x1 - plot_x0) / ticks[-1]
    y0 = top
    for t in ticks:
        x = plot_x0 + t * scale
        svg.line(x, y0, x, y0 + len(groups) * gh, "var(--grid)")
        svg.text(x, y0 + len(groups) * gh + 18, tick_label(t, ticks), 11, "var(--muted)", "middle",
                 extra='font-variant-numeric="tabular-nums"')
    svg.text(plot_x1, y0 + len(groups) * gh + 36, unit, 11, "var(--muted)", "end")
    svg.line(plot_x0, y0, plot_x0, y0 + len(groups) * gh, "var(--axis)")
    for gi, (gkey, glabel) in enumerate(groups):
        gy = y0 + gi * gh + group_pad / 2
        svg.text(plot_x0 - 12, gy + len(servers) * (bar + gap) / 2 + 4, glabel, 12, "var(--ink)", "end")
        best = None
        vals = {s: values[gi].get(s) for s in servers}
        ok = [v for v in vals.values() if v is not None]
        if ok:
            best = max(ok) if higher_better else min(ok)
        for si, s in enumerate(servers):
            y = gy + si * (bar + gap)
            v = vals.get(s)
            if v is None:
                svg.text(plot_x0 + 6, y + bar - 3, "DNF", 10, "var(--muted)")
                continue
            tip = f"{labels[s]} / {glabel}: {fmt(v, 2)} {unit}"
            if ranges and ranges[gi].get(s):
                lo, hi = ranges[gi][s]
                tip += f" (runs {fmt(lo, 2)} to {fmt(hi, 2)})"
            svg.bar_h(plot_x0, y, v * scale, bar, color_of(s), tip)
            if ranges and ranges[gi].get(s):
                lo, hi = ranges[gi][s]
                if hi > lo:
                    cy = y + bar / 2
                    svg.line(plot_x0 + lo * scale, cy, plot_x0 + hi * scale, cy, "var(--ink2)", 1)
                    svg.line(plot_x0 + lo * scale, cy - 3, plot_x0 + lo * scale, cy + 3, "var(--ink2)", 1)
                    svg.line(plot_x0 + hi * scale, cy - 3, plot_x0 + hi * scale, cy + 3, "var(--ink2)", 1)
            if v == best:  # direct-label only the group's extreme
                lx = plot_x0 + (max(v, (ranges[gi][s][1] if ranges and ranges[gi].get(s) else v))) * scale + 8
                svg.text(lx, y + bar - 3, fmt(v, 2 if v < 100 else 0), 11, "var(--ink)", weight="600",
                         extra='font-variant-numeric="tabular-nums"')
    svg.legend(24, h - 14, [(color_of(s), labels[s]) for s in servers])
    return svg.done()


def latency_dots(title, subtitle, servers, labels, pct):
    """pct[s] -> {p50, p90, p99, p999} in microseconds, log x axis."""
    w, left, right, top, row = 960, 230, 60, 74, 44
    h = top + len(servers) * row + 80
    svg = SVG(w, h, title)
    svg.text(24, 30, title, 17, "var(--ink)", weight="600")
    svg.text(24, 50, subtitle, 12, "var(--muted)")
    keys = ("p50_us", "p90_us", "p99_us", "p999_us")
    vals = [pct[s][k] for s in servers for k in keys if pct.get(s, {}).get(k)]
    if not vals:
        svg.text(left, top + 20, "no data", 12)
        return svg.done()
    steps = [m * 10 ** k for k in range(-1, 7) for m in (1, 2, 5)]
    lo = max(v for v in steps if v <= min(vals))
    hi = min(v for v in steps if v >= max(vals))
    x0, x1 = left, w - right

    def xs(v):
        return x0 + (math.log10(v) - math.log10(lo)) / (math.log10(hi) - math.log10(lo)) * (x1 - x0)

    t = lo
    while t <= hi:
        for m in (1, 2, 5):
            v = t * m
            if lo <= v <= hi:
                svg.line(xs(v), top, xs(v), top + len(servers) * row, "var(--grid)")
                svg.text(xs(v), top + len(servers) * row + 18, f"{v:g}", 11, "var(--muted)", "middle")
        t *= 10
    svg.text(x1, top + len(servers) * row + 36, "microseconds, log scale", 11, "var(--muted)", "end")
    names = [("p50", "p50_us"), ("p90", "p90_us"), ("p99", "p99_us"), ("p99.9", "p999_us")]
    for si, s in enumerate(servers):
        cy = top + si * row + row / 2
        svg.text(x0 - 12, cy + 4, labels[s], 12, "var(--ink)", "end")
        p = pct.get(s)
        if not p or not p.get("p50_us"):
            svg.text(x0 + 6, cy + 4, "DNF", 10, "var(--muted)")
            continue
        xa, xb = xs(p["p50_us"]), xs(p["p999_us"])
        svg.line(xa, cy, xb, cy, color_of(s), 2, 'stroke-linecap="round"')
        for nm, key in names:
            svg.dot(xs(p[key]), cy, color_of(s), f"{labels[s]} {nm}: {fmt(p[key])} us")
        svg.text(xa - 10, cy + 4, fmt(p["p50_us"]), 11, "var(--ink2)", "end",
                 extra='font-variant-numeric="tabular-nums"')
        svg.text(xb + 10, cy + 4, fmt(p["p999_us"]), 11, "var(--ink2)",
                 extra='font-variant-numeric="tabular-nums"')
    svg.text(x0, top - 8, "dots, left to right: p50, p90, p99, p99.9; the printed values are p50 and p99.9", 11,
             "var(--muted)")
    svg.legend(24, h - 14, [(color_of(s), labels[s]) for s in servers])
    return svg.done()


def small_bars(title, subtitle, panels, servers, labels):
    """panels: [(panel_title, unit, {s: value}, higher_better)] -> side-by-side single bars per server."""
    n = len(panels)
    label_w = 236
    w, top = 960, 84
    pw = (w - 24 - label_w - 24) / n
    bar, gap = 14, 6
    h = top + len(servers) * (bar + gap) + 90
    svg = SVG(w, h, title)
    svg.text(24, 30, title, 17, "var(--ink)", weight="600")
    svg.text(24, 50, subtitle, 12, "var(--muted)")
    for pi, (ptitle, unit, vals, higher_better) in enumerate(panels):
        px0 = 24 + label_w + pi * pw
        px1 = px0 + pw - 64
        svg.text(px0, top - 4, ptitle, 12, "var(--ink)", weight="600")
        ok = [v for v in vals.values() if v is not None]
        vmax = max(ok) if ok else 1
        ticks = nice_ticks(vmax, 3)
        scale = (px1 - px0) / ticks[-1]
        for t in ticks:
            svg.line(px0 + t * scale, top + 4, px0 + t * scale, top + 4 + len(servers) * (bar + gap), "var(--grid)")
            svg.text(px0 + t * scale, top + 4 + len(servers) * (bar + gap) + 16, tick_label(t, ticks), 10,
                     "var(--muted)", "middle")
        svg.text(px1, top + 4 + len(servers) * (bar + gap) + 32, unit, 10, "var(--muted)", "end")
        svg.line(px0, top + 4, px0, top + 4 + len(servers) * (bar + gap), "var(--axis)")
        best = (max(ok) if higher_better else min(ok)) if ok else None
        for si, s in enumerate(servers):
            y = top + 4 + si * (bar + gap)
            if pi == 0:
                svg.text(px0 - 12, y + bar - 3, labels[s], 11, "var(--ink)", "end")
            v = vals.get(s)
            if v is None:
                svg.text(px0 + 6, y + bar - 3, "DNF", 10, "var(--muted)")
                continue
            svg.bar_h(px0, y, v * scale, bar, color_of(s), f"{labels[s]}: {fmt(v, 2)} {unit}")
            if v == best:
                svg.text(px0 + v * scale + 6, y + bar - 3, fmt(v, 2 if v < 100 else 0), 10, "var(--ink)",
                         weight="600", extra='font-variant-numeric="tabular-nums"')
    svg.legend(24, h - 14, [(color_of(s), labels[s]) for s in servers])
    return svg.done()


def timelines(title, subtitle, scen_labels, series, servers, labels):
    """series[scen][s] -> [(t_s, mib_s), ...]; one small panel per scenario, 2 columns."""
    cols = 2
    n = len(scen_labels)
    rows = math.ceil(n / cols)
    w, top, ph, pw = 960, 74, 190, (960 - 48) / cols
    h = top + rows * ph + 50
    svg = SVG(w, h, title)
    svg.text(24, 30, title, 17, "var(--ink)", weight="600")
    svg.text(24, 50, subtitle, 12, "var(--muted)")
    for i, (skey, slabel) in enumerate(scen_labels):
        r, c = divmod(i, cols)
        px0 = 24 + c * pw + 60
        px1 = 24 + (c + 1) * pw - 20
        py0 = top + r * ph + 30
        py1 = py0 + ph - 64
        data = series.get(skey, {})
        svg.text(px0 - 60, py0 - 16, slabel, 12, "var(--ink)", weight="600")
        allv = [v for s in data.values() for _, v in s]
        allt = [t for s in data.values() for t, _ in s]
        if not allv:
            svg.text(px0, (py0 + py1) / 2, "no data", 11, "var(--muted)")
            continue
        vmax, tmax = max(allv), max(allt)
        ticks = nice_ticks(vmax, 3)
        ys = lambda v: py1 - v / ticks[-1] * (py1 - py0)  # noqa: E731
        xs = lambda t: px0 + t / tmax * (px1 - px0)  # noqa: E731
        for t in ticks:
            svg.line(px0, ys(t), px1, ys(t), "var(--grid)")
            svg.text(px0 - 6, ys(t) + 4, tick_label(t, ticks), 10, "var(--muted)", "end",
                     extra='font-variant-numeric="tabular-nums"')
        svg.line(px0, py1, px1, py1, "var(--axis)")
        for tx in range(0, int(tmax) + 1, 2):
            svg.text(xs(tx), py1 + 14, f"{tx}s", 10, "var(--muted)", "middle")
        for s in servers:
            pts = data.get(s)
            if not pts:
                continue
            d = " ".join(f"{'M' if j == 0 else 'L'}{xs(t):.1f},{ys(v):.1f}" for j, (t, v) in enumerate(pts))
            svg.add(f'<path d="{d}" fill="none" stroke="{color_of(s)}" stroke-width="2" stroke-linejoin="round" '
                    f'stroke-linecap="round"/>')
            t, v = pts[-1]
            svg.dot(xs(t), ys(v), color_of(s), f"{labels[s]} / {slabel}: {fmt(v)} MiB/s at {t:.2f}s", 3.5)
            for t, v in pts:  # invisible wide hit targets for hover
                svg.add(f'<rect class="mark" x="{xs(t) - 4:.1f}" y="{py0}" width="8" height="{py1 - py0}" '
                        f'fill="transparent" data-tip="{esc(f"{labels[s]} / {slabel}: {fmt(v)} MiB/s at {t:.2f}s")}"/>')
    svg.text(24, h - 30, "MiB/s per 250 ms sample at the echo port, median run of each server", 11, "var(--muted)")
    svg.legend(24, h - 12, [(color_of(s), labels[s]) for s in servers])
    return svg.done()


# -------------------------------------------------------------------------------------- report
def build(results_dir, png=False):
    results_dir = pathlib.Path(results_dir)
    data = json.load(open(results_dir / "results.json"))
    meta, summary, runs = data["meta"], data["summary"], data["runs"]
    servers = [s for s in SERVER_ORDER if s in meta["servers"]] + [s for s in meta["servers"] if s not in SERVER_ORDER]
    labels = {s: meta["servers"][s]["label"] for s in servers}
    scen = meta["scenarios"]
    tp = [(k, v["label"]) for k, v in scen.items() if v["kind"] == "tp"]
    charts = {}

    def table(scen_keys, key):
        return [{s: summary.get(k, {}).get(s, {}).get(key) for s in servers} for k, _ in scen_keys]

    def ranges(scen_keys, key):
        out = []
        for k, _ in scen_keys:
            row = {}
            for s in servers:
                vals = [r[key] for r in runs if r["scenario"] == k and r["server"] == s and r.get("ok") and key in r]
                row[s] = (min(vals), max(vals)) if vals else None
            out.append(row)
        return out

    charts["throughput"] = grouped_bars_h(
        "Throughput through the echo port", f"MiB/s, one direction; median of {meta['repeats']} runs of "
        f"{meta['duration']} s, whiskers span the runs", tp, servers, labels, table(tp, "mib_s"), "MiB/s",
        ranges(tp, "mib_s"))
    charts["efficiency"] = grouped_bars_h(
        "Relay efficiency", "MiB relayed for every CPU-second the server spent; higher means cheaper per byte", tp,
        servers, labels, table(tp, "mib_per_cpu_s"), "MiB per CPU-second", ranges(tp, "mib_per_cpu_s"))
    charts["cpu"] = grouped_bars_h(
        "Server CPU while relaying", "CPU cores kept busy by the server process during the window", tp,
        servers, labels, table(tp, "server_cpu_cores"), "cores", ranges(tp, "server_cpu_cores"),
        higher_better=False)
    if "rtt-64" in summary:
        charts["latency"] = latency_dots(
            "Round-trip latency", "64-byte echo, one stream, one message in flight; p50, p90, p99 and p99.9 of "
            f"every round trip in {meta['duration']} s (median run)", servers, labels,
            {s: summary["rtt-64"].get(s, {}) for s in servers})
    churn = [k for k, v in scen.items() if v["kind"] == "churn" and k in summary]
    if churn:
        ck = churn[0]
        charts["churn"] = small_bars(
            "Stream churn", scen[ck]["label"] + ": open a TCP stream, echo one byte, close it, repeat",
            [("Lifecycles per second", "streams/s", {s: summary[ck].get(s, {}).get("per_s") for s in servers}, True),
             ("Server CPU", "cores", {s: summary[ck].get(s, {}).get("server_cpu_cores") for s in servers}, False),
             ("Peak RSS", "MiB", {s: summary[ck].get(s, {}).get("server_peak_rss_mib") for s in servers}, False)],
            servers, labels)
    # timelines from the median run of each (scenario, server)
    series = {}
    for k, _ in tp:
        series[k] = {}
        for s in servers:
            rs = sorted([r for r in runs if r["scenario"] == k and r["server"] == s and r.get("ok")],
                        key=lambda r: r["mib_s"])
            if not rs:
                continue
            tl = rs[len(rs) // 2].get("timeline") or []
            pts, prev_t, prev_b = [], 0.0, 0
            for t, b in tl:
                if t > prev_t:
                    pts.append((t, (b - prev_b) / 1048576 / (t - prev_t)))
                prev_t, prev_b = t, b
            series[k][s] = pts
    charts["timeline"] = timelines("Throughput over time", "Whether each server keeps its rate up for the whole window", tp, series,
                                   servers, labels)

    out = results_dir / "charts"
    out.mkdir(exist_ok=True)
    for name, svg in charts.items():
        (out / f"{name}.svg").write_text(svg)
        dark = svg.replace(f' style="{SVG_STYLE}"', ' style="' + "".join(f"--{k}:{v};" for k, v in DARK.items()) + '"', 1)
        (out / f"{name}-dark.svg").write_text(dark)
    (results_dir / "report.html").write_text(report_html(meta, summary, runs, servers, labels, scen, charts))
    if png:
        for name in charts:
            rasterise(out / f"{name}.svg", out / f"{name}.png")
            rasterise(out / f"{name}-dark.svg", out / f"{name}-dark.png")
    print(f"wrote {len(charts)} charts (light and dark) to {out} and {results_dir / 'report.html'}")


def rasterise(svg_path, png_path, scale=2):
    import re
    m = re.search(r'width="(\d+)" height="(\d+)"', svg_path.read_text())
    w, h = int(m.group(1)), int(m.group(2))
    for exe in ("chromium-browser", "google-chrome", "chromium"):
        try:
            subprocess.run([exe, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--window-size={w},{h}",
                            f"--force-device-scale-factor={scale}", f"--screenshot={png_path}",
                            f"file://{svg_path.resolve()}"], check=True, capture_output=True, timeout=60)
            return
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue
    print(f"could not rasterise {svg_path}", file=sys.stderr)


def report_html(meta, summary, runs, servers, labels, scen, charts):
    tp = [(k, v["label"]) for k, v in scen.items() if v["kind"] == "tp"]

    def cell(v, d=0):
        return f'<td class="num">{fmt(v, d)}</td>' if v is not None else '<td class="num dnf">DNF</td>'

    def tp_table(key, d=0):
        head = "".join(f"<th>{esc(l)}</th>" for _, l in tp)
        rows = "".join(f"<tr><th>{esc(labels[s])}</th>" + "".join(cell(summary.get(k, {}).get(s, {}).get(key), d)
                                                                   for k, _ in tp) + "</tr>" for s in servers)
        return f'<div class="tablewrap"><table><thead><tr><th></th>{head}</tr></thead><tbody>{rows}</tbody></table></div>'

    def win_table():
        others = [s for s in servers if s != "holywisp"]
        rows = []
        for k, l in tp:
            vals = {s: summary.get(k, {}).get(s, {}).get("mib_s") for s in servers}
            ok = {s: v for s, v in vals.items() if v is not None}
            if not ok:
                continue
            best = max(ok, key=ok.get)
            hw = vals.get("holywisp")
            rel = "".join(f"<td class='num'>{(f'{(hw / vals[o] - 1) * 100:+.0f}%' if hw and vals.get(o) else '')}</td>"
                          for o in others)
            rows.append(f"<tr><th>{esc(l)}</th><td>{esc(labels[best])}</td>" + "".join(cell(vals[s]) for s in servers)
                        + rel + "</tr>")
        head = "".join(f"<th>{esc(labels[s])}</th>" for s in servers)
        relhead = "".join(f"<th>vs {esc(labels[o])}</th>" for o in others)
        return (f'<div class="tablewrap"><table><thead><tr><th>scenario</th><th>fastest</th>{head}{relhead}</tr>'
                f'</thead><tbody>{"".join(rows)}</tbody></table></div>')

    rtt_rows = ""
    if "rtt-64" in summary:
        for s in servers:
            a = summary["rtt-64"].get(s, {})
            rtt_rows += (f"<tr><th>{esc(labels[s])}</th>" + "".join(cell(a.get(k)) for k in
                                                                    ("p50_us", "p90_us", "p99_us", "p999_us", "mean_us", "rps")) +
                         f"{cell(a.get('stalls'))}</tr>")
    churn_rows = ""
    ck = next((k for k, v in scen.items() if v["kind"] == "churn" and k in summary), None)
    if ck:
        for s in servers:
            a = summary[ck].get(s, {})
            churn_rows += (f"<tr><th>{esc(labels[s])}</th>{cell(a.get('per_s'))}{cell(a.get('failed'))}"
                           f"{cell(a.get('server_cpu_cores'), 2)}{cell(a.get('server_peak_rss_mib'), 1)}</tr>")
    stalls = {}
    for r in runs:
        if r.get("client_stalls") or r.get("stalls"):
            stalls.setdefault(r["server"], set()).add(r["scenario"])
    dnfs = {}
    for r in runs:
        if not r.get("ok"):
            dnfs.setdefault(r["server"], {}).setdefault(r["scenario"], []).append(r.get("error", "?"))

    v = meta.get("versions", {})
    setup = f"""
<dl class="setup">
<dt>Host</dt><dd>{esc(meta['cpu'])}, Linux {esc(v.get('kernel', ''))}</dd>
<dt>Method</dt><dd>Each server runs on its own in front of one TCP echo service on loopback. Clients push data
through Wisp streams to the echo port, and the figure we report is how many bytes per second crossed that port in
one direction, counted by the echo service itself (wispmark reads the same figure from iftop). Every cell is the
median of {meta['repeats']} runs of {meta['duration']} s, each after a 1.5 s warm-up, with the server order
reversed on alternate repeats. CPU time and peak RSS are read from /proc for the server process over the same
window.</dd>
<dt>Servers</dt><dd>holyWisp {esc(v.get('holywisp', ''))} ({esc(v.get('holywisp_git', ''))}, release build, {esc(v.get('gcc', '').split(' ')[0])});
wispurr Go {esc(v.get('wispurr_go_git', ''))} ({esc(v.get('go', ''))}); wispurr C++23 built with {esc(v.get('gcc', ''))};
wisp-server-python {esc(v.get('wisp_python_git', ''))} on {esc(v.get('python', ''))}, default thread count.
All run with flood protection, reputation and per-IP connection limits off, loopback and literal-IP egress
allowed, error-level logging, default worker count. The host was not idle during the run (a desktop session was using several cores), so compare servers within a row, not numbers across runs.</dd>
<dt>Clients</dt><dd>wisp-js {esc(v.get('wisp-js', ''))} on Node {esc(v.get('node', ''))}, which is the client wispmark uses (50 KiB payloads),
and the native pump from this repository, built on libholywisp-client (64 KiB packets unless stated, and it
respects the server's CONTINUE window).</dd>
</dl>"""

    def section(id_, title, body):
        return f'<section id="{id_}"><h2>{esc(title)}</h2>{body}</section>'

    findings = []
    findings.append(
        "<li><strong>The Go wispurr needed a smaller window to finish.</strong> Its shipped speed config "
        "advertises a CONTINUE window of 32768 packets, and at that setting it stops relaying within a second "
        "or two no matter which client is talking to it. wisp-js freezes after about half a gigabyte without "
        "a single stream being closed or a line being logged, and a client that respects the window blocks "
        "after exactly 32768 packets because the server never counts DATA that arrives before its outbound "
        "dial has completed, so the CONTINUE it owes never goes out. At a window of 128 it runs steadily, so "
        "that is what its numbers here use. The C++23 build measures the same at 128 and 32768 and keeps its "
        "shipped 32768."
        + (f" Runs that still failed: {esc(', '.join(sorted(dnfs.get('wispurr-go', {}))))}." if dnfs.get("wispurr-go") else "")
        + "</li>")
    findings.append(
        "<li><strong>How holyWisp moves bulk data.</strong> Toward the client, a stream whose remote "
        "delivers full reads gets its own pipe and is relayed with splice(), with pipe payloads queued in "
        "order behind the frame bytes, so nothing is copied through user space. Toward the remote, "
        "consecutive frames for a stream leave in one vectored write and frames of 128 KiB or more are "
        "forwarded while they are still arriving. The advertised CONTINUE window is 128 packets; refills "
        "share a per-connection budget between streams, and a CONTINUE is held back while bytes are still "
        "queued toward the remote.</li>")
    findings.append(
        "<li><strong>One connection or many.</strong> Both holyWisp and the C++23 wispurr run a connection "
        "on one event loop (wispurr can split a connection's two directions across loops, but its source "
        "defaults to one and notes the split costs more CPU than it returns). They are close when a single "
        "connection carries everything; holyWisp pulls ahead as traffic spreads over connections, where it "
        "relays more bytes per CPU-second.</li>")
    if "wisp-python" in servers:
        findings.append(
            "<li><strong>wisp-server-python needed two install fixes.</strong> On this host's Python 3.14 it "
            "tries to run its workers in subinterpreters and fails to start, so it runs on a Python 3.13 that uv "
            "fetched. And with the websockets release a fresh install pulls in today (17.x), its single "
            "WebSocket reader blocks on a full per-stream queue and the whole connection deadlocks once more "
            "than two streams are busy, leaving a few MiB/s; pinned below 14 it behaves normally, so that is "
            "what these numbers use. Its WebSocket library also caps messages at 1 MiB, so the 1 MiB packet "
            "scenario is beyond it.</li>")
    findings.append(
        "<li><strong>Build notes.</strong> The C++23 wispurr needed <code>#include &lt;cstdint&gt;</code> in "
        "<code>json.cpp</code> to compile with GCC 16, and it is linked dynamically against libstdc++ "
        "because this host has no static copy. The Go wispurr rejects the <code>frameObfuscation</code> key "
        "that its C++ sibling accepts, so it has a config file of its own.</li>")

    tokens_light = "".join(f"--{k}:{v};" for k, v in LIGHT.items())
    tokens_dark = "".join(f"--{k}:{v};" for k, v in DARK.items())
    charts_html = {k: v.replace(f' style="{SVG_STYLE}"', "") for k, v in charts.items()}
    cmd_rows = "".join(f"<tr><th>{esc(labels[s])}</th><td><code>{esc(meta['servers'][s]['cmd'])}</code></td></tr>"
                       for s in servers)
    cmd_rows += "".join(f"<tr><th>{esc(v['label'])}</th><td><code>{esc(v['cmd'])}</code>"
                        f"{' x ' + str(v['procs']) if v['procs'] > 1 else ''}</td></tr>" for v in scen.values())
    return f"""<title>Wisp Relay Benchmarks</title>
<meta name="claude:viewport-fit-sides" content="cover">
<style>
/* Layout: one reading column, charts full width of the column, tables under each chart. */
:root {{ {tokens_light} --page:#f9f9f7; --border:rgba(11,11,11,0.10); --accent:#2a78d6; --code:#f0efec;
  --font: "IBM Plex Sans", system-ui, -apple-system, "Segoe UI", sans-serif; --mono: "IBM Plex Mono", ui-monospace, Menlo, monospace; }}
@media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{ {tokens_dark} --page:#0d0d0d; --border:rgba(255,255,255,0.10); --accent:#3987e5; --code:#262624; color-scheme: dark; }} }}
:root[data-theme="dark"] {{ {tokens_dark} --page:#0d0d0d; --border:rgba(255,255,255,0.10); --accent:#3987e5; --code:#262624; color-scheme: dark; }}
body {{ background: var(--page); color: var(--ink); font-family: var(--font); font-size: 15px; line-height: 1.5; margin: 0;
  padding-block: 32px 64px; padding-left: max(16px, env(safe-area-inset-left, 0px)); padding-right: max(16px, env(safe-area-inset-right, 0px)); }}
main {{ max-width: 1000px; margin: 0 auto; display: grid; gap: 40px; }}
header h1 {{ font-size: 2rem; margin: 0 0 6px; letter-spacing: -0.01em; text-wrap: balance; }}
header p {{ margin: 0; color: var(--ink2); max-width: 65ch; }}
h2 {{ font-size: 1.25rem; margin: 0 0 12px; }}
section {{ display: grid; gap: 14px; min-width: 0; }}
figure {{ margin: 0; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 8px; overflow-x: auto; }}
figure svg {{ display: block; width: 100%; height: auto; min-width: 640px; }}
figure svg rect:first-child {{ fill: var(--surface); }}
.tablewrap {{ overflow-x: auto; }}
table {{ border-collapse: collapse; font-size: 13px; width: 100%; }}
th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
thead th {{ color: var(--ink2); font-weight: 500; }}
tbody th {{ font-weight: 500; white-space: nowrap; }}
td.num {{ text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }}
td.dnf {{ color: var(--muted); }}
dl.setup {{ display: grid; grid-template-columns: max-content 1fr; gap: 8px 18px; margin: 0; font-size: 14px; }}
dl.setup dt {{ color: var(--ink2); font-weight: 500; }}
dl.setup dd {{ margin: 0; min-width: 0; max-width: 75ch; }}
code {{ font-family: var(--mono); font-size: 12.5px; background: var(--code); padding: 1px 5px; border-radius: 4px; overflow-wrap: anywhere; }}
ul.findings {{ margin: 0; padding-left: 1.2em; display: grid; gap: 10px; max-width: 75ch; }}
.legendnote {{ color: var(--muted); font-size: 13px; }}
#tip {{ position: fixed; pointer-events: none; background: var(--ink); color: var(--surface); font-size: 12px; padding: 6px 9px;
  border-radius: 6px; max-width: 320px; z-index: 20; transform: translate(-50%, calc(-100% - 12px)); }}
details summary {{ cursor: pointer; color: var(--ink2); }}
@media (max-width: 640px) {{ dl.setup {{ grid-template-columns: 1fr; }} header h1 {{ font-size: 1.5rem; }} }}
@media (prefers-reduced-motion: no-preference) {{ .mark {{ transition: opacity .12s; }} }}
.mark:hover {{ opacity: .85; }}
</style>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono&display=swap">
<main>
<header>
<h1>Wisp Relay Benchmarks</h1>
<p>holyWisp side by side with both wispurr implementations, on one host, through the same echo service, driven by
the same clients. Run started {esc(meta['started'])}.</p>
</header>
{section("setup", "Setup", setup)}
{section("scoreboard", "Who wins where", win_table() + '<p class="legendnote">Throughput in MiB/s; the "vs" columns are holyWisp relative to that server.</p>')}
{section("throughput", "Throughput", f'<figure>{charts_html["throughput"]}</figure>' + tp_table("mib_s"))}
{section("efficiency", "Efficiency", f'<figure>{charts_html["efficiency"]}</figure>' + tp_table("mib_per_cpu_s"))}
{section("cpu", "Server CPU", f'<figure>{charts_html["cpu"]}</figure>' + tp_table("server_cpu_cores", 2))}
{section("latency", "Latency", (f'<figure>{charts_html["latency"]}</figure>' if "latency" in charts_html else "") +
         '<div class="tablewrap"><table><thead><tr><th></th><th>p50 us</th><th>p90 us</th><th>p99 us</th><th>p99.9 us</th><th>mean us</th><th>round trips/s</th><th>window stalls</th></tr></thead>'
         f'<tbody>{rtt_rows}</tbody></table></div>')}
{section("churn", "Stream churn", (f'<figure>{charts_html["churn"]}</figure>' if "churn" in charts_html else "") +
         '<div class="tablewrap"><table><thead><tr><th></th><th>lifecycles/s</th><th>failed</th><th>server cores</th><th>peak RSS MiB</th></tr></thead>'
         f'<tbody>{churn_rows}</tbody></table></div>')}
{section("timeline", "Throughput over time", f'<figure>{charts_html["timeline"]}</figure>')}
{section("findings", "Findings", '<ul class="findings">' + "".join(findings) + '</ul>')}
{section("commands", "Exact commands", f'<details><summary>Server and client command lines</summary><div class="tablewrap"><table><tbody>{cmd_rows}</tbody></table></div></details>')}
</main>
<div id="tip" hidden></div>
<script>
(function () {{
  var tip = document.getElementById('tip');
  document.addEventListener('mousemove', function (e) {{
    var m = e.target.closest ? e.target.closest('.mark') : null;
    if (!m || !m.dataset.tip) {{ tip.hidden = true; return; }}
    tip.textContent = m.dataset.tip; tip.hidden = false;
    tip.style.left = e.clientX + 'px'; tip.style.top = e.clientY + 'px';
  }});
  document.addEventListener('mouseleave', function () {{ tip.hidden = true; }});
}})();
</script>
"""


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    build(args[0] if args else "bench/results/full", png="--png" in sys.argv)
