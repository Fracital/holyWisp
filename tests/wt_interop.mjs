#!/usr/bin/env node
// Manual interop check, not part of ctest: other people's HTTP/3 and WebTransport against the
// listener, each skipped when it is not on the machine.
//
//   node tests/wt_interop.mjs [path/to/holywisp] [path/to/chrome]
//
// Starts the server on loopback (an ephemeral port, its own TCP and UDP echo services), then:
// - curl --http3-only -k GET / (curl's ngtcp2 and nghttp3): a request that is not a WebTransport
//   CONNECT is answered 421 (alt-svc: clear, so a page sent here goes back to TCP);
// - headless Chrome: a page on 127.0.0.1 fetches /webtransport.json, opens new WebTransport() with
//   the pinned hashes and speaks Wisp v1 over the session (the stream-0 CONTINUE, a TCP stream
//   echoed on the Wisp stream, a UDP stream echoed by datagram), then a second session offering
//   "wisp-v2" (the server's INFO comes first), and a third that is open when the server is stopped
//   (SIGTERM): it must end cleanly ("server stopping") within a few seconds, not at the idle timeout.
//   It reports back by POST.
// Exits 0 when everything that ran passed. Nothing leaves the machine.
import { execFileSync, spawn } from "node:child_process";
import dgram from "node:dgram";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const server = process.argv[2] || path.join(root, "build/release/holywisp");
const chrome =
  process.argv[3] ||
  ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"].find((c) =>
    (process.env.PATH || "").split(":").some((d) => fs.existsSync(path.join(d, c))),
  );
if (!fs.existsSync(server)) fail(`no server binary at ${server} (make release)`);

const children = [];
let profile;
process.on("exit", () => {
  for (const c of children) if (c.exitCode === null) c.kill("SIGKILL");
  if (profile) fs.rmSync(profile, { recursive: true, force: true });
});
function fail(msg) {
  console.error(`wt_interop: ${msg}`);
  process.exit(1);
}

const listen = (srv, ...args) => new Promise((ok) => srv.listen(0, "127.0.0.1", ...args, () => ok(srv.address().port)));

// A stream the client ended is reset toward the remote (AGENTS.md, "Closing toward the remote").
const tcpEcho = net.createServer((s) => {
  s.on("error", () => {});
  s.pipe(s);
});
const tcpPort = await listen(tcpEcho);
const udpEcho = dgram.createSocket("udp4");
udpEcho.on("message", (m, r) => udpEcho.send(m, r.port, r.address));
await new Promise((ok) => udpEcho.bind(0, "127.0.0.1", ok));
const udpPort = udpEcho.address().port;

// A free port for the server: TCP and UDP share the number.
const probe = net.createServer();
const wispPort = await listen(probe);
await new Promise((ok) => probe.close(ok));

const hw = spawn(
  server,
  ["--host", "127.0.0.1", "--port", String(wispPort), "--allow-loopback", "--allow-direct-ip", "--webtransport=true"],
  { stdio: ["ignore", "inherit", "inherit"] },
);
children.push(hw);
hw.on("exit", (code) => code !== null && code !== 0 && fail(`server exited ${code}`));

await new Promise((ok) => setTimeout(ok, 500)); // the server binds and makes its certificate

const results = {};
let curlVersion = "";
try {
  curlVersion = execFileSync("curl", ["--version"], { encoding: "utf8" });
} catch {}
if (/HTTP3/.test(curlVersion)) {
  let code = "";
  try {
    code = execFileSync(
      "curl",
      ["-s", "-k", "--http3-only", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", `https://127.0.0.1:${wispPort}/`],
      { encoding: "utf8" },
    );
  } catch (e) {
    code = String(e.stdout || e.message);
  }
  results.curl = { status: code, ok: code === "421" };
} else {
  results.curl = "skipped: no curl with HTTP/3";
}
if (!chrome) {
  results.chrome = "skipped: no Chrome or Chromium on PATH (pass its path as the second argument)";
  report();
}

function report() {
  console.log(JSON.stringify(results, null, 2));
  const ran = Object.values(results).filter((r) => typeof r === "object");
  hw.removeAllListeners("exit");
  process.exit(ran.every((r) => r.ok) ? 0 : 1); // the exit handler kills the server and Chrome
}

const page = `<!doctype html><meta charset="utf-8"><title>wt</title><script type="module">
const report = (r) => fetch("/result", { method: "POST", body: JSON.stringify(r) });
const steps = {};
try {
  const cfg = await (await fetch("http://127.0.0.1:${wispPort}/webtransport.json")).json();
  steps.hashes = cfg.hashes.length;
  const serverCertificateHashes = cfg.hashes.map((h) => ({
    algorithm: h.algorithm,
    value: Uint8Array.from(atob(h.value), (c) => c.charCodeAt(0)),
  }));
  const wt = new WebTransport("https://127.0.0.1:${wispPort}/", { serverCertificateHashes });
  await wt.ready;
  steps.ready = true;
  const bidi = await wt.createBidirectionalStream();
  const writer = bidi.writable.getWriter();
  const reader = bidi.readable.getReader();
  const packet = (type, id, payload) => {
    const b = new Uint8Array(5 + payload.length);
    b[0] = type;
    new DataView(b.buffer).setUint32(1, id, true);
    b.set(payload, 5);
    return b;
  };
  const framed = (p) => {
    const b = new Uint8Array(4 + p.length);
    new DataView(b.buffer).setUint32(0, p.length, true);
    b.set(p, 4);
    return b;
  };
  const connect = (id, type, port, host) => {
    const h = new TextEncoder().encode(host);
    const p = new Uint8Array(3 + h.length);
    p[0] = type;
    new DataView(p.buffer).setUint16(1, port, true);
    p.set(h, 3);
    return packet(0x01, id, p);
  };
  let buf = new Uint8Array(0);
  const nextPacket = async () => {
    for (;;) {
      if (buf.length >= 4) {
        const n = new DataView(buf.buffer, buf.byteOffset).getUint32(0, true);
        if (buf.length >= 4 + n) {
          const p = buf.slice(4, 4 + n);
          buf = buf.slice(4 + n);
          return { type: p[0], id: new DataView(p.buffer).getUint32(1, true), payload: p.slice(5) };
        }
      }
      const { value, done } = await reader.read();
      if (done) throw new Error("the Wisp stream ended");
      const m = new Uint8Array(buf.length + value.length);
      m.set(buf);
      m.set(value, buf.length);
      buf = m;
    }
  };
  const first = await nextPacket();
  steps.continue0 = first.type === 0x03 && first.id === 0;
  await writer.write(framed(connect(1, 0x01, ${tcpPort}, "127.0.0.1")));
  await writer.write(framed(packet(0x02, 1, new TextEncoder().encode("hello from chrome"))));
  for (;;) {
    const p = await nextPacket();
    if (p.id === 1 && p.type === 0x02) {
      steps.tcpEcho = new TextDecoder().decode(p.payload);
      break;
    }
    if (p.id === 1 && p.type === 0x04) throw new Error("TCP stream closed " + p.payload[0]);
  }
  await writer.write(framed(connect(2, 0x02, ${udpPort}, "127.0.0.1")));
  const dw = wt.datagrams.writable.getWriter();
  const dr = wt.datagrams.readable.getReader();
  const got = (async () => {
    for (;;) {
      const { value } = await dr.read();
      if (value[0] === 0x02 && new DataView(value.buffer, value.byteOffset).getUint32(1, true) === 2) {
        return new TextDecoder().decode(value.slice(5));
      }
    }
  })();
  for (let i = 0; i < 20 && !steps.udpEcho; i++) {
    await dw.write(packet(0x02, 2, new TextEncoder().encode("datagram " + i)));
    steps.udpEcho = await Promise.race([got, new Promise((ok) => setTimeout(() => ok(undefined), 250))]);
  }
  wt.close({ closeCode: 0, reason: "done" });
  // v2: offering any protocol is the opt-in, and the server speaks first with INFO.
  const wt2 = new WebTransport("https://127.0.0.1:${wispPort}/", { serverCertificateHashes, protocols: ["wisp-v2"] });
  await wt2.ready;
  if (wt2.protocol === undefined) {
    steps.v2 = "skipped: this Chrome has no WebTransport protocols option";
  } else {
    const r2 = (await wt2.createBidirectionalStream()).readable.getReader();
    const { value } = await r2.read();
    steps.v2 = { protocol: wt2.protocol, firstPacket: value && value.length > 4 ? value[4] : -1 };
    steps.v2ok = wt2.protocol === "wisp-v2" && steps.v2.firstPacket === 0x05;
  }
  wt2.close({ closeCode: 0, reason: "done" });
  // The server stops with a session open: the session's close capsule, then CONNECTION_CLOSE.
  const wt3 = new WebTransport("https://127.0.0.1:${wispPort}/", { serverCertificateHashes });
  await wt3.ready;
  const t0 = performance.now();
  await fetch("/stop", { method: "POST" });
  const how = await Promise.race([
    wt3.closed.then((i) => ({ closed: i }), (e) => ({ error: String(e) })),
    new Promise((ok) => setTimeout(() => ok({ timeout: true }), 10000)),
  ]);
  steps.stop = { ...how, ms: Math.round(performance.now() - t0) };
  steps.stopOk = !!how.closed && how.closed.reason === "server stopping" && steps.stop.ms < 5000; // not "Connection lost."
  steps.ok =
    steps.continue0 &&
    steps.tcpEcho === "hello from chrome" &&
    !!steps.udpEcho &&
    (typeof steps.v2 === "string" || steps.v2ok) &&
    steps.stopOk;
} catch (e) {
  steps.error = String(e && e.stack ? e.stack : e);
}
await report(steps);
</script>`;

const site = http.createServer((req, res) => {
  if (req.method === "POST" && req.url === "/stop") {
    hw.removeAllListeners("exit");
    hw.kill("SIGTERM");
    res.end("ok");
    return;
  }
  if (req.method === "POST" && req.url === "/result") {
    let body = "";
    req.on("data", (d) => (body += d));
    req.on("end", () => {
      res.end("ok");
      results.chrome = JSON.parse(body);
      report();
    });
    return;
  }
  res.setHeader("content-type", "text/html");
  res.end(page);
});
const sitePort = await listen(site);

profile = fs.mkdtempSync(path.join(os.tmpdir(), "wt-chrome-"));
const browser = spawn(
  chrome,
  [
    "--headless=new",
    "--no-first-run",
    "--no-default-browser-check",
    `--user-data-dir=${profile}`,
    `http://127.0.0.1:${sitePort}/`,
  ],
  { stdio: ["ignore", "ignore", "ignore"] },
);
children.push(browser);
setTimeout(() => {
  results.chrome = { error: "no result from the page in 30 s", ok: false };
  report();
}, 30000);
