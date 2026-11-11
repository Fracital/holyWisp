// The wrapper against the real server: lifecycle, route(), and what the server is told about
// who is connecting. Everything stays on loopback and binds its own services.
import assert from "node:assert/strict";
import { once } from "node:events";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFile, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { connect, createServer as createTcpServer, Socket } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { Duplex } from "node:stream";
import { test } from "node:test";
import { inspect } from "node:util";
import { workerArgs } from "../dist/config.js";
import { holyWisp } from "../dist/index.js";
import { holyWispVite } from "../dist/vite.js";
import {
	binary,
	canConnectFrom,
	connectPacket,
	CONTINUE,
	DATA,
	echo,
	front,
	INFO,
	packet,
	rawUpgrade,
	spy,
	upgrade,
	wsClient,
} from "./helpers.mjs";

const base = { binary, port: 0, logLevel: "none" };

async function started(t, options = {}, workers = 1) {
	const wisp = new holyWisp({ ...base, ...options });
	await wisp.start(workers);
	t.after(() => wisp.stop());
	return wisp;
}

test("start, health, stats, stop, start again", async (t) => {
	const wisp = new holyWisp(base);
	assert.equal(wisp.isRunning, false);
	assert.deepEqual(wisp.ports, []);
	assert.equal(await wisp.start(2), wisp);
	t.after(() => (wisp.isRunning ? wisp.stop() : undefined));
	assert.equal(wisp.isRunning, true);
	assert.equal(wisp.ports.length, 1);
	assert.equal(wisp.port, wisp.ports[0]);
	assert.ok(wisp.pid > 0);

	const health = await fetch(`http://127.0.0.1:${wisp.port}/health`);
	assert.deepEqual(await health.json(), { status: "ok" });
	const stats = await wisp.stats();
	assert.deepEqual(stats.streams, { total: 0, active: 0 });
	// Plain HTTP requests are connections too: the readiness probes and this one.
	assert.ok(stats.connections.total >= 1);

	await assert.rejects(wisp.start(), /already running/);
	await wisp.stop();
	assert.equal(wisp.isRunning, false);
	assert.deepEqual(wisp.ports, []);
	await assert.rejects(wisp.stats(), /not running/);

	await wisp.start();
	assert.equal(wisp.isRunning, true);
	await wisp.stop();
});

test("the binary reports the package's version", async () => {
	const { execFileSync } = await import("node:child_process");
	const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
	const reported = execFileSync(binary, ["--version"], { encoding: "utf8" }).trim();
	assert.ok(reported.startsWith(`holywisp ${version}`), `${reported} is not ${version}`);
});

test("a taken port moves the server to the next free one", async (t) => {
	const squatter = createTcpServer();
	squatter.listen(0, "127.0.0.1");
	await once(squatter, "listening");
	t.after(() => new Promise((resolve) => squatter.close(resolve)));
	const taken = squatter.address().port;

	const wisp = await started(t, { port: taken });
	assert.ok(wisp.port > taken, `${wisp.port} should be above ${taken}`);
});

test("kill() ends the process", async (t) => {
	const wisp = await started(t);
	const pid = wisp.pid;
	wisp.kill();
	assert.equal(wisp.isRunning, false);
	// Signal 0 probes for existence; the process is gone within a moment.
	for (let i = 0; i < 100; i++) {
		try {
			process.kill(pid, 0);
		} catch {
			return;
		}
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
	assert.fail("the server survived kill()");
});

test("a missing binary and a config the server refuses both fail start() with the reason", async () => {
	await assert.rejects(new holyWisp({ ...base, binary: "/nonexistent/holywisp" }).start(), /no binary at/);
	// Twisp without a password user is refused by the server's own validator.
	const refused = new holyWisp({ ...base, enableTwisp: true });
	await assert.rejects(refused.start(), /exited before becoming ready[\s\S]*enable-twisp/);
	assert.equal(refused.isRunning, false);
	await assert.rejects(new holyWisp(base).start(1.5), RangeError);
});

test("route() relays a Wisp v1 session to a TCP echo service", async (t) => {
	const wisp = await started(t, { allowLoopbackIPs: true, allowDirectIP: true }, 2);
	const port = await front(t, wisp);
	const echoPort = await echo(t);
	const { ws, next } = await wsClient(t, `ws://127.0.0.1:${port}/wisp/`);

	const opening = await next();
	assert.equal(opening.type, CONTINUE);
	assert.equal(opening.stream, 0);
	const window = opening.payload.readUInt32LE(0);
	assert.ok(window >= 4);

	ws.send(connectPacket(1, "127.0.0.1", echoPort));
	ws.send(packet(DATA, 1, Buffer.from("hello through node")));
	const reply = await next();
	assert.equal(reply.type, DATA);
	assert.equal(reply.stream, 1);
	assert.equal(reply.payload.toString(), "hello through node");

	// Enough to cross several socket buffers in both directions, inside one flow-control window.
	const chunk = Buffer.alloc(64 * 1024);
	for (let i = 0; i < chunk.length; i++) chunk[i] = i % 251;
	const chunks = Math.min(window - 1, 48);
	for (let i = 0; i < chunks; i++) ws.send(packet(DATA, 1, chunk));
	const received = [];
	let total = 0;
	while (total < chunks * chunk.length) {
		const message = await next();
		if (message.type === CONTINUE) continue;
		assert.equal(message.type, DATA);
		received.push(message.payload);
		total += message.payload.length;
	}
	const all = Buffer.concat(received);
	assert.equal(all.length, chunks * chunk.length);
	for (let i = 0; i < chunks; i++) {
		assert.ok(all.subarray(i * chunk.length, (i + 1) * chunk.length).equals(chunk), `chunk ${i} differs`);
	}

	const stats = await wisp.stats();
	assert.equal(stats.streams.active, 1);
	assert.ok(stats.bytes.in >= chunks * chunk.length);
});

test("route() carries the v2 handshake: the offered subprotocol comes back and INFO is first", async (t) => {
	const wisp = await started(t, { passwordUsers: { alice: "correct horse" } });
	const port = await front(t, wisp);
	const token = "0b0e7b6e-5d0f-4c3a-9a51-1f2d3c4b5a69";
	const { ws, next } = await wsClient(t, `ws://127.0.0.1:${port}/`, [token]);
	assert.equal(ws.protocol, token);
	const info = await next();
	assert.equal(info.type, INFO);
	assert.equal(info.payload[0], 2);
	// Extensions follow the version: id(u8) len(u32 LE) meta. Password auth (0x02) is advertised.
	const ids = [];
	for (let at = 2; at + 5 <= info.payload.length; at += 5 + info.payload.readUInt32LE(at + 1)) ids.push(info.payload[at]);
	assert.ok(ids.includes(0x02), `extensions ${ids}`);
});

test("passwords reach the server through a private file that is gone once it is up", async (t) => {
	const before = new Set(readdirSync(tmpdir()).filter((name) => name.startsWith("holywisp-")));
	const wisp = await started(t, { passwordUsers: { alice: "correct horse" }, proxyUDP: "refuse" });
	const left = readdirSync(tmpdir()).filter((name) => name.startsWith("holywisp-") && !before.has(name));
	assert.deepEqual(left, []);
	const cmdline = `/proc/${wisp.pid}/cmdline`;
	if (!existsSync(cmdline)) return t.diagnostic("no /proc here; argument list not inspected");
	const args = readFileSync(cmdline, "utf8").split("\0");
	assert.ok(args.includes("--proxy-udp=refuse"));
	assert.ok(!args.join(" ").includes("correct horse"));
});

test("a request that is not a WebSocket upgrade gets the server's own answer back through route()", async (t) => {
	const wisp = await started(t, { nonWSResponse: "not here\nsecond line" });
	const port = await front(t, wisp);
	// An upgrade to a WebSocket version that does not exist: plain HTTP as far as the server cares.
	const { status, body } = await upgrade(port, { "Sec-WebSocket-Version": "12" }, "/elsewhere");
	assert.equal(status, 200);
	assert.equal(body, "not here\nsecond line");
});

test("route() answers 503 when the server is not running", async (t) => {
	const wisp = new holyWisp(base);
	const port = await front(t, wisp);
	const { status, socket } = await upgrade(port);
	socket.destroy();
	assert.equal(status, 503);
});

// The per-IP connection limit shows which address the server believed: with a limit of two per
// window, a third upgrade from the same client is refused, and one from a new client is not.
const limited = { connectionsLimitPerIP: 2, connectionWindowSeconds: 60 };

async function statuses(port, forwarded) {
	const out = [];
	for (const address of forwarded) {
		const { status, socket } = await upgrade(port, { "X-Forwarded-For": address, "CF-Connecting-IP": address });
		socket.destroy();
		out.push(status);
	}
	return out;
}

test("a client cannot pick its own address: forwarding headers from an untrusted peer are dropped", async (t) => {
	const wisp = await started(t, limited);
	const port = await front(t, wisp);
	const got = await statuses(port, ["198.51.100.1", "198.51.100.2", "198.51.100.3"]);
	assert.deepEqual(got.slice(0, 2), [101, 101]);
	assert.notEqual(got[2], 101, "the third upgrade from one peer got through by claiming a new address");
});

test("forwarding headers from a trusted proxy name the client", async (t) => {
	const wisp = await started(t, { ...limited, trustedProxies: ["127.0.0.0/8"] });
	const port = await front(t, wisp);
	assert.deepEqual(await statuses(port, ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"]), [
		101, 101, 101, 101,
	]);
	const same = await statuses(port, ["203.0.113.9", "203.0.113.9", "203.0.113.9"]);
	assert.deepEqual(same.slice(0, 2), [101, 101]);
	assert.notEqual(same[2], 101);
});

test("parseRealIP: false ignores the headers even from a listed proxy", async (t) => {
	const wisp = await started(t, { ...limited, parseRealIP: false, trustedProxies: ["127.0.0.0/8"] });
	const port = await front(t, wisp);
	const got = await statuses(port, ["198.51.100.1", "198.51.100.2", "198.51.100.3"]);
	assert.notEqual(got[2], 101);
});

test("route() answers 502 when the server has gone away underneath it", async (t) => {
	const wisp = await started(t, { autoRestart: false });
	const port = await front(t, wisp);
	// Dead, but the wrapper has not been told yet: what a crash looks like to the next upgrade.
	process.kill(wisp.pid, "SIGKILL");
	let status = 101;
	for (let i = 0; i < 100 && status === 101; i++) {
		const answer = await upgrade(port);
		answer.socket.destroy();
		status = answer.status;
	}
	assert.ok(status === 502 || status === 503, `status ${status}`);
	// The wrapper learns of the exit from the process's own close event, a moment later.
	for (let i = 0; i < 100 && wisp.isRunning; i++) await new Promise((resolve) => setTimeout(resolve, 20));
	assert.equal(wisp.isRunning, false);
	// With autoRestart off it stays down, and can be started by hand.
	await new Promise((resolve) => setTimeout(resolve, 300));
	assert.equal(wisp.isRunning, false);
	assert.equal(wisp.restarts, 0);
	await wisp.start();
	assert.equal(wisp.isRunning, true);
});

async function until(what, condition) {
	for (let i = 0; i < 500; i++) {
		if (condition()) return;
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
	assert.fail(`timed out waiting for ${what}`);
}

test("a server that dies is started again on the same port, and relays again", async (t) => {
	const wisp = await started(t, { allowLoopbackIPs: true, allowDirectIP: true, passwordUsers: { u: "secret-on-restart" } });
	const port = await front(t, wisp);
	const echoPort = await echo(t);
	const session = async () => {
		const { ws, next } = await wsClient(t, `ws://127.0.0.1:${port}/`);
		assert.equal((await next()).type, CONTINUE);
		ws.send(connectPacket(1, "127.0.0.1", echoPort));
		ws.send(packet(DATA, 1, Buffer.from("still here")));
		const reply = await next();
		assert.equal(reply.type, DATA);
		assert.equal(String(reply.payload), "still here");
		ws.close();
	};
	await session();

	for (let round = 1; round <= 2; round++) {
		const { pid, port: serverPort } = wisp;
		process.kill(pid, "SIGKILL");
		await until("the exit to be noticed", () => !wisp.isRunning);
		// The gap is a 503 from route(), not a hang-up.
		const during = await upgrade(port);
		during.socket.destroy();
		assert.ok(during.status === 503 || during.status === 101, `status ${during.status}`);
		await until("the restart", () => wisp.isRunning);
		assert.notEqual(wisp.pid, pid);
		assert.equal(wisp.port, serverPort);
		assert.equal(wisp.restarts, round);
		await session();
	}
	// The secrets file a restart writes is removed like the first one.
	assert.deepEqual(
		readdirSync(tmpdir()).filter((name) => name.startsWith("holywisp-") && existsSync(`${tmpdir()}/${name}/secrets.conf`)),
		[],
	);

	const last = wisp.pid;
	await wisp.stop();
	assert.equal(wisp.isRunning, false);
	assert.ok(await gone(last));
	await new Promise((resolve) => setTimeout(resolve, 300));
	assert.equal(wisp.isRunning, false, "stop() is final");
});

test("stop() and kill() in the gap before a restart cancel it", async (t) => {
	for (const end of ["stop", "kill"]) {
		const wisp = await started(t);
		const { port } = wisp;
		process.kill(wisp.pid, "SIGKILL");
		await until("the exit to be noticed", () => !wisp.isRunning);
		await wisp[end]();
		await new Promise((resolve) => setTimeout(resolve, 400));
		assert.equal(wisp.isRunning, false);
		assert.equal(wisp.restarts, 0);
		// Nothing is listening where it was.
		await assert.rejects(new Promise((resolve, reject) => new Socket().once("error", reject).connect(port, "127.0.0.1", resolve)));
		// And it is an ordinary stopped instance: start() works.
		await wisp.start();
		assert.equal(wisp.isRunning, true);
		await wisp.stop();
	}
});

test("a server that keeps dying is retried with a growing delay, and stop() ends that too", async (t) => {
	const wisp = await started(t);
	const first = wisp.pid;
	// From now on every start fails: the binary is gone.
	wisp.config.binary = `${binary}.does-not-exist`;
	process.kill(first, "SIGKILL");
	await until("the exit to be noticed", () => !wisp.isRunning);
	await new Promise((resolve) => setTimeout(resolve, 500));
	assert.equal(wisp.isRunning, false);
	assert.equal(wisp.restarts, 0);
	// The binary comes back and so does the server, without anyone calling start().
	wisp.config.binary = binary;
	await until("the restart", () => wisp.isRunning);
	assert.equal(wisp.restarts, 1);
});

// A parent that dies must not leave a server behind on its port.
async function orphanCheck(t, ending) {
	const { spawn } = await import("node:child_process");
	const script = `
		import { holyWisp } from ${JSON.stringify(new URL("../dist/index.js", import.meta.url).href)};
		const wisp = new holyWisp({ binary: ${JSON.stringify(binary)}, port: 0, logLevel: "none" });
		await wisp.start();
		console.log(wisp.pid);
		${ending}
	`;
	const parent = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: ["ignore", "pipe", "inherit"] });
	t.after(() => parent.kill("SIGKILL"));
	const [line] = await once(parent.stdout, "data");
	const serverPid = Number(String(line).trim());
	assert.ok(serverPid > 0);
	return { parent, serverPid };
}

// Signal 0 probes for a pid, and a process that has exited keeps its pid until something waits for
// it. Its parent is dead here, so that is init's job, and in a container whose init does not do it
// (a GitHub Actions job container) the pid stays for ever: a zombie, which holds no port and runs
// no code. Linux says so in /proc; elsewhere the probe is the whole answer.
function alive(pid) {
	try {
		process.kill(pid, 0);
	} catch {
		return false;
	}
	try {
		const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
		return stat.slice(stat.lastIndexOf(") ") + 2, stat.lastIndexOf(") ") + 3) !== "Z";
	} catch {
		return true;
	}
}

async function gone(pid) {
	for (let i = 0; i < 150; i++) {
		if (!alive(pid)) return true;
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
	return false;
}

test("the server goes when its parent exits without stop()", async (t) => {
	const { parent, serverPid } = await orphanCheck(t, "process.exit(3);");
	const [code] = await once(parent, "exit");
	assert.equal(code, 3);
	assert.ok(await gone(serverPid), "the server outlived its parent");
});

test("the server goes when its parent is killed outright", async (t) => {
	// No handler runs in the parent: the server notices by itself, from its stdin closing. (On
	// Windows too, where this is what every kill() is.)
	const { parent, serverPid } = await orphanCheck(t, "setInterval(() => {}, 1000);");
	parent.kill("SIGKILL");
	const [, signal] = await once(parent, "exit");
	assert.equal(signal, "SIGKILL");
	assert.ok(await gone(serverPid), "the server outlived its parent");
});

test("the server goes when a signal ends its parent, and the signal still ends the parent", { skip: process.platform === "win32" }, async (t) => {
	const { parent, serverPid } = await orphanCheck(t, "setInterval(() => {}, 1000);");
	parent.kill("SIGTERM");
	const [code, signal] = await once(parent, "exit");
	assert.equal(code, null);
	assert.equal(signal, "SIGTERM");
	assert.ok(await gone(serverPid), "the server outlived its parent");
});

test("an application's own signal handler is left in charge", { skip: process.platform === "win32" }, async (t) => {
	const { parent, serverPid } = await orphanCheck(
		t,
		`process.on("SIGTERM", async () => { await wisp.stop(); console.log("clean"); process.exit(0); });
		setInterval(() => {}, 1000);`,
	);
	parent.kill("SIGTERM");
	const [said] = await once(parent.stdout, "data");
	assert.equal(String(said).trim(), "clean");
	const [code] = await once(parent, "exit");
	assert.equal(code, 0);
	assert.ok(await gone(serverPid));
});

// The two below stand a plain HTTP server in for holyWisp, to watch route()'s upstream socket.
async function standIn(t, onUpgrade) {
	const server = createServer();
	server.on("upgrade", onUpgrade);
	server.listen(0, "127.0.0.1");
	await once(server, "listening");
	t.after(() => new Promise((resolve) => server.close(resolve)));
	// A started instance, because route() only speaks for a server it has a secret for; then its
	// port is swapped for the stand-in's.
	const wisp = await started(t);
	wisp.boundPort = server.address().port;
	return wisp;
}

/** A socket that was never connected, with the peer address route() will not go without. */
function unconnected() {
	const client = new Socket();
	Object.defineProperty(client, "remoteAddress", { value: "127.0.0.9" });
	return client;
}

const bareRequest = { url: "/wisp", method: "GET", rawHeaders: ["Connection", "Upgrade", "Upgrade", "websocket"] };

test("a client error before the upgrade completes closes the upstream connection", async (t) => {
	let closed;
	const upstreamClosed = new Promise((resolve) => (closed = resolve));
	const client = unconnected();
	const wisp = await standIn(t, (_req, socket) => {
		socket.on("error", () => {});
		socket.on("close", closed);
		// An HTTP server's sockets stay half-open after the peer's FIN until they are ended.
		socket.on("end", () => socket.end());
		socket.resume();
		client.emit("error", new Error("read ECONNRESET"));
	});
	wisp.route(bareRequest, client, Buffer.alloc(0));
	await upstreamClosed;
	assert.equal(client.destroyed, true);
});

test("a client that goes away before the upgrade completes closes the upstream connection", async (t) => {
	let closed;
	const upstreamClosed = new Promise((resolve) => (closed = resolve));
	const client = unconnected();
	const wisp = await standIn(t, (_req, socket) => {
		socket.on("error", () => {});
		socket.on("close", closed);
		// An HTTP server's sockets stay half-open after the peer's FIN until they are ended.
		socket.on("end", () => socket.end());
		socket.resume();
		client.destroy();
	});
	wisp.route(bareRequest, client, Buffer.alloc(0));
	await upstreamClosed;
	assert.equal(client.destroyed, true);
});

test("the Vite plugin starts a server and routes only its path", async (t) => {
	const httpServer = createServer((_req, res) => res.writeHead(404).end());
	const stray = [];
	httpServer.on("upgrade", (req, socket) => {
		if (!req.url.startsWith("/wisp/")) stray.push(socket.destroy());
	});
	httpServer.listen(0, "127.0.0.1");
	await once(httpServer, "listening");
	const warnings = [];
	const vite = { httpServer, config: { logger: { warn: (message) => warnings.push(message) } } };

	const plugin = holyWispVite({ path: "/wisp/", config: base, apply: "serve" });
	assert.equal(plugin.name, "holywisp");
	await plugin.configurePreviewServer(vite);
	assert.equal(httpServer.listenerCount("upgrade"), 1, "apply: serve must not attach to preview");
	await plugin.configureServer(vite);
	assert.equal(httpServer.listenerCount("upgrade"), 2);

	const port = httpServer.address().port;
	const routed = await upgrade(port, {}, "/wisp/");
	routed.socket.destroy();
	assert.equal(routed.status, 101);
	await assert.rejects(upgrade(port, {}, "/hmr"));
	assert.equal(stray.length, 1);

	await plugin.configureServer({ httpServer: null, config: vite.config });
	assert.match(warnings[0], /middleware mode/);

	// Closing the dev server stops the wisp server with it.
	httpServer.closeAllConnections();
	await new Promise((resolve) => httpServer.close(resolve));
	const health = () => fetch(`http://127.0.0.1:${port}/health`);
	await assert.rejects(health());
});

// ------------------------------------------------------------------------------------------
// What the server is told about the client, and who it takes that from.

const SECRET_LINE = /^X-HolyWisp-Proxy-Secret: ([0-9a-f]{64})$/;
const named = (head, name) => head.filter((line) => line.toLowerCase().startsWith(`${name.toLowerCase()}:`));
const junk = (count) => Array.from({ length: count }, (_, i) => `X-Junk-${i}: ${i}`);
// The lines rawUpgrade() sends before a test's own.
const fixed = 5;

test("what route() says about the client is written first, and a client's copy of it never arrives", async (t) => {
	// The server keeps a bounded number of headers and reads the first of a name. Neither helps a
	// client whose own lines all come after the wrapper's.
	const claims = [
		"X-Forwarded-For: 6.6.6.6",
		"x-forwarded-for: 7.7.7.7",
		"X-FORWARDED-FOR: 8.8.8.8, 9.9.9.9",
		"X-HolyWisp-Proxy-Secret: guess",
		"x-holywisp-proxy-secret: guess",
		`X-HOLYWISP-PROXY-SECRET: ${"0".repeat(64)}`,
	];
	{
		const wisp = await started(t);
		const port = await front(t, wisp);
		const upstream = await spy(t, wisp);
		await rawUpgrade(port, [...junk(60), ...claims, "CF-Connecting-IP: 6.6.6.6"]);
		const head = await upstream.next();
		assert.equal(head[0], "GET / HTTP/1.1");
		assert.match(head[1], SECRET_LINE);
		assert.equal(head[2], "X-Forwarded-For: 127.0.0.1");
		assert.equal(named(head, "X-Forwarded-For").length, 1);
		assert.equal(named(head, "X-HolyWisp-Proxy-Secret").length, 1);
		// Everything else arrives as it was sent, in its order. CF-Connecting-IP is not a header the
		// server reads unless it is listed, so it is just another header.
		assert.deepEqual(head.slice(3 + fixed), [...junk(60), "CF-Connecting-IP: 6.6.6.6"]);
	}
	{
		// Every listed header is dropped, in any case, however often it comes.
		const wisp = await started(t, { trustedHeaders: ["X-Real-IP", "CF-Connecting-IP"] });
		const port = await front(t, wisp);
		const upstream = await spy(t, wisp);
		const theirs = ["x-real-ip: 6.6.6.6", "CF-CONNECTING-IP: 6.6.6.6", "Cf-Connecting-Ip: 7.7.7.7"];
		await rawUpgrade(port, [...junk(50), ...theirs, ...claims]);
		const head = await upstream.next();
		assert.match(head[1], SECRET_LINE);
		assert.equal(head[2], "X-Real-IP: 127.0.0.1");
		assert.deepEqual([...named(head, "X-Real-IP"), ...named(head, "CF-Connecting-IP")], ["X-Real-IP: 127.0.0.1"]);
		assert.equal(named(head, "X-HolyWisp-Proxy-Secret").length, 1);
		// X-Forwarded-For is not read by this server, so it is the client's to send.
		assert.equal(named(head, "X-Forwarded-For").length, 3);
	}
	{
		// From a trusted proxy the forwarding headers are kept, and still come first.
		const wisp = await started(t, { trustedProxies: ["127.0.0.1"], trustedHeaders: ["X-Real-IP", "X-Forwarded-For"] });
		const port = await front(t, wisp);
		const upstream = await spy(t, wisp);
		const proxied = ["X-Forwarded-For: 198.51.100.7", "x-forwarded-for: 198.51.100.8", "X-Real-IP: 203.0.113.5"];
		await rawUpgrade(port, [...junk(60), ...proxied, ...claims.slice(3)]);
		const head = await upstream.next();
		assert.match(head[1], SECRET_LINE);
		assert.equal(head[2], "X-Real-IP: 203.0.113.5");
		assert.equal(head[3], "X-Forwarded-For: 198.51.100.7, 198.51.100.8, 127.0.0.1");
		assert.equal(named(head, "X-HolyWisp-Proxy-Secret").length, 1);
		assert.deepEqual(head.slice(4 + fixed), junk(60));

		// The server keeps 511 bytes of a value. A list longer than that is cut on the left, where
		// the client's own entries are, never on the right, where the proxies wrote theirs.
		const long = Array.from({ length: 80 }, (_, i) => `203.0.113.${i}`).join(", ");
		await rawUpgrade(port, [`X-Forwarded-For: ${long}`, "X-Forwarded-For: 198.51.100.7"]);
		const value = named(await upstream.next(), "X-Forwarded-For");
		assert.equal(value.length, 1);
		assert.ok(value[0].endsWith(", 203.0.113.79, 198.51.100.7, 127.0.0.1"), value[0]);
		assert.ok(Buffer.byteLength(value[0]) < 500, `${Buffer.byteLength(value[0])} bytes`);
	}
});

test("a long header list does not push the client's address out of the server's sight", async (t) => {
	// The client arrives through a trusted proxy as 203.0.113.9 and has used up its two upgrades.
	// With enough headers of its own in front, the line naming it used to fall off the end of what
	// the server keeps, and it was the wrapper's address, with a fresh allowance.
	const wisp = await started(t, { ...limited, trustedProxies: ["127.0.0.1"] });
	const port = await front(t, wisp);
	const from = (address, extra = []) => rawUpgrade(port, [...extra, `X-Forwarded-For: ${address}`]);
	assert.deepEqual([await from("203.0.113.9"), await from("203.0.113.9")], [101, 101]);
	assert.notEqual(await from("203.0.113.9", junk(43)), 101);
	assert.notEqual(await from("203.0.113.9", junk(200)), 101);
	// A request with many headers that is still within what the server takes is told apart as usual.
	assert.deepEqual([await from("203.0.113.10", junk(40)), await from("203.0.113.10", junk(40))], [101, 101]);
	assert.notEqual(await from("203.0.113.10", junk(40)), 101);
});

test("a client that is not behind a proxy cannot shed its address with a long header list either", async (t) => {
	const wisp = await started(t, limited);
	const port = await front(t, wisp);
	// The client has to be someone other than this process's own 127.0.0.1 to be told apart from it.
	if (!(await canConnectFrom("127.0.0.2", port))) return t.skip("this machine cannot connect from 127.0.0.2");
	const from = (extra = []) => rawUpgrade(port, extra, { local: "127.0.0.2" });
	assert.deepEqual([await from(), await from()], [101, 101]);
	assert.notEqual(await from(junk(43)), 101);
	assert.notEqual(await from(junk(44)), 101);
	// Nobody was counted as the wrapper itself: its own allowance is untouched.
	assert.deepEqual([await rawUpgrade(port), await rawUpgrade(port)], [101, 101]);
});

test("the server believes route() and no other process on loopback", async (t) => {
	const wisp = await started(t, limited);
	const port = await front(t, wisp);
	// Another local process, straight to the server's port, a new address in every request. It is
	// 127.0.0.1 each time: two upgrades, and then it has to wait like anybody else.
	const direct = (lines) => rawUpgrade(wisp.port, lines);
	const got = [];
	for (let i = 1; i <= 4; i++) got.push(await direct([`X-Forwarded-For: 198.51.100.${i}`]));
	assert.deepEqual(got.slice(0, 2), [101, 101]);
	assert.notEqual(got[2], 101, "a local process picked its own address");
	assert.notEqual(got[3], 101);
	assert.notEqual(await direct([`X-HolyWisp-Proxy-Secret: ${"0".repeat(64)}`, "X-Forwarded-For: 198.51.100.5"]), 101);
	assert.notEqual(await direct(["X-HolyWisp-Proxy-Secret: ", "X-Forwarded-For: 198.51.100.6"]), 101);

	// What route() sends is what makes the difference, which is why it must stay between the two.
	const upstream = await spy(t, wisp);
	await rawUpgrade(port);
	const secret = SECRET_LINE.exec((await upstream.next())[1])[1];
	upstream.restore();
	assert.equal(await direct([`X-HolyWisp-Proxy-Secret: ${secret}`, "X-Forwarded-For: 198.51.100.7"]), 101);
	// It is not on the instance for anything that prints or serialises it to find.
	assert.ok(!inspect(wisp, { depth: 8, showHidden: true }).includes(secret));
	assert.ok(!JSON.stringify(wisp).includes(secret));
	const cmdline = `/proc/${wisp.pid}/cmdline`;
	if (!existsSync(cmdline)) return t.diagnostic("no /proc here; argument list not inspected");
	assert.ok(!readFileSync(cmdline, "latin1").includes(secret), "the secret is in the argument list");
	assert.ok(!readFileSync(cmdline, "latin1").includes("trusted-proxy-secret"));
});

test("a restarted server has a secret of its own, and route() speaks with it", async (t) => {
	const wisp = await started(t, { ...limited, trustedProxies: ["127.0.0.1"] });
	const port = await front(t, wisp);
	const secretNow = async () => {
		const upstream = await spy(t, wisp);
		await rawUpgrade(port);
		const head = await upstream.next();
		upstream.restore();
		return SECRET_LINE.exec(head[1])[1];
	};
	const first = await secretNow();
	process.kill(wisp.pid, "SIGKILL");
	await until("the exit to be noticed", () => !wisp.isRunning);
	await until("the restart", () => wisp.isRunning);
	const second = await secretNow();
	assert.notEqual(second, first);
	// The new server takes route()'s word: four clients, each within its own allowance.
	assert.deepEqual(await statuses(port, ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"]), [101, 101, 101, 101]);
	// And the secret of the server that died is worth nothing to it.
	const stale = [];
	for (let i = 1; i <= 3; i++) {
		stale.push(await rawUpgrade(wisp.port, [`X-HolyWisp-Proxy-Secret: ${first}`, `X-Forwarded-For: 203.0.113.${i}`]));
	}
	assert.deepEqual(stale.slice(0, 2), [101, 101]);
	assert.notEqual(stale[2], 101);
});

test("a header that is not listed is not believed, even from a trusted proxy", async (t) => {
	// CF-Connecting-IP was read by default, and before X-Forwarded-For. A proxy that is not
	// Cloudflare passes it through as the client sent it.
	const wisp = await started(t, { ...limited, trustedProxies: ["127.0.0.1"] });
	const port = await front(t, wisp);
	const got = [];
	for (let i = 1; i <= 3; i++) {
		got.push(await rawUpgrade(port, [`CF-Connecting-IP: 198.51.100.${i}`, "X-Forwarded-For: 203.0.113.9"]));
	}
	assert.deepEqual(got.slice(0, 2), [101, 101]);
	assert.notEqual(got[2], 101, "the client chose its address with CF-Connecting-IP");
});

test("a server started with host: undefined or an empty host listens on loopback only", async (t) => {
	for (const host of [undefined, ""]) {
		const wisp = new holyWisp({ ...base, host });
		// Looked at before anything is started: a server without --host is on every interface.
		const hosts = workerArgs(wisp.config, { port: 1, workers: 1 }).args.filter((arg) => arg.startsWith("--host"));
		assert.deepEqual(hosts, ["--host=127.0.0.1"]);
		await wisp.start();
		t.after(() => (wisp.isRunning ? wisp.stop() : undefined));
		const health = await fetch(`http://127.0.0.1:${wisp.port}/health`);
		assert.equal(health.status, 200);
		// Nothing answers on that port at this machine's other addresses.
		const others = Object.values(networkInterfaces())
			.flat()
			.filter((entry) => entry.family === "IPv4" && !entry.internal)
			.slice(0, 2);
		for (const { address } of others) {
			const reached = await new Promise((resolve) => {
				const probe = connect({ host: address, port: wisp.port, timeout: 300 });
				const settle = (answer) => () => {
					probe.destroy();
					resolve(answer);
				};
				probe.once("connect", settle(true));
				probe.once("error", settle(false));
				probe.once("timeout", settle(false));
			});
			assert.equal(reached, false, `the server answers on ${address}`);
		}
		const cmdline = `/proc/${wisp.pid}/cmdline`;
		if (existsSync(cmdline)) assert.ok(readFileSync(cmdline, "latin1").split("\0").includes("--host=127.0.0.1"));
		await wisp.stop();
	}
});

/** A directory for a stand-in server binary, and a way to write one. Not for Windows: it is a shell script. */
function fakeBinary(t, script) {
	const dir = mkdtempSync(join(tmpdir(), "hw-wrapper-test-"));
	t.after(() => rmSync(dir, { recursive: true, force: true }));
	const file = join(dir, "fake-holywisp");
	writeFileSync(file, `#!/bin/sh\n${script(dir)}\n`, { mode: 0o755 });
	return { dir, file };
}

const noShell = { skip: process.platform === "win32" };

test("whatever the server says about its config, its secrets reach neither the Error nor the log", noShell, async (t) => {
	// A server that refuses its config and quotes every line of it while doing so, which is the
	// worst a real one could do. ($1 is --config, $2 the file.)
	const { file } = fakeBinary(
		t,
		() => `while IFS= read -r line; do printf '%s\\n' "holywisp: $2:1: bad value in '$line'" >&2; done < "$2"\nexit 2`,
	);
	const password = "hunter2-SECRET-PASSWORD";
	const logged = [];
	const log = console.log;
	console.log = (...parts) => logged.push(parts.join(" "));
	t.after(() => (console.log = log));
	const wisp = new holyWisp({
		binary: file,
		port: 0,
		logLevel: "error",
		autoRestart: false,
		passwordUsers: { alice: password, bob: "b" },
		proxy: "socks5://puser:PROXY-CREDENTIAL@127.0.0.1:1",
	});
	const message = await wisp.start().then(
		() => assert.fail("started"),
		(err) => err.message,
	);
	console.log = log;
	assert.match(message, /exited before becoming ready \(code 2/);
	// The lines were quoted and logged, four of them, with their values blanked.
	assert.equal(message.match(/bad value in/g)?.length, 4, message);
	assert.equal(logged.filter((line) => line.includes("bad value in")).length, 4);
	const all = [message, ...logged].join("\n");
	assert.match(all, /password-user = \[redacted\]|password-user = "\[redacted\]"/);
	for (const secret of [password, "SECRET", "PROXY-CREDENTIAL", "puser:", "alice:", "bob:b"]) {
		assert.ok(!all.includes(secret), `'${secret}' in: ${all}`);
	}
	assert.doesNotMatch(all, /[0-9a-f]{64}/, "the proxy secret");
	assert.match(all, /trusted-proxy-secret = "\[redacted\]"/);
});

test("the Vite plugin leaves a request target that is not a URL alone", async (t) => {
	const httpServer = createServer((_req, res) => res.writeHead(404).end());
	// Vite's own upgrade handler (HMR), which takes what is not for the plugin.
	httpServer.on("upgrade", (req, socket) => {
		if (!req.url.startsWith("/wisp/")) socket.destroy();
	});
	httpServer.listen(0, "127.0.0.1");
	await once(httpServer, "listening");
	t.after(() => {
		httpServer.closeAllConnections();
		return new Promise((resolve) => httpServer.close(resolve));
	});
	const plugin = holyWispVite({ path: "/wisp/", config: base });
	await plugin.configureServer({ httpServer, config: { logger: { warn() {} } } });
	const port = httpServer.address().port;

	// `//[` is a request target Node's HTTP parser accepts and `new URL` does not. Thrown inside
	// the upgrade event it is an uncaught exception: the end of the dev server.
	const thrown = [];
	const onThrown = (err) => thrown.push(err);
	process.on("uncaughtException", onThrown);
	t.after(() => process.removeListener("uncaughtException", onThrown));
	for (const target of ["//[", "//[::1", "http://[/wisp/"]) {
		assert.equal(await rawUpgrade(port, [], { path: target }), 0, target);
	}
	await new Promise((resolve) => setTimeout(resolve, 20));
	assert.deepEqual(thrown, []);
	// And the plugin still does its job.
	assert.equal(await rawUpgrade(port, [], { path: "/wisp/" }), 101);
});

/** What route() is handed for a socket, reduced to what it uses: a peer address and a place to write. */
function clientStub(remoteAddress) {
	const written = [];
	const stub = new Duplex({
		read() {},
		write(chunk, _encoding, done) {
			written.push(chunk);
			done();
		},
	});
	if (remoteAddress !== undefined) stub.remoteAddress = remoteAddress;
	stub.answer = () => Buffer.concat(written).toString("latin1");
	return stub;
}

test("a peer address is written in the form the server reads: no zone, no IPv4-in-IPv6", async (t) => {
	// Node reports a link-local IPv6 peer as fe80::1%eth0. The server cannot parse that, and what it
	// cannot parse it ignores: such a client was the wrapper's own 127.0.0.1.
	const wisp = await started(t);
	const upstream = await spy(t, wisp);
	for (const [reported, written] of [
		["fe80::1%eth0", "fe80::1"],
		["fe80::abcd:1%3", "fe80::abcd:1"],
		["::ffff:192.0.2.7", "192.0.2.7"],
		["2001:db8::7", "2001:db8::7"],
	]) {
		wisp.route(bareRequest, clientStub(reported), Buffer.alloc(0));
		const head = await upstream.next();
		assert.equal(head[2], `X-Forwarded-For: ${written}`, reported);
	}
	// A zone does not hide a trusted proxy from trustedProxies either.
	const behind = await started(t, { trustedProxies: ["fe80::/10"] });
	const behindUpstream = await spy(t, behind);
	const forwarded = { ...bareRequest, rawHeaders: [...bareRequest.rawHeaders, "X-Forwarded-For", "198.51.100.7"] };
	behind.route(forwarded, clientStub("fe80::1%eth0"), Buffer.alloc(0));
	assert.equal((await behindUpstream.next())[2], "X-Forwarded-For: 198.51.100.7, fe80::1");
});

test("a peer that is not an address is refused; a socket with none at all is loopback", async (t) => {
	const wisp = await started(t);
	let reached = 0;
	const upstream = createTcpServer((socket) => {
		reached++;
		socket.destroy();
	});
	upstream.listen(0, "127.0.0.1");
	await once(upstream, "listening");
	t.after(() => new Promise((resolve) => upstream.close(resolve)));
	wisp.boundPort = upstream.address().port;
	for (const address of ["", "not-an-address", "%eth0"]) {
		const client = clientStub(address);
		wisp.route(bareRequest, client, Buffer.alloc(0));
		await once(client, "close");
		assert.match(client.answer(), /^HTTP\/1\.1 403 Forbidden\r\n/, String(address));
	}
	// A socket that went away before it was routed has no address either, and is not passed on.
	const gone = clientStub(undefined);
	gone.destroy();
	wisp.route(bareRequest, gone, Buffer.alloc(0));
	await new Promise((resolve) => setTimeout(resolve, 50));
	assert.equal(reached, 0, "the upgrade was passed on");

	// A front on a Unix socket: its clients are local processes, which is what 127.0.0.1 means.
	const local = await started(t);
	const localUpstream = await spy(t, local);
	local.route(bareRequest, clientStub(undefined), Buffer.alloc(0));
	assert.equal((await localUpstream.next())[2], "X-Forwarded-For: 127.0.0.1");
	// And a proxy there is believed when loopback is trusted, as it would be over TCP.
	const behind = await started(t, { trustedProxies: ["127.0.0.1"] });
	const behindUpstream = await spy(t, behind);
	const forwarded = { ...bareRequest, rawHeaders: [...bareRequest.rawHeaders, "X-Forwarded-For", "198.51.100.7"] };
	behind.route(forwarded, clientStub(undefined), Buffer.alloc(0));
	assert.equal((await behindUpstream.next())[2], "X-Forwarded-For: 198.51.100.7, 127.0.0.1");
});

test("a port that answers is not taken for the server when the server itself has gone", noShell, async (t) => {
	// Between the wrapper finding a port free and the server binding it, somebody else can take
	// it. The server then exits ("Address already in use"), but the port answers /health. This
	// stand-in says which port it was given, waits until that port has answered once, and exits
	// the way the server does.
	const { dir, file } = fakeBinary(
		t,
		(where) => `for arg in "$@"; do case "$arg" in --port=*) echo "\${arg#--port=}" > '${where}/port.tmp' ;; esac; done
mv '${where}/port.tmp' '${where}/port'
while [ ! -e '${where}/answered' ]; do sleep 0.005; done
echo "holywisp: cannot start: Address already in use" >&2
exit 1`,
	);
	const wisp = new holyWisp({ ...base, binary: file, autoRestart: false });
	let requests = 0;
	const squatter = createServer(async (_req, res) => {
		if (++requests === 1) writeFile(join(dir, "answered"), "", () => {});
		// Later answers wait for the wrapper to have seen its server exit, so that what is tested
		// is its decision and not how fast a shell gets to `exit`.
		else {
			for (let i = 0; i < 200 && wisp.child?.exitCode === null; i++) await new Promise((resolve) => setTimeout(resolve, 2));
		}
		res.writeHead(200, { "Content-Type": "application/json", Connection: "close" }).end('{"status":"ok"}');
	});
	t.after(() => {
		squatter.closeAllConnections();
		return new Promise((resolve) => squatter.close(resolve));
	});
	const starting = wisp.start();
	starting.catch(() => {});
	t.after(() => (wisp.isRunning ? wisp.stop() : undefined));
	await until("the stand-in to say its port", () => existsSync(join(dir, "port")));
	squatter.listen(Number(readFileSync(join(dir, "port"), "utf8")), "127.0.0.1");
	await assert.rejects(starting, /exited before becoming ready[\s\S]*Address already in use/);
	assert.equal(wisp.isRunning, false);
	assert.ok(requests >= 1);
});
