// The wrapper against the real server: lifecycle, route(), and what the server is told about
// who is connecting. Everything stays on loopback and binds its own services.
import assert from "node:assert/strict";
import { once } from "node:events";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import { createServer as createTcpServer, Socket } from "node:net";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { holyWisp } from "../dist/index.js";
import { holyWispVite } from "../dist/vite.js";
import { binary, connectPacket, CONTINUE, DATA, echo, front, INFO, packet, upgrade, wsClient } from "./helpers.mjs";

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
	const wisp = new holyWisp(base);
	wisp.child = {};
	wisp.boundPort = server.address().port;
	return wisp;
}

const bareRequest = { url: "/wisp", method: "GET", rawHeaders: ["Connection", "Upgrade", "Upgrade", "websocket"] };

test("a client error before the upgrade completes closes the upstream connection", async (t) => {
	let closed;
	const upstreamClosed = new Promise((resolve) => (closed = resolve));
	const client = new Socket();
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
	const client = new Socket();
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
