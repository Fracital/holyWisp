// Shared by the tests: which binary to run, and the few lines of Wisp and HTTP they speak.
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { createServer, request } from "node:http";
import { connect, createServer as createTcpServer } from "node:net";
import { arch, platform } from "node:os";
import { fileURLToPath } from "node:url";

// The packaged binary when `make npm` has built one, else the tree's release build.
const packaged = fileURLToPath(
	new URL(`../bin/${platform()}-${arch()}/holywisp${platform() === "win32" ? ".exe" : ""}`, import.meta.url),
);
const built = fileURLToPath(new URL("../../build/release/holywisp", import.meta.url));
export const binary = process.env.HOLYWISP_BIN ?? (existsSync(packaged) ? packaged : built);

export const CONNECT = 0x01;
export const DATA = 0x02;
export const CONTINUE = 0x03;
export const CLOSE = 0x04;
export const INFO = 0x05;

export function packet(type, stream, payload = Buffer.alloc(0)) {
	const head = Buffer.alloc(5);
	head[0] = type;
	head.writeUInt32LE(stream, 1);
	return Buffer.concat([head, payload]);
}

export function connectPacket(stream, host, port) {
	const body = Buffer.alloc(3 + Buffer.byteLength(host));
	body[0] = 0x01; // TCP
	body.writeUInt16LE(port, 1);
	body.write(host, 3);
	return packet(CONNECT, stream, body);
}

export function parse(data) {
	const buf = Buffer.from(data);
	return { type: buf[0], stream: buf.readUInt32LE(1), payload: buf.subarray(5) };
}

/** An HTTP server whose upgrades go to `wisp.route()`. Resolves to its port. */
export async function front(t, wisp, filter = () => true) {
	const server = createServer((_req, res) => res.writeHead(404).end());
	server.on("upgrade", (req, socket, head) => {
		if (filter(req)) wisp.route(req, socket, head);
		else socket.destroy();
	});
	server.listen(0, "127.0.0.1");
	await once(server, "listening");
	t.after(() => {
		server.closeAllConnections();
		return new Promise((resolve) => server.close(resolve));
	});
	return server.address().port;
}

/** A TCP server on loopback that sends back what it receives. Resolves to its port. */
export async function echo(t) {
	const server = createTcpServer((socket) => {
		socket.on("error", () => {});
		socket.pipe(socket);
	});
	server.listen(0, "127.0.0.1");
	await once(server, "listening");
	t.after(() => new Promise((resolve) => server.close(resolve)));
	return server.address().port;
}

/** A WebSocket client with its messages queued, so a test can await them one at a time. */
export async function wsClient(t, url, protocols) {
	const ws = new WebSocket(url, protocols);
	ws.binaryType = "arraybuffer";
	const queue = [];
	const waiting = [];
	ws.addEventListener("message", (event) => {
		const next = waiting.shift();
		if (next) next.resolve(parse(event.data));
		else queue.push(parse(event.data));
	});
	const failed = (why) => () => {
		for (const next of waiting.splice(0)) next.reject(new Error(`websocket ${why}`));
	};
	ws.addEventListener("close", failed("closed"));
	ws.addEventListener("error", failed("failed"));
	t.after(() => ws.close());
	await new Promise((resolve, reject) => {
		ws.addEventListener("open", resolve, { once: true });
		ws.addEventListener("error", () => reject(new Error(`cannot open ${url}`)), { once: true });
	});
	const next = () =>
		queue.length > 0 ? Promise.resolve(queue.shift()) : new Promise((resolve, reject) => waiting.push({ resolve, reject }));
	return { ws, next };
}

/**
 * A bare upgrade request with whatever headers the test wants. Resolves to the status and the
 * socket; anything but 101 is a refusal.
 */
export function upgrade(port, headers = {}, path = "/") {
	return new Promise((resolve, reject) => {
		const req = request({
			host: "127.0.0.1",
			port,
			path,
			agent: false,
			headers: {
				Connection: "Upgrade",
				Upgrade: "websocket",
				"Sec-WebSocket-Version": "13",
				"Sec-WebSocket-Key": randomBytes(16).toString("base64"),
				...headers,
			},
		});
		req.once("upgrade", (res, socket) => {
			socket.on("error", () => {});
			resolve({ status: res.statusCode, socket });
		});
		req.once("response", (res) => {
			let body = "";
			res.setEncoding("utf8");
			res.on("data", (chunk) => (body += chunk));
			res.on("end", () => resolve({ status: res.statusCode, socket: res.socket, body }));
		});
		req.once("error", reject);
		req.end();
	});
}

const upgradeLines = [
	"Host: front.test",
	"Upgrade: websocket",
	"Connection: Upgrade",
	"Sec-WebSocket-Version: 13",
	"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
];

/**
 * An upgrade written byte for byte, so that a test decides every header line, how many there are
 * and (with `local`) which loopback address it comes from. Resolves to the status code, or 0 when
 * the connection closed without an answer.
 */
export function rawUpgrade(port, lines = [], { path = "/", local } = {}) {
	return new Promise((resolve, reject) => {
		const socket = connect({ host: "127.0.0.1", port, localAddress: local });
		let answer = "";
		const done = () => {
			socket.destroy();
			resolve(Number(/^HTTP\/1\.1 (\d{3})/.exec(answer)?.[1] ?? 0));
		};
		let connected = false;
		socket.once("connect", () => {
			connected = true;
			socket.write(`GET ${path} HTTP/1.1\r\n${[...upgradeLines, ...lines].join("\r\n")}\r\n\r\n`);
		});
		socket.on("data", (chunk) => {
			answer += chunk.toString("latin1");
			if (answer.includes("\r\n")) done();
		});
		// A reset once connected is an answer too: the other side hung up without one.
		socket.on("error", (err) => (connected ? done() : reject(err)));
		socket.once("close", done);
	});
}

/** Whether this machine lets a client connect from `local` (macOS has 127.0.0.1 and nothing else of 127/8). */
export async function canConnectFrom(local, port) {
	return new Promise((resolve) => {
		const socket = connect({ host: "127.0.0.1", port, localAddress: local });
		socket.once("connect", () => {
			socket.destroy();
			resolve(true);
		});
		socket.once("error", () => resolve(false));
	});
}

/**
 * Stand a recording TCP server in for holyWisp behind `wisp`, which must be running: route() then
 * writes to it what it would have written to the server. `heads` collects every request head it
 * received, as the list of its lines; each is answered 400. `restore()` points `wisp` back at its
 * real server.
 */
export async function spy(t, wisp) {
	const heads = [];
	const waiting = [];
	const server = createTcpServer((socket) => {
		let text = "";
		socket.on("error", () => {});
		socket.on("data", (chunk) => {
			text += chunk.toString("latin1");
			const end = text.indexOf("\r\n\r\n");
			if (end < 0) return;
			socket.removeAllListeners("data");
			const lines = text.slice(0, end).split("\r\n");
			const next = waiting.shift();
			if (next) next(lines);
			else heads.push(lines);
			socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
		});
	});
	server.listen(0, "127.0.0.1");
	await once(server, "listening");
	t.after(() => new Promise((resolve) => server.close(resolve)));
	const real = wisp.boundPort;
	wisp.boundPort = server.address().port;
	return {
		/** The next head route() writes. */
		next: () => (heads.length > 0 ? Promise.resolve(heads.shift()) : new Promise((resolve) => waiting.push(resolve))),
		restore: () => {
			if (wisp.boundPort === server.address().port) wisp.boundPort = real;
		},
	};
}
