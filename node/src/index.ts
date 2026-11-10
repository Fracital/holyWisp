/*
 * holyWisp for Node.js: run the server as a child process and hand it WebSocket upgrades.
 *
 *   const wisp = new holywisp({ port: 6001 });
 *   await wisp.start(4);
 *   httpServer.on("upgrade", (req, socket, head) => wisp.route(req, socket, head));
 *
 * The shape is wispurr's Node wrapper, with one difference underneath. wispurr starts N
 * processes on N ports and deals upgrades out between them. holyWisp is one process with N
 * worker threads behind one port, which the kernel balances, so the rate limits, the reputation
 * table and the DNS cache are one set shared by every worker instead of N independent ones.
 */
import { spawn, type ChildProcess } from "node:child_process";
import * as fs from "node:fs";
import { request, type IncomingMessage } from "node:http";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { createInterface } from "node:readline";
import type { Duplex } from "node:stream";
import { trustedHeaders, workerArgs, type holywispConfig, type holywispOptions } from "./config.js";
import { Logger } from "./logger.js";
import { bundledBinary, platformKey } from "./path.js";

export type {
	FilterList,
	FloodProtectionConfig,
	LogLevel,
	PortEntry,
	ReputationConfig,
	ReputationEvent,
	holywispConfig,
	holywispOptions,
} from "./config.js";

/** `GET /stats` of the running server. */
export type holywispStats = {
	uptimeSeconds: number;
	connections: { total: number; active: number };
	streams: { total: number; active: number };
	/** Bytes relayed: `in` is client to remote, `out` is remote to client. */
	bytes: { in: number; out: number };
	refused: { connectionRate: number; connectionLimit: number; reputation: number };
	blocked: { filter: number; egress: number };
	throttled: { source: number; dest: number; syns: number };
	synSignatures: number;
	wsClosedViolations: number;
	authFailures: number;
	dnsCacheEntries: number;
	reputation: { sources: number; destinations: number };
};

const READY_TIMEOUT_MS = 10_000;
const MAX_WORKERS = 1024;
// autoRestart: the wait before the first attempt, its ceiling, and how long a server must have
// stayed up for its next death to count as a first one again.
const RESTART_MIN_MS = 100;
const RESTART_MAX_MS = 5000;
const RESTART_SETTLED_MS = 10_000;

// Children of every instance. A server left behind by a dead parent would keep its port and keep
// relaying with nobody in charge of it, so none is: they are killed when this process exits, and
// when a signal is about to end it (Node dies of SIGINT/SIGTERM/SIGHUP without running `exit`
// handlers). A process killed outright (SIGKILL, OOM) can do neither; for that the server watches
// the pipe on its stdin (`stop-on-stdin-eof`) and stops by itself when the kernel closes it.
const live = new Set<ChildProcess>();
const fatalSignals = ["SIGINT", "SIGTERM", "SIGHUP"] as const;

function onExit(): void {
	for (const orphan of live) orphan.kill("SIGKILL");
}

function onSignal(signal: NodeJS.Signals): void {
	// The application has its own handler: shutting down, and when, is its decision. It ends in
	// stop() or in an exit, which onExit() covers.
	if (process.listenerCount(signal) > 1) return;
	for (const child of live) terminate(child);
	unhook();
	// With our handler gone the signal does what it would have done without this module.
	process.kill(process.pid, signal);
}

/**
 * Ask a server to shut down. Windows has no SIGTERM (kill() there ends the process on the spot,
 * with nothing saved), so the request is the one it does have: its stdin closing.
 */
function terminate(child: ChildProcess): void {
	if (process.platform === "win32") child.stdin?.end();
	else child.kill("SIGTERM");
}

function unhook(): void {
	process.removeListener("exit", onExit);
	for (const signal of fatalSignals) process.removeListener(signal, onSignal);
}

function track(child: ChildProcess): void {
	if (live.size === 0) {
		process.on("exit", onExit);
		for (const signal of fatalSignals) process.on(signal, onSignal);
	}
	live.add(child);
}

function untrack(child: ChildProcess): void {
	if (live.delete(child) && live.size === 0) unhook();
}

/** Node reports IPv4 peers of a dual-stack listener as `::ffff:a.b.c.d`. */
function plainAddress(address: string | undefined): string | undefined {
	if (!address) return undefined;
	const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
	return mapped ? mapped[1] : address;
}

function family(address: string): "ipv4" | "ipv6" {
	return net.isIPv6(address) ? "ipv6" : "ipv4";
}

function blockList(entries: readonly string[]): net.BlockList {
	const set = new net.BlockList();
	for (const entry of entries) {
		const [address = "", prefix, ...rest] = entry.split("/");
		if (!net.isIP(address) || rest.length > 0) {
			throw new TypeError(`holywisp: trustedProxies: '${entry}' is not an address or CIDR`);
		}
		if (prefix === undefined) {
			set.addAddress(address, family(address));
			continue;
		}
		const bits = Number(prefix);
		if (!/^\d+$/.test(prefix) || bits > (net.isIPv6(address) ? 128 : 32)) {
			throw new TypeError(`holywisp: trustedProxies: '${entry}' is not an address or CIDR`);
		}
		set.addSubnet(address, bits, family(address));
	}
	return set;
}

/** The first free port at or above `from` on `host`; any free port when `from` is 0. */
async function freePort(from: number, host: string | undefined): Promise<number> {
	const tryPort = (port: number) =>
		new Promise<number | undefined>((resolve, reject) => {
			const probe = net.createServer();
			probe.unref();
			probe.once("error", (err: NodeJS.ErrnoException) => {
				if (err.code === "EADDRINUSE" || err.code === "EACCES") resolve(undefined);
				else reject(err);
			});
			probe.listen({ port, host, exclusive: true }, () => {
				const bound = (probe.address() as net.AddressInfo).port;
				probe.close(() => resolve(bound));
			});
		});
	if (from === 0) {
		const port = await tryPort(0);
		if (port !== undefined) return port;
	} else {
		for (let candidate = from; candidate <= 65535; candidate++) {
			const port = await tryPort(candidate);
			if (port !== undefined) return port;
		}
	}
	throw new Error(`holywisp: no available port at or above ${from}`);
}

function httpGet(host: string, port: number, path: string, timeoutMs: number): Promise<{ status: number; body: string }> {
	return new Promise((resolve, reject) => {
		const req = request({ host, port, path, agent: false, timeout: timeoutMs }, (res) => {
			let body = "";
			res.setEncoding("utf8");
			res.on("data", (chunk: string) => (body += chunk));
			res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
			res.on("error", reject);
		});
		req.once("timeout", () => req.destroy(new Error("timed out")));
		req.once("error", reject);
		req.end();
	});
}

/** Let what is already written reach the peer, then close; do not wait on a peer that never reads. */
function finish(stream: Duplex, hadError: boolean): void {
	if (hadError || stream.destroyed) {
		stream.destroy();
		return;
	}
	const linger = setTimeout(() => stream.destroy(), 5000);
	linger.unref();
	stream.end(() => {
		clearTimeout(linger);
		stream.destroy();
	});
}

export class holywisp {
	/** The options this instance was built with, plus the wrapper's own defaults. */
	readonly config: holywispConfig;
	private child: ChildProcess | undefined;
	private boundPort: number | undefined;
	private starting = false;
	/** start() was called and neither stop() nor kill() since: a server that exits is restarted. */
	private wanted = false;
	private workers = 1;
	/** The port the last server had, so that a restart comes back where it was. */
	private lastPort: number | undefined;
	private readySince = 0;
	private restartTimer: ReturnType<typeof setTimeout> | undefined;
	private restartDelay = RESTART_MIN_MS;
	/** A restart in flight. Never rejects. */
	private relaunch: Promise<void> | undefined;
	private restartCount = 0;
	private readonly logger: Logger;
	/** Header names the server reads a client address from, in its order. */
	private readonly headers: string[];
	private readonly headerSet: Set<string>;
	/** The caller's reverse proxies: peers whose forwarding headers are passed on, not replaced. */
	private readonly trusted: net.BlockList;

	constructor(options: holywispOptions = {}) {
		this.config = { host: "127.0.0.1", ...structuredClone(options) };
		this.logger = new Logger(this.config.logLevel ?? "warn");
		this.headers = trustedHeaders(this.config);
		this.headerSet = new Set(this.headers.map((header) => header.toLowerCase()));
		this.trusted = blockList(this.config.parseRealIP === false ? [] : (this.config.trustedProxies ?? []));
		this.basePort();
		// Reject a bad option here, where the mistake is, instead of at start().
		workerArgs(this.config, { port: 1, workers: 1 });
	}

	get isRunning(): boolean {
		return this.child !== undefined && this.boundPort !== undefined;
	}

	/** The port the server listens on, once started. */
	get port(): number | undefined {
		return this.boundPort;
	}

	/** The same as a list, for wispurr parity: empty when stopped, one entry when running. */
	get ports(): readonly number[] {
		return this.boundPort === undefined ? [] : [this.boundPort];
	}

	get pid(): number | undefined {
		return this.child?.pid;
	}

	/** How many times `autoRestart` has brought the server back since `start()`. */
	get restarts(): number {
		return this.restartCount;
	}

	/** Where this process reaches the server: loopback when it listens on every interface. */
	private get workerHost(): string {
		const host = this.config.host;
		if (!host || host === "0.0.0.0") return "127.0.0.1";
		return host === "::" ? "::1" : host;
	}

	private basePort(): number {
		const port = Array.isArray(this.config.port) ? this.config.port[0] : this.config.port;
		const base = port ?? 6001;
		if (!Number.isInteger(base) || base < 0 || base > 65535) {
			throw new RangeError("holywisp: port must be an integer between 0 and 65535");
		}
		return base;
	}

	private binary(): string {
		const chosen = this.config.binary ?? process.env["HOLYWISP_BIN"];
		const binary = chosen ?? bundledBinary;
		if (fs.existsSync(binary)) return binary;
		if (chosen) throw new Error(`holywisp: no binary at ${chosen}`);
		throw new Error(
			`holywisp: this package has no prebuilt server for ${platformKey}. ` +
				"Build holyWisp from source and point the `binary` option (or HOLYWISP_BIN) at it.",
		);
	}

	/**
	 * Start the server with `workers` worker threads (0 = one per CPU) and resolve once it
	 * answers on its port.
	 */
	async start(workers: number = 1): Promise<this> {
		if (!Number.isInteger(workers) || workers < 0 || workers > MAX_WORKERS) {
			throw new RangeError(`holywisp: worker count must be an integer from 0 (one per CPU) to ${MAX_WORKERS}`);
		}
		if (this.child || this.starting || this.wanted) {
			throw new Error("holywisp: already running; stop it before starting again");
		}
		this.starting = true;
		this.wanted = true;
		this.workers = workers;
		this.lastPort = undefined;
		this.restartDelay = RESTART_MIN_MS;
		this.restartCount = 0;
		try {
			await this.launch();
			return this;
		} catch (err) {
			this.wanted = false;
			throw err;
		} finally {
			this.starting = false;
		}
	}

	/** Run one server process and wait until it answers. The caller has set `wanted`. */
	private async launch(): Promise<void> {
		const workers = this.workers;
		let secretsDir: string | undefined;
		try {
			const binary = this.binary();
			const bindHost = this.config.host || undefined;
			const port = await freePort(this.lastPort ?? this.basePort(), bindHost);
			const { args, secrets, ignored } = workerArgs(this.config, { port, workers });
			for (const option of ignored) this.logger.warn(`ignoring ${option}`);

			if (secrets.length > 0) {
				// Passwords go through a file only this user can read, not the argument list, which
				// any local user can see. The server reads it once at startup.
				secretsDir = fs.mkdtempSync(path.join(os.tmpdir(), "holywisp-"));
				const file = path.join(secretsDir, "secrets.conf");
				fs.writeFileSync(file, secrets.join("\n") + "\n", { mode: 0o600 });
				args.unshift("--config", file);
			}

			// stdin is a pipe nothing is ever written to: see `stop-on-stdin-eof` in config.ts.
			const child = spawn(binary, args, { stdio: ["pipe", "ignore", "pipe"], windowsHide: true });
			await new Promise<void>((resolve, reject) => {
				child.once("spawn", resolve);
				child.once("error", reject);
			});
			child.stdin!.on("error", () => {});
			if (!this.wanted) {
				child.kill("SIGKILL");
				throw new Error("holywisp: stopped while starting");
			}
			track(child);

			// What it said last, for the error if it dies before it is ready.
			const recent: string[] = [];
			createInterface({ input: child.stderr! }).on("line", (line) => {
				recent.push(line);
				if (recent.length > 20) recent.shift();
				this.logger.server(line);
			});
			child.on("error", (err) => this.logger.error(`server process error: ${err.message}`));
			child.once("close", (code, signal) => {
				untrack(child);
				const how = `server exited with code ${code}, signal ${signal ?? "none"}`;
				// It was up and nobody asked it to stop. (One that dies before it is ready is the
				// business of whoever is waiting for it in waitReady.)
				const died = this.child === child && this.boundPort !== undefined && this.wanted;
				if (died) this.logger.error(`${how}, unasked`);
				else if (code === 0 || signal === "SIGTERM" || signal === "SIGKILL") this.logger.info(how);
				else this.logger.error(how);
				if (this.child === child) {
					this.child = undefined;
					this.boundPort = undefined;
				}
				if (!died) return;
				if (this.config.autoRestart === false) {
					this.wanted = false;
					return;
				}
				if (Date.now() - this.readySince >= RESTART_SETTLED_MS) this.restartDelay = RESTART_MIN_MS;
				this.scheduleRestart();
			});

			this.child = child;
			try {
				await this.waitReady(child, port, recent);
			} catch (err) {
				child.kill("SIGKILL");
				if (this.child === child) this.child = undefined;
				throw err;
			}
			this.boundPort = port;
			this.lastPort = port;
			this.readySince = Date.now();
			this.logger.info(`listening on ${this.workerHost}:${port}, ${workers || "one per CPU"} worker(s)`);
		} finally {
			if (secretsDir) fs.rmSync(secretsDir, { recursive: true, force: true });
		}
	}

	private scheduleRestart(): void {
		const delay = this.restartDelay;
		this.restartDelay = Math.min(delay * 2, RESTART_MAX_MS);
		this.logger.warn(`restarting the server in ${delay} ms`);
		this.restartTimer = setTimeout(() => {
			this.restartTimer = undefined;
			this.relaunch = this.launch()
				.then(
					() => {
						this.restartCount++;
						this.logger.warn(`the server is back on port ${this.boundPort}`);
					},
					(err: Error) => {
						if (!this.wanted) return;
						this.logger.error(`restart failed: ${err.message}`);
						this.scheduleRestart();
					},
				)
				.finally(() => {
					this.relaunch = undefined;
				});
		}, delay);
	}

	/** stop() and kill(): nothing is to come back. True if a restart was pending or in flight. */
	private cancelRestart(): boolean {
		const pending = this.restartTimer !== undefined || this.relaunch !== undefined;
		this.wanted = false;
		clearTimeout(this.restartTimer);
		this.restartTimer = undefined;
		return pending;
	}

	private async waitReady(child: ChildProcess, port: number, recent: readonly string[]): Promise<void> {
		const deadline = Date.now() + READY_TIMEOUT_MS;
		while (Date.now() < deadline) {
			if (!this.wanted) throw new Error("holywisp: stopped while starting");
			if (child.exitCode !== null || child.signalCode !== null) {
				// Let the last stderr lines arrive before quoting them.
				await new Promise((resolve) => setImmediate(resolve));
				const said = recent.length > 0 ? `: ${recent.join("\n")}` : "";
				throw new Error(
					`holywisp: server exited before becoming ready (code ${child.exitCode}, ` +
						`signal ${child.signalCode ?? "none"})${said}`,
				);
			}
			const healthy = await httpGet(this.workerHost, port, "/health", 500).then(
				(res) => res.status === 200,
				() => false,
			);
			if (healthy) return;
			await new Promise((resolve) => setTimeout(resolve, 20));
		}
		throw new Error(`holywisp: server on port ${port} did not become ready within ${READY_TIMEOUT_MS / 1000} seconds`);
	}

	/**
	 * Hand a WebSocket upgrade to the server: the handler for an HTTP server's `upgrade` event.
	 *
	 * The server is told the address of `socket`'s peer, so its per-client limits and reputation
	 * apply to the real client and not to this process. Forwarding headers that came with the
	 * request are only passed on when that peer is one of `trustedProxies`; from anyone else they
	 * are a claim the client made about itself, and are dropped.
	 */
	route(req: IncomingMessage, socket: Duplex, head: Buffer): void {
		const port = this.boundPort;
		if (port === undefined) {
			this.logger.error("route() called while the server is not running");
			socket.end("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", () =>
				socket.destroy(),
			);
			return;
		}

		const peer = plainAddress((socket as Partial<net.Socket>).remoteAddress);
		const trustedPeer = peer !== undefined && net.isIP(peer) !== 0 && this.trusted.check(peer, family(peer));
		const lines = [`${req.method ?? "GET"} ${req.url ?? "/"} HTTP/1.1`];
		const forwardedFor: string[] = [];
		const raw = req.rawHeaders;
		for (let i = 0; i + 1 < raw.length; i += 2) {
			const name = raw[i] as string;
			const value = raw[i + 1] as string;
			const lower = name.toLowerCase();
			if (this.headerSet.has(lower)) {
				if (!trustedPeer) continue;
				if (lower === "x-forwarded-for") {
					forwardedFor.push(value);
					continue;
				}
			}
			lines.push(`${name}: ${value}`);
		}
		if (trustedPeer) {
			// A hop in a chain of proxies: add the one we saw to the list, as a proxy does.
			if (this.headerSet.has("x-forwarded-for")) {
				lines.push(`X-Forwarded-For: ${[...forwardedFor, peer].join(", ")}`);
			}
		} else if (peer !== undefined) {
			lines.push(`${this.headers[0]}: ${peer}`);
		}

		const upstream = net.connect({ host: this.workerHost, port, noDelay: true });
		let connected = false;
		// Whether the server has said anything yet. Until it has, the client is still waiting for an
		// HTTP answer, and if the server goes away it gets one from here instead of a hang-up.
		let answered = false;
		const badGateway = () => {
			if (socket.destroyed) return;
			socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", () => socket.destroy());
		};
		socket.on("error", () => {
			upstream.destroy();
			socket.destroy();
		});
		socket.once("close", (hadError: boolean) => finish(upstream, hadError || !connected));
		upstream.on("error", (err) => {
			upstream.destroy();
			if (answered) {
				socket.destroy();
				return;
			}
			this.logger.error(`the server is not answering: ${err.message}`);
			badGateway();
		});
		upstream.once("close", (hadError) => {
			if (hadError) return; // the error handler above has dealt with the client
			if (answered) finish(socket, false);
			else badGateway();
		});
		upstream.once("connect", () => {
			connected = true;
			if (socket.destroyed) {
				upstream.destroy();
				return;
			}
			(socket as Partial<net.Socket>).setNoDelay?.(true);
			upstream.write(lines.join("\r\n") + "\r\n\r\n");
			if (head.length > 0) upstream.write(head);
			// From here it is bytes both ways; the 101 (or the refusal) is the server's own.
			upstream.once("data", () => {
				answered = true;
			});
			socket.pipe(upstream);
			upstream.pipe(socket);
		});
	}

	/** The server's counters (`GET /stats`). */
	async stats(): Promise<holywispStats> {
		if (this.boundPort === undefined) throw new Error("holywisp: not running");
		const res = await httpGet(this.workerHost, this.boundPort, "/stats", 5000);
		if (res.status !== 200) throw new Error(`holywisp: /stats answered ${res.status}`);
		return JSON.parse(res.body) as holywispStats;
	}

	/**
	 * Ask the server to shut down (SIGTERM; on Windows, by closing its stdin) and kill it if it has
	 * not exited after `timeoutMs`. Cancels a pending restart.
	 */
	async stop(timeoutMs = 10_000): Promise<void> {
		if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
			throw new RangeError("holywisp: stop timeout must be a non-negative number");
		}
		const pending = this.cancelRestart();
		// A restart that has already spawned its server: let it settle, then stop what it left.
		await this.relaunch;
		const child = this.child;
		if (!child) {
			if (!pending) this.logger.warn("stop() called while the server is not running");
			return;
		}
		const exited =
			child.exitCode !== null || child.signalCode !== null
				? Promise.resolve()
				: new Promise<void>((resolve) => child.once("close", () => resolve()));
		terminate(child);
		let timer: ReturnType<typeof setTimeout> | undefined;
		const graceful = await Promise.race([
			exited.then(() => true),
			new Promise<boolean>((resolve) => {
				timer = setTimeout(() => resolve(false), timeoutMs);
			}),
		]);
		clearTimeout(timer);
		if (!graceful) {
			child.kill("SIGKILL");
			await exited;
		}
		if (this.child === child) {
			this.child = undefined;
			this.boundPort = undefined;
		}
	}

	/** SIGKILL the server now. Cancels a pending restart. */
	kill(): void {
		const pending = this.cancelRestart();
		const child = this.child;
		if (!child) {
			if (!pending) this.logger.warn("kill() called while the server is not running");
			return;
		}
		child.kill("SIGKILL");
		this.child = undefined;
		this.boundPort = undefined;
	}
}

export { holywisp as HolyWisp };
export default holywisp;
