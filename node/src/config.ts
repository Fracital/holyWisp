/*
 * The options the wrapper accepts and how they become `holywisp` flags.
 *
 * The names are wispurr's (camelCase, the same nesting) so a config written for it can be passed
 * as it is; holyWisp's own knobs are added at the top level. Nothing here carries a default: an
 * option that is left out is simply not passed, and the binary's own default applies
 * (`holywisp --help` lists them). The exceptions are the ones where the binary's default is wrong
 * behind `route()`: the address it binds, and whose word it takes for a client's address.
 */

export type PortEntry = number | [number, number];

export type FilterList = {
	/** Hostnames; `*.example.com` matches subdomains. An object is read as its keys. */
	hostnames?: string[] | Record<string, unknown>;
	/** Ports or `[low, high]` ranges. An object is read as its keys (`"80"`, `"8000-8999"`). */
	ports?: PortEntry[] | Record<string, unknown>;
};

export type FloodProtectionConfig = {
	enabled?: boolean;
	maxConnectsPerSourceIPPerSecond?: number;
	maxConnectsPerDestPerSecond?: number;
	maxConnectsPerDestPerMinute?: number;
	maxInFlightSyns?: number;
	/** Of `maxInFlightSyns`, how many one client address may hold at a time. */
	maxInFlightSynsPerIP?: number;
	maxConcurrentStreamsPerConnection?: number;
	maxConcurrentConnections?: number;
	/** Of `maxConcurrentConnections`, how many one client address may hold at a time. */
	maxConcurrentConnectionsPerIP?: number;
	synFloodSignature?: {
		enabled?: boolean;
		windowMs?: number;
		minSamples?: number;
		failedHandshakeRatio?: number;
	};
	wsCloseAfterViolations?: number;
	logBlockedDials?: boolean;
};

export type ReputationEvent =
	| "privateEgress"
	| "synSignature"
	| "twispNoAuth"
	| "burstRate"
	| "successfulStream"
	| "requestKnownBadDest"
	| "authFailure"
	| "protocolViolation";

export type ReputationConfig = {
	enabled?: boolean;
	/** JSON file the scores persist to. Left out: scores live in memory only. */
	storePath?: string;
	saveIntervalSeconds?: number;
	scoreDecayPerHour?: number;
	evictAfterDays?: number;
	thresholds?: { warn?: number; throttle?: number; strict?: number };
	weights?: Partial<Record<ReputationEvent, number>>;
	destinationWeights?: Partial<Record<ReputationEvent, number>>;
};

export type LogLevel = "debug" | "info" | "warn" | "error" | "none";

export type holyWispConfig = {
	/**
	 * Port the server listens on (default 6001). If it is taken, the next free one above it is
	 * used; 0 asks the OS for any free port. An array is accepted for wispurr compatibility and
	 * its first entry is used: holyWisp runs every worker on one port.
	 */
	port?: number | number[];
	/**
	 * Address the server binds. The wrapper's default is `127.0.0.1`, because `route()` is the
	 * way in; set `0.0.0.0` (or `::`) to expose the port itself as well. Left out, `undefined` or
	 * empty all mean the default: the server is never put on every interface by accident.
	 */
	host?: string;
	/** Path to a `holywisp` binary to run instead of the one shipped for this platform. */
	binary?: string;
	/**
	 * Start the server again when it exits without `stop()` or `kill()` having been called
	 * (default true). It comes back on the same port if that is still free, after a delay that
	 * starts at 100 ms and doubles up to 5 s while it keeps dying; `route()` answers 503 meanwhile.
	 */
	autoRestart?: boolean;

	allowTCP?: boolean;
	allowUDP?: boolean;
	allowDirectIP?: boolean;
	allowPrivateIPs?: boolean;
	allowLoopbackIPs?: boolean;
	allowLinkLocalIPs?: boolean;
	blacklist?: FilterList;
	whitelist?: FilterList;

	enableV2?: boolean;
	enableTwisp?: boolean;
	motd?: string;
	/** Defaults to true when `passwordUsers` has entries. False ignores them. */
	passwordAuth?: boolean;
	passwordAuthRequired?: boolean;
	/**
	 * user -> password. A value starting with `$` is a crypt(3) hash. A user name is 1 to 63 bytes
	 * with no `:`, a password at most 127 bytes on one line.
	 */
	passwordUsers?: Record<string, string>;

	/**
	 * Whether proxy headers from `trustedProxies` are believed. `route()` always tells the server
	 * the address of the socket it was handed; this only decides whether a header that arrived
	 * with the request can override that.
	 */
	parseRealIP?: boolean;
	/** Addresses or CIDRs of reverse proxies in front of this process (nginx, a CDN edge). */
	trustedProxies?: string[];
	/**
	 * Headers a trusted proxy puts the client address in. Default `X-Forwarded-For` only. Name a
	 * header here only if the proxy in front overwrites it on every request: one it passes through
	 * as the client sent it lets the client choose its own address.
	 */
	trustedHeaders?: string[];

	/**
	 * Origins a browser may connect from, each `scheme://host[:port]`. Left out or empty, any page
	 * on the web can open a connection through its visitor's browser, which is what a public relay
	 * wants. A request with no `Origin` header (anything that is not a browser) is never refused.
	 */
	allowedOrigins?: string[];

	connectionsLimitPerIP?: number;
	connectionWindowSeconds?: number;
	bandwidthLimitKbps?: number;
	floodProtection?: FloodProtectionConfig;
	reputation?: ReputationConfig;

	/** Upstream `socks5://`, `socks5h://` or `http://` proxy for outbound TCP. */
	proxy?: string;
	/** With a proxy: relay UDP around it (`direct`) or refuse it (`refuse`, the default). */
	proxyUDP?: "direct" | "refuse";
	dnsServers?: string[];
	dnsResultOrder?: "ipv4first" | "ipv6first" | "verbatim";
	dnsTtlSeconds?: number;
	dnsNegativeTtlSeconds?: number;
	dnsTimeoutMs?: number;

	/** The CONTINUE window, in packets. */
	bufferRemainingLength?: number;
	maxMessageSize?: number;
	wsWriteHighWater?: number;
	streamQueueMax?: number;
	connQueueMax?: number;
	socketBufferSize?: number;
	clientRecvBuffer?: number;
	connectTimeoutMs?: number;
	handshakeTimeoutSeconds?: number;
	/** A client that takes nothing of what is queued for it this long is closed (default 120, 0 off). */
	clientWriteTimeoutSeconds?: number;
	/** A connection with no traffic in either direction this long is closed (default 0, off). */
	idleTimeoutSeconds?: number;
	resolverThreads?: number;
	busyPollUs?: number;
	tcpNoDelay?: boolean;
	tcpQuickAck?: boolean;
	listenBacklog?: number;

	nonWSResponse?: string;
	/** Serve the built-in browser client on `GET /` of the server's own port. */
	serveWebclient?: boolean;
	webclientWispUrl?: string;
	/** Default `warn`. Also the level the wrapper's own messages are filtered at. */
	logLevel?: LogLevel;

	// wispurr options with no holyWisp counterpart. Accepted so a wispurr config type-checks and
	// runs; start() says which of them it dropped.
	/** Ignored: holyWisp sizes its read buffers itself. */
	tcpBufferSize?: number;
	/** Ignored: see `streamQueueMax` and `connQueueMax`. */
	pendingQueueSize?: number;
	/** Ignored: holyWisp never negotiates permessage-deflate. */
	websocketPermessageDeflate?: boolean;
	/** Ignored: `dnsServers` picks the built-in resolver, its absence the system one. */
	dnsMethod?: "lookup" | "resolve";
	/** Ignored: holyWisp serves no directory; serve files from your own HTTP server. */
	staticDir?: string;
};

/** Everything is optional, so the options are the config. Kept as a name for wispurr parity. */
export type holyWispOptions = holyWispConfig;

/** Headers the server reads a client address from when none are configured (server.c). */
export const DEFAULT_TRUSTED_HEADERS: readonly string[] = ["X-Forwarded-For"];

/** The loopback addresses `route()` reaches the server from; it must believe their headers. */
export const INTERNAL_PROXIES: readonly string[] = ["127.0.0.1", "::1"];

/**
 * The header `route()` proves itself with (`trusted-proxy-secret`, conn.c). The loopback addresses
 * above are every local process's, so the address alone says nothing about who is asking.
 */
export const PROXY_SECRET_HEADER = "X-HolyWisp-Proxy-Secret";

/** Where the server listens when the caller does not say. */
export const DEFAULT_HOST = "127.0.0.1";

// What the server's own fields hold (server.h): one byte less than each array.
const MAX_USER_BYTES = 63;
const MAX_PASSWORD_BYTES = 127;
const MAX_PROXY_BYTES = 255;
/** A secret shorter than this is only hidden as part of the value it sits in; see `redactor`. */
const MIN_REDACTED_LENGTH = 4;

export type WorkerArgs = {
	/** `--key=value` flags, safe to show in a process list. */
	args: string[];
	/** `key = value` config-file lines for what must not be: passwords, proxy credentials. */
	secrets: string[];
	/** Options that were given but have no effect, with the reason. */
	ignored: string[];
	/** What `secrets` holds, as the strings that must not show up in a log line or an Error. */
	sensitive: string[];
};

function fail(message: string): never {
	throw new TypeError(`holyWisp: ${message}`);
}

function integer(name: string, value: unknown): number {
	if (typeof value !== "number" || !Number.isInteger(value)) fail(`${name} must be an integer`);
	return value;
}

function text(name: string, value: unknown): string {
	if (typeof value !== "string") fail(`${name} must be a string`);
	if (value.includes("\0")) fail(`${name} must not contain a NUL byte`);
	return value;
}

function list(name: string, value: unknown): string[] {
	if (!Array.isArray(value)) fail(`${name} must be an array`);
	return value.map((entry, i) => text(`${name}[${i}]`, entry));
}

function keysOrEntries<T>(value: T[] | Record<string, unknown> | undefined): (T | string)[] {
	if (value === undefined) return [];
	return Array.isArray(value) ? value : Object.keys(value);
}

function portEntry(name: string, entry: PortEntry | string): string {
	if (Array.isArray(entry)) {
		if (entry.length !== 2) fail(`${name}: a range is [low, high]`);
		return `${integer(name, entry[0])}-${integer(name, entry[1])}`;
	}
	return typeof entry === "number" ? String(integer(name, entry)) : text(name, entry);
}

/**
 * One config-file line. The file format has no escapes: a value is either wrapped in double
 * quotes (and then holds no quote) or bare (and then is trimmed, and cut at a `#` that follows
 * whitespace). Anything that fits neither is refused rather than silently altered.
 */
export function configLine(key: string, value: string, what: string = key): string {
	// `what` is how an error names the value. The value itself is never part of one: it is a secret.
	if (/[\r\n\0]/.test(value)) fail(`${what} must not contain a line break`);
	let line: string;
	if (!value.includes('"')) {
		line = `${key} = "${value}"`;
	} else if (/^["#\s]|\s$|\s#/.test(value)) {
		fail(`${what} has a value the config file cannot hold (a double quote together with leading/trailing space or a '#')`);
	} else {
		line = `${key} = ${value}`;
	}
	// The parser reads 1024-byte lines.
	if (Buffer.byteLength(line) > 1000) fail(`${what} is too long`);
	return line;
}

/** The address the server is told to bind: the caller's, or loopback when there is none. */
export function bindHost(config: holyWispConfig): string {
	const host: unknown = config.host;
	if (host === undefined || host === null || host === "") return DEFAULT_HOST;
	return text("host", host);
}

/**
 * One `passwordUsers` entry as its config-file line. Checked here and not left to the server, whose
 * complaint would be about a line that holds the password. An error names the user, never the
 * password.
 */
function passwordUserLine(user: string, pass: unknown): string {
	if (user === "") fail("passwordUsers: a user name must be non-empty");
	if (user.includes(":")) {
		// What follows the colon may well be a password that was put in the wrong place.
		const shown = JSON.stringify(user.slice(0, user.indexOf(":")));
		fail(`passwordUsers: a user name must hold no ':' (the name that starts ${shown})`);
	}
	const shown = JSON.stringify(user.length > 80 ? `${user.slice(0, 80)}...` : user);
	if (/[\0-\x1f\x7f]/.test(user)) fail(`passwordUsers: the user name ${shown} must not contain a control character`);
	if (Buffer.byteLength(user) > MAX_USER_BYTES) {
		fail(`passwordUsers: the user name ${shown} is longer than ${MAX_USER_BYTES} bytes`);
	}
	const what = `the password of passwordUsers user ${shown}`;
	if (typeof pass !== "string") fail(`${what} must be a string`);
	if (pass === "") fail(`${what} must not be empty`);
	if (/[\r\n\0]/.test(pass)) fail(`${what} must not contain a line break or a NUL byte`);
	if (Buffer.byteLength(pass) > MAX_PASSWORD_BYTES) fail(`${what} is longer than ${MAX_PASSWORD_BYTES} bytes`);
	return configLine("password-user", `${user}:${pass}`, what);
}

/**
 * A function that blanks every string of `sensitive` in a text: for what the server wrote to
 * stderr, before it reaches a log line or an Error. A whole config value is always blanked. A
 * part of one (a password by itself) only from four characters up: blanking every `a` of a
 * message would not hide that the password is `a`, it would only make the message unreadable.
 */
export function redactor(sensitive: readonly string[]): (text: string) => string {
	const needles = [...new Set(sensitive)].filter((secret) => secret.length > 0).sort((a, b) => b.length - a.length);
	return (text) => {
		for (const needle of needles) text = text.split(needle).join("[redacted]");
		return text;
	};
}

/** Translate a config into what one `holywisp` process is started with. */
export function workerArgs(
	config: holyWispConfig,
	run: { port: number; workers: number; /** This start's `trusted-proxy-secret`. */ proxySecret?: string },
): WorkerArgs {
	const args: string[] = [];
	const secrets: string[] = [];
	const ignored: string[] = [];
	const sensitive: string[] = [];
	const part = (secret: string) => {
		if (secret.length >= MIN_REDACTED_LENGTH) sensitive.push(secret);
	};

	const flag = (key: string, value: string | number | boolean) => {
		args.push(`--${key}=${value}`);
	};
	const bool = (key: string, name: string, value: boolean | undefined) => {
		if (value === undefined) return;
		if (typeof value !== "boolean") fail(`${name} must be a boolean`);
		flag(key, value);
	};
	const int = (key: string, name: string, value: number | undefined, scale = 1) => {
		if (value === undefined) return;
		flag(key, integer(name, value) * scale);
	};
	const str = (key: string, name: string, value: string | undefined) => {
		if (value === undefined) return;
		flag(key, text(name, value));
	};

	// Always passed: the server's own default is every interface.
	flag("host", bindHost(config));
	flag("port", run.port);
	flag("workers", run.workers);

	bool("allow-tcp", "allowTCP", config.allowTCP);
	bool("allow-udp", "allowUDP", config.allowUDP);
	bool("allow-direct-ip", "allowDirectIP", config.allowDirectIP);
	bool("allow-private", "allowPrivateIPs", config.allowPrivateIPs);
	bool("allow-loopback", "allowLoopbackIPs", config.allowLoopbackIPs);
	bool("allow-link-local", "allowLinkLocalIPs", config.allowLinkLocalIPs);
	for (const [option, hostKey, portKey] of [
		["blacklist", "block-host", "block-port"],
		["whitelist", "allow-host", "allow-port"],
	] as const) {
		const filter = config[option];
		for (const host of keysOrEntries(filter?.hostnames)) flag(hostKey, text(`${option}.hostnames`, host));
		for (const port of keysOrEntries(filter?.ports)) flag(portKey, portEntry(`${option}.ports`, port));
	}

	bool("enable-v2", "enableV2", config.enableV2);
	bool("enable-twisp", "enableTwisp", config.enableTwisp);
	str("motd", "motd", config.motd);
	const users = Object.entries(config.passwordUsers ?? {});
	if (config.passwordAuth ?? users.length > 0) {
		for (const [user, pass] of users) {
			secrets.push(passwordUserLine(user, pass));
			sensitive.push(`${user}:${pass}`);
			part(pass);
		}
	} else if (users.length > 0) {
		ignored.push("passwordUsers (passwordAuth is false)");
	}
	bool("password-required", "passwordAuthRequired", config.passwordAuthRequired);

	// The server always parses the headers: that is how route() tells it who the client is.
	// What `parseRealIP: false` turns off is believing anyone but route() itself.
	flag("parse-real-ip", true);
	flag("trusted-headers-reset", true);
	for (const header of trustedHeaders(config)) flag("trusted-header", header);
	const proxies = config.parseRealIP === false ? [] : list("trustedProxies", config.trustedProxies ?? []);
	for (const proxy of new Set([...INTERNAL_PROXIES, ...proxies])) flag("trusted-proxy", proxy);
	// And only with the secret of this start, which travels like a password: in the file.
	if (run.proxySecret !== undefined) {
		secrets.push(configLine("trusted-proxy-secret", run.proxySecret));
		sensitive.push(run.proxySecret);
	}

	if (config.allowedOrigins !== undefined) {
		for (const origin of list("allowedOrigins", config.allowedOrigins)) flag("allow-origin", origin);
	}

	int("connections-limit-per-ip", "connectionsLimitPerIP", config.connectionsLimitPerIP);
	int("connection-window-s", "connectionWindowSeconds", config.connectionWindowSeconds);
	int("bandwidth-limit-kbps", "bandwidthLimitKbps", config.bandwidthLimitKbps);

	const flood = config.floodProtection;
	if (flood) {
		bool("flood-protection", "floodProtection.enabled", flood.enabled);
		int("max-connects-per-source-per-second", "maxConnectsPerSourceIPPerSecond", flood.maxConnectsPerSourceIPPerSecond);
		int("max-connects-per-dest-per-second", "maxConnectsPerDestPerSecond", flood.maxConnectsPerDestPerSecond);
		int("max-connects-per-dest-per-minute", "maxConnectsPerDestPerMinute", flood.maxConnectsPerDestPerMinute);
		int("max-in-flight-syns", "maxInFlightSyns", flood.maxInFlightSyns);
		int("max-in-flight-syns-per-ip", "maxInFlightSynsPerIP", flood.maxInFlightSynsPerIP);
		int("max-streams-per-conn", "maxConcurrentStreamsPerConnection", flood.maxConcurrentStreamsPerConnection);
		int("max-concurrent-connections", "maxConcurrentConnections", flood.maxConcurrentConnections);
		int(
			"max-concurrent-connections-per-ip",
			"maxConcurrentConnectionsPerIP",
			flood.maxConcurrentConnectionsPerIP,
		);
		const sig = flood.synFloodSignature;
		if (sig) {
			bool("syn-signature", "synFloodSignature.enabled", sig.enabled);
			int("syn-signature-window-ms", "synFloodSignature.windowMs", sig.windowMs);
			int("syn-signature-min-samples", "synFloodSignature.minSamples", sig.minSamples);
			if (sig.failedHandshakeRatio !== undefined) {
				const ratio = sig.failedHandshakeRatio;
				if (typeof ratio !== "number" || !(ratio >= 0 && ratio <= 1)) {
					fail("synFloodSignature.failedHandshakeRatio must be between 0 and 1");
				}
				flag("syn-signature-failed-ratio", ratio);
			}
		}
		int("ws-close-after-violations", "wsCloseAfterViolations", flood.wsCloseAfterViolations);
		bool("log-blocked-dials", "logBlockedDials", flood.logBlockedDials);
	}

	const rep = config.reputation;
	if (rep) {
		bool("reputation", "reputation.enabled", rep.enabled);
		str("reputation-store", "reputation.storePath", rep.storePath);
		int("reputation-save-interval-s", "reputation.saveIntervalSeconds", rep.saveIntervalSeconds);
		int("reputation-decay-per-hour", "reputation.scoreDecayPerHour", rep.scoreDecayPerHour);
		int("reputation-evict-after-days", "reputation.evictAfterDays", rep.evictAfterDays);
		int("reputation-warn", "reputation.thresholds.warn", rep.thresholds?.warn);
		int("reputation-throttle", "reputation.thresholds.throttle", rep.thresholds?.throttle);
		int("reputation-strict", "reputation.thresholds.strict", rep.thresholds?.strict);
		for (const [event, weight] of Object.entries(rep.weights ?? {})) {
			flag("reputation-weight", `${event}:${integer(`reputation.weights.${event}`, weight)}`);
		}
		for (const [event, weight] of Object.entries(rep.destinationWeights ?? {})) {
			// wispurr's per-destination escalation step is not an event here.
			if (event === "distinctSourcesEscalation") {
				ignored.push("reputation.destinationWeights.distinctSourcesEscalation (fixed at 1)");
				continue;
			}
			flag("reputation-dest-weight", `${event}:${integer(`reputation.destinationWeights.${event}`, weight)}`);
		}
	}

	// A proxy URL may carry credentials, so it travels with the passwords.
	if (config.proxy) {
		const proxy = text("proxy", config.proxy);
		// The server answers a value that does not fit by quoting it.
		if (Buffer.byteLength(proxy) > MAX_PROXY_BYTES) fail(`proxy is longer than ${MAX_PROXY_BYTES} bytes`);
		secrets.push(configLine("proxy", proxy));
		sensitive.push(proxy);
		const credentials = /^[^:/?#]*:\/\/([^/?#]*)@/.exec(proxy)?.[1];
		if (credentials !== undefined) {
			part(credentials);
			if (credentials.includes(":")) part(credentials.slice(credentials.indexOf(":") + 1));
		}
	}
	if (config.proxyUDP !== undefined) {
		if (config.proxyUDP !== "direct" && config.proxyUDP !== "refuse") fail("proxyUDP must be 'direct' or 'refuse'");
		flag("proxy-udp", config.proxyUDP);
	}
	if (config.dnsServers !== undefined) {
		for (const server of list("dnsServers", config.dnsServers)) flag("dns-server", server);
	}
	str("dns-order", "dnsResultOrder", config.dnsResultOrder);
	int("dns-ttl-s", "dnsTtlSeconds", config.dnsTtlSeconds);
	int("dns-negative-ttl-s", "dnsNegativeTtlSeconds", config.dnsNegativeTtlSeconds);
	int("dns-timeout-ms", "dnsTimeoutMs", config.dnsTimeoutMs);

	int("buffer-remaining", "bufferRemainingLength", config.bufferRemainingLength);
	int("max-message-size", "maxMessageSize", config.maxMessageSize);
	int("ws-write-high-water", "wsWriteHighWater", config.wsWriteHighWater);
	int("stream-queue-max", "streamQueueMax", config.streamQueueMax);
	int("conn-queue-max", "connQueueMax", config.connQueueMax);
	int("socket-buffer-size", "socketBufferSize", config.socketBufferSize);
	int("client-recv-buffer", "clientRecvBuffer", config.clientRecvBuffer);
	int("connect-timeout-ms", "connectTimeoutMs", config.connectTimeoutMs);
	int("handshake-timeout-ms", "handshakeTimeoutSeconds", config.handshakeTimeoutSeconds, 1000);
	int("client-write-timeout-s", "clientWriteTimeoutSeconds", config.clientWriteTimeoutSeconds);
	int("idle-timeout-s", "idleTimeoutSeconds", config.idleTimeoutSeconds);
	int("resolver-threads", "resolverThreads", config.resolverThreads);
	int("busy-poll-us", "busyPollUs", config.busyPollUs);
	bool("tcp-nodelay", "tcpNoDelay", config.tcpNoDelay);
	bool("tcp-quickack", "tcpQuickAck", config.tcpQuickAck);
	int("listen-backlog", "listenBacklog", config.listenBacklog);

	str("non-ws-response", "nonWSResponse", config.nonWSResponse);
	bool("serve-webclient", "serveWebclient", config.serveWebclient);
	str("webclient-wisp-url", "webclientWispUrl", config.webclientWispUrl);
	// `none` still has the server report errors: the wrapper drops them like everything else, but
	// keeps the last lines so that a server that will not start can say why.
	const level = config.logLevel ?? "warn";
	if (!["debug", "info", "warn", "error", "none"].includes(level)) fail("logLevel must be debug, info, warn, error or none");
	flag("log-level", level === "none" ? "error" : level);
	if (config.autoRestart !== undefined && typeof config.autoRestart !== "boolean") fail("autoRestart must be a boolean");
	// The wrapper holds a pipe to the server's stdin and never writes to it. When this process is
	// gone, however it went, the pipe closes and the server shuts down.
	flag("stop-on-stdin-eof", true);

	if (config.tcpBufferSize !== undefined) ignored.push("tcpBufferSize (holyWisp sizes its own buffers)");
	if (config.pendingQueueSize !== undefined) ignored.push("pendingQueueSize (use streamQueueMax / connQueueMax)");
	if (config.dnsMethod !== undefined) ignored.push("dnsMethod (set dnsServers for the built-in resolver)");
	if (config.websocketPermessageDeflate) ignored.push("websocketPermessageDeflate (not supported)");
	if (config.staticDir) ignored.push("staticDir (holyWisp serves no directory)");

	return { args, secrets, ignored, sensitive };
}

/** The headers the server is told to read, in order. Never empty: route() needs one to write to. */
export function trustedHeaders(config: holyWispConfig): string[] {
	const headers = list("trustedHeaders", config.trustedHeaders ?? [...DEFAULT_TRUSTED_HEADERS]);
	for (const header of headers) {
		if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(header)) fail(`trustedHeaders: '${header}' is not a header name`);
		if (header.toLowerCase() === PROXY_SECRET_HEADER.toLowerCase()) {
			fail(`trustedHeaders: ${PROXY_SECRET_HEADER} is the wrapper's own and never carries an address`);
		}
	}
	return headers.length > 0 ? headers : ["X-Forwarded-For"];
}
