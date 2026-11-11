import assert from "node:assert/strict";
import { test } from "node:test";
import { configLine, redactor, workerArgs } from "../dist/config.js";
import { holyWisp } from "../dist/index.js";

const run = { port: 6001, workers: 2 };

test("an empty config passes only what the wrapper decides", () => {
	const { args, secrets, ignored, sensitive } = workerArgs({}, run);
	assert.deepEqual(args, [
		"--host=127.0.0.1",
		"--port=6001",
		"--workers=2",
		"--parse-real-ip=true",
		"--trusted-headers-reset=true",
		"--trusted-header=X-Forwarded-For",
		"--trusted-proxy=127.0.0.1",
		"--trusted-proxy=::1",
		"--log-level=warn",
		"--stop-on-stdin-eof=true",
	]);
	assert.deepEqual(secrets, []);
	assert.deepEqual(ignored, []);
	assert.deepEqual(sensitive, []);
});

test("the only header trusted by default is X-Forwarded-For, and a list of one's own replaces it", () => {
	const headers = (config) => workerArgs(config, run).args.filter((arg) => arg.startsWith("--trusted-header="));
	// CF-Connecting-IP is a client's to send unless a Cloudflare edge is what is in front.
	assert.deepEqual(headers({}), ["--trusted-header=X-Forwarded-For"]);
	assert.deepEqual(headers({ trustedProxies: ["10.0.0.1"] }), ["--trusted-header=X-Forwarded-For"]);
	assert.deepEqual(headers({ trustedHeaders: ["CF-Connecting-IP", "X-Forwarded-For"] }), [
		"--trusted-header=CF-Connecting-IP",
		"--trusted-header=X-Forwarded-For",
	]);
	assert.deepEqual(headers({ trustedHeaders: [] }), ["--trusted-header=X-Forwarded-For"]);
});

test("the proxy secret travels in the file with the passwords, never in the argument list", () => {
	const proxySecret = "5ec2e7".repeat(11);
	const { args, secrets, sensitive } = workerArgs({ passwordUsers: { alice: "pw-of-alice" } }, { ...run, proxySecret });
	assert.deepEqual(secrets, ['password-user = "alice:pw-of-alice"', `trusted-proxy-secret = "${proxySecret}"`]);
	assert.ok(!args.join(" ").includes(proxySecret));
	assert.ok(!args.some((arg) => arg.includes("trusted-proxy-secret")));
	assert.ok(sensitive.includes(proxySecret));
	// Without one (the constructor's dry run) the key is not written at all.
	assert.deepEqual(workerArgs({}, run).secrets, []);
});

test("a wispurr config maps onto the server's flags", () => {
	const { args, ignored } = workerArgs(
		{
			host: "0.0.0.0",
			allowTCP: true,
			allowUDP: false,
			allowDirectIP: true,
			allowPrivateIPs: false,
			allowLoopbackIPs: true,
			tcpBufferSize: 1048576,
			pendingQueueSize: 268435456,
			bufferRemainingLength: 256,
			tcpNoDelay: true,
			blacklist: { hostnames: { "bad.example": true }, ports: [25, [6881, 6889]] },
			whitelist: { hostnames: ["*.example.com"], ports: { "443": true } },
			websocketPermessageDeflate: false,
			dnsServers: ["1.1.1.1"],
			dnsMethod: "resolve",
			dnsResultOrder: "ipv6first",
			handshakeTimeoutSeconds: 10,
			clientWriteTimeoutSeconds: 30,
			idleTimeoutSeconds: 600,
			allowedOrigins: ["https://app.example", "http://localhost:5173"],
			motd: 'hello "world" # not a comment',
			nonWSResponse: "line one\nline two",
			logLevel: "info",
			staticDir: "",
			floodProtection: {
				enabled: true,
				maxConcurrentStreamsPerConnection: 64,
				maxInFlightSynsPerIP: 128,
				maxConcurrentConnectionsPerIP: 40,
				synFloodSignature: { enabled: false, failedHandshakeRatio: 0.5 },
			},
			reputation: {
				enabled: true,
				storePath: "./data/rep.json",
				thresholds: { strict: 90 },
				weights: { privateEgress: 15, successfulStream: -2 },
				destinationWeights: { synSignature: 30, distinctSourcesEscalation: 1 },
			},
		},
		run,
	);
	for (const expected of [
		"--host=0.0.0.0",
		"--allow-udp=false",
		"--allow-direct-ip=true",
		"--allow-loopback=true",
		"--buffer-remaining=256",
		"--block-host=bad.example",
		"--block-port=25",
		"--block-port=6881-6889",
		"--allow-host=*.example.com",
		"--allow-port=443",
		"--dns-server=1.1.1.1",
		"--dns-order=ipv6first",
		"--handshake-timeout-ms=10000",
		"--client-write-timeout-s=30",
		"--idle-timeout-s=600",
		"--allow-origin=https://app.example",
		"--allow-origin=http://localhost:5173",
		"--max-in-flight-syns-per-ip=128",
		"--max-concurrent-connections-per-ip=40",
		'--motd=hello "world" # not a comment',
		"--non-ws-response=line one\nline two",
		"--log-level=info",
		"--max-streams-per-conn=64",
		"--syn-signature=false",
		"--syn-signature-failed-ratio=0.5",
		"--reputation-store=./data/rep.json",
		"--reputation-strict=90",
		"--reputation-weight=privateEgress:15",
		"--reputation-weight=successfulStream:-2",
		"--reputation-dest-weight=synSignature:30",
	]) {
		assert.ok(args.includes(expected), `missing ${expected}`);
	}
	assert.equal(ignored.length, 4);
	assert.match(ignored.join("\n"), /tcpBufferSize[\s\S]*pendingQueueSize[\s\S]*dnsMethod/);
	assert.match(ignored.join("\n"), /distinctSourcesEscalation/);
});

test("passwords and proxy credentials stay out of the argument list", () => {
	const { args, secrets } = workerArgs(
		{ passwordUsers: { alice: "s3cret pass#1", bob: 'has"quote' }, proxy: "socks5://u:p@10.0.0.1:1080" },
		run,
	);
	assert.deepEqual(secrets, [
		'password-user = "alice:s3cret pass#1"',
		'password-user = bob:has"quote',
		'proxy = "socks5://u:p@10.0.0.1:1080"',
	]);
	assert.ok(!args.join(" ").includes("s3cret"));
	assert.ok(!args.join(" ").includes("u:p@"));
});

test("passwordAuth: false drops the users and says so", () => {
	const { secrets, ignored } = workerArgs({ passwordAuth: false, passwordUsers: { alice: "x" } }, run);
	assert.deepEqual(secrets, []);
	assert.match(ignored[0], /passwordUsers/);
});

test("a secret the config file cannot hold is refused, not altered", () => {
	assert.throws(() => configLine("password-user", 'a:"quoted" #x'), /cannot hold/);
	assert.throws(() => configLine("password-user", 'a:trailing" '), /cannot hold/);
	assert.throws(() => configLine("password-user", "a:two\nlines"), /line break/);
	assert.throws(() => workerArgs({ passwordUsers: { "a:b": "x" } }, run), /no ':'/);
});

// Whatever is wrong with an entry, the complaint is the wrapper's, made before a server is started,
// and it names the user without holding the password. The server's own complaint would be about a
// config line, and used to quote it.
test("a passwordUsers entry the server would refuse is refused first, without the password", () => {
	const password = "hunter2-SECRET-PASSWORD";
	const thrown = (passwordUsers, extra = {}) => {
		try {
			new holyWisp({ passwordUsers, ...extra });
		} catch (err) {
			assert.ok(err instanceof TypeError);
			assert.ok(!err.message.includes(password), `the error holds the password: ${err.message}`);
			assert.ok(!err.message.includes("SECRET"), `the error holds part of the password: ${err.message}`);
			return err.message;
		}
		return assert.fail("accepted");
	};
	const long = "u".repeat(64);
	assert.match(thrown({ [long]: password }), new RegExp(`"${long}" is longer than 63 bytes`));
	// Bytes, not characters: 32 two-byte letters are 64 bytes.
	assert.match(thrown({ ["\u00e9".repeat(32)]: password }), /longer than 63 bytes/);
	assert.match(thrown({ "": password }), /non-empty/);
	// A name with a colon is likely `user:password` in the wrong place: only what precedes it is shown.
	assert.match(thrown({ [`carol:${password}`]: "x" }), /no ':' \(the name that starts "carol"\)/);
	assert.match(thrown({ "da\nve": password }), /"da\\nve" must not contain a control character/);
	assert.match(thrown({ erin: `${password}\nmotd = owned` }), /user "erin" must not contain a line break/);
	assert.match(thrown({ erin: `${password}\r` }), /user "erin" must not contain a line break/);
	assert.match(thrown({ frank: password + "x".repeat(128) }), /user "frank" is longer than 127 bytes/);
	assert.match(thrown({ grace: 12345 }), /user "grace" must be a string/);
	assert.match(thrown({ heidi: `"${password}" #x` }), /user "heidi" has a value the config file cannot hold/);
	// The limits themselves are accepted.
	const { secrets } = workerArgs({ passwordUsers: { ["u".repeat(63)]: "p".repeat(127) } }, run);
	assert.equal(secrets.length, 1);
	// A proxy URL the server's field cannot hold is quoted by the server too, credentials and all.
	const proxy = `socks5://puser:${password}@127.0.0.1:1080/${"x".repeat(240)}`;
	try {
		new holyWisp({ proxy });
		assert.fail("accepted");
	} catch (err) {
		assert.match(err.message, /proxy is longer than 255 bytes/);
		assert.ok(!err.message.includes(password));
	}
});

test("what the secrets file holds is blanked in anything the server says", () => {
	const proxySecret = "ab12".repeat(16);
	const { sensitive } = workerArgs(
		{ passwordUsers: { alice: "correct horse", bob: "b" }, proxy: "socks5://puser:PROXY-SECRET@127.0.0.1:1080" },
		{ ...run, proxySecret },
	);
	const redact = redactor(sensitive);
	for (const leak of [
		"holywisp: /tmp/x/secrets.conf:1: bad value 'alice:correct horse' for 'password-user'",
		"config: bad value 'socks5://puser:PROXY-SECRET@127.0.0.1:1080' for 'proxy'",
		"config: proxy: cannot reach puser:PROXY-SECRET@127.0.0.1",
		"proxy: authentication failed (password PROXY-SECRET)",
		`bad value '${proxySecret}' for 'trusted-proxy-secret'`,
		`X-HolyWisp-Proxy-Secret: ${proxySecret}`,
		"password-user = bob:b",
	]) {
		const shown = redact(leak);
		assert.match(shown, /\[redacted\]/, leak);
		for (const secret of ["correct horse", "PROXY-SECRET", proxySecret, "bob:b"]) {
			assert.ok(!shown.includes(secret), `'${secret}' survived in: ${shown}`);
		}
	}
	// A one-letter password is hidden where it is a value, and the rest of the text stays readable.
	assert.equal(redact("cannot bind"), "cannot bind");
	assert.equal(redactor([])("nothing to hide"), "nothing to hide");
});

test("parseRealIP: false trusts only route() itself", () => {
	const { args } = workerArgs({ parseRealIP: false, trustedProxies: ["10.0.0.0/8"] }, run);
	assert.ok(args.includes("--parse-real-ip=true"));
	assert.ok(args.includes("--trusted-proxy=127.0.0.1"));
	assert.ok(!args.includes("--trusted-proxy=10.0.0.0/8"));
	const trusting = workerArgs({ trustedProxies: ["10.0.0.0/8", "127.0.0.1"] }, run).args;
	assert.deepEqual(
		trusting.filter((arg) => arg.startsWith("--trusted-proxy=")),
		["--trusted-proxy=127.0.0.1", "--trusted-proxy=::1", "--trusted-proxy=10.0.0.0/8"],
	);
});

test("the constructor rejects options of the wrong shape", () => {
	assert.throws(() => new holyWisp({ allowUDP: "yes" }), /allowUDP must be a boolean/);
	assert.throws(() => new holyWisp({ port: 70000 }), RangeError);
	assert.throws(() => new holyWisp({ connectionsLimitPerIP: 1.5 }), /must be an integer/);
	assert.throws(() => new holyWisp({ trustedProxies: ["not-an-address"] }), /trustedProxies/);
	assert.throws(() => new holyWisp({ trustedHeaders: ["Bad Header"] }), /not a header name/);
	assert.throws(() => new holyWisp({ trustedHeaders: ["x-holywisp-proxy-secret"] }), /the wrapper's own/);
	assert.throws(() => new holyWisp({ floodProtection: { synFloodSignature: { failedHandshakeRatio: 2 } } }), /between 0 and 1/);
});

test("the wrapper binds loopback unless told otherwise, and uses the first port of a list", () => {
	assert.equal(new holyWisp().config.host, "127.0.0.1");
	assert.equal(new holyWisp({ host: "0.0.0.0" }).config.host, "0.0.0.0");
	assert.deepEqual(new holyWisp({ port: [7001, 7002] }).ports, []);
});

// `host: process.env.WISP_HOST` with the variable unset. The server's own default is every
// interface, so "no host" must never reach it as "no --host".
test("a host that is undefined or empty is loopback, not every interface", () => {
	const hostArgs = (config) => workerArgs(config, run).args.filter((arg) => arg.startsWith("--host"));
	for (const host of [undefined, "", null]) {
		const wisp = new holyWisp({ host });
		assert.equal(wisp.config.host, "127.0.0.1", `host: ${JSON.stringify(host)}`);
		assert.deepEqual(hostArgs(wisp.config), ["--host=127.0.0.1"]);
		// And when the option reaches workerArgs as it was given.
		assert.deepEqual(hostArgs({ host }), ["--host=127.0.0.1"]);
	}
	assert.deepEqual(hostArgs({}), ["--host=127.0.0.1"]);
	// `config` can be changed between starts: taking the host away there does not open the port either.
	const wisp = new holyWisp({ host: "127.0.0.1" });
	delete wisp.config.host;
	assert.deepEqual(hostArgs(wisp.config), ["--host=127.0.0.1"]);
	// A host that was asked for is passed as it is.
	assert.deepEqual(hostArgs(new holyWisp({ host: "::1" }).config), ["--host=::1"]);
	assert.deepEqual(hostArgs(new holyWisp({ host: "0.0.0.0" }).config), ["--host=0.0.0.0"]);
	assert.throws(() => new holyWisp({ host: 0 }), /host must be a string/);
});
