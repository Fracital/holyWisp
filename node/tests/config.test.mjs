import assert from "node:assert/strict";
import { test } from "node:test";
import { configLine, workerArgs } from "../dist/config.js";
import { holywisp } from "../dist/index.js";

const run = { port: 6001, workers: 2 };

test("an empty config passes only what the wrapper decides", () => {
	const { args, secrets, ignored } = workerArgs({}, run);
	assert.deepEqual(args, [
		"--port=6001",
		"--workers=2",
		"--parse-real-ip=true",
		"--trusted-headers-reset=true",
		"--trusted-header=CF-Connecting-IP",
		"--trusted-header=X-Forwarded-For",
		"--trusted-proxy=127.0.0.1",
		"--trusted-proxy=::1",
		"--log-level=warn",
		"--stop-on-stdin-eof=true",
	]);
	assert.deepEqual(secrets, []);
	assert.deepEqual(ignored, []);
});

test("a wispurr config maps onto holywisp flags", () => {
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
			motd: 'hello "world" # not a comment',
			nonWSResponse: "line one\nline two",
			logLevel: "info",
			staticDir: "",
			floodProtection: {
				enabled: true,
				maxConcurrentStreamsPerConnection: 64,
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
	assert.throws(() => new holywisp({ allowUDP: "yes" }), /allowUDP must be a boolean/);
	assert.throws(() => new holywisp({ port: 70000 }), RangeError);
	assert.throws(() => new holywisp({ connectionsLimitPerIP: 1.5 }), /must be an integer/);
	assert.throws(() => new holywisp({ trustedProxies: ["not-an-address"] }), /trustedProxies/);
	assert.throws(() => new holywisp({ trustedHeaders: ["Bad Header"] }), /not a header name/);
	assert.throws(() => new holywisp({ floodProtection: { synFloodSignature: { failedHandshakeRatio: 2 } } }), /between 0 and 1/);
});

test("the wrapper binds loopback unless told otherwise, and uses the first port of a list", () => {
	assert.equal(new holywisp().config.host, "127.0.0.1");
	assert.equal(new holywisp({ host: "0.0.0.0" }).config.host, "0.0.0.0");
	assert.deepEqual(new holywisp({ port: [7001, 7002] }).ports, []);
});
