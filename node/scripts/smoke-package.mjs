// Run from a directory the packed tarball was installed into: proves the published package,
// with the binary it carries for this platform, starts and relays.
//   npm install ./holywisp-*.tgz && node smoke-package.mjs
import assert from "node:assert/strict";
import { once } from "node:events";
import { createServer } from "node:http";
import { holywisp } from "holywisp";

const wisp = new holywisp({ port: 0, logLevel: "error" });
const front = createServer();
front.on("upgrade", (req, socket, head) => wisp.route(req, socket, head));

try {
	await wisp.start(2);
	const health = await fetch(`http://127.0.0.1:${wisp.port}/health`, { signal: AbortSignal.timeout(5000) });
	assert.deepEqual(await health.json(), { status: "ok" });

	front.listen(0, "127.0.0.1");
	await once(front, "listening");
	const ws = new WebSocket(`ws://127.0.0.1:${front.address().port}/`);
	ws.binaryType = "arraybuffer";
	const [message] = await once(ws, "message");
	const first = Buffer.from(message.data);
	// Wisp v1 opens with CONTINUE on stream 0.
	assert.equal(first[0], 0x03);
	assert.equal(first.readUInt32LE(1), 0);
	ws.close();
} finally {
	front.closeAllConnections();
	front.close();
	await wisp.stop();
}
assert.equal(wisp.isRunning, false);
console.log(`holywisp package works on ${process.platform}-${process.arch}.`);
