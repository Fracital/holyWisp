/*
 * Vite plugin: run holyWisp next to the dev (and preview) server and route a path to it.
 *
 *   import { holyWispVite } from "holywisp/vite";
 *   export default { plugins: [holyWispVite({ path: "/wisp/" })] };
 */
import type { IncomingMessage, Server } from "node:http";
import type { Http2SecureServer } from "node:http2";
import { holyWisp, type holyWispOptions } from "./index.js";

type ViteServer = {
	httpServer: Server | Http2SecureServer | null;
	config: { logger: { warn(msg: string): void } };
};

export type holyWispVitePlugin = {
	name: string;
	configureServer(server: ViteServer): Promise<void>;
	configurePreviewServer(server: ViteServer): Promise<void>;
};

export type holyWispViteOptions = {
	/** Upgrades whose path starts with this string (or for which this returns true) go to holyWisp. */
	path: string | ((req: IncomingMessage) => boolean);
	config?: holyWispOptions;
	/** Worker threads; 0 = one per CPU. Default 1. */
	workers?: number;
	apply?: "serve" | "preview" | "both";
};

export function holyWispVite(options: holyWispViteOptions): holyWispVitePlugin {
	const apply = options.apply ?? "both";
	const prefix = options.path;
	const matches =
		typeof prefix === "function"
			? prefix
			: (req: IncomingMessage) => {
					// The request target is whatever the client sent, and not everything is a URL
					// (`//[`). One that cannot be read is not ours; it must not throw inside the
					// dev server's upgrade event, which would take the dev server down.
					try {
						return new URL(req.url ?? "/", "http://localhost").pathname.startsWith(prefix);
					} catch {
						return false;
					}
				};

	async function attach(server: ViteServer) {
		const { httpServer } = server;
		if (!httpServer) {
			server.config.logger.warn(
				"[holyWisp] Vite has no HTTP server (middleware mode); attach wisp.route() to your own server instead.",
			);
			return;
		}
		const wisp = new holyWisp(options.config);
		await wisp.start(options.workers ?? 1);

		httpServer.on("upgrade", (req, socket, head) => {
			if (matches(req)) wisp.route(req, socket, head);
		});
		httpServer.once("close", () => {
			if (wisp.isRunning) void wisp.stop();
		});
	}

	return {
		name: "holywisp",
		async configureServer(server) {
			if (apply !== "preview") await attach(server);
		},
		async configurePreviewServer(server) {
			if (apply !== "serve") await attach(server);
		},
	};
}
