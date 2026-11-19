/*
 * Vite plugin: run holyWisp next to the dev (and preview) server and route a path to it, and with
 * `config.webTransport` its `/webtransport.json` too.
 *
 *   import { holyWispVite } from "holywisp/vite";
 *   export default { plugins: [holyWispVite({ path: "/wisp/" })] };
 */
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { Http2SecureServer } from "node:http2";
import { holyWisp, type holyWispOptions } from "./index.js";

type ViteServer = {
	httpServer: Server | Http2SecureServer | null;
	middlewares?: { use(fn: (req: IncomingMessage, res: ServerResponse, next: () => void) => void): void };
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
		// With webTransport on, the page's GET /webtransport.json on the dev server's origin is the
		// server's (holyWisp.routeRequest); every other request goes on to Vite.
		if (options.config?.webTransport) {
			server.middlewares?.use((req, res, next) => {
				if (!wisp.routeRequest(req, res)) next();
			});
		}
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
