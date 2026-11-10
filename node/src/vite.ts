/*
 * Vite plugin: run holyWisp next to the dev (and preview) server and route a path to it.
 *
 *   import { holywispVite } from "holywisp/vite";
 *   export default { plugins: [holywispVite({ path: "/wisp/" })] };
 */
import type { IncomingMessage, Server } from "node:http";
import type { Http2SecureServer } from "node:http2";
import { holywisp, type holywispOptions } from "./index.js";

type ViteServer = {
	httpServer: Server | Http2SecureServer | null;
	config: { logger: { warn(msg: string): void } };
};

export type holywispVitePlugin = {
	name: string;
	configureServer(server: ViteServer): Promise<void>;
	configurePreviewServer(server: ViteServer): Promise<void>;
};

export type holywispViteOptions = {
	/** Upgrades whose path starts with this string (or for which this returns true) go to holyWisp. */
	path: string | ((req: IncomingMessage) => boolean);
	config?: holywispOptions;
	/** Worker threads; 0 = one per CPU. Default 1. */
	workers?: number;
	apply?: "serve" | "preview" | "both";
};

export function holywispVite(options: holywispViteOptions): holywispVitePlugin {
	const apply = options.apply ?? "both";
	const prefix = options.path;
	const matches =
		typeof prefix === "function"
			? prefix
			: (req: IncomingMessage) => new URL(req.url ?? "/", "http://localhost").pathname.startsWith(prefix);

	async function attach(server: ViteServer) {
		const { httpServer } = server;
		if (!httpServer) {
			server.config.logger.warn(
				"[holywisp] Vite has no HTTP server (middleware mode); attach wisp.route() to your own server instead.",
			);
			return;
		}
		const wisp = new holywisp(options.config);
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
