import crypto from "node:crypto";
import http from "node:http";
import { createBrowser } from "./browser.mjs";
import { HEARTBEAT_MS, IDLE_MS, TEST_TOKEN } from "./config.mjs";
import { createHistory } from "./history.mjs";
import { HttpError, sendJson } from "./http.mjs";
import { loadPage } from "./page.mjs";
import { createQueue } from "./queue.mjs";
import { createRouter } from "./router.mjs";
import { createStateFile } from "./state-file.mjs";
import { approvalServerVersion } from "./version.mjs";

/** @param {string} stateFile */
export function startServer(stateFile) {
	const runtime = { port: 0, lastActivity: Date.now() };
	/** @type {Set<http.ServerResponse>} */
	const sseClients = new Set();
	const sessionToken = crypto.randomBytes(24).toString("hex");
	// The approver token stays in memory only. Never write or log it.
	const approverToken = TEST_TOKEN || crypto.randomBytes(24).toString("hex");
	const { otherInstanceAlive, writeState, removeStateFile } = createStateFile(stateFile);
	/** @type {import('./types.mjs').Broadcast} */
	const broadcast = (event, data) => {
		const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
		for (const client of sseClients) client.write(msg);
	};
	const historyStore = createHistory(stateFile, broadcast);
	const openBrowser = createBrowser(runtime, sseClients, approverToken);
	const queue = createQueue(sseClients, openBrowser, historyStore, broadcast);
	const { pendingList } = queue;
	const { loadHistory } = historyStore;
	const route = createRouter(
		runtime,
		queue,
		historyStore,
		sseClients,
		openBrowser,
		sessionToken,
		approverToken,
		loadPage(),
		approvalServerVersion(),
		shutdown,
	);
	const server = http.createServer((req, res) => {
		route(req, res).catch((e) => {
			if (res.headersSent) return res.destroy();
			if (e instanceof HttpError) {
				return sendJson(res, e.status, { error: e.message }, e.status === 413 ? { connection: "close" } : undefined);
			}
			sendJson(res, 500, { error: "internal error" });
		});
	});
	server.requestTimeout = 0; // long polls and SSE must stay open
	server.headersTimeout = 15_000;

	// ---------- lifecycle ----------

	/** @param {number} [code] */
	function shutdown(code = 0) {
		removeStateFile();
		process.exit(code);
	}

	async function main() {
		if (await otherInstanceAlive()) process.exit(0);

		await new Promise((resolve, reject) => {
			server.once("error", reject);
			server.listen(0, "127.0.0.1", () => resolve(undefined));
		});
		runtime.port = /** @type {import('node:net').AddressInfo} */ (server.address()).port;

		const state = { port: runtime.port, pid: process.pid, sessionToken, startedAt: Date.now() };
		if (!writeState(state, false)) {
			// A state file exists. Stale files are replaced. Live instances win.
			if (await otherInstanceAlive()) process.exit(0);
			writeState(state, true);
		}
		loadHistory();

		process.on("SIGINT", () => shutdown(0));
		process.on("SIGTERM", () => shutdown(0));
		process.on("exit", removeStateFile);

		setInterval(() => {
			for (const c of sseClients) c.write(": ping\n\n");
		}, HEARTBEAT_MS).unref();

		setInterval(
			() => {
				if (pendingList().length === 0 && sseClients.size === 0 && Date.now() - runtime.lastActivity >= IDLE_MS)
					shutdown(0);
			},
			Math.max(50, Math.min(30_000, Math.floor(IDLE_MS / 4))),
		).unref();

		console.log(`approval-server listening on 127.0.0.1:${runtime.port}`);
	}

	return main();
}
