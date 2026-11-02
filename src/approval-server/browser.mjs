import { spawn } from "node:child_process";
import { NO_OPEN, OPEN_DEBOUNCE_MS } from "./config.mjs";

// Browser launch failures are optional: the queue remains available at its local URL.
/** @param {import('./types.mjs').Runtime} runtime @param {Set<import('node:http').ServerResponse>} sseClients @param {string} approverToken */
export function createBrowser(runtime, sseClients, approverToken) {
	let lastOpen = 0;
	function openBrowser(force = false) {
		if (NO_OPEN) return;
		if (!force && (sseClients.size > 0 || Date.now() - lastOpen < OPEN_DEBOUNCE_MS)) return;
		lastOpen = Date.now();
		const url = `http://127.0.0.1:${runtime.port}/#a=${approverToken}`;
		let cmd;
		let args;
		/** @type {import("node:child_process").SpawnOptions} */
		let opts = { detached: true, stdio: "ignore" };
		if (process.platform === "darwin") [cmd, args] = ["open", [url]];
		else if (process.platform === "win32") {
			[cmd, args] = ["cmd", ["/c", "start", '""', url]];
			opts = { ...opts, windowsVerbatimArguments: true };
		} else [cmd, args] = ["xdg-open", [url]];
		try {
			const child = spawn(cmd, args, opts);
			child.on("error", () => {});
			child.unref();
		} catch {}
	}

	return openBrowser;
}
