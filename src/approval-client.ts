import { spawn } from "node:child_process";
import { realpathSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { approvalServerVersion } from "./approval-server/version.mjs";
import type { ApprovalOutcome, ApprovalRequester, HistoryReporter, IntentProposal, QueueState } from "./types.ts";

// Client for the shared approval queue (approval-server/server.mjs). One local server serves all
// pi sessions, so the user watches one browser tab. Every failure returns undefined so the
// caller can fall back to the terminal prompt. The client never stores the approver token:
// only the browser has it, so a session can submit and wait but never decide.
// The extension may be loaded through a symlink, so resolve the real location of the sibling server file.
const SERVER_PATH = join(dirname(realpathSync(fileURLToPath(import.meta.url))), "approval-server", "server.mjs");
const QUEUE_START_TIMEOUT_MS = 5000;
const QUEUE_LONG_POLL_MS = 25_000;

async function queueCall(
	state: QueueState,
	method: string,
	path: string,
	options: { body?: unknown; signal?: AbortSignal } = {},
): Promise<{ status: number; json: Record<string, unknown> }> {
	const response = await fetch(`http://127.0.0.1:${state.port}${path}`, {
		method,
		headers: {
			authorization: `Bearer ${state.sessionToken}`,
			...(options.body === undefined ? {} : { "content-type": "application/json" }),
		},
		body: options.body === undefined ? undefined : JSON.stringify(options.body),
		signal: options.signal,
	});
	const json = (await response.json().catch(() => ({}))) as Record<string, unknown>;
	return { status: response.status, json };
}

async function readQueueState(statePath: string): Promise<QueueState | undefined> {
	try {
		const parsed = JSON.parse(await readFile(statePath, "utf8")) as Partial<QueueState>;
		if (typeof parsed.port === "number" && typeof parsed.pid === "number" && typeof parsed.sessionToken === "string") {
			return { port: parsed.port, pid: parsed.pid, sessionToken: parsed.sessionToken };
		}
	} catch {
		// No state file yet.
	}
	return undefined;
}

async function queueVersion(state: QueueState): Promise<string | undefined> {
	try {
		const { status, json } = await queueCall(state, "GET", "/api/health", { signal: AbortSignal.timeout(1500) });
		if (status !== 200) return undefined;
		// Servers from before the version check report no version.
		return typeof json.version === "string" ? json.version : "";
	} catch {
		return undefined;
	}
}

async function isQueueHealthy(state: QueueState): Promise<boolean> {
	return (await queueVersion(state)) !== undefined;
}

let expectedServerVersion: string | undefined;
function serverFileVersion(): string | undefined {
	// Hash the files on disk, so an update replaces a server that still runs old code.
	try {
		expectedServerVersion ??= approvalServerVersion();
	} catch {
		// Unreadable server files: keep any running server instead of failing the request.
		return undefined;
	}
	return expectedServerVersion;
}

// Stops a server that runs other code. New servers accept a shutdown request. Older
// servers do not have it, so they get SIGTERM. The pid comes from the state file of a
// server that accepted our session token.
async function stopQueueServer(state: QueueState): Promise<void> {
	const { status } = await queueCall(state, "POST", "/api/shutdown", { signal: AbortSignal.timeout(1500) }).catch(
		() => ({ status: 0 }),
	);
	if (status !== 200) {
		try {
			process.kill(state.pid, "SIGTERM");
		} catch {
			// The process is already gone.
		}
	}
	const deadline = Date.now() + QUEUE_START_TIMEOUT_MS;
	while (Date.now() < deadline && (await isQueueHealthy(state)))
		await new Promise((resolve) => setTimeout(resolve, 100));
}

async function ensureQueueServer(statePath: string): Promise<QueueState | undefined> {
	const existing = await readQueueState(statePath);
	if (existing) {
		const running = await queueVersion(existing);
		const expected = serverFileVersion();
		if (running !== undefined && (!expected || running === expected)) return existing;
		if (running !== undefined) await stopQueueServer(existing);
	}

	try {
		spawn(process.execPath, [SERVER_PATH, statePath], { detached: true, stdio: "ignore" }).unref();
	} catch {
		return undefined;
	}

	const deadline = Date.now() + QUEUE_START_TIMEOUT_MS;
	while (Date.now() < deadline) {
		await new Promise((resolve) => setTimeout(resolve, 150));
		const state = await readQueueState(statePath);
		if (state && (await isQueueHealthy(state))) return state;
	}
	return undefined;
}

// Reports a decision to the queue server so the browser history shows it. Best effort: it never
// throws and never delays the command. It starts the server when needed, without opening a tab.
export function createHistoryReporter(statePath: string): HistoryReporter {
	return async (entry) => {
		try {
			const state = await ensureQueueServer(statePath);
			if (state) await queueCall(state, "POST", "/api/history", { body: entry, signal: AbortSignal.timeout(5000) });
		} catch {
			// History is a convenience. A failure must not affect the gate.
		}
	};
}

// Opens the queue and history page in the browser. Returns false when the server is unavailable.
export async function openApprovalPage(statePath: string): Promise<boolean> {
	try {
		const state = await ensureQueueServer(statePath);
		if (!state) return false;
		return (await queueCall(state, "POST", "/api/open", { signal: AbortSignal.timeout(5000) })).status === 200;
	} catch {
		return false;
	}
}

export function createApprovalRequester(statePath: string): ApprovalRequester {
	return async (request, signal, lifecycle) => {
		if (signal.aborted) return { status: "cancelled" };
		const state = await ensureQueueServer(statePath);
		if (!state) return undefined;

		let id: string;
		try {
			const created = await queueCall(state, "POST", "/api/requests", {
				body: request,
				signal: AbortSignal.any([signal, AbortSignal.timeout(QUEUE_START_TIMEOUT_MS)]),
			});
			if (created.status !== 200 || typeof created.json.id !== "string") return undefined;
			id = created.json.id;
		} catch {
			return signal.aborted ? { status: "cancelled" } : undefined;
		}

		let parked = false;
		const deadline = Date.now() + (request.ttlMs ?? 600_000);
		const park = () => {
			parked = true;
			void queueCall(state, "POST", `/api/requests/${id}/park`, { signal: AbortSignal.timeout(5000) }).catch(
				() => undefined,
			);
		};
		const cancel = () =>
			void queueCall(state, "DELETE", `/api/requests/${id}`, { signal: AbortSignal.timeout(5000) }).catch(
				() => undefined,
			);
		signal.addEventListener("abort", cancel, { once: true });
		lifecycle?.parkSignal.addEventListener("abort", park, { once: true });
		if (lifecycle?.parkSignal.aborted) park();
		try {
			if (signal.aborted) {
				cancel();
				return { status: "cancelled" };
			}
			while (!signal.aborted && Date.now() < deadline) {
				let waited: Awaited<ReturnType<typeof queueCall>>;
				try {
					waited = await queueCall(state, "GET", `/api/requests/${id}/wait?timeoutMs=${QUEUE_LONG_POLL_MS}`, {
						signal: AbortSignal.any([signal, AbortSignal.timeout(QUEUE_LONG_POLL_MS + 5000)]),
					});
				} catch {
					if (!parked || signal.aborted) return signal.aborted ? { status: "cancelled" } : undefined;
					await delay(300, undefined, { signal });
					continue;
				}
				const status = waited.json.status;
				if (waited.status !== 200) {
					if (!parked || waited.status === 404) return undefined;
					await delay(300, undefined, { signal });
					continue;
				}
				if (status === "pending") continue;
				if (
					status === "approved" ||
					status === "denied" ||
					status === "redirected" ||
					status === "expired" ||
					status === "cancelled"
				) {
					const outcome: ApprovalOutcome = {
						status,
						historyId: id,
						note: typeof waited.json.note === "string" ? waited.json.note : undefined,
						scope: waited.json.scope === "session" ? "session" : waited.json.scope === "intent" ? "intent" : "once",
						intent: waited.json.intent as IntentProposal | undefined,
					};
					if (parked) lifecycle?.onLateOutcome(outcome);
					return outcome;
				}
				return undefined;
			}
			return { status: signal.aborted ? "cancelled" : "expired" };
		} catch {
			return signal.aborted ? { status: "cancelled" } : undefined;
		} finally {
			signal.removeEventListener("abort", cancel);
			lifecycle?.parkSignal.removeEventListener("abort", park);
		}
	};
}
