#!/usr/bin/env node
// Approval server: one small local HTTP server shared by all pi sessions.
// It holds one queue of permission requests. A browser tab shows the queue.
// Usage: node approval-server.mjs <stateFilePath>
// Node built-ins only. The browser UI is inlined at the end of this file.
//
// Env:
//   APPROVAL_IDLE_MS                 idle exit time in ms (default 20 minutes)
//   APPROVAL_NO_OPEN=1               never open the browser (tests)
//   APPROVAL_TEST_APPROVER_TOKEN     TEST ONLY. Use this value as approver token
//                                    and allow ttlMs >= 100. The real client never sets it.
//   APPROVAL_HISTORY_MAX_LINES       TEST ONLY. Rotate the history file above this many lines (default 2000).
//   APPROVAL_HISTORY_KEEP            TEST ONLY. Entries kept in memory and after rotation (default 500).
//
// History: decisions are kept in memory (ring buffer) and in a JSONL file
// next to the state file. The file path is fixed. No request can change it.

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const MAX_BODY = 64 * 1024;
const MAX_PENDING = 200;
const KEEP_RESOLVED_MS = 2 * 60 * 1000;
const DEFAULT_TTL_MS = 10 * 60 * 1000;
const MAX_TTL_MS = 60 * 60 * 1000;
const MAX_WAIT_MS = 30_000;
const HEARTBEAT_MS = 15_000;
const OPEN_DEBOUNCE_MS = 15_000;
const IDLE_MS = Number(process.env.APPROVAL_IDLE_MS) > 0 ? Number(process.env.APPROVAL_IDLE_MS) : 20 * 60 * 1000;
const TEST_TOKEN = process.env.APPROVAL_TEST_APPROVER_TOKEN || "";
const MIN_TTL_MS = TEST_TOKEN ? 100 : 10_000;
const NO_OPEN = process.env.APPROVAL_NO_OPEN === "1";
const posInt = (v, d) => (Number.isInteger(Number(v)) && Number(v) > 0 ? Number(v) : d);
const HISTORY_KEEP = posInt(process.env.APPROVAL_HISTORY_KEEP, 500);
const HISTORY_MAX_LINES = posInt(process.env.APPROVAL_HISTORY_MAX_LINES, 2000);
const HISTORY_SNAPSHOT = 200;
const HISTORY_RATE_LIMIT = 200;
const HISTORY_RATE_WINDOW_MS = 10_000;
const DAY_MS = 24 * 60 * 60 * 1000;

const stateFile = process.argv[2];
if (!stateFile || !path.isAbsolute(stateFile)) {
	console.error("usage: node approval-server.mjs <absolute-state-file-path>");
	process.exit(2);
}

// ---------- state file ----------

function readState() {
	try {
		const s = JSON.parse(fs.readFileSync(stateFile, "utf8"));
		return s && Number.isInteger(s.pid) && Number.isInteger(s.port) ? s : null;
	} catch {
		return null;
	}
}

async function otherInstanceAlive() {
	const s = readState();
	if (!s || s.pid === process.pid) return false;
	try {
		process.kill(s.pid, 0);
	} catch (e) {
		if (e.code !== "EPERM") return false;
	}
	try {
		const r = await fetch(`http://127.0.0.1:${s.port}/api/health`, {
			headers: { authorization: `Bearer ${s.sessionToken}` },
			signal: AbortSignal.timeout(1500),
		});
		return r.ok;
	} catch {
		return false;
	}
}

// Atomic create. Returns false if another process won the race (file exists).
function writeState(data, force) {
	fs.mkdirSync(path.dirname(stateFile), { recursive: true, mode: 0o700 });
	const tmp = `${stateFile}.${process.pid}.tmp`;
	fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
	try {
		if (!force) {
			try {
				fs.linkSync(tmp, stateFile);
				return true;
			} catch (e) {
				if (e.code === "EEXIST") return false;
				// Hard links not supported here. Fall through to rename.
			}
		}
		fs.renameSync(tmp, stateFile);
		return true;
	} finally {
		try {
			fs.unlinkSync(tmp);
		} catch {}
	}
}

function removeStateFile() {
	const s = readState();
	if (s && s.pid === process.pid) {
		try {
			fs.unlinkSync(stateFile);
		} catch {}
	}
}

// ---------- helpers ----------

const sessionToken = crypto.randomBytes(24).toString("hex");
// The approver token stays in memory only. Never write or log it.
const approverToken = TEST_TOKEN || crypto.randomBytes(24).toString("hex");

const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
const tokenOk = (given, expected) => typeof given === "string" && crypto.timingSafeEqual(sha(given), sha(expected));
const clip = (v, n) => String(v).slice(0, n);

const SECURITY_HEADERS = {
	"x-content-type-options": "nosniff",
	"cache-control": "no-store",
	"referrer-policy": "no-referrer",
};

function sendJson(res, status, body, extra) {
	const payload = JSON.stringify(body);
	res.writeHead(status, {
		...SECURITY_HEADERS,
		"content-type": "application/json; charset=utf-8",
		"content-length": Buffer.byteLength(payload),
		...extra,
	});
	res.end(payload);
}

class HttpError extends Error {
	constructor(status, message) {
		super(message);
		this.status = status;
	}
}

function readJson(req) {
	return new Promise((resolve, reject) => {
		const declared = Number(req.headers["content-length"]);
		if (declared > MAX_BODY) {
			req.resume();
			return reject(new HttpError(413, "body too large"));
		}
		const chunks = [];
		let size = 0;
		let over = false;
		req.on("data", (c) => {
			if (over) return;
			size += c.length;
			if (size > MAX_BODY) {
				over = true;
				chunks.length = 0;
				reject(new HttpError(413, "body too large"));
				return;
			}
			chunks.push(c);
		});
		req.on("end", () => {
			if (over) return;
			try {
				const v = JSON.parse(Buffer.concat(chunks).toString("utf8") || "null");
				if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error("not an object");
				resolve(v);
			} catch {
				reject(new HttpError(400, "invalid JSON"));
			}
		});
		req.on("error", reject);
	});
}

// ---------- request queue ----------

/** @type {Map<string, any>} */
const requests = new Map();
/** @type {Set<http.ServerResponse>} */
const sseClients = new Set();
let lastActivity = Date.now();
let lastOpen = 0;
let port = 0;

const isPending = (r) => r.status === "pending";
const pendingList = () => [...requests.values()].filter(isPending);

// ---------- history ----------

const historyFile = path.join(path.dirname(stateFile), "approval-history.jsonl");
/** Newest entry is last. */
const history = [];
let historyLines = 0;
let historyCalls = [];

const newestFirst = (n) => history.slice(-n).reverse();

function normalizeEntry(body) {
	for (const k of REQUIRED_STRINGS) if (typeof body[k] !== "string") throw new HttpError(400, `${k} must be a string`);
	if (!["low", "medium", "critical"].includes(body.risk)) throw new HttpError(400, "bad risk");
	if (!["approved", "denied"].includes(body.status)) throw new HttpError(400, "bad status");
	if (!["auto", "human", "rule", "hard-deny"].includes(body.source)) throw new HttpError(400, "bad source");
	if (body.via !== undefined && !["browser", "terminal"].includes(body.via)) throw new HttpError(400, "bad via");
	if (!Array.isArray(body.reasons) || body.reasons.some((x) => typeof x !== "string"))
		throw new HttpError(400, "reasons must be a string array");
	for (const k of ["model", "note"]) if (body[k] !== undefined && typeof body[k] !== "string") throw new HttpError(400, `${k} must be a string`);
	const e = {
		sessionId: clip(body.sessionId, 200),
		sessionLabel: clip(body.sessionLabel, 200),
		cwd: clip(body.cwd, 200),
		command: clip(body.command, 8000),
		risk: body.risk,
		tldr: clip(body.tldr, 600),
		status: body.status,
		source: body.source,
		reasons: body.reasons.slice(0, 20).map((x) => clip(x, 200)),
	};
	if (body.via) e.via = body.via;
	if (body.model) e.model = clip(body.model, 200);
	if (body.note) e.note = clip(body.note, 500);
	return e;
}

function rewriteHistoryFile() {
	const tmp = `${historyFile}.${process.pid}.tmp`;
	fs.writeFileSync(tmp, history.map((e) => JSON.stringify(e) + "\n").join(""), { mode: 0o600 });
	fs.renameSync(tmp, historyFile);
	historyLines = history.length;
}

function loadHistory() {
	let text;
	try {
		text = fs.readFileSync(historyFile, "utf8");
	} catch {
		return;
	}
	const lines = text.split("\n").filter(Boolean);
	historyLines = lines.length;
	for (const line of lines.slice(-HISTORY_KEEP)) {
		try {
			const o = JSON.parse(line);
			if (typeof o.id !== "string" || typeof o.ts !== "number" || !Number.isFinite(o.ts)) continue;
			history.push({ id: clip(o.id, 100), ts: o.ts, ...normalizeEntry(o) });
		} catch {}
	}
	try {
		if (historyLines > HISTORY_MAX_LINES) rewriteHistoryFile();
	} catch {}
}

function addHistory(fields, ts = Date.now()) {
	const entry = { id: crypto.randomUUID(), ts, ...fields };
	history.push(entry);
	if (history.length > HISTORY_KEEP) history.shift();
	try {
		fs.appendFileSync(historyFile, JSON.stringify(entry) + "\n", { mode: 0o600 });
		historyLines++;
		if (historyLines > HISTORY_MAX_LINES) rewriteHistoryFile();
	} catch {}
	broadcast("history", entry);
	return entry;
}

function historyFromRequest(r, status, note, via) {
	const e = {
		sessionId: r.sessionId,
		sessionLabel: r.sessionLabel,
		cwd: r.cwd,
		command: r.command,
		risk: r.risk,
		tldr: r.tldr,
		status,
		source: "human",
		reasons: r.reasons,
	};
	if (via) e.via = via;
	if (r.model) e.model = r.model;
	if (note) e.note = note;
	return e;
}

function publicRequest(r) {
	return {
		id: r.id,
		sessionId: r.sessionId,
		sessionLabel: r.sessionLabel,
		cwd: r.cwd,
		kind: r.kind,
		command: r.command,
		risk: r.risk,
		tldr: r.tldr,
		recommendation: r.recommendation,
		reasons: r.reasons,
		model: r.model,
		createdAt: r.createdAt,
		expiresAt: r.expiresAt,
	};
}

function result(r) {
	const out = { status: r.status };
	if (r.note) out.note = r.note;
	if (r.scope) out.scope = r.scope;
	return out;
}

function broadcast(event, data) {
	const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
	for (const c of sseClients) c.write(msg);
}

function resolveRequest(r, status, extra = {}) {
	if (!isPending(r)) return false;
	r.status = status;
	if (extra.note) r.note = extra.note;
	if (extra.scope) r.scope = extra.scope;
	clearTimeout(r.expiryTimer);
	for (const w of r.waiters) {
		clearTimeout(w.timer);
		sendJson(w.res, 200, result(r));
	}
	r.waiters.clear();
	broadcast("resolved", { id: r.id, status });
	setTimeout(() => requests.delete(r.id), KEEP_RESOLVED_MS).unref();
	return true;
}

function openBrowser(force = false) {
	if (NO_OPEN) return;
	if (!force && (sseClients.size > 0 || Date.now() - lastOpen < OPEN_DEBOUNCE_MS)) return;
	lastOpen = Date.now();
	const url = `http://127.0.0.1:${port}/#a=${approverToken}`;
	let cmd;
	let args;
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

const REQUIRED_STRINGS = ["sessionId", "sessionLabel", "cwd", "command", "tldr"];

function createRequest(body) {
	for (const k of REQUIRED_STRINGS) if (typeof body[k] !== "string") throw new HttpError(400, `${k} must be a string`);
	if (!["command", "lockdown"].includes(body.kind)) throw new HttpError(400, "bad kind");
	if (!["low", "medium", "critical"].includes(body.risk)) throw new HttpError(400, "bad risk");
	if (!["approve", "deny", "review"].includes(body.recommendation)) throw new HttpError(400, "bad recommendation");
	if (!Array.isArray(body.reasons) || body.reasons.some((x) => typeof x !== "string"))
		throw new HttpError(400, "reasons must be a string array");
	if (body.model !== undefined && typeof body.model !== "string") throw new HttpError(400, "model must be a string");
	if (body.ttlMs !== undefined && !(typeof body.ttlMs === "number" && Number.isFinite(body.ttlMs)))
		throw new HttpError(400, "ttlMs must be a number");
	if (pendingList().length >= MAX_PENDING) throw new HttpError(429, "too many pending requests");

	const ttl = Math.min(MAX_TTL_MS, Math.max(MIN_TTL_MS, body.ttlMs ?? DEFAULT_TTL_MS));
	const now = Date.now();
	const r = {
		id: crypto.randomUUID(),
		sessionId: clip(body.sessionId, 200),
		sessionLabel: clip(body.sessionLabel, 200),
		cwd: clip(body.cwd, 200),
		kind: body.kind,
		command: clip(body.command, 8000),
		risk: body.risk,
		tldr: clip(body.tldr, 600),
		recommendation: body.recommendation,
		reasons: body.reasons.slice(0, 20).map((x) => clip(x, 200)),
		model: clip(body.model ?? "", 200),
		createdAt: now,
		expiresAt: now + ttl,
		status: "pending",
		waiters: new Set(),
	};
	r.expiryTimer = setTimeout(() => {
		if (resolveRequest(r, "expired")) addHistory(historyFromRequest(r, "denied", "Timed out without an answer."));
	}, ttl);
	requests.set(r.id, r);
	const noViewer = sseClients.size === 0;
	broadcast("added", publicRequest(r));
	if (noViewer) openBrowser();
	return r;
}

function decide(r, body) {
	if (!["approve", "deny"].includes(body.decision)) throw new HttpError(400, "bad decision");
	if (body.note !== undefined && typeof body.note !== "string") throw new HttpError(400, "note must be a string");
	if (body.scope !== undefined && !["once", "session"].includes(body.scope)) throw new HttpError(400, "bad scope");
	if (body.confirm !== undefined && typeof body.confirm !== "boolean") throw new HttpError(400, "confirm must be a boolean");
	if (!isPending(r)) throw new HttpError(409, "request is not pending");
	const note = body.note ? clip(body.note, 500) : undefined;
	if (body.decision === "deny") {
		resolveRequest(r, "denied", { note, scope: "once" });
		addHistory(historyFromRequest(r, "denied", note, "browser"));
		return;
	}
	const scope = body.scope ?? "once";
	if (scope === "session" && r.kind !== "lockdown") throw new HttpError(400, "scope session is not supported");
	if (r.risk === "critical" && body.confirm !== true) throw new HttpError(400, "critical request needs confirm: true");
	resolveRequest(r, "approved", { note, scope });
	addHistory(historyFromRequest(r, "approved", note, "browser"));
}

// ---------- HTTP routing ----------

function handleWait(req, res, url, r) {
	if (!isPending(r)) return sendJson(res, 200, result(r));
	const asked = Number(url.searchParams.get("timeoutMs"));
	const timeout = Math.min(MAX_WAIT_MS, Number.isFinite(asked) && asked >= 0 && url.searchParams.has("timeoutMs") ? asked : 25_000);
	const waiter = { res, timer: null };
	waiter.timer = setTimeout(() => {
		r.waiters.delete(waiter);
		sendJson(res, 200, { status: "pending" });
	}, timeout);
	r.waiters.add(waiter);
	res.on("close", () => {
		clearTimeout(waiter.timer);
		r.waiters.delete(waiter);
	});
}

function handleEvents(req, res) {
	res.writeHead(200, {
		...SECURITY_HEADERS,
		"content-type": "text/event-stream; charset=utf-8",
		connection: "keep-alive",
	});
	sseClients.add(res);
	res.on("close", () => sseClients.delete(res));
	const snapshot = { pending: pendingList().map(publicRequest), history: newestFirst(HISTORY_SNAPSHOT) };
	res.write(`event: snapshot\ndata: ${JSON.stringify(snapshot)}\n\n`);
}

const PAGE_HEADERS = {
	...SECURITY_HEADERS,
	"content-type": "text/html; charset=utf-8",
	// img-src data: is added so the tab icon (data: SVG) can change.
	"content-security-policy":
		"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'",
};

async function route(req, res) {
	const host = req.headers.host;
	if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`) return sendJson(res, 403, { error: "forbidden host" });
	lastActivity = Date.now();
	const url = new URL(req.url, "http://127.0.0.1");
	const p = url.pathname;
	const method = req.method;

	if (method === "GET" && p === "/") {
		res.writeHead(200, PAGE_HEADERS);
		return res.end(PAGE);
	}

	const sessionAuth = () => {
		const m = /^Bearer (.+)$/.exec(req.headers.authorization || "");
		if (!m || !tokenOk(m[1], sessionToken)) throw new HttpError(401, "unauthorized");
	};
	const approverAuth = (given) => {
		if (!tokenOk(given, approverToken)) throw new HttpError(401, "unauthorized");
	};

	if (method === "GET" && p === "/api/health") {
		sessionAuth();
		return sendJson(res, 200, { ok: true });
	}
	if (method === "POST" && p === "/api/open") {
		// The user asked for the page (the /approvals command), so open it even when a tab is connected.
		sessionAuth();
		openBrowser(true);
		return sendJson(res, 200, { ok: true });
	}
	if (method === "POST" && p === "/api/requests") {
		sessionAuth();
		const r = createRequest(await readJson(req));
		return sendJson(res, 200, { id: r.id });
	}
	if (method === "POST" && p === "/api/history") {
		sessionAuth();
		const now = Date.now();
		historyCalls = historyCalls.filter((t) => now - t < HISTORY_RATE_WINDOW_MS);
		if (historyCalls.length >= HISTORY_RATE_LIMIT) throw new HttpError(429, "too many history posts");
		historyCalls.push(now);
		const body = await readJson(req);
		if (body.ts !== undefined && !(typeof body.ts === "number" && Number.isFinite(body.ts))) throw new HttpError(400, "ts must be a number");
		const fields = normalizeEntry(body);
		const ts = body.ts !== undefined && body.ts >= now - DAY_MS && body.ts <= now + 60_000 ? body.ts : now;
		return sendJson(res, 200, { id: addHistory(fields, ts).id });
	}
	if (method === "GET" && p === "/api/history") {
		approverAuth(req.headers["x-approver-token"]);
		const asked = Number(url.searchParams.get("limit"));
		const limit = Number.isInteger(asked) && asked > 0 ? Math.min(asked, 500) : 200;
		return sendJson(res, 200, { history: newestFirst(limit) });
	}
	if (method === "GET" && p === "/api/events") {
		approverAuth(url.searchParams.get("a"));
		return handleEvents(req, res);
	}
	const m = /^\/api\/requests\/([^/]+)(\/wait|\/decision)?$/.exec(p);
	if (m) {
		const [, id, sub] = m;
		if (method === "GET" && sub === "/wait") {
			sessionAuth();
			const r = requests.get(id);
			if (!r) throw new HttpError(404, "unknown request");
			return handleWait(req, res, url, r);
		}
		if (method === "DELETE" && !sub) {
			sessionAuth();
			const r = requests.get(id);
			if (!r) throw new HttpError(404, "unknown request");
			resolveRequest(r, "cancelled");
			return sendJson(res, 200, { ok: true });
		}
		if (method === "POST" && sub === "/decision") {
			approverAuth(req.headers["x-approver-token"]);
			const body = await readJson(req);
			const r = requests.get(id);
			if (!r) throw new HttpError(404, "unknown request");
			decide(r, body);
			return sendJson(res, 200, { ok: true });
		}
	}
	throw new HttpError(404, "not found");
}

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

function shutdown(code = 0) {
	removeStateFile();
	process.exit(code);
}

async function main() {
	if (await otherInstanceAlive()) process.exit(0);

	await new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", resolve);
	});
	port = server.address().port;

	const state = { port, pid: process.pid, sessionToken, startedAt: Date.now() };
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
			if (pendingList().length === 0 && sseClients.size === 0 && Date.now() - lastActivity >= IDLE_MS) shutdown(0);
		},
		Math.max(50, Math.min(30_000, Math.floor(IDLE_MS / 4))),
	).unref();

	console.log(`approval-server listening on 127.0.0.1:${port}`);
}

main().catch((e) => {
	console.error(`approval-server failed: ${e.message}`);
	process.exit(1);
});

// ---------- browser UI (inlined) ----------
// Do not use backticks or dollar-brace in the page code. It is a raw template string.

const PAGE = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Permission Gate</title>
<link id="icon" rel="icon" href="data:,">
<style>
:root {
  --bg: #0e1116; --card: #161b22; --card-2: #1c222b; --line: #2a313c; --text: #e6edf3; --muted: #9ba7b4;
  --green: #3fb950; --amber: #e3a428; --red: #f85149; --blue: #4c8dff;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body { margin: 0; color: var(--text); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; -webkit-font-smoothing: antialiased; }
.wrap { max-width: 860px; margin: 0 auto; padding: 0 20px 64px; }
.sticky { position: sticky; top: 0; background: var(--bg); z-index: 5; margin-bottom: 20px; }
header { display: flex; align-items: center; gap: 12px; padding: 22px 0 14px; }
[hidden] { display: none !important; }
.tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--line); }
.tab { background: none; border: 0; border-bottom: 2px solid transparent; margin-bottom: -1px; color: var(--muted); font: inherit; font-size: 14px; font-weight: 600; padding: 8px 14px; cursor: pointer; border-radius: 6px 6px 0 0; }
.tab:hover { color: var(--text); }
.tab[aria-selected="true"] { color: var(--text); border-bottom-color: var(--blue); }
h1 { font-size: 19px; font-weight: 650; margin: 0; letter-spacing: .1px; }
.dot { width: 10px; height: 10px; border-radius: 50%; background: var(--red); box-shadow: 0 0 0 3px rgba(248,81,73,.18); flex: none; }
.dot.on { background: var(--green); box-shadow: 0 0 0 3px rgba(63,185,80,.18); }
.count { color: var(--muted); font-size: 14px; }
.spacer { flex: 1; }
.link { background: none; border: 0; color: var(--blue); font: inherit; font-size: 13px; cursor: pointer; padding: 2px 4px; border-radius: 4px; text-decoration: underline; text-underline-offset: 2px; }
button:focus-visible, input:focus-visible { outline: 2px solid var(--blue); outline-offset: 2px; }
.banner { border: 1px solid rgba(248,81,73,.45); background: rgba(248,81,73,.1); color: #ffb4af; padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
.banner[hidden] { display: none; }
.empty { text-align: center; padding: 90px 20px; color: var(--muted); }
.empty strong { display: block; color: var(--text); font-size: 18px; font-weight: 600; margin-bottom: 6px; }
.empty[hidden] { display: none; }
.group { margin-bottom: 26px; }
.group-title { display: flex; align-items: baseline; gap: 8px; margin: 0 0 10px 2px; font-size: 13px; font-weight: 600; color: var(--text); }
.group-title span { color: var(--muted); font-weight: 400; font-family: var(--mono); font-size: 12px; }
.cards { display: flex; flex-direction: column; gap: 12px; }
.card { position: relative; background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px 18px 16px 24px; overflow: hidden; transition: opacity .35s, transform .35s; }
.card::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 5px; background: var(--green); }
.card.risk-medium::before { background: var(--amber); }
.card.risk-critical { border-color: rgba(248,81,73,.7); background: linear-gradient(rgba(248,81,73,.07), rgba(248,81,73,.07)), var(--card); }
.card.risk-critical::before { background: var(--red); }
.card.leaving { opacity: 0; transform: translateY(-6px); pointer-events: none; }
.top { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 10px; }
.badge { font-size: 11px; font-weight: 700; letter-spacing: .6px; padding: 2px 8px; border-radius: 999px; color: #0b0f14; background: var(--green); }
.risk-medium .badge { background: var(--amber); }
.risk-critical .badge { background: var(--red); color: #fff; }
.pill { font-size: 12px; font-weight: 600; padding: 2px 10px; border-radius: 999px; border: 1px solid; }
.pill.approve { color: #6ee07f; border-color: rgba(63,185,80,.5); background: rgba(63,185,80,.1); }
.pill.deny { color: #ff8a84; border-color: rgba(248,81,73,.55); background: rgba(248,81,73,.1); }
.pill.review { color: #f0be5a; border-color: rgba(227,164,40,.5); background: rgba(227,164,40,.1); }
.time { margin-left: auto; color: var(--muted); font-size: 12.5px; white-space: nowrap; }
.tldr { font-size: 18px; line-height: 1.4; font-weight: 600; margin: 0 0 12px; overflow-wrap: anywhere; }
.lock { border: 1px solid rgba(227,164,40,.5); background: rgba(227,164,40,.1); color: #f3cd7e; border-radius: 8px; padding: 8px 12px; font-size: 13.5px; margin: 0 0 12px; }
.cmd-wrap { margin-bottom: 10px; }
.cmd { background: #0b0e13; border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }
.cmd-text { margin: 0; font: 13px/1.5 var(--mono); white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; max-height: 18em; overflow: hidden; color: #d7dee6; }
.cmd-text.open { max-height: none; }
.toggle { margin-top: 4px; padding-left: 0; }
.toggle[hidden] { display: none; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
.chip { font-size: 12px; color: var(--muted); background: var(--card-2); border: 1px solid var(--line); border-radius: 6px; padding: 1px 8px; overflow-wrap: anywhere; }
.meta { display: flex; flex-wrap: wrap; gap: 4px 14px; color: var(--muted); font-size: 12.5px; margin-bottom: 14px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.note { flex: 1 1 200px; min-width: 160px; height: 36px; background: #0b0e13; color: var(--text); border: 1px solid var(--line); border-radius: 8px; padding: 0 10px; font: inherit; font-size: 13.5px; }
.note::placeholder { color: #7d8895; }
.btn { height: 36px; padding: 0 16px; border-radius: 8px; border: 1px solid var(--line); background: var(--card-2); color: var(--text); font: inherit; font-size: 14px; font-weight: 600; cursor: pointer; }
.btn:hover:not(:disabled) { border-color: #3b4452; background: #232a35; }
.btn.primary { background: #238636; border-color: #2ea043; color: #fff; }
.btn.primary:hover:not(:disabled) { background: #2ea043; border-color: #3fb950; }
.btn.armed, .btn.armed:hover:not(:disabled) { background: #da3633; border-color: #f85149; color: #fff; }
.btn:disabled { opacity: .45; cursor: not-allowed; }
.err { color: #ff8a84; font-size: 13px; flex-basis: 100%; }
.err:empty { display: none; }
.badge.b-medium { background: var(--amber); }
.badge.b-critical { background: var(--red); color: #fff; }
.cmd-text.scroll { max-height: 24em; overflow: auto; }
.toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 8px; }
.seg { display: inline-flex; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
.seg button { background: var(--card); color: var(--muted); border: 0; border-right: 1px solid var(--line); font: inherit; font-size: 13px; font-weight: 600; height: 32px; padding: 0 14px; cursor: pointer; }
.seg button:last-child { border-right: 0; }
.seg button:hover { color: var(--text); }
.seg button[aria-pressed="true"] { background: #243044; color: var(--text); }
.seg button:focus-visible { outline-offset: -2px; }
.search { flex: 1 1 220px; min-width: 160px; height: 32px; background: #0b0e13; color: var(--text); border: 1px solid var(--line); border-radius: 8px; padding: 0 10px; font: inherit; font-size: 13.5px; }
.search::placeholder { color: #7d8895; }
.showing { color: var(--muted); font-size: 12.5px; margin: 0 2px 10px; }
.hlist { list-style: none; margin: 0; padding: 0; border: 1px solid var(--line); border-radius: 10px; overflow: hidden; background: var(--card); overflow-anchor: none; }
.hrow { border-bottom: 1px solid var(--line); }
.hrow:last-child { border-bottom: 0; }
.hhead { display: grid; grid-template-columns: 66px 84px 74px 74px minmax(0, 1fr); gap: 4px 12px; align-items: center; width: 100%; text-align: left; background: none; border: 0; color: var(--text); font: inherit; padding: 9px 14px; cursor: pointer; }
.hhead:hover, .hrow.open .hhead { background: var(--card-2); }
.hhead:focus-visible { outline-offset: -2px; }
.hhead .pill, .hhead .badge { justify-self: start; text-align: center; }
.htime { font-size: 12.5px; line-height: 1.25; font-variant-numeric: tabular-nums; }
.htime small { display: block; color: var(--muted); font-size: 11px; }
.hsrc { font-size: 12.5px; color: var(--muted); }
.hmain { display: block; min-width: 0; }
.htldr { display: block; font-size: 14px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.hsub { display: flex; gap: 8px; font-size: 12px; color: var(--muted); min-width: 0; }
.hsub .lbl { flex: none; max-width: 35%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hsub code { font: 12px var(--mono); min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hrow.open .htldr { white-space: normal; overflow-wrap: anywhere; }
.hrow.open .hsub { display: none; }
.hrow.open .hhead { align-items: start; }
.hrow.open .hhead > :not(.hmain) { align-self: start; height: 22px; display: inline-flex; align-items: center; }
.hrow.open .htime small { display: none; }
.hdetail { padding: 2px 14px 14px; background: var(--card-2); }
.hdetail .cmd { margin-bottom: 10px; }
.hdetail .meta { margin-bottom: 0; }
.hnote { color: var(--text); font-size: 13px; margin-top: 8px; overflow-wrap: anywhere; }
@media (max-width: 700px) {
  .hhead { grid-template-columns: auto auto auto 1fr; }
  .hmain { grid-column: 1 / -1; }
  .htldr { white-space: normal; overflow-wrap: anywhere; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; }
  .hrow.open .htldr { display: block; }
}
@media (max-width: 560px) { .time { margin-left: 0; } .btn { flex: 1 1 auto; } }
@media (prefers-reduced-motion: reduce) { .card { transition: none; } }
</style>
</head>
<body>
<div class="wrap">
  <div class="sticky">
    <header>
      <span id="dot" class="dot" role="img" aria-label="Disconnected"></span>
      <h1>Permission Gate</h1>
      <span id="count" class="count">0 pending</span>
      <span class="spacer"></span>
      <button id="notify" class="link" type="button" hidden>Enable notifications</button>
    </header>
    <div class="tabs" role="tablist" aria-label="Views">
      <button id="tab-pending" class="tab" role="tab" type="button" aria-selected="true" aria-controls="panel-pending">Pending (0)</button>
      <button id="tab-history" class="tab" role="tab" type="button" aria-selected="false" aria-controls="panel-history" tabindex="-1">History (0)</button>
    </div>
  </div>
  <div id="banner" class="banner" role="status" hidden>Disconnected. Retrying...</div>
  <section id="panel-pending" role="tabpanel" aria-labelledby="tab-pending">
    <div id="empty" class="empty"><strong>No pending approvals</strong>New requests from your pi sessions will show up here.</div>
    <main id="list" aria-live="polite"></main>
  </section>
  <section id="panel-history" role="tabpanel" aria-labelledby="tab-history" hidden>
    <div class="toolbar">
      <div class="seg" role="group" aria-label="Filter by result">
        <button type="button" data-f="all" aria-pressed="true">All</button>
        <button type="button" data-f="approved" aria-pressed="false">Approved</button>
        <button type="button" data-f="denied" aria-pressed="false">Denied</button>
      </div>
      <input id="search" class="search" type="search" placeholder="Search history" aria-label="Search command, summary, session and reasons" autocomplete="off">
    </div>
    <p id="showing" class="showing">Showing 0 of 0</p>
    <div id="hempty" class="empty"><strong id="hempty-t">No decisions yet</strong><span id="hempty-s">Decisions will be listed here.</span></div>
    <ul id="hlist" class="hlist" hidden></ul>
  </section>
</div>
<script>
(function () {
  'use strict';
  var TITLE = 'Permission Gate';
  var token = null;
  try {
    var m = /[#&]a=([^&]+)/.exec(location.hash);
    if (m) {
      token = decodeURIComponent(m[1]);
      sessionStorage.setItem('pg-token', token);
      history.replaceState(null, '', location.pathname + location.search);
    } else {
      token = sessionStorage.getItem('pg-token');
    }
  } catch (e) {}

  var $ = function (id) { return document.getElementById(id); };
  var listEl = $('list'), emptyEl = $('empty'), bannerEl = $('banner'), dotEl = $('dot'), countEl = $('count'), notifyEl = $('notify');
  var tabPendingEl = $('tab-pending');
  var cards = {};      // id -> card object
  var groups = {};     // sessionId -> group element
  var connected = false;
  var flashTimer = null, flashOn = false;

  function h(tag, cls, text) {
    var el = document.createElement(tag);
    if (cls) el.className = cls;
    if (text !== undefined) el.textContent = text;
    return el;
  }

  function pendingCount() {
    var n = 0;
    for (var id in cards) if (!cards[id].leaving) n++;
    return n;
  }

  function baseName(p) {
    var parts = String(p).split(/[\\/]/).filter(Boolean);
    return parts.length ? parts[parts.length - 1] : String(p);
  }

  function rel(ms) {
    var s = Math.max(0, Math.round((Date.now() - ms) / 1000));
    if (s < 10) return 'just now';
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    return Math.floor(s / 3600) + 'h ago';
  }

  function left(ms) {
    var s = Math.round((ms - Date.now()) / 1000);
    if (s <= 0) return 'expired';
    var mm = Math.floor(s / 60), ss = s % 60;
    return 'expires in ' + mm + ':' + (ss < 10 ? '0' : '') + ss;
  }

  // ----- title, favicon, notifications -----
  function setIcon(n) {
    var color = n ? '#f85149' : '#6e7681';
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><circle cx="16" cy="16" r="13" fill="' + color + '"/></svg>';
    $('icon').href = 'data:image/svg+xml,' + encodeURIComponent(svg);
  }
  function updateTitle() {
    var n = pendingCount();
    document.title = n ? (flashOn ? '\u26A0 Needs approval' : '(' + n + ') ' + TITLE) : TITLE;
    setIcon(n);
  }
  function startFlash() {
    if (flashTimer) return;
    flashTimer = setInterval(function () { flashOn = !flashOn; updateTitle(); }, 1000);
  }
  function stopFlash() {
    if (flashTimer) clearInterval(flashTimer);
    flashTimer = null; flashOn = false; updateTitle();
  }
  document.addEventListener('visibilitychange', function () { if (!document.hidden) stopFlash(); });

  function refreshNotifyLink() {
    notifyEl.hidden = !('Notification' in window) || Notification.permission !== 'default';
  }
  notifyEl.addEventListener('click', function () {
    if ('Notification' in window) Notification.requestPermission().then(refreshNotifyLink, refreshNotifyLink);
  });
  refreshNotifyLink();

  function notifyNew(r) {
    if (!document.hidden) return;
    startFlash();
    try {
      if ('Notification' in window && Notification.permission === 'granted') {
        new Notification('Permission Gate: ' + r.risk, { body: r.tldr, tag: r.id });
      }
    } catch (e) {}
  }

  // ----- cards -----
  function setBusy(c, busy) { c.busy = busy; syncDisabled(); }
  function syncDisabled() {
    for (var id in cards) {
      var c = cards[id], off = !connected || c.busy;
      for (var i = 0; i < c.buttons.length; i++) c.buttons[i].disabled = off;
    }
  }

  function send(c, decision, scope, confirm) {
    setBusy(c, true);
    c.err.textContent = '';
    var body = { decision: decision, scope: scope, note: c.note.value.trim() || undefined };
    if (confirm) body.confirm = true;
    fetch('/api/requests/' + encodeURIComponent(c.req.id) + '/decision', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-approver-token': token || '' },
      body: JSON.stringify(body)
    }).then(function (res) {
      if (res.ok) return; // the resolved event removes the card
      return res.json().catch(function () { return {}; }).then(function (j) {
        c.err.textContent = res.status === 401 ? 'Not authorized. Open the link from pi again.' : (j.error || 'Request failed (' + res.status + ')');
        setBusy(c, false);
      });
    }).catch(function () {
      c.err.textContent = 'Network error. Try again.';
      setBusy(c, false);
    });
  }

  function approveButton(c, label, scope, primary) {
    var b = h('button', 'btn' + (primary ? ' primary' : ''), label);
    b.type = 'button';
    var timer = null;
    function reset() { timer = null; b.classList.remove('armed'); b.textContent = label; }
    b.addEventListener('click', function () {
      if (c.req.risk === 'critical' && !timer) {
        b.classList.add('armed');
        b.textContent = 'Confirm: run this critical command';
        timer = setTimeout(reset, 5000);
        return;
      }
      if (timer) { clearTimeout(timer); reset(); }
      send(c, 'approve', scope, c.req.risk === 'critical');
    });
    return b;
  }

  function buildCard(r) {
    var c = { req: r, busy: false, expanded: false, leaving: false, buttons: [] };
    var el = h('article', 'card risk-' + r.risk);
    c.el = el;

    var top = h('div', 'top');
    top.appendChild(h('span', 'badge', r.risk === 'critical' ? 'CRITICAL' : r.risk.toUpperCase() + ' RISK'));
    if (r.kind !== 'lockdown') {
      if (r.recommendation === 'approve') top.appendChild(h('span', 'pill approve', 'Recommended: APPROVE'));
      else if (r.recommendation === 'deny') top.appendChild(h('span', 'pill deny', 'Recommended: DENY'));
      else top.appendChild(h('span', 'pill review', 'Needs your review'));
    }
    c.timeEl = h('span', 'time');
    top.appendChild(c.timeEl);
    el.appendChild(top);

    el.appendChild(h('p', 'tldr', r.tldr));
    if (r.kind === 'lockdown') {
      el.appendChild(h('div', 'lock', 'Lockdown: the agent was blocked several times. Every command needs your approval until you lift it.'));
    }

    var cw = h('div', 'cmd-wrap');
    c.cmd = h('pre', 'cmd-text', r.command);
    var box = h('div', 'cmd');
    box.appendChild(c.cmd);
    c.toggle = h('button', 'link toggle', 'Show more');
    c.toggle.type = 'button';
    c.toggle.hidden = true;
    c.toggle.addEventListener('click', function () {
      c.expanded = !c.expanded;
      c.cmd.classList.toggle('open', c.expanded);
      c.toggle.textContent = c.expanded ? 'Show less' : 'Show more';
    });
    cw.appendChild(box);
    cw.appendChild(c.toggle);
    el.appendChild(cw);

    if (r.reasons.length) {
      var chips = h('div', 'chips');
      r.reasons.forEach(function (x) { chips.appendChild(h('span', 'chip', x)); });
      el.appendChild(chips);
    }

    var meta = h('div', 'meta');
    if (r.model) meta.appendChild(h('span', '', 'Model: ' + r.model));
    c.expEl = h('span');
    meta.appendChild(c.expEl);
    el.appendChild(meta);

    var actions = h('div', 'actions');
    c.note = h('input', 'note');
    c.note.type = 'text';
    c.note.maxLength = 500;
    c.note.placeholder = 'Note for the agent (optional)';
    c.note.setAttribute('aria-label', 'Note for the agent (optional)');
    var approve = approveButton(c, r.kind === 'lockdown' ? 'Approve this command' : 'Approve', 'once', true);
    c.buttons.push(approve);
    actions.appendChild(approve);
    if (r.kind === 'lockdown') {
      var lift = approveButton(c, 'Approve and lift lockdown', 'session', false);
      c.buttons.push(lift);
      actions.appendChild(lift);
    }
    var deny = h('button', 'btn', 'Deny');
    deny.type = 'button';
    deny.addEventListener('click', function () { send(c, 'deny', 'once', false); });
    c.buttons.push(deny);
    actions.appendChild(deny);
    actions.appendChild(c.note);
    c.err = h('div', 'err');
    c.err.setAttribute('role', 'alert');
    actions.appendChild(c.err);
    el.appendChild(actions);

    updateTimes(c);
    return c;
  }

  function updateTimes(c) {
    c.timeEl.textContent = rel(c.req.createdAt);
    c.expEl.textContent = left(c.req.expiresAt);
  }

  function measure(c) {
    if (c.expanded) return;
    c.toggle.hidden = c.cmd.scrollHeight <= c.cmd.clientHeight + 1;
  }

  // Put children in order without moving nodes that are already right.
  function place(parent, kids) {
    for (var i = 0; i < kids.length; i++) {
      if (parent.children[i] !== kids[i]) parent.insertBefore(kids[i], parent.children[i] || null);
    }
  }

  function render() {
    var bySession = {};
    for (var id in cards) {
      var c = cards[id], sid = c.req.sessionId;
      (bySession[sid] = bySession[sid] || []).push(c);
    }
    var order = Object.keys(bySession);
    order.forEach(function (sid) {
      bySession[sid].sort(function (a, b) { return b.req.createdAt - a.req.createdAt; });
    });
    order.sort(function (a, b) { return bySession[b][0].req.createdAt - bySession[a][0].req.createdAt; });

    for (var gid in groups) {
      if (!bySession[gid]) { groups[gid].remove(); delete groups[gid]; }
    }
    var groupEls = order.map(function (sid) {
      var first = bySession[sid][0].req, g = groups[sid];
      if (!g) {
        g = h('section', 'group');
        g.appendChild(h('h2', 'group-title'));
        g.appendChild(h('div', 'cards'));
        groups[sid] = g;
      }
      var t = g.firstChild;
      t.textContent = first.sessionLabel || 'Session';
      var folder = baseName(first.cwd);
      t.appendChild(h('span', '', (folder === first.sessionLabel ? '' : folder + ' \u00B7 ') + sid.slice(0, 8)));
      place(g.lastChild, bySession[sid].map(function (c) { return c.el; }));
      return g;
    });
    place(listEl, groupEls);

    for (var k in cards) measure(cards[k]);
    var n = pendingCount();
    countEl.textContent = n + ' pending';
    tabPendingEl.textContent = 'Pending (' + n + ')';
    emptyEl.hidden = n > 0 || Object.keys(cards).length > 0;
    updateTitle();
    syncDisabled();
  }

  function addCard(r) {
    if (cards[r.id]) return false;
    cards[r.id] = buildCard(r);
    return true;
  }

  function removeCard(id) {
    var c = cards[id];
    if (!c || c.leaving) return;
    c.leaving = true;
    c.el.classList.add('leaving');
    setTimeout(function () {
      c.el.remove();
      if (cards[id] === c) delete cards[id];
      render();
    }, 380);
    render();
  }

  // ----- connection -----
  function setConnected(on) {
    connected = on;
    dotEl.classList.toggle('on', on);
    dotEl.setAttribute('aria-label', on ? 'Connected' : 'Disconnected');
    bannerEl.hidden = on;
    syncDisabled();
  }

  var es = null, backoff = 1000, retryTimer = null;
  function connect() {
    if (!token) { bannerEl.textContent = 'No access token. Open the link that pi opened for you.'; bannerEl.hidden = false; return; }
    es = new EventSource('/api/events?a=' + encodeURIComponent(token));
    es.onopen = function () { backoff = 1000; setConnected(true); };
    es.onerror = function () {
      es.close();
      setConnected(false);
      clearTimeout(retryTimer);
      retryTimer = setTimeout(connect, backoff);
      backoff = Math.min(backoff * 2, 15000);
    };
    es.addEventListener('snapshot', function (e) {
      var data = JSON.parse(e.data), seen = {};
      data.pending.forEach(function (r) { seen[r.id] = true; addCard(r); });
      Object.keys(cards).forEach(function (id) { if (!seen[id]) removeCard(id); });
      render();
      setHistory(data.history || []);
    });
    es.addEventListener('added', function (e) {
      var r = JSON.parse(e.data);
      if (addCard(r)) { render(); notifyNew(r); }
    });
    es.addEventListener('resolved', function (e) { removeCard(JSON.parse(e.data).id); });
    es.addEventListener('history', function (e) { addHistoryEntry(JSON.parse(e.data)); });
  }

  // ----- history -----
  var HMAX = 500;
  var hist = [];           // newest first
  var histIds = {};        // id -> true
  var rows = {};           // id -> <li>
  var hFilter = 'all', hQuery = '', expandedId = null;
  var hlistEl = $('hlist'), hemptyEl = $('hempty'), showingEl = $('showing'), tabHistoryEl = $('tab-history'), searchEl = $('search');
  var panelPending = $('panel-pending'), panelHistory = $('panel-history');
  var SRC = { auto: 'Auto', human: 'You', rule: 'Rule', 'hard-deny': 'Hard deny' };

  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  function clock(d) { return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); }

  function matches(e) {
    if (hFilter !== 'all' && e.status !== hFilter) return false;
    if (!hQuery) return true;
    var hay = e.command + '\n' + e.tldr + '\n' + e.sessionLabel + '\n' + e.reasons.join('\n');
    return hay.toLowerCase().indexOf(hQuery) !== -1;
  }

  function buildDetail(e) {
    var d = h('div', 'hdetail');
    var box = h('div', 'cmd');
    box.appendChild(h('pre', 'cmd-text scroll', e.command));
    d.appendChild(box);
    if (e.reasons.length) {
      var chips = h('div', 'chips');
      e.reasons.forEach(function (x) { chips.appendChild(h('span', 'chip', x)); });
      d.appendChild(chips);
    }
    var meta = h('div', 'meta');
    meta.appendChild(h('span', '', new Date(e.ts).toLocaleString()));
    var folder = baseName(e.cwd), label = e.sessionLabel || 'Session';
    meta.appendChild(h('span', '', 'Session: ' + label + (folder === label ? '' : ' (' + folder + ')')));
    if (e.model) meta.appendChild(h('span', '', 'Model: ' + e.model));
    if (e.via) meta.appendChild(h('span', '', 'Via: ' + e.via));
    d.appendChild(meta);
    if (e.note) d.appendChild(h('div', 'hnote', 'Note: ' + e.note));
    return d;
  }

  function setOpen(li, open) {
    li.classList.toggle('open', open);
    li.firstChild.setAttribute('aria-expanded', open ? 'true' : 'false');
    var det = li.querySelector('.hdetail');
    if (open && !det) li.appendChild(buildDetail(li._e));
    if (!open && det) det.remove();
  }

  function buildRow(e) {
    var li = h('li', 'hrow');
    li._e = e;
    var head = h('button', 'hhead');
    head.type = 'button';
    head.setAttribute('aria-expanded', 'false');
    var d = new Date(e.ts);
    var t = h('span', 'htime', clock(d));
    if (d.toDateString() !== new Date().toDateString()) {
      t.appendChild(h('small', '', d.toLocaleDateString([], { day: 'numeric', month: 'short' })));
    }
    head.appendChild(t);
    head.appendChild(h('span', 'pill ' + (e.status === 'approved' ? 'approve' : 'deny'), e.status === 'approved' ? 'Approved' : 'Denied'));
    head.appendChild(h('span', 'hsrc', SRC[e.source] || e.source));
    head.appendChild(h('span', 'badge b-' + e.risk, e.risk.toUpperCase()));
    var main = h('span', 'hmain');
    main.appendChild(h('span', 'htldr', e.tldr));
    var sub = h('span', 'hsub');
    sub.appendChild(h('span', 'lbl', e.sessionLabel));
    sub.appendChild(h('code', '', e.command.split('\n')[0]));
    main.appendChild(sub);
    head.appendChild(main);
    head.addEventListener('click', function () {
      var open = !li.classList.contains('open');
      var prev = hlistEl.querySelector('.hrow.open');
      if (prev && prev !== li) setOpen(prev, false);
      setOpen(li, open);
      expandedId = open ? e.id : null;
    });
    li.appendChild(head);
    rows[e.id] = li;
    return li;
  }

  function updateHistoryMeta() {
    var total = hist.length, shown = hlistEl.children.length;
    tabHistoryEl.textContent = 'History (' + total + ')';
    showingEl.textContent = 'Showing ' + shown + ' of ' + total;
    hlistEl.hidden = shown === 0;
    hemptyEl.hidden = shown > 0;
    $('hempty-t').textContent = total === 0 ? 'No decisions yet' : 'No matching decisions';
    $('hempty-s').textContent = total === 0 ? 'Decisions will be listed here.' : 'Try another filter or search.';
  }

  function renderHistory() {
    var frag = document.createDocumentFragment();
    rows = {};
    hist.forEach(function (e) {
      if (!matches(e)) return;
      var li = buildRow(e);
      if (e.id === expandedId) setOpen(li, true);
      frag.appendChild(li);
    });
    hlistEl.textContent = '';
    hlistEl.appendChild(frag);
    updateHistoryMeta();
  }

  function setHistory(list) {
    hist = list.slice(0, HMAX);
    histIds = {};
    hist.forEach(function (e) { histIds[e.id] = true; });
    renderHistory();
  }

  // Insert one new entry at the top. Keep scroll position and open rows.
  function addHistoryEntry(e) {
    if (histIds[e.id]) return;
    histIds[e.id] = true;
    hist.unshift(e);
    if (hist.length > HMAX) {
      var old = hist.pop();
      delete histIds[old.id];
      if (rows[old.id]) { rows[old.id].remove(); delete rows[old.id]; }
    }
    if (matches(e)) {
      var before = document.documentElement.scrollHeight;
      hlistEl.insertBefore(buildRow(e), hlistEl.firstChild);
      if (!panelHistory.hidden && window.scrollY > 0) window.scrollBy(0, document.documentElement.scrollHeight - before);
    }
    updateHistoryMeta();
  }

  var filterBtns = document.querySelectorAll('.seg button');
  Array.prototype.forEach.call(filterBtns, function (b) {
    b.addEventListener('click', function () {
      hFilter = b.getAttribute('data-f');
      Array.prototype.forEach.call(filterBtns, function (o) { o.setAttribute('aria-pressed', o === b ? 'true' : 'false'); });
      renderHistory();
    });
  });
  searchEl.addEventListener('input', function () {
    hQuery = searchEl.value.trim().toLowerCase();
    renderHistory();
  });

  // ----- tabs -----
  var tabs = { pending: tabPendingEl, history: tabHistoryEl };
  var panels = { pending: panelPending, history: panelHistory };
  var tabNames = ['pending', 'history'];
  function selectTab(name, focus) {
    tabNames.forEach(function (k) {
      var on = k === name;
      tabs[k].setAttribute('aria-selected', on ? 'true' : 'false');
      tabs[k].tabIndex = on ? 0 : -1;
      panels[k].hidden = !on;
    });
    try { sessionStorage.setItem('pg-tab', name); } catch (e) {}
    if (focus) tabs[name].focus();
    if (name === 'pending') for (var id in cards) measure(cards[id]);
  }
  tabNames.forEach(function (name, i) {
    tabs[name].addEventListener('click', function () { selectTab(name, false); });
    tabs[name].addEventListener('keydown', function (ev) {
      var next = ev.key === 'ArrowRight' ? (i + 1) % 2 : ev.key === 'ArrowLeft' ? (i + 1) % 2 : ev.key === 'Home' ? 0 : ev.key === 'End' ? 1 : -1;
      if (next < 0) return;
      ev.preventDefault();
      selectTab(tabNames[next], true);
    });
  });
  var savedTab = null;
  try { savedTab = sessionStorage.getItem('pg-tab'); } catch (e) {}

  setInterval(function () {
    for (var id in cards) updateTimes(cards[id]);
  }, 1000);
  window.addEventListener('resize', function () { for (var id in cards) measure(cards[id]); });

  render();
  updateHistoryMeta();
  selectTab(savedTab === 'history' ? 'history' : 'pending', false);
  setConnected(false);
  connect();
})();
</script>
</body>
</html>
`;
