import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { HISTORY_KEEP, HISTORY_MAX_LINES } from "./config.mjs";
import { REQUIRED_STRINGS, inspectionDisplay } from "./display.mjs";
import { HttpError, clip } from "./http.mjs";

// History is best-effort: missing files, bad lines, and write failures must not block approvals.
/** @param {string} stateFile @param {import('./types.mjs').Broadcast} broadcast */
export function createHistory(stateFile, broadcast) {
	const historyFile = path.join(path.dirname(stateFile), "approval-history.jsonl");
	/** Newest entry is last. */
	/** @type {import('./types.mjs').HistoryEntry[]} */
	const history = [];
	let historyLines = 0;

	/** @param {number} n */
	const newestFirst = (n) => history.slice(-n).reverse();

	/** @param {import('./types.mjs').Body} body @returns {import('./types.mjs').HistoryFields} */
	function normalizeEntry(body) {
		for (const k of REQUIRED_STRINGS) if (typeof body[k] !== "string") throw new HttpError(400, `${k} must be a string`);
		if (!["low", "medium", "critical"].includes(body.risk)) throw new HttpError(400, "bad risk");
		if (body.via !== undefined && !["browser", "terminal"].includes(body.via)) throw new HttpError(400, "bad via");
		if (!Array.isArray(body.reasons) || body.reasons.some((x) => typeof x !== "string"))
			throw new HttpError(400, "reasons must be a string array");
		for (const k of /** @type {const} */ (["model"]))
			if (body[k] !== undefined && typeof body[k] !== "string") throw new HttpError(400, `${k} must be a string`);
		/** @type {import('./types.mjs').HistoryFields} */
		const e = {
			sessionId: clip(body.sessionId, 200),
			sessionLabel: clip(body.sessionLabel, 200),
			cwd: clip(body.cwd, 4096),
			...inspectionDisplay(body),
			command: clip(body.command, 8000),
			risk: body.risk,
			tldr: clip(body.tldr, 600),
			reasons: body.reasons.slice(0, 20).map((x) => clip(x, 200)),
		};
		if (body.via) e.via = body.via;
		if (body.model) e.model = clip(body.model, 200);
		if (["approved", "denied", "redirected", "expired"].includes(body.status ?? "")) e.status = body.status;
		if (["auto", "human", "rule", "hard-deny", "grant"].includes(body.source ?? "")) e.source = body.source;
		if (typeof body.note === "string" && body.note) e.note = clip(body.note, 500);
		if (["approve", "deny", "review"].includes(body.recommendation)) e.recommendation = body.recommendation;
		if (["once", "session", "intent"].includes(body.scope ?? "")) e.scope = body.scope;
		if (typeof body.grantId === "string") e.grantId = clip(body.grantId, 100);
		for (const key of /** @type {const} */ (["shownAt", "answeredAt"]))
			if (typeof body[key] === "number" && Number.isFinite(body[key])) e[key] = body[key];
		return e;
	}

	function rewriteHistoryFile() {
		const tmp = `${historyFile}.${process.pid}.tmp`;
		fs.writeFileSync(tmp, history.map((e) => `${JSON.stringify(e)}\n`).join(""), { mode: 0o600 });
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

	/** @param {import('./types.mjs').HistoryFields} fields @param {number} [ts] */
	function addHistory(fields, ts = Date.now()) {
		const entry = { id: crypto.randomUUID(), ts, ...fields };
		history.push(entry);
		if (history.length > HISTORY_KEEP) history.shift();
		try {
			fs.appendFileSync(historyFile, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
			historyLines++;
			if (historyLines > HISTORY_MAX_LINES) rewriteHistoryFile();
		} catch {}
		broadcast("history", entry);
		return entry;
	}

	/** @param {import('./types.mjs').Request} r @param {string} status @param {string} [note] @param {string} [via] */
	function historyFromRequest(r, status, note, via) {
		/** @type {import('./types.mjs').HistoryFields} */
		const e = {
			sessionId: r.sessionId,
			sessionLabel: r.sessionLabel,
			cwd: r.cwd,
			...inspectionDisplay(r),
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
		e.recommendation = r.recommendation;
		e.shownAt = r.createdAt;
		if (r.answeredAt !== undefined) e.answeredAt = r.answeredAt;
		if (r.scope) e.scope = r.scope;
		// The gate reconciles scope and grant metadata after it validates the answer.
		return { ...normalizeEntry(/** @type {import('./types.mjs').Body} */ (e)), id: r.id };
	}

	return { history, newestFirst, normalizeEntry, rewriteHistoryFile, loadHistory, addHistory, historyFromRequest };
}
