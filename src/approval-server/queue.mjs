import crypto from "node:crypto";
import { DEFAULT_TTL_MS, KEEP_RESOLVED_MS, MAX_PENDING, MAX_TTL_MS, MIN_TTL_MS } from "./config.mjs";
import { REQUIRED_STRINGS, inspectionDisplay, normalizeIntent } from "./display.mjs";
import { HttpError, clip, sendJson } from "./http.mjs";

/** @param {Set<import('node:http').ServerResponse>} sseClients @param {(force?: boolean) => void} openBrowser @param {import('./types.mjs').HistoryStore} historyStore @param {import('./types.mjs').Broadcast} broadcast */
export function createQueue(sseClients, openBrowser, historyStore, broadcast) {
	/** @type {Map<string, import('./types.mjs').Request>} */
	const requests = new Map();
	const { addHistory, historyFromRequest } = historyStore;
	/** @param {import('./types.mjs').Request} r */
	const isPending = (r) => r.status === "pending";
	const pendingList = () => [...requests.values()].filter(isPending);
	/** @param {import('./types.mjs').Request} r */
	function publicRequest(r) {
		return {
			id: r.id,
			sessionId: r.sessionId,
			sessionLabel: r.sessionLabel,
			cwd: r.cwd,
			...inspectionDisplay(r),
			kind: r.kind,
			command: r.command,
			risk: r.risk,
			tldr: r.tldr,
			recommendation: r.recommendation,
			reasons: r.reasons,
			model: r.model,
			createdAt: r.createdAt,
			expiresAt: r.expiresAt,
			parked: r.parked,
			...(r.intentProposal ? { intentProposal: r.intentProposal } : {}),
		};
	}

	/** @param {import('./types.mjs').Request} r */
	function result(r) {
		/** @type {import('./types.mjs').Resolution & {status: string}} */
		const out = { status: r.status };
		if (r.note) out.note = r.note;
		if (r.scope) out.scope = r.scope;
		if (r.intent) out.intent = r.intent;
		return out;
	}

	/** @param {import('./types.mjs').Request} r @param {string} status @param {import('./types.mjs').Resolution} [extra] */
	function resolveRequest(r, status, extra = {}) {
		if (!isPending(r)) return false;
		r.status = status;
		if (extra.note) r.note = extra.note;
		if (extra.scope) r.scope = extra.scope;
		if (extra.intent) r.intent = extra.intent;
		if (["approved", "denied", "redirected"].includes(status)) r.answeredAt = Date.now();
		clearTimeout(r.expiryTimer);
		for (const w of r.waiters) {
			clearTimeout(w.timer ?? undefined);
			sendJson(w.res, 200, result(r));
		}
		r.waiters.clear();
		broadcast("resolved", { id: r.id, status });
		setTimeout(() => requests.delete(r.id), KEEP_RESOLVED_MS).unref();
		return true;
	}

	/** @param {import('./types.mjs').Body} body */
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

		let intentProposal;
		if (body.intentProposal !== undefined) {
			if (body.kind !== "command" || body.risk === "critical")
				throw new HttpError(400, "intent is not supported for this request");
			intentProposal = normalizeIntent(body.intentProposal);
		}
		const ttl = Math.min(MAX_TTL_MS, Math.max(MIN_TTL_MS, body.ttlMs ?? DEFAULT_TTL_MS));
		const now = Date.now();
		/** @type {import('./types.mjs').Request} */
		const r = {
			id: crypto.randomUUID(),
			sessionId: clip(body.sessionId, 200),
			sessionLabel: clip(body.sessionLabel, 200),
			cwd: clip(body.cwd, 4096),
			...inspectionDisplay(body),
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
			parked: false,
			intentProposal,
			waiters: new Set(),
		};
		r.expiryTimer = setTimeout(() => {
			if (resolveRequest(r, "expired")) addHistory(historyFromRequest(r, "expired", "Timed out without an answer."));
		}, ttl);
		requests.set(r.id, r);
		const noViewer = sseClients.size === 0;
		broadcast("added", publicRequest(r));
		if (noViewer) openBrowser();
		return r;
	}

	/** @param {import('./types.mjs').Request} r @param {import('./types.mjs').Body} body */
	function decide(r, body) {
		if (!["approve", "deny", "redirect"].includes(body.decision)) throw new HttpError(400, "bad decision");
		if (body.note !== undefined && typeof body.note !== "string") throw new HttpError(400, "note must be a string");
		if (body.scope !== undefined && !["once", "session", "intent"].includes(body.scope))
			throw new HttpError(400, "bad scope");
		if (body.confirm !== undefined && typeof body.confirm !== "boolean")
			throw new HttpError(400, "confirm must be a boolean");
		if (!isPending(r)) throw new HttpError(409, "request is not pending");
		const scope = body.scope ?? "once";
		if (scope === "session" && r.kind !== "lockdown") throw new HttpError(400, "scope session is not supported");
		if (scope === "intent" && !r.intentProposal) throw new HttpError(400, "scope intent is not supported");
		const edited = body.intent === undefined ? undefined : normalizeIntent(body.intent);
		const note = body.note ? clip(body.decision === "redirect" ? body.note.trim() : body.note, 500) : undefined;
		if (body.decision === "redirect" && !note) throw new HttpError(400, "redirect needs a note");
		if (body.decision !== "approve") {
			const status = body.decision === "redirect" ? "redirected" : "denied";
			resolveRequest(r, status, { note, scope: "once" });
			addHistory(historyFromRequest(r, status, note, "browser"));
			return;
		}
		if (r.risk === "critical" && body.confirm !== true) throw new HttpError(400, "critical request needs confirm: true");
		resolveRequest(r, "approved", { note, scope, intent: scope === "intent" ? (edited ?? r.intentProposal) : undefined });
		addHistory(historyFromRequest(r, "approved", note, "browser"));
	}

	return { requests, pendingList, publicRequest, result, broadcast, resolveRequest, createRequest, decide, isPending };
}
