import { DAY_MS, HISTORY_RATE_LIMIT, HISTORY_RATE_WINDOW_MS, HISTORY_SNAPSHOT, MAX_WAIT_MS } from "./config.mjs";
import { HttpError, readJson, SECURITY_HEADERS, sendJson, tokenOk } from "./http.mjs";

/**
 * @param {import('./types.mjs').Runtime} runtime
 * @param {import('./types.mjs').Queue} queue
 * @param {import('./types.mjs').HistoryStore} historyStore
 * @param {Set<import('node:http').ServerResponse>} sseClients
 * @param {(force?: boolean) => void} openBrowser
 * @param {string} sessionToken
 * @param {string} approverToken
 * @param {string} page
 * @param {string} version
 * @param {(code?: number) => void} shutdown
 */
export function createRouter(
	runtime,
	queue,
	historyStore,
	sseClients,
	openBrowser,
	sessionToken,
	approverToken,
	page,
	version,
	shutdown,
) {
	const { requests, pendingList, publicRequest, result, broadcast, resolveRequest, createRequest, decide, isPending } =
		queue;
	const { history, newestFirst, normalizeEntry, rewriteHistoryFile, addHistory } = historyStore;
	/** @type {number[]} */
	let historyCalls = [];
	/** @param {import('node:http').IncomingMessage} _req @param {import('node:http').ServerResponse} res @param {URL} url @param {import('./types.mjs').Request} r */
	function handleWait(_req, res, url, r) {
		if (!isPending(r)) return sendJson(res, 200, result(r));
		const asked = Number(url.searchParams.get("timeoutMs"));
		const timeout = Math.min(
			MAX_WAIT_MS,
			Number.isFinite(asked) && asked >= 0 && url.searchParams.has("timeoutMs") ? asked : 25_000,
		);
		/** @type {import('./types.mjs').Waiter} */
		const waiter = { res, timer: null };
		waiter.timer = setTimeout(() => {
			r.waiters.delete(waiter);
			sendJson(res, 200, { status: "pending" });
		}, timeout);
		r.waiters.add(waiter);
		res.on("close", () => {
			clearTimeout(waiter.timer ?? undefined);
			r.waiters.delete(waiter);
		});
	}

	/** @param {import('node:http').IncomingMessage} _req @param {import('node:http').ServerResponse} res */
	function handleEvents(_req, res) {
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

	/** @param {import('node:http').IncomingMessage} req @param {import('node:http').ServerResponse} res */
	async function route(req, res) {
		const host = req.headers.host;
		if (host !== `127.0.0.1:${runtime.port}` && host !== `localhost:${runtime.port}`)
			return sendJson(res, 403, { error: "forbidden host" });
		runtime.lastActivity = Date.now();
		const url = new URL(/** @type {string} */ (req.url), "http://127.0.0.1");
		const p = url.pathname;
		const method = req.method;

		if (method === "GET" && p === "/") {
			res.writeHead(200, PAGE_HEADERS);
			return res.end(page);
		}

		const sessionAuth = () => {
			const m = /^Bearer (.+)$/.exec(req.headers.authorization || "");
			if (!m || !tokenOk(m[1], sessionToken)) throw new HttpError(401, "unauthorized");
		};
		/** @param {unknown} given */
		const approverAuth = (given) => {
			if (!tokenOk(given, approverToken)) throw new HttpError(401, "unauthorized");
		};

		if (method === "GET" && p === "/api/health") {
			sessionAuth();
			return sendJson(res, 200, { ok: true, version });
		}
		if (method === "POST" && p === "/api/shutdown") {
			// A gate with newer code replaces this server. Tell open tabs, then exit.
			sessionAuth();
			broadcast("replaced", {});
			sendJson(res, 200, { ok: true });
			setTimeout(() => shutdown(0), 100).unref();
			return;
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
			if (body.ts !== undefined && !(typeof body.ts === "number" && Number.isFinite(body.ts)))
				throw new HttpError(400, "ts must be a number");
			const fields = normalizeEntry(body);
			const ts = body.ts !== undefined && body.ts >= now - DAY_MS && body.ts <= now + 60_000 ? body.ts : now;
			if (body.id !== undefined) {
				const index = history.findIndex((entry) => entry.id === body.id && entry.sessionId === fields.sessionId);
				if (index < 0) throw new HttpError(404, "history entry not found for this session");
				const entry = { id: history[index].id, ts, ...fields };
				history[index] = entry;
				try {
					rewriteHistoryFile();
				} catch {}
				broadcast("history", entry);
				return sendJson(res, 200, { id: entry.id });
			}
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
		const m = /^\/api\/requests\/([^/]+)(\/wait|\/decision|\/park)?$/.exec(p);
		if (m) {
			const [, id, sub] = m;
			if (method === "GET" && sub === "/wait") {
				sessionAuth();
				const r = requests.get(id);
				if (!r) throw new HttpError(404, "unknown request");
				return handleWait(req, res, url, r);
			}
			if (method === "POST" && sub === "/park") {
				sessionAuth();
				const r = requests.get(id);
				if (!r) throw new HttpError(404, "unknown request");
				if (!isPending(r)) throw new HttpError(409, "request is not pending");
				r.parked = true;
				broadcast("parked", { id });
				return sendJson(res, 200, { ok: true });
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

	return route;
}
