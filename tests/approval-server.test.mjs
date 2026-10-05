import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { fileURLToPath } from "node:url";

const SERVER = fileURLToPath(new URL("../extensions/approval-server.mjs", import.meta.url));
const APPROVER = "test-approver-token";
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "approval-server-test-"));
const children = new Set();

after(() => {
	for (const c of children) c.kill("SIGKILL");
	fs.rmSync(tmpRoot, { recursive: true, force: true });
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function entry(over = {}) {
	return {
		sessionId: "sess-1",
		sessionLabel: "demo",
		cwd: "/tmp/demo",
		command: "ls -la",
		risk: "low",
		tldr: "Lists files.",
		status: "approved",
		source: "auto",
		reasons: ["rule:ls"],
		...over,
	};
}

function spawnServer(stateFile, env = {}) {
	const child = spawn(process.execPath, [SERVER, stateFile], {
		env: { ...process.env, APPROVAL_NO_OPEN: "1", APPROVAL_TEST_APPROVER_TOKEN: APPROVER, ...env },
		stdio: ["ignore", "pipe", "pipe"],
	});
	children.add(child);
	child.stdoutText = "";
	child.stdout.on("data", (d) => (child.stdoutText += d));
	child.exited = new Promise((resolve) => child.on("exit", (code, signal) => resolve({ code, signal })));
	return child;
}

async function startServer(env, existingDir) {
	const dir = existingDir ?? fs.mkdtempSync(path.join(tmpRoot, "s-"));
	const stateFile = path.join(dir, "sub", "queue.json");
	const child = spawnServer(stateFile, env);
	let state;
	for (let i = 0; i < 100 && !state; i++) {
		try {
			state = JSON.parse(fs.readFileSync(stateFile, "utf8"));
		} catch {
			await sleep(50);
		}
	}
	assert.ok(state, "state file was written");
	const base = `http://127.0.0.1:${state.port}`;
	const s = {
		child,
		state,
		stateFile,
		base,
		async call(method, p, { token = state.sessionToken, approver, body, raw } = {}) {
			const headers = {};
			if (token) headers.authorization = `Bearer ${token}`;
			if (approver) headers["x-approver-token"] = approver;
			if (body !== undefined || raw !== undefined) headers["content-type"] = "application/json";
			const res = await fetch(base + p, { method, headers, body: raw ?? (body === undefined ? undefined : JSON.stringify(body)) });
			const text = await res.text();
			let json;
			try {
				json = JSON.parse(text);
			} catch {}
			return { status: res.status, json, headers: res.headers, text };
		},
		create(over = {}) {
			return s.call("POST", "/api/requests", {
				body: {
					sessionId: "sess-1",
					sessionLabel: "demo",
					cwd: "/tmp/demo",
					kind: "command",
					command: "ls -la",
					risk: "low",
					tldr: "Lists files.",
					recommendation: "approve",
					reasons: ["rule:ls"],
					...over,
				},
			});
		},
		decide(id, body) {
			return s.call("POST", `/api/requests/${id}/decision`, { token: null, approver: APPROVER, body });
		},
		dir,
		historyFile: path.join(dir, "sub", "approval-history.jsonl"),
		postHistory(over = {}) {
			return s.call("POST", "/api/history", { body: entry(over) });
		},
		getHistory(query = "") {
			return s.call("GET", `/api/history${query}`, { token: null, approver: APPROVER });
		},
		async stop() {
			child.kill("SIGTERM");
			await child.exited;
		},
	};
	return s;
}

// Reads server-sent events from a fetch response.
async function openSse(base, token) {
	const ctrl = new AbortController();
	const res = await fetch(`${base}/api/events?a=${token}`, { signal: ctrl.signal });
	assert.equal(res.status, 200);
	const reader = res.body.getReader();
	const dec = new TextDecoder();
	let buf = "";
	return {
		async next(name, timeoutMs = 3000) {
			const end = Date.now() + timeoutMs;
			for (;;) {
				const i = buf.indexOf("\n\n");
				if (i >= 0) {
					const block = buf.slice(0, i);
					buf = buf.slice(i + 2);
					const ev = /^event: (.+)$/m.exec(block)?.[1];
					const data = /^data: (.+)$/m.exec(block)?.[1];
					if (ev === name) return JSON.parse(data);
					continue;
				}
				const left = end - Date.now();
				if (left <= 0) throw new Error(`timeout waiting for SSE event ${name}`);
				const chunk = await Promise.race([reader.read(), sleep(left).then(() => null)]);
				if (!chunk) throw new Error(`timeout waiting for SSE event ${name}`);
				if (chunk.done) throw new Error("SSE closed");
				buf += dec.decode(chunk.value, { stream: true });
			}
		},
		close: () => ctrl.abort(),
	};
}

function rawStatus(port, host, extra = {}) {
	return new Promise((resolve, reject) => {
		const r = http.request({ host: "127.0.0.1", port, path: "/", headers: { host }, ...extra }, (rs) => {
			rs.resume();
			resolve(rs.statusCode);
		});
		r.on("error", reject);
		r.end();
	});
}

test("prints one line, writes state file with mode 0600 and no approver token", async () => {
	const s = await startServer();
	try {
		assert.match(s.child.stdoutText.trim(), /^approval-server listening on 127\.0\.0\.1:\d+$/);
		assert.equal(s.child.stdoutText.includes(APPROVER), false);
		const raw = fs.readFileSync(s.stateFile, "utf8");
		assert.equal(raw.includes(APPROVER), false);
		assert.deepEqual(Object.keys(JSON.parse(raw)).sort(), ["pid", "port", "sessionToken", "startedAt"]);
		assert.equal(fs.statSync(s.stateFile).mode & 0o777, 0o600);
		assert.equal(s.state.pid, s.child.pid);
	} finally {
		await s.stop();
	}
});

test("single instance: second start exits 0 and keeps the state file", async () => {
	const s = await startServer();
	try {
		const second = spawnServer(s.stateFile);
		const { code } = await second.exited;
		assert.equal(code, 0);
		assert.equal(second.stdoutText, "");
		assert.equal(JSON.parse(fs.readFileSync(s.stateFile, "utf8")).pid, s.child.pid);
		assert.equal((await s.call("GET", "/api/health")).status, 200);
	} finally {
		await s.stop();
	}
});

test("stale state file is overwritten", async () => {
	const dir = fs.mkdtempSync(path.join(tmpRoot, "stale-"));
	const stateFile = path.join(dir, "q.json");
	fs.writeFileSync(stateFile, JSON.stringify({ port: 1, pid: 2 ** 22 + 12345, sessionToken: "x", startedAt: 1 }));
	const child = spawnServer(stateFile);
	for (let i = 0; i < 100 && JSON.parse(fs.readFileSync(stateFile, "utf8")).pid !== child.pid; i++) await sleep(50);
	assert.equal(JSON.parse(fs.readFileSync(stateFile, "utf8")).pid, child.pid);
	child.kill("SIGTERM");
	await child.exited;
});

test("security headers on the page and host header check", async () => {
	const s = await startServer();
	try {
		const res = await fetch(s.base + "/");
		assert.equal(res.status, 200);
		const html = await res.text();
		assert.match(html, /Permission Gate/);
		assert.match(res.headers.get("content-security-policy"), /default-src 'none'; script-src 'unsafe-inline'/);
		assert.equal(res.headers.get("x-content-type-options"), "nosniff");
		assert.equal(res.headers.get("cache-control"), "no-store");
		assert.equal(res.headers.get("referrer-policy"), "no-referrer");
		assert.equal(html.includes(APPROVER), false);

		for (const host of ["evil.example.com", `evil.example.com:${s.state.port}`, "127.0.0.1"]) {
			assert.equal(await rawStatus(s.state.port, host), 403, host);
		}
		assert.equal(await rawStatus(s.state.port, `localhost:${s.state.port}`), 200);
	} finally {
		await s.stop();
	}
});

test("token separation", async () => {
	const s = await startServer();
	try {
		assert.equal((await s.call("GET", "/api/health")).status, 200);
		assert.equal((await s.call("GET", "/api/health", { token: null })).status, 401);
		assert.equal((await s.call("GET", "/api/health", { token: "nope" })).status, 401);
		// approver token on session endpoints
		assert.equal((await s.call("GET", "/api/health", { token: APPROVER })).status, 401);
		assert.equal((await s.call("POST", "/api/requests", { token: APPROVER, body: {} })).status, 401);
		// session token on approver endpoints
		const { json: created } = await s.create();
		const asSession = await s.call("POST", `/api/requests/${created.id}/decision`, { approver: s.state.sessionToken, body: { decision: "approve" } });
		assert.equal(asSession.status, 401);
		assert.equal((await fetch(`${s.base}/api/events?a=${s.state.sessionToken}`)).status, 401);
		assert.equal((await fetch(`${s.base}/api/events`)).status, 401);
		// bearer token alone is not approver auth
		const noHeader = await s.call("POST", `/api/requests/${created.id}/decision`, { body: { decision: "approve" } });
		assert.equal(noHeader.status, 401);
		// approver token does not work for wait or delete
		assert.equal((await s.call("GET", `/api/requests/${created.id}/wait`, { token: APPROVER })).status, 401);
		assert.equal((await s.call("DELETE", `/api/requests/${created.id}`, { token: APPROVER })).status, 401);
	} finally {
		await s.stop();
	}
});

test("create, wait times out as pending, approve resolves the wait", async () => {
	const s = await startServer();
	try {
		const created = await s.create();
		assert.equal(created.status, 200);
		const { id } = created.json;
		assert.match(id, /^[0-9a-f-]{36}$/);

		const t0 = Date.now();
		const pending = await s.call("GET", `/api/requests/${id}/wait?timeoutMs=300`);
		assert.deepEqual(pending.json, { status: "pending" });
		assert.ok(Date.now() - t0 >= 250);

		const waiting = s.call("GET", `/api/requests/${id}/wait?timeoutMs=5000`);
		const waiting2 = s.call("GET", `/api/requests/${id}/wait?timeoutMs=5000`);
		await sleep(100);
		const d = await s.decide(id, { decision: "approve", note: "go" });
		assert.equal(d.status, 200);
		assert.deepEqual((await waiting).json, { status: "approved", note: "go", scope: "once" });
		assert.deepEqual((await waiting2).json, { status: "approved", note: "go", scope: "once" });
		// late wait still gets the result
		assert.equal((await s.call("GET", `/api/requests/${id}/wait`)).json.status, "approved");
		// not pending any more
		assert.equal((await s.decide(id, { decision: "deny" })).status, 409);
		assert.equal((await s.decide("unknown-id", { decision: "deny" })).status, 404);
		assert.equal((await s.call("GET", "/api/requests/unknown-id/wait")).status, 404);
	} finally {
		await s.stop();
	}
});

test("deny with note", async () => {
	const s = await startServer();
	try {
		const { id } = (await s.create()).json;
		const waiting = s.call("GET", `/api/requests/${id}/wait?timeoutMs=5000`);
		assert.equal((await s.decide(id, { decision: "deny", note: "not now" })).status, 200);
		const r = (await waiting).json;
		assert.equal(r.status, "denied");
		assert.equal(r.note, "not now");
	} finally {
		await s.stop();
	}
});

test("input validation and limits", async () => {
	const s = await startServer();
	try {
		assert.equal((await s.create({ risk: "huge" })).status, 400);
		assert.equal((await s.create({ kind: "other" })).status, 400);
		assert.equal((await s.create({ reasons: "x" })).status, 400);
		assert.equal((await s.create({ command: 5 })).status, 400);
		assert.equal((await s.call("POST", "/api/requests", { raw: "{nope" })).status, 400);
		const { id } = (await s.create({ command: "x".repeat(9000), tldr: "t".repeat(900), ttlMs: 1 })).json;
		const events = await openSse(s.base, APPROVER);
		const snap = await events.next("snapshot");
		events.close();
		const r = snap.pending.find((p) => p.id === id);
		assert.equal(r.command.length, 8000);
		assert.equal(r.tldr.length, 600);
		assert.equal(r.expiresAt - r.createdAt, 100); // test minimum
		assert.equal("sessionToken" in r, false);
	} finally {
		await s.stop();
	}
});

test("critical approve needs confirm; scope rules", async () => {
	const s = await startServer();
	try {
		const crit = (await s.create({ risk: "critical", command: "rm -rf /tmp/demo-dir" })).json.id;
		assert.equal((await s.decide(crit, { decision: "approve" })).status, 400);
		assert.equal((await s.decide(crit, { decision: "approve", confirm: false })).status, 400);
		assert.equal((await s.decide(crit, { decision: "approve", confirm: true, scope: "session" })).status, 400);
		assert.equal((await s.call("GET", `/api/requests/${crit}/wait?timeoutMs=100`)).json.status, "pending");
		assert.equal((await s.decide(crit, { decision: "approve", confirm: true })).status, 200);
		assert.equal((await s.call("GET", `/api/requests/${crit}/wait`)).json.status, "approved");

		// deny never needs confirm
		const crit2 = (await s.create({ risk: "critical" })).json.id;
		assert.equal((await s.decide(crit2, { decision: "deny" })).status, 200);

		// scope session: not for normal commands
		const cmd = (await s.create()).json.id;
		assert.equal((await s.decide(cmd, { decision: "approve", scope: "session" })).status, 400);
		assert.equal((await s.decide(cmd, { decision: "approve", scope: "bogus" })).status, 400);
		assert.equal((await s.decide(cmd, { decision: "approve", scope: "once" })).status, 200);

		// lockdown allows scope session
		const lock = (await s.create({ kind: "lockdown", risk: "medium" })).json.id;
		const waiting = s.call("GET", `/api/requests/${lock}/wait?timeoutMs=5000`);
		assert.equal((await s.decide(lock, { decision: "approve", scope: "session" })).status, 200);
		assert.deepEqual((await waiting).json, { status: "approved", scope: "session" });
	} finally {
		await s.stop();
	}
});

test("DELETE cancels and resolves the waiter", async () => {
	const s = await startServer();
	try {
		const { id } = (await s.create()).json;
		const waiting = s.call("GET", `/api/requests/${id}/wait?timeoutMs=5000`);
		await sleep(100);
		const del = await s.call("DELETE", `/api/requests/${id}`);
		assert.equal(del.status, 200);
		assert.deepEqual(del.json, { ok: true });
		assert.deepEqual((await waiting).json, { status: "cancelled" });
		assert.equal((await s.call("GET", `/api/requests/${id}/wait`)).json.status, "cancelled");
		assert.equal((await s.decide(id, { decision: "approve" })).status, 409);
		assert.equal((await s.call("DELETE", "/api/requests/unknown")).status, 404);
	} finally {
		await s.stop();
	}
});

test("TTL expiry notifies waiters", async () => {
	const s = await startServer();
	try {
		const { id } = (await s.create({ ttlMs: 300 })).json;
		const t0 = Date.now();
		const r = await s.call("GET", `/api/requests/${id}/wait?timeoutMs=5000`);
		assert.deepEqual(r.json, { status: "expired" });
		assert.ok(Date.now() - t0 < 3000);
		assert.equal((await s.decide(id, { decision: "approve" })).status, 409);
	} finally {
		await s.stop();
	}
});

test("client disconnect during wait does not break the server", async () => {
	const s = await startServer();
	try {
		const { id } = (await s.create()).json;
		for (let i = 0; i < 5; i++) {
			const ctrl = new AbortController();
			const p = fetch(`${s.base}/api/requests/${id}/wait?timeoutMs=20000`, { headers: { authorization: `Bearer ${s.state.sessionToken}` }, signal: ctrl.signal });
			await sleep(50);
			ctrl.abort();
			await p.catch(() => {});
		}
		await sleep(100);
		assert.equal((await s.decide(id, { decision: "deny" })).status, 200);
	} finally {
		await s.stop();
	}
});

test("SSE: snapshot, added, resolved", async () => {
	const s = await startServer();
	try {
		const first = (await s.create({ tldr: "first" })).json.id;
		const events = await openSse(s.base, APPROVER);
		const snap = await events.next("snapshot");
		assert.deepEqual(snap.pending.map((p) => p.id), [first]);

		const second = (await s.create({ tldr: "second", risk: "medium" })).json.id;
		const added = await events.next("added");
		assert.equal(added.id, second);
		assert.equal(added.tldr, "second");
		assert.deepEqual(Object.keys(added).sort(), [
			"command", "createdAt", "cwd", "expiresAt", "id", "kind", "model", "reasons", "recommendation", "risk", "sessionId", "sessionLabel", "tldr",
		]);

		await s.decide(first, { decision: "deny" });
		assert.deepEqual(await events.next("resolved"), { id: first, status: "denied" });
		await s.call("DELETE", `/api/requests/${second}`);
		assert.deepEqual(await events.next("resolved"), { id: second, status: "cancelled" });
		events.close();
	} finally {
		await s.stop();
	}
});

test("body too large returns 413", async () => {
	const s = await startServer();
	try {
		const big = await s.call("POST", "/api/requests", { raw: JSON.stringify({ command: "x".repeat(70 * 1024) }) });
		assert.equal(big.status, 413);
		// chunked body without content-length
		const status = await new Promise((resolve, reject) => {
			const r = http.request(
				{ host: "127.0.0.1", port: s.state.port, path: "/api/requests", method: "POST", headers: { authorization: `Bearer ${s.state.sessionToken}`, "transfer-encoding": "chunked" } },
				(rs) => {
					rs.resume();
					resolve(rs.statusCode);
				},
			);
			r.on("error", reject);
			r.write("x".repeat(40 * 1024));
			r.write("x".repeat(40 * 1024));
			r.end();
		});
		assert.equal(status, 413);
		assert.equal((await s.call("GET", "/api/health")).status, 200);
	} finally {
		await s.stop();
	}
});

test("state file is removed on SIGTERM", async () => {
	const s = await startServer();
	assert.ok(fs.existsSync(s.stateFile));
	s.child.kill("SIGTERM");
	const { code } = await s.child.exited;
	assert.equal(code, 0);
	assert.equal(fs.existsSync(s.stateFile), false);
});

test("idle exit removes the state file", async () => {
	const s = await startServer({ APPROVAL_IDLE_MS: "300" });
	const { code } = await s.child.exited;
	assert.equal(code, 0);
	assert.equal(fs.existsSync(s.stateFile), false);
});

// ---------- history ----------

test("history: POST validation", async () => {
	const s = await startServer();
	try {
		for (const bad of [
			{ risk: "huge" },
			{ status: "cancelled" },
			{ source: "robot" },
			{ via: "phone" },
			{ reasons: "x" },
			{ reasons: [1] },
			{ command: 5 },
			{ model: 5 },
			{ note: 5 },
			{ ts: "yesterday" },
		]) {
			assert.equal((await s.postHistory(bad)).status, 400, JSON.stringify(bad));
		}
		assert.equal((await s.call("POST", "/api/history", { raw: "{nope" })).status, 400);
		const ok = await s.postHistory({ command: "x".repeat(9000), tldr: "t".repeat(900), model: "m", note: "n", via: "terminal", source: "human", status: "denied" });
		assert.equal(ok.status, 200);
		assert.match(ok.json.id, /^[0-9a-f-]{36}$/);
		const h = (await s.getHistory()).json.history;
		assert.equal(h.length, 1);
		assert.equal(h[0].id, ok.json.id);
		assert.equal(h[0].command.length, 8000);
		assert.equal(h[0].tldr.length, 600);
		assert.equal(h[0].via, "terminal");
		assert.equal(h[0].model, "m");
		assert.equal(h[0].note, "n");
		assert.ok(Math.abs(h[0].ts - Date.now()) < 5000);
	} finally {
		await s.stop();
	}
});

test("history: ts is kept only inside the last 24 hours", async () => {
	const s = await startServer();
	try {
		const recent = Date.now() - 3 * 3600 * 1000;
		await s.postHistory({ ts: recent, tldr: "recent" });
		await s.postHistory({ ts: Date.now() - 3 * 24 * 3600 * 1000, tldr: "old" });
		const h = (await s.getHistory()).json.history; // newest first
		assert.equal(h[1].tldr, "recent");
		assert.equal(h[1].ts, recent);
		assert.equal(h[0].tldr, "old");
		assert.ok(Date.now() - h[0].ts < 5000);
	} finally {
		await s.stop();
	}
});

test("history: persists across restart (newest first, limit, bad lines ignored)", async () => {
	const dir = fs.mkdtempSync(path.join(tmpRoot, "persist-"));
	const s1 = await startServer({}, dir);
	for (let i = 0; i < 5; i++) await s1.postHistory({ tldr: `entry ${i}` });
	assert.equal(fs.statSync(s1.historyFile).mode & 0o777, 0o600);
	await s1.stop();
	fs.appendFileSync(s1.historyFile, "this is not json\n{\"id\":1}\n");

	const s2 = await startServer({}, dir);
	try {
		const h = (await s2.getHistory()).json.history;
		assert.deepEqual(h.map((e) => e.tldr), ["entry 4", "entry 3", "entry 2", "entry 1", "entry 0"]);
		assert.equal((await s2.getHistory("?limit=2")).json.history.length, 2);
		assert.equal((await s2.getHistory("?limit=99999")).json.history.length, 5);
		assert.equal((await s2.getHistory("?limit=abc")).json.history.length, 5);
	} finally {
		await s2.stop();
	}
});

test("history: browser decisions and expiry are recorded, cancel is not", async () => {
	const s = await startServer();
	try {
		const a = (await s.create({ tldr: "approve me", model: "mod" })).json.id;
		const d = (await s.create({ tldr: "deny me" })).json.id;
		const c = (await s.create({ tldr: "cancel me" })).json.id;
		const x = (await s.create({ tldr: "expire me", ttlMs: 300 })).json.id;
		await s.decide(a, { decision: "approve", note: "ok" });
		await s.decide(d, { decision: "deny", note: "no" });
		await s.call("DELETE", `/api/requests/${c}`);
		assert.equal((await s.call("GET", `/api/requests/${x}/wait?timeoutMs=5000`)).json.status, "expired");

		const h = (await s.getHistory()).json.history;
		assert.deepEqual(h.map((e) => e.tldr), ["expire me", "deny me", "approve me"]);
		const [expired, denied, approved] = h;
		assert.equal(approved.status, "approved");
		assert.equal(approved.source, "human");
		assert.equal(approved.via, "browser");
		assert.equal(approved.note, "ok");
		assert.equal(approved.model, "mod");
		assert.equal(denied.status, "denied");
		assert.equal(denied.note, "no");
		assert.equal(expired.status, "denied");
		assert.equal(expired.source, "human");
		assert.equal(expired.note, "Timed out without an answer.");
		assert.equal(expired.command, "ls -la");
		// a failed decision (critical without confirm) is not recorded
		const crit = (await s.create({ risk: "critical" })).json.id;
		assert.equal((await s.decide(crit, { decision: "approve" })).status, 400);
		assert.equal((await s.getHistory()).json.history.length, 3);
	} finally {
		await s.stop();
	}
});

test("history: SSE snapshot contains history and a history event arrives live", async () => {
	const s = await startServer();
	try {
		await s.postHistory({ tldr: "first" });
		await s.postHistory({ tldr: "second" });
		const events = await openSse(s.base, APPROVER);
		const snap = await events.next("snapshot");
		assert.deepEqual(snap.pending, []);
		assert.deepEqual(snap.history.map((e) => e.tldr), ["second", "first"]);

		const posted = await s.postHistory({ tldr: "third", source: "rule", status: "denied" });
		const live = await events.next("history");
		assert.equal(live.id, posted.json.id);
		assert.equal(live.tldr, "third");
		assert.equal(live.source, "rule");

		const id = (await s.create({ tldr: "queue" })).json.id;
		await events.next("added");
		await s.decide(id, { decision: "deny" });
		assert.deepEqual(await events.next("resolved"), { id, status: "denied" });
		assert.equal((await events.next("history")).tldr, "queue");
		events.close();
	} finally {
		await s.stop();
	}
});

test("history: snapshot is limited to 200 entries", async () => {
	const dir = fs.mkdtempSync(path.join(tmpRoot, "seed-"));
	fs.mkdirSync(path.join(dir, "sub"), { recursive: true });
	const seedFile = path.join(dir, "sub", "approval-history.jsonl");
	const lines = [];
	for (let i = 0; i < 205; i++) lines.push(JSON.stringify({ id: `id${i}`, ts: Date.now() - (205 - i) * 1000, ...entry({ tldr: `e${i}`, status: "approved", source: "auto" }) }));
	fs.writeFileSync(seedFile, lines.join("\n") + "\n");
	const s = await startServer({}, dir);
	try {
		const events = await openSse(s.base, APPROVER);
		const snap = await events.next("snapshot");
		events.close();
		assert.equal(snap.history.length, 200);
		assert.equal(snap.history[0].tldr, "e204");
		assert.equal((await s.getHistory("?limit=500")).json.history.length, 205);
	} finally {
		await s.stop();
	}
});

test("history: token separation", async () => {
	const s = await startServer();
	try {
		assert.equal((await s.call("POST", "/api/history", { token: null, body: entry() })).status, 401);
		assert.equal((await s.call("POST", "/api/history", { token: APPROVER, body: entry() })).status, 401);
		assert.equal((await s.call("POST", "/api/history", { token: null, approver: APPROVER, body: entry() })).status, 401);
		// session token cannot read history
		assert.equal((await s.call("GET", "/api/history")).status, 401);
		assert.equal((await s.call("GET", "/api/history", { token: null, approver: s.state.sessionToken })).status, 401);
		assert.equal((await s.call("GET", "/api/history", { token: null })).status, 401);
		assert.equal((await s.getHistory()).status, 200);
	} finally {
		await s.stop();
	}
});

test("history: rate guard answers 429 after 200 posts in 10 s", async () => {
	const s = await startServer();
	try {
		const statuses = [];
		for (let i = 0; i < 205; i++) statuses.push((await s.postHistory({ tldr: `r${i}` })).status);
		assert.equal(statuses.filter((x) => x === 200).length, 200);
		assert.equal(statuses.filter((x) => x === 429).length, 5);
		// other endpoints are not affected
		assert.equal((await s.create()).status, 200);
	} finally {
		await s.stop();
	}
});

test("history: file is rotated and the memory ring is limited", async () => {
	const s = await startServer({ APPROVAL_HISTORY_MAX_LINES: "10", APPROVAL_HISTORY_KEEP: "4" });
	try {
		for (let i = 0; i < 11; i++) await s.postHistory({ tldr: `n${i}` });
		// the 11th line passes the limit and triggers a rewrite with the last 4
		const lines = fs.readFileSync(s.historyFile, "utf8").split("\n").filter(Boolean);
		assert.equal(lines.length, 4);
		assert.deepEqual(lines.map((l) => JSON.parse(l).tldr), ["n7", "n8", "n9", "n10"]);
		assert.equal(fs.statSync(s.historyFile).mode & 0o777, 0o600);
		assert.equal(fs.readdirSync(path.dirname(s.historyFile)).some((f) => f.endsWith(".tmp")), false);
		await s.postHistory({ tldr: "n11" });
		const h = (await s.getHistory()).json.history;
		assert.deepEqual(h.map((e) => e.tldr), ["n11", "n10", "n9", "n8"]);
	} finally {
		await s.stop();
	}
});

test("history: posting does not need a browser and counts as activity", async () => {
	// APPROVAL_NO_OPEN=1 is set for all tests. This test checks the idle timer only.
	const s = await startServer({ APPROVAL_IDLE_MS: "1200" });
	for (let i = 0; i < 4; i++) {
		await sleep(400);
		assert.equal((await s.postHistory()).status, 200);
	}
	assert.equal(s.child.exitCode, null, "server still runs while history posts arrive");
	const { code } = await s.child.exited;
	assert.equal(code, 0);
});

test("page contains the history tab UI", async () => {
	const s = await startServer();
	try {
		const html = await (await fetch(s.base + "/")).text();
		for (const needle of ['role="tablist"', 'role="tabpanel"', "History (0)", "No decisions yet", "Showing 0 of 0"]) {
			assert.ok(html.includes(needle), needle);
		}
	} finally {
		await s.stop();
	}
});

test("open: needs the session token and answers 200 (no browser in tests)", async () => {
	const s = await startServer();
	try {
		assert.equal((await s.call("POST", "/api/open", { token: null })).status, 401);
		assert.equal((await s.call("POST", "/api/open", { token: null, approver: APPROVER })).status, 401);
		assert.equal((await s.call("POST", "/api/open")).status, 200);
	} finally {
		await s.stop();
	}
});
