import assert from "node:assert/strict";
import http from "node:http";
import { test } from "node:test";
import { APPROVER, openSse, sleep, startServer } from "./helpers/approval-server.mjs";

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
			const p = fetch(`${s.base}/api/requests/${id}/wait?timeoutMs=20000`, {
				headers: { authorization: `Bearer ${s.state.sessionToken}` },
				signal: ctrl.signal,
			});
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
		assert.deepEqual(
			snap.pending.map((p) => p.id),
			[first],
		);

		const second = (await s.create({ tldr: "second", risk: "medium" })).json.id;
		const added = await events.next("added");
		assert.equal(added.id, second);
		assert.equal(added.tldr, "second");
		assert.deepEqual(Object.keys(added).sort(), [
			"command",
			"createdAt",
			"cwd",
			"expiresAt",
			"id",
			"kind",
			"model",
			"parked",
			"reasons",
			"recommendation",
			"risk",
			"sessionId",
			"sessionLabel",
			"tldr",
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
				{
					host: "127.0.0.1",
					port: s.state.port,
					path: "/api/requests",
					method: "POST",
					headers: { authorization: `Bearer ${s.state.sessionToken}`, "transfer-encoding": "chunked" },
				},
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

