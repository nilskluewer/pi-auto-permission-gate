import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { APPROVER, entry, openSse, sleep, startServer, tmpRoot } from "./helpers/approval-server.mjs";

test("history: POST validation", async () => {
	const s = await startServer();
	try {
		for (const bad of [
			{ risk: "huge" },
			{ via: "phone" },
			{ reasons: "x" },
			{ reasons: [1] },
			{ command: 5 },
			{ model: 5 },
			{ ts: "yesterday" },
		]) {
			assert.equal((await s.postHistory(bad)).status, 400, JSON.stringify(bad));
		}
		assert.equal((await s.call("POST", "/api/history", { raw: "{nope" })).status, 400);
		const ok = await s.postHistory({
			command: "x".repeat(9000),
			tldr: "t".repeat(900),
			model: "m",
			note: "n",
			via: "terminal",
			source: "human",
			status: "denied",
		});
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
	fs.appendFileSync(s1.historyFile, 'this is not json\n{"id":1}\n');

	const s2 = await startServer({}, dir);
	try {
		const h = (await s2.getHistory()).json.history;
		assert.deepEqual(
			h.map((e) => e.tldr),
			["entry 4", "entry 3", "entry 2", "entry 1", "entry 0"],
		);
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
		assert.deepEqual(
			h.map((e) => e.tldr),
			["expire me", "deny me", "approve me"],
		);
		const [expired, denied, approved] = h;
		assert.equal(approved.status, "approved");
		assert.equal(approved.source, "human");
		assert.equal(approved.via, "browser");
		assert.equal(approved.note, "ok");
		assert.equal(approved.model, "mod");
		assert.equal(denied.status, "denied");
		assert.equal(denied.note, "no");
		assert.equal(expired.status, "expired");
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
		assert.deepEqual(
			snap.history.map((e) => e.tldr),
			["second", "first"],
		);

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
	for (let i = 0; i < 205; i++)
		lines.push(
			JSON.stringify({
				id: `id${i}`,
				ts: Date.now() - (205 - i) * 1000,
				...entry({ tldr: `e${i}`, status: "approved", source: "auto" }),
			}),
		);
	fs.writeFileSync(seedFile, `${lines.join("\n")}\n`);
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
		assert.equal(
			(await s.call("POST", "/api/history", { token: null, approver: APPROVER, body: entry() })).status,
			401,
		);
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
		assert.deepEqual(
			lines.map((l) => JSON.parse(l).tldr),
			["n7", "n8", "n9", "n10"],
		);
		assert.equal(fs.statSync(s.historyFile).mode & 0o777, 0o600);
		assert.equal(
			fs.readdirSync(path.dirname(s.historyFile)).some((f) => f.endsWith(".tmp")),
			false,
		);
		await s.postHistory({ tldr: "n11" });
		const h = (await s.getHistory()).json.history;
		assert.deepEqual(
			h.map((e) => e.tldr),
			["n11", "n10", "n9", "n8"],
		);
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
