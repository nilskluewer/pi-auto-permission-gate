import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { APPROVER, rawStatus, sleep, spawnServer, startServer, tmpRoot } from "./helpers/approval-server.mjs";

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
		const res = await fetch(`${s.base}/`);
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
		const asSession = await s.call("POST", `/api/requests/${created.id}/decision`, {
			approver: s.state.sessionToken,
			body: { decision: "approve" },
		});
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

test("health reports the server version, and shutdown replaces the server", async () => {
	const { approvalServerVersion } = await import("../src/approval-server/version.mjs");
	const s = await startServer();
	const health = await s.call("GET", "/api/health");
	assert.equal(health.json.version, approvalServerVersion());
	assert.equal((await s.call("POST", "/api/shutdown", { token: "wrong" })).status, 401);
	assert.equal(s.child.exitCode, null, "an unauthorized shutdown must not stop the server");
	assert.equal((await s.call("POST", "/api/shutdown")).status, 200);
	const { code } = await s.child.exited;
	assert.equal(code, 0);
	assert.equal(fs.existsSync(s.stateFile), false);
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

test("page contains the history tab UI", async () => {
	const s = await startServer();
	try {
		const html = await (await fetch(`${s.base}/`)).text();
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

