import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { after } from "node:test";
import { fileURLToPath } from "node:url";

const SERVER = fileURLToPath(new URL("../../src/approval-server/server.mjs", import.meta.url));
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
			const res = await fetch(base + p, {
				method,
				headers,
				body: raw ?? (body === undefined ? undefined : JSON.stringify(body)),
			});
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

// Contract oracle: reject silent redirects, lost intent edits, resolved parking, and expiry-as-denial.
const intentProposal = {
	label: "read via cat in /tmp/demo/",
	access: "read",
	reasons: ["rule:ls"],
	targets: ["exec:cat", "path:/tmp/demo/"],
};


export { SERVER, APPROVER, tmpRoot, sleep, entry, spawnServer, startServer, openSse, rawStatus, intentProposal };
