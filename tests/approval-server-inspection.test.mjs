import assert from "node:assert/strict";
import fs from "node:fs";
import { test } from "node:test";
import { APPROVER, openSse, startServer } from "./helpers/approval-server.mjs";

test("inspection metadata survives queue and history without persisting source contents", async () => {
	const s = await startServer();
	try {
		const paths = [
			{ path: "/project/scripts/cleanup.py", role: "script", inspected: true, unresolved: false },
			{ path: "/project/scripts/helper.py", role: "local dependency", inspected: true, unresolved: false },
			{ path: "$OUT/report.json", role: "output target", inspected: false, unresolved: true },
		];
		const pathNotes = ["One output path depends on the environment."];
		const cwd = `/project/${"long-directory/".repeat(20)}`;
		const created = await s.create({
			cwd,
			paths,
			pathNotes,
			files: [{ path: "cleanup.py", content: "SOURCE-MUST-NOT-PERSIST" }],
			fingerprints: { secret: "SOURCE-MUST-NOT-PERSIST" },
		});
		assert.equal(created.status, 200);
		const events = await openSse(s.base, APPROVER);
		const pending = await events.next("snapshot");
		events.close();
		const request = pending.pending.find((r) => r.id === created.json.id);
		assert.deepEqual(request.paths, paths);
		assert.deepEqual(request.pathNotes, pathNotes);
		assert.equal(request.cwd, cwd);
		assert.doesNotMatch(JSON.stringify(request), /SOURCE-MUST-NOT-PERSIST/);
		assert.equal((await s.decide(created.json.id, { decision: "approve" })).status, 200);
		const history = (await s.getHistory()).json.history[0];
		assert.deepEqual(history.paths, paths);
		assert.deepEqual(history.pathNotes, pathNotes);
		assert.equal(history.cwd, cwd);
		assert.doesNotMatch(fs.readFileSync(s.historyFile, "utf8"), /SOURCE-MUST-NOT-PERSIST/);
	} finally {
		await s.stop();
	}
});

test("inspection metadata validates types and limits rather than silently dropping paths", async () => {
	const s = await startServer();
	try {
		for (const over of [
			{ paths: "not an array" },
			{ paths: Array.from({ length: 257 }, () => ({ path: "/x", role: "input" })) },
			{ paths: [{ path: "/x", role: "input", inspected: "yes" }] },
			{ paths: [{ path: "/x", role: "input", unresolved: 1 }] },
			{ paths: [{ path: 4, role: "input" }] },
			{ paths: [{ path: "x".repeat(4097), role: "input" }] },
			{ pathNotes: "not an array" },
			{ pathNotes: [42] },
			{ pathNotes: Array(65).fill("note") },
		])
			assert.equal((await s.create(over)).status, 400, JSON.stringify(over).slice(0, 100));
		const legacy = await s.create();
		assert.equal(legacy.status, 200, "old clients remain supported");
		assert.equal((await s.postHistory({ paths: [{ path: "/x", role: "input", inspected: "yes" }] })).status, 400);
	} finally {
		await s.stop();
	}
});

test("inspection metadata persists across server restart and history posts", async () => {
	const s = await startServer();
	const metadata = {
		paths: [{ path: "/project/main.py", role: "script", inspected: true, unresolved: false }],
		pathNotes: [],
	};
	await s.postHistory(metadata);
	await s.stop();
	const restarted = await startServer(undefined, s.dir);
	try {
		const history = (await restarted.getHistory()).json.history[0];
		assert.deepEqual(history.paths, metadata.paths);
		assert.deepEqual(history.pathNotes, []);
	} finally {
		await restarted.stop();
	}
});

test("page provides native collapsible paths, project, and execution summary labels", async () => {
	const s = await startServer();
	try {
		const html = await (await fetch(`${s.base}/`)).text();
		for (const label of [
			"Execution summary",
			"Files and paths",
			"Unresolved paths",
			"Code inspected",
			"Static references only",
			"Project",
		])
			assert.ok(html.includes(label), label);
		assert.ok(html.includes('h("details", "path-details")'));
		assert.ok(html.includes('h("summary"'));
		assert.ok(!html.includes("innerHTML ="), "path metadata must not be injected as HTML");
	} finally {
		await s.stop();
	}
});
