import assert from "node:assert/strict";
import { test } from "node:test";
import { APPROVER, intentProposal, openSse, startServer } from "./helpers/approval-server.mjs";

test("redirect requires a trimmed note and delivers steering plus history", async () => {
	const s = await startServer();
	try {
		const { id } = (await s.create()).json;
		for (const note of [undefined, "", "  \n\t"]) {
			const rejected = await s.decide(id, { decision: "redirect", note });
			assert.equal(rejected.status, 400);
			assert.equal(rejected.json.error, "redirect needs a note");
		}
		assert.equal((await s.getHistory()).json.history.length, 0);
		const waiting = s.call("GET", `/api/requests/${id}/wait?timeoutMs=5000`);
		assert.equal((await s.decide(id, { decision: "redirect", note: "  Use uv instead.  " })).status, 200);
		assert.deepEqual((await waiting).json, { status: "redirected", note: "Use uv instead.", scope: "once" });
		const history = (await s.getHistory()).json.history[0];
		assert.equal(history.status, "redirected");
		assert.equal(history.note, "Use uv instead.");
		assert.equal(history.scope, "once");
		assert.equal(history.recommendation, "approve");
		assert.ok(history.answeredAt >= history.shownAt);
	} finally {
		await s.stop();
	}
});

test("intent is command-only and non-critical, validates shape and clips display bounds", async () => {
	const s = await startServer();
	try {
		for (const over of [{ risk: "critical" }, { kind: "lockdown" }]) {
			assert.equal((await s.create({ ...over, intentProposal })).status, 400);
		}
		for (const bad of [
			null,
			[],
			{},
			{ ...intentProposal, access: "execute" },
			{ ...intentProposal, label: 1 },
			{ ...intentProposal, reasons: [1] },
			{ ...intentProposal, targets: [null] },
		]) {
			assert.equal((await s.create({ intentProposal: bad })).status, 400, JSON.stringify(bad));
		}
		const long = {
			...intentProposal,
			label: "l".repeat(200),
			targets: ["p".repeat(4100), ...Array(33).fill("path:/tmp/")],
			reasons: Array(22).fill("reason"),
		};
		const created = await s.create({ intentProposal: long });
		assert.equal(created.status, 200);
		const events = await openSse(s.base, APPROVER);
		try {
			const request = (await events.next("snapshot")).pending[0];
			assert.equal(request.parked, false);
			assert.equal(request.intentProposal.label.length, 160);
			assert.equal(request.intentProposal.targets.length, 32);
			assert.equal(request.intentProposal.targets[0].length, 4096);
			assert.equal(request.intentProposal.reasons.length, 20);
		} finally {
			events.close();
		}
	} finally {
		await s.stop();
	}
});

test("intent decisions preserve default and edited payloads without semantic narrowing", async () => {
	const s = await startServer();
	try {
		const plain = (await s.create()).json.id;
		assert.equal((await s.decide(plain, { decision: "approve", scope: "intent" })).status, 400);
		for (const edited of [
			undefined,
			{ ...intentProposal, label: "Custom intent", access: "write", targets: ["path:/tmp/elsewhere/"] },
		]) {
			const { id } = (await s.create({ intentProposal })).json;
			assert.equal(
				(await s.decide(id, { decision: "approve", scope: "intent", intent: { ...intentProposal, targets: [4] } }))
					.status,
				400,
			);
			assert.equal((await s.decide(id, { decision: "approve", scope: "session" })).status, 400);
			assert.equal((await s.decide(id, { decision: "approve", scope: "intent", intent: edited })).status, 200);
			assert.deepEqual((await s.call("GET", `/api/requests/${id}/wait`)).json, {
				status: "approved",
				scope: "intent",
				intent: edited ?? intentProposal,
			});
			assert.equal((await s.getHistory()).json.history[0].scope, "intent");
		}
	} finally {
		await s.stop();
	}
});

test("parking is session-authenticated, stays pending, broadcasts and delivers late approval", async () => {
	const s = await startServer();
	let events;
	try {
		events = await openSse(s.base, APPROVER);
		await events.next("snapshot");
		const { id } = (await s.create({ intentProposal })).json;
		const added = await events.next("added");
		assert.deepEqual(added.intentProposal, intentProposal);
		assert.equal(added.parked, false);
		const park = `/api/requests/${id}/park`;
		assert.equal((await s.call("POST", park, { token: null, approver: APPROVER })).status, 401);
		assert.equal((await s.call("POST", "/api/requests/missing/park")).status, 404);
		assert.equal((await s.call("POST", park)).status, 200);
		assert.deepEqual(await events.next("parked"), { id });
		assert.deepEqual((await s.call("GET", `/api/requests/${id}/wait?timeoutMs=0`)).json, { status: "pending" });
		const snapshot = await openSse(s.base, APPROVER);
		try {
			assert.equal((await snapshot.next("snapshot")).pending[0].parked, true);
		} finally {
			snapshot.close();
		}
		const waiting = s.call("GET", `/api/requests/${id}/wait?timeoutMs=5000`);
		await s.decide(id, { decision: "approve" });
		assert.deepEqual((await waiting).json, { status: "approved", scope: "once" });
		assert.equal((await s.call("POST", park)).status, 409);
		assert.equal((await s.getHistory()).json.history.length, 1);
	} finally {
		events?.close();
		await s.stop();
	}
});

test("parked requests still expire and history distinguishes no answer", async () => {
	const s = await startServer();
	try {
		const { id } = (await s.create({ ttlMs: 200 })).json;
		assert.equal((await s.call("POST", `/api/requests/${id}/park`)).status, 200);
		assert.equal((await s.call("GET", `/api/requests/${id}/wait?timeoutMs=5000`)).json.status, "expired");
		const history = (await s.getHistory()).json.history[0];
		assert.equal(history.status, "expired");
		assert.equal(history.note, "Timed out without an answer.");
		assert.equal(history.answeredAt, undefined);
		assert.equal(typeof history.shownAt, "number");
	} finally {
		await s.stop();
	}
});

test("history keeps fatigue metadata and drops unknown optional values across restart", async () => {
	const s = await startServer();
	try {
		const metadata = {
			status: "redirected",
			source: "grant",
			recommendation: "review",
			scope: "intent",
			grantId: "g".repeat(110),
			note: "n".repeat(510),
			shownAt: 123,
			answeredAt: 456,
		};
		assert.equal((await s.postHistory(metadata)).status, 200);
		assert.equal(
			(
				await s.postHistory({
					status: "cancelled",
					source: "robot",
					note: 5,
					recommendation: "bogus",
					scope: "forever",
					grantId: 7,
					shownAt: "123",
					answeredAt: null,
				})
			).status,
			200,
		);
		const entries = (await s.getHistory()).json.history;
		for (const key of ["status", "source", "note", "recommendation", "scope", "grantId", "shownAt", "answeredAt"])
			assert.equal(entries[0][key], undefined, key);
		assert.equal(entries[1].grantId.length, 100);
		assert.equal(entries[1].note.length, 500);
		await s.stop();
		const restarted = await startServer(undefined, s.dir);
		try {
			const saved = (await restarted.getHistory()).json.history[1];
			assert.deepEqual(saved, entries[1]);
		} finally {
			await restarted.stop();
		}
	} finally {
		await s.stop();
	}
});

test("page provides intent editing, redirect, parking, and distinct history states", async () => {
	const s = await startServer();
	try {
		const html = await (await fetch(`${s.base}/`)).text();
		for (const label of [
			"Approve once",
			"Approve for session…",
			"Redirect…",
			"Intent targets (one per line)",
			"Agent stopped waiting — your answer is still delivered",
			"Redirected",
			"Expired",
		])
			assert.ok(html.includes(label), label);
		assert.ok(html.includes("es.addEventListener('parked'"));
	} finally {
		await s.stop();
	}
});

