// Covers approval outcomes behavior.
import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { ALLOW, autoState, createHarness, DENY, run, scriptProject } from "./helpers/gate-harness.mjs";

test("decisions are reported to the browser history, except browser answers the server logs itself", async () => {
	const auto = createHarness({
		hasUI: true,
		fastPass: true,
		globalModeState: autoState(),
		classifierSequence: [{ text: ALLOW }],
	});
	await auto.startSession();
	await run(auto, "git reset --hard HEAD~1");
	assert.equal(auto.historyPosts.length, 1);
	assert.deepEqual(
		{ status: auto.historyPosts[0].status, source: auto.historyPosts[0].source, risk: auto.historyPosts[0].risk },
		{ status: "approved", source: "auto", risk: "low" },
	);
	assert.equal(auto.historyPosts[0].tldr, "Routine project work.");
	assert.equal(auto.historyPosts[0].sessionLabel, "project");
	assert.deepEqual(auto.historyPosts[0].reasons, ["git reset hard"]);

	const hard = createHarness({ hasUI: true, globalModeState: autoState() });
	await hard.startSession();
	await run(hard, "rm -rf /");
	assert.deepEqual(
		{ status: hard.historyPosts[0].status, source: hard.historyPosts[0].source, risk: hard.historyPosts[0].risk },
		{ status: "denied", source: "hard-deny", risk: "critical" },
	);

	const terminal = createHarness({ hasUI: true, choice: "Yes", globalModeState: autoState(), classifierText: DENY });
	await terminal.startSession();
	await run(terminal, "git reset --hard HEAD~1");
	assert.deepEqual(
		{
			status: terminal.historyPosts[0].status,
			source: terminal.historyPosts[0].source,
			via: terminal.historyPosts[0].via,
		},
		{ status: "approved", source: "human", via: "terminal" },
	);

	const browser = createHarness({
		hasUI: true,
		terminalWaits: true,
		globalModeState: autoState(),
		classifierText: DENY,
		approval: async () => ({ status: "approved" }),
	});
	await browser.startSession();
	await run(browser, "git reset --hard HEAD~1");
	assert.equal(browser.historyPosts.length, 0);

	const headless = createHarness({ hasUI: false, globalModeState: autoState(), classifierText: ALLOW });
	await headless.startSession();
	await run(headless, "git reset --hard HEAD~1");
	assert.equal(headless.historyPosts.length, 0);
});

// Spec: absence and steering are not denials. Repeated outcomes must not cause lockdown.
test("short waits expire without lockdown and a late answer is exact and single-use", async (t) => {
	const dir = await scriptProject(t);
	const callbacks = [];
	const requests = [];
	const h = createHarness({
		hasUI: true,
		terminalWaits: true,
		approvalWaitMs: 2,
		now: () => 12345,
		approval: async (r, _s, lifecycle) => {
			requests.push(r);
			callbacks.push(lifecycle);
			return new Promise(() => {});
		},
	});
	h.context.cwd = dir;
	await h.startSession();
	for (let i = 0; i < 4; i++) {
		const result = await run(h, "python main.py");
		assert.equal(result.block, true);
		assert.match(result.reason, /user is away/i);
		const entry = h.decisionEntries().at(-1).data;
		assert.equal(entry.status, "expired");
		assert.equal(entry.shownAt, 12345);
		assert.equal(entry.answeredAt, undefined);
		assert.equal(h.historyPosts.at(-1).status, "expired");
		assert.equal(h.historyPosts.at(-1).answeredAt, undefined);
		assert.equal(h.selectCalls.at(-1).signal.aborted, true, "short wait cancels the terminal dialog");
	}
	assert.equal(await run(h, "pwd"), undefined, "expiry must not enter lockdown");
	assert.equal(requests[0].ttlMs, 2 + 10 * 60 * 1000, "the browser request stays open 10 minutes after the wait");
	callbacks[0].onLateOutcome({ status: "approved" });
	assert.equal(h.messages.length, 1);
	assert.deepEqual(h.messages[0].options, { triggerTurn: true, deliverAs: "followUp" });
	assert.equal(
		(await run(h, "python  main.py")).block,
		true,
		"same snapshot does not authorize a different command string",
	);
	assert.equal(await run(h, "python main.py"), undefined);
	assert.equal(h.decisionEntries().at(-1).data.note, "late approval");
	assert.equal(h.decisionEntries().at(-1).data.recommendation, "deny");
	assert.equal(h.decisionEntries().at(-1).data.shownAt, 12345);
	assert.equal(h.decisionEntries().at(-1).data.answeredAt, 12345);
	assert.equal((await run(h, "python main.py")).block, true, "late approval is single-use");
	callbacks[1].onLateOutcome({ status: "approved" });
	await writeFile(join(dir, "main.py"), "print('changed after late answer')\n");
	assert.equal((await run(h, "python main.py")).block, true, "changed script must prompt again");
});

test("redirect returns the instruction without retry notice or lockdown, with measurement", async () => {
	const h = createHarness({
		hasUI: true,
		terminalWaits: true,
		approval: async () => ({ status: "redirected", note: "Use uv instead" }),
		now: () => 900,
	});
	await h.startSession();
	for (let i = 0; i < 4; i++) {
		const result = await run(h, "python3 -c 'print(1)'");
		assert.match(result.reason, /The user redirected you: Use uv instead/);
		assert.doesNotMatch(result.reason, /Do not retry/);
		const entry = h.decisionEntries().at(-1).data;
		assert.equal(entry.status, "redirected");
		assert.equal(entry.recommendation, "deny");
		assert.equal(entry.shownAt, 900);
		assert.equal(entry.answeredAt, 900);
		assert.equal(entry.scope, "once");
		assert.equal(entry.note, "Use uv instead");
	}
	assert.equal(await run(h, "pwd"), undefined);
});

test("terminal redirect rejects empty input, can be cancelled, and preserves steering", async () => {
	const h = createHarness({ hasUI: true, selectResponses: ["Redirect…", "Redirect…"], inputValue: "" });
	let inputs = 0;
	h.context.ui.input = async () => (++inputs === 1 ? "  " : "Use uv");
	await h.startSession();
	const result = await run(h, "python3 -c 'print(1)'");
	assert.equal(inputs, 2);
	assert.match(result.reason, /The user redirected you: Use uv/);
	assert.doesNotMatch(result.reason, /Do not retry/);
	assert.equal(h.decisionEntries().at(-1).data.status, "redirected");
	const cancelled = createHarness({ hasUI: true, choice: "Redirect…" });
	await cancelled.startSession();
	assert.equal((await run(cancelled, "python3 -c 'print(1)'")).block, true);
	assert.equal(cancelled.decisionEntries().at(-1).data.status, "blocked");
});

test("empty browser redirects fail closed instead of returning an empty instruction", async () => {
	const h = createHarness({
		hasUI: true,
		terminalWaits: true,
		approval: async () => ({ status: "redirected", note: " " }),
	});
	await h.startSession();
	const result = await run(h, "python3 -c 'print(1)'");
	assert.match(result.reason, /Redirect needs an instruction/);
	assert.equal(h.decisionEntries().at(-1).data.status, "blocked");
});

test("terminal-only expiry cannot promise a late answer", async () => {
	const previous = process.env.PI_PERMISSION_GATE_BROWSER;
	process.env.PI_PERMISSION_GATE_BROWSER = "0";
	try {
		const h = createHarness({ hasUI: true, browserDisabled: true, terminalWaits: true, approvalWaitMs: 1 });
		await h.startSession();
		const result = await run(h, "python3 -c 'print(1)'");
		assert.match(result.reason, /late answers are not possible/);
		assert.equal(h.decisionEntries().at(-1).data.status, "expired");
		const unreachable = createHarness({ hasUI: true, terminalWaits: true, approvalWaitMs: 1 });
		await unreachable.startSession();
		assert.match((await run(unreachable, "python3 -c 'print(1)'")).reason, /late answers are not possible/);
	} finally {
		if (previous === undefined) delete process.env.PI_PERMISSION_GATE_BROWSER;
		else process.env.PI_PERMISSION_GATE_BROWSER = previous;
	}
});

test("late redirects and denials are delivered once, but not after session replacement", async () => {
	const callbacks = [];
	const h = createHarness({
		hasUI: true,
		terminalWaits: true,
		approvalWaitMs: 1,
		approval: async (_r, _s, lifecycle) => {
			callbacks.push(lifecycle);
			return new Promise(() => {});
		},
	});
	await h.startSession();
	for (let i = 0; i < 3; i++) await run(h, "python3 -c 'print(1)'");
	assert.equal(callbacks[0].parkSignal.aborted, true);
	callbacks[0].onLateOutcome({ status: "redirected", note: "Use uv" });
	callbacks[0].onLateOutcome({ status: "redirected", note: "Use uv" });
	callbacks[1].onLateOutcome({ status: "denied" });
	assert.equal(h.messages.length, 2);
	assert.match(h.messages[0].message.content, /redirected you: Use uv/);
	assert.match(h.messages[1].message.content, /user denied/i);
	await h.startSession({ type: "session_start", reason: "switch" });
	callbacks[2].onLateOutcome({ status: "approved" });
	assert.equal(h.messages.length, 2);
	assert.equal((await run(h, "python3 -c 'print(1)'")).block, true);
});

test("history maps new terminal outcomes and grant decisions; old entries still render", async (t) => {
	const dir = await scriptProject(t);
	const h = createHarness({ hasUI: true, choice: "Yes", now: () => 77 });
	h.context.cwd = dir;
	await h.startSession();
	await run(h, "python main.py");
	const once = h.historyPosts.at(-1);
	assert.equal(once.recommendation, "deny");
	assert.equal(once.shownAt, 77);
	assert.equal(once.answeredAt, 77);
	assert.equal(once.scope, "once");
	h.context.ui.select = async (_title, options) =>
		options.find((option) => option.startsWith("Yes, for this session:"));
	await run(h, "python main.py");
	await run(h, "python main.py");
	assert.equal(h.historyPosts.at(-1).source, "grant");
	assert.ok(h.historyPosts.at(-1).grantId);
	h.context.ui.select = async () => "Redirect…";
	h.context.ui.input = async () => "Use uv";
	await run(h, "uv run python main.py");
	assert.equal(h.historyPosts.at(-1).status, "redirected");
	assert.equal(h.historyPosts.at(-1).note, "Use uv");
	const renderer = h.renderers.get("permission-gate-decision");
	const theme = { fg: (_color, text) => text, bold: (text) => text };
	const old = renderer(
		{ data: { command: "echo old", status: "approved", source: "human" } },
		{ expanded: true },
		theme,
	);
	assert.match(old.render(120).join("\n"), /APPROVED/);
	assert.doesNotMatch(old.render(120).join("\n"), /undefined/);
	const fresh = renderer({ data: h.decisionEntries().at(-1).data }, { expanded: true }, theme);
	assert.match(fresh.render(120).join("\n"), /REDIRECTED/);
	assert.match(fresh.render(120).join("\n"), /Recommended: deny · Scope: once · Answered after \d+\.\d s/);
	assert.match(fresh.render(120).join("\n"), /Note: Use uv/);
});

test("browser history is reconciled with the validated grant scope and grant ID", async () => {
	const h = createHarness({
		hasUI: true,
		terminalWaits: true,
		now: () => 101,
		approval: async () => ({ status: "approved", scope: "intent", historyId: "queue-request-id" }),
	});
	await h.startSession();
	await run(h, "python3 -c 'print(1)'");
	assert.equal(h.historyPosts.length, 1);
	assert.equal(h.historyPosts[0].id, "queue-request-id");
	assert.equal(h.historyPosts[0].grantId, h.decisionEntries().at(-1).data.grantId);
	assert.equal(h.historyPosts[0].scope, "intent");
	assert.equal(h.historyPosts[0].shownAt, 101);
	assert.equal(h.historyPosts[0].answeredAt, 101);
});
