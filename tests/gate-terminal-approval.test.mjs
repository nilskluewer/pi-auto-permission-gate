// Exercises the real terminal approval component through the gate's event hooks.
import assert from "node:assert/strict";
import test from "node:test";
import { autoState, createHarness, DENY, run } from "./helpers/gate-harness.mjs";
import { createTerminalUI } from "./helpers/terminal-ui.mjs";

function terminalHarness(options = {}) {
	const h = createHarness({ hasUI: true, mode: "tui", globalModeState: autoState(), classifierText: DENY, ...options });
	const ui = createTerminalUI();
	h.context.ui.custom = ui.custom;
	return { h, ui };
}

test("terminal approval wins the browser race and cancels its request", async () => {
	let browserSignal;
	const { h, ui } = terminalHarness({
		approval: (_request, signal) => {
			browserSignal = signal;
			return new Promise((resolve) => signal.addEventListener("abort", () => resolve({ status: "cancelled" })));
		},
	});
	await h.startSession();
	const result = run(h, "git reset --hard HEAD~1");
	const component = await ui.ready;
	component.handleInput("\x1b[B");
	component.handleInput("\r");
	assert.equal(await result, undefined);
	assert.equal(browserSignal.aborted, true);
	assert.equal(ui.completions, 1);
	assert.equal(h.decisionEntries().at(-1).data.status, "approved");
});

test("a browser answer closes expanded terminal details without authorizing a second answer", async () => {
	let answer;
	const { h, ui } = terminalHarness({
		approval: () =>
			new Promise((resolve) => {
				answer = resolve;
			}),
	});
	await h.startSession();
	const result = run(h, "git reset --hard HEAD~1");
	const component = await ui.ready;
	component.handleInput("\x1b[A");
	component.handleInput("\x1b[A");
	component.handleInput("\r");
	assert.match(component.render(100).join("\n"), /▾ Files and paths/);
	answer({ status: "denied" });
	assert.equal((await result).block, true);
	assert.equal(ui.completions, 1);
	assert.equal(h.decisionEntries().at(-1).data.status, "blocked");
});

test("terminal expiry closes the component and remains a non-approval", async () => {
	const { h, ui } = terminalHarness({ approvalWaitMs: 20 });
	await h.startSession();
	const result = run(h, "git reset --hard HEAD~1");
	await ui.ready;
	assert.equal((await result).block, true);
	assert.equal(ui.completions, 1);
	assert.equal(h.decisionEntries().at(-1).data.status, "expired");
});

for (const cancel of ["gate off", "session shutdown", "outer abort"]) {
	test(`${cancel} closes terminal approval and preserves the existing cancellation result`, async () => {
		const { h, ui } = terminalHarness();
		await h.startSession();
		const ctrl = new AbortController();
		h.context.signal = ctrl.signal;
		const result = run(h, "git reset --hard HEAD~1");
		await ui.ready;
		if (cancel === "gate off") await h.commands.get("permission-gate").handler("off", h.context);
		else if (cancel === "session shutdown") await h.handlers.get("session_shutdown")({}, h.context);
		else ctrl.abort();
		if (cancel === "gate off") assert.equal(await result, undefined);
		else assert.equal((await result).block, true);
		assert.equal(ui.completions, 1);
	});
}

test("terminal redirect preserves the instruction instead of approving the command", async () => {
	const { h, ui } = terminalHarness({ inputValue: "Use a new feature branch instead." });
	await h.startSession();
	const result = run(h, "git reset --hard HEAD~1");
	const component = await ui.ready;
	component.handleInput("\x1b[B");
	component.handleInput("\x1b[B");
	component.handleInput("\x1b[B");
	component.handleInput("\r");
	const outcome = await result;
	assert.equal(outcome.block, true);
	assert.match(outcome.reason, /Use a new feature branch instead/);
	assert.equal(h.decisionEntries().at(-1).data.status, "redirected");
});
