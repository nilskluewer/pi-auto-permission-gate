// Covers switch behavior.
import assert from "node:assert/strict";
import test from "node:test";
import { createHarness, HARD_DENY } from "./helpers/gate-harness.mjs";

test("startOff (--no-permission-gate): the gate does nothing, also for hard-deny commands", async () => {
	const harness = createHarness({ hasUI: true, startOff: () => true });
	await harness.startSession();
	assert.equal(await harness.invoke(HARD_DENY), undefined);
	assert.equal(harness.classifierCalls.length, 0);
	assert.equal(harness.decisionEntries().length, 0);
	assert.equal(harness.statuses.get("permission-gate"), "permission gate: OFF");
	assert.equal(harness.notifications.filter((n) => n.level === "warning").length, 0);
});

test("/permission-gate off and on change the gate at runtime", async () => {
	const harness = createHarness({ hasUI: true });
	await harness.startSession();
	const gate = harness.commands.get("permission-gate");
	assert.equal((await harness.invoke(HARD_DENY))?.block, true);

	await gate.handler("off", harness.context);
	assert.equal(await harness.invoke(HARD_DENY), undefined);
	assert.equal(harness.statuses.get("permission-gate"), "permission gate: OFF");

	await harness.startSession({ type: "session_start", reason: "new" });
	assert.equal(await harness.invoke(HARD_DENY), undefined, "off stays off for the whole pi process");

	await gate.handler("on", harness.context);
	assert.equal((await harness.invoke(HARD_DENY))?.block, true);
	assert.equal(harness.statuses.get("permission-gate")?.startsWith("permission gate: ON"), true);
});

test("the default export registers --no-permission-gate", async () => {
	const { default: register, NO_GATE_FLAG } = await import("../src/index.ts");
	const flags = [];
	register({
		registerFlag: (name) => flags.push(name),
		getFlag: () => false,
		on() {},
		registerCommand() {},
		registerEntryRenderer() {},
	});
	assert.deepEqual(flags, ["no-permission-gate"]);
	assert.equal(NO_GATE_FLAG, "no-permission-gate");
});

test("--no-permission-gate or PI_PERMISSION_GATE=0 starts the gate off", async () => {
	const { startsOff, GATE_ENV } = await import("../src/index.ts");
	assert.equal(GATE_ENV, "PI_PERMISSION_GATE");
	assert.equal(startsOff(true, {}), true);
	assert.equal(startsOff(false, { PI_PERMISSION_GATE: "0" }), true);
	assert.equal(startsOff(false, {}), false);
	assert.equal(startsOff(false, { PI_PERMISSION_GATE: "1" }), false);
	assert.equal(startsOff(false, { PI_PERMISSION_GATE: "" }), false);
});

// Off bypasses every rule and cancels all remaining stages of an active review.
for (const commandName of ["permission-gate", "automode-settings"]) {
	test(`${commandName} off disables the full gate and shares persisted status`, async () => {
		const globalModeState = { current: undefined };
		const h = createHarness({
			hasUI: true,
			globalModeState,
			fastPass: true,
			globalRules: { current: { allowedCommands: [], disallowedCommands: ["git status"] } },
		});
		await h.startSession();
		await h.commands.get(commandName).handler("off", h.context);
		for (const command of [HARD_DENY.input.command, "git status", "npm run build"]) {
			assert.equal(await h.invoke({ toolName: "bash", input: { command } }), undefined);
		}
		assert.equal(h.classifierCalls.length, 0);
		assert.equal(h.decisionEntries().length, 0);
		assert.equal(h.approvalRequests.length, 0);
		assert.equal(globalModeState.current.autoModeEnabled, false);
		for (const name of ["permission-gate", "automode-settings"]) {
			await h.commands.get(name).handler("status", h.context);
			assert.match(h.notifications.at(-1).message, /Permission gate: OFF/);
		}
		const resumed = createHarness({ hasUI: true, globalModeState });
		await resumed.startSession();
		assert.equal(await resumed.invoke(HARD_DENY), undefined);
		await resumed.commands.get(commandName).handler("on", resumed.context);
		assert.equal(globalModeState.current.autoModeEnabled, true);
		assert.equal((await resumed.invoke(HARD_DENY)).block, true);
		assert.equal((await resumed.invoke({ toolName: "bash", input: { command: "npm run build" } })).block, true);
		assert.ok(resumed.classifierCalls.length > 0);
	});

	test(`${commandName} off cancels an active classifier without waiting or starting another pass`, async () => {
		let release, entered;
		const paused = new Promise((resolve) => {
			release = resolve;
		});
		const started = new Promise((resolve) => {
			entered = resolve;
		});
		const h = createHarness({
			hasUI: true,
			fastPass: true,
			beforeClassifier: async () => {
				entered();
				await paused;
			},
		});
		await h.startSession();
		const pending = h.invoke({ toolName: "bash", input: { command: "npm run build" } });
		await started;
		await h.commands.get(commandName).handler("off", h.context);
		assert.equal(h.classifierCalls[0].options.signal.aborted, true);
		const timeout = Symbol("timeout");
		const outcome = await Promise.race([pending, new Promise((resolve) => setTimeout(() => resolve(timeout), 100))]);
		release();
		assert.notEqual(outcome, timeout, "off releases the tool even if the provider ignores abort");
		assert.equal(outcome, undefined);
		await h.commands.get(commandName).handler("on", h.context);
		await new Promise((resolve) => setImmediate(resolve));
		assert.equal(h.classifierCalls.length, 1, "no deep pass or retry after off, even after re-enable");
		assert.equal(h.decisionEntries().length, 0);
		assert.equal(h.approvalRequests.length, 0);
		assert.equal(h.historyPosts.length, 0);
	});

	test(`${commandName} off cancels terminal and browser approvals`, async () => {
		let requested, late;
		const started = new Promise((resolve) => {
			requested = resolve;
		});
		const h = createHarness({
			hasUI: true,
			terminalWaits: true,
			approval: async (_request, signal, lifecycle) => {
				late = lifecycle.onLateOutcome;
				requested();
				return new Promise((resolve) =>
					signal.addEventListener("abort", () => resolve({ status: "cancelled" }), { once: true }),
				);
			},
		});
		await h.startSession();
		const pending = h.invoke({ toolName: "bash", input: { command: "npm run build" } });
		await started;
		await h.commands.get(commandName).handler("off", h.context);
		assert.equal(await pending, undefined);
		assert.equal(h.selectCalls.at(-1).signal.aborted, true);
		await h.commands.get(commandName).handler("on", h.context);
		late({ status: "approved" });
		assert.equal(h.messages.length, 0);
		assert.equal(h.decisionEntries().length, 0);
	});
}

test("startup flag overrides the switch without persisting and explicit toggles survive session changes", async () => {
	const globalModeState = { current: { autoModeEnabled: true } };
	const h = createHarness({ hasUI: true, globalModeState, startOff: () => true });
	await h.startSession();
	assert.equal(await h.invoke(HARD_DENY), undefined);
	assert.equal(globalModeState.current.autoModeEnabled, true);
	await h.startSession({ type: "session_start", reason: "new" });
	assert.equal(await h.invoke(HARD_DENY), undefined);
	await h.commands.get("permission-gate").handler("on", h.context);
	await h.startSession({ type: "session_start", reason: "new" });
	assert.equal((await h.invoke(HARD_DENY)).block, true);
	await h.commands.get("automode-settings").handler("off", h.context);
	assert.equal(globalModeState.current.autoModeEnabled, false);
});

test("off during provider auth does not start request auth or classification", async () => {
	let release,
		entered,
		requestAuthCalls = 0;
	const paused = new Promise((resolve) => {
		release = resolve;
	});
	const started = new Promise((resolve) => {
		entered = resolve;
	});
	const h = createHarness({ hasUI: true, fastPass: true });
	await h.startSession();
	h.context.modelRegistry.getProviderAuth = async () => {
		entered();
		await paused;
		return { auth: { apiKey: "test-token" }, env: {} };
	};
	h.context.modelRegistry.getApiKeyAndHeaders = async () => {
		requestAuthCalls++;
		return { ok: true };
	};
	const pending = h.invoke({ toolName: "bash", input: { command: "npm run build" } });
	await started;
	await h.commands.get("permission-gate").handler("off", h.context);
	release();
	assert.equal(await pending, undefined);
	await new Promise((resolve) => setImmediate(resolve));
	assert.equal(requestAuthCalls, 0);
	assert.equal(h.classifierCalls.length, 0);
});

test("session replacement cancels an ignored-abort provider without recording into the new session", async () => {
	let release, entered;
	const paused = new Promise((resolve) => {
		release = resolve;
	});
	const started = new Promise((resolve) => {
		entered = resolve;
	});
	const h = createHarness({
		hasUI: true,
		fastPass: true,
		beforeClassifier: async () => {
			entered();
			await paused;
		},
	});
	await h.startSession();
	const pending = h.invoke({ toolName: "bash", input: { command: "npm run build" } });
	await started;
	await h.startSession({ type: "session_start", reason: "new" });
	assert.equal((await pending).block, true);
	release();
	await new Promise((resolve) => setImmediate(resolve));
	assert.equal(h.classifierCalls.length, 1);
	assert.equal(h.decisionEntries().length, 0);
	assert.equal(h.historyPosts.length, 0);
});

test("off invalidates expired browser approvals, including after re-enable", async () => {
	let lifecycle;
	const h = createHarness({
		hasUI: true,
		terminalWaits: true,
		approvalWaitMs: 1,
		approval: async (_request, signal, callbacks) => {
			lifecycle = callbacks;
			return new Promise((resolve) =>
				signal.addEventListener("abort", () => resolve({ status: "cancelled" }), { once: true }),
			);
		},
	});
	await h.startSession();
	const event = { toolName: "bash", input: { command: "npm run build" } };
	assert.equal((await h.invoke(event)).block, true);
	assert.equal(lifecycle.parkSignal.aborted, true);
	await h.commands.get("permission-gate").handler("off", h.context);
	await h.commands.get("permission-gate").handler("on", h.context);
	const count = h.classifierCalls.length;
	lifecycle.onLateOutcome({ status: "approved" });
	assert.equal(h.messages.length, 0);
	assert.equal((await h.invoke(event)).block, true, "the expired approval cannot authorize a retry");
	assert.ok(h.classifierCalls.length > count);
});
