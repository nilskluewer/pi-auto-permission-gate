// Covers settings behavior.
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ALLOW, createHarness, HARD_DENY, run } from "./helpers/gate-harness.mjs";

test("dialog approval waits offer the same supported values as direct settings", async () => {
	const h = createHarness({
		hasUI: true,
		mode: "rpc",
		selectResponses: ["Approval wait - 300 seconds", "1800", "Cancel"],
	});
	await h.startSession();
	await h.commands.get("automode-settings").handler("", h.context);
	assert.deepEqual(h.selectCalls.find((call) => call.title === "Approval wait (seconds)").options, [
		"60",
		"120",
		"300",
		"600",
		"900",
		"1800",
		"Cancel",
	]);
	assert.equal(h.modeEntries().at(-1).data.approvalWaitSeconds, 1800);
});

test("registers only the settings, gate switch, and approvals commands", () => {
	const harness = createHarness();
	assert.deepEqual([...harness.commands.keys()], ["automode-settings", "permission-gate", "approvals"]);
});

test("central auto-mode settings command groups configuration", async () => {
	const harness = createHarness({ hasUI: true, editedPreferences: "- Prefer bounded changes" });
	const command = harness.commands.get("automode-settings");

	await harness.startSession();
	await command.handler("status", harness.context);
	assert.match(harness.notifications.at(-1).message, /Permission gate: ON/);

	await command.handler("preferences Prefer bounded changes", harness.context);
	assert.match(harness.notifications.at(-1).message, /preference note/);
	await command.handler("prompt", harness.context);
	assert.equal(harness.editorCalls.at(-1).title, "Auto-mode classifier prompt (close without saving)");
});

test("edits preference notes from the unified settings page", async () => {
	const globalPreferences = { current: "- Existing preference" };
	const harness = createHarness({
		hasUI: true,
		mode: "rpc",
		globalPreferences,
		editedPreferences: "- Edited preference",
		selectResponses: ["Classifier preferences - 1 note", "Edit preference notes", "Cancel"],
	});

	await harness.startSession();
	await harness.commands.get("automode-settings").handler("", harness.context);

	assert.equal(globalPreferences.current, "- Edited preference");
	assert.equal(harness.editorCalls.at(-1).title, "Edit auto-mode classifier preference notes");
	assert.equal(harness.editorCalls.at(-1).initialValue, "- Existing preference");
});

test("opens the unified settings entry point and exposes active command patterns", async () => {
	const harness = createHarness({
		hasUI: true,
		mode: "rpc",
		globalRules: {
			current: {
				allowedCommands: ["npm test*"],
				disallowedCommands: ["npm publish*"],
			},
		},
		editedRules: JSON.stringify({
			allowedCommands: ["npm test*", "uv run python*"],
			disallowedCommands: ["npm publish*"],
		}),
		selectResponses: ["Command rules - 1 allowed / 1 denied", "Allowed - npm test*", "Cancel"],
		ruleSaveChoice: "Apply to this session only",
	});

	await harness.startSession();
	await harness.commands.get("automode-settings").handler("", harness.context);

	assert.equal(harness.selectCalls[0].title, "Permission Gate Settings");
	assert.ok(harness.selectCalls[0].options.some((option) => option.startsWith("Command rules - 1 allowed / 1 denied")));
	assert.equal(harness.selectCalls[1].title, "Command rules (global)");
	assert.ok(harness.selectCalls[1].options.includes("Allowed - npm test*"));
	assert.ok(harness.selectCalls[1].options.includes("Denied - npm publish*"));
	assert.match(harness.notifications.at(-1).message, /session only/);
});

test("toggles the single gate from the unified settings page", async () => {
	const globalModeState = { current: { autoModeEnabled: false } };
	const harness = createHarness({
		hasUI: true,
		mode: "rpc",
		globalModeState,
		selectResponses: ["Permission gate - off", "on", "Cancel"],
	});

	await harness.startSession();
	await harness.commands.get("automode-settings").handler("", harness.context);

	assert.equal(globalModeState.current.autoModeEnabled, true);
	assert.deepEqual(
		harness.selectCalls.map((call) => call.title),
		[
			"Permission Gate Settings",
			"Permission gate. Off: no checks, classifier, or approvals.",
			"Permission Gate Settings",
		],
	);
	assert.match(harness.notifications.at(-1).message, /Permission gate: ON/);
});

test("turns the permission gate fully off from the unified settings page", async () => {
	const harness = createHarness({
		hasUI: true,
		mode: "rpc",
		selectResponses: ["Permission gate - on", "off", "Cancel"],
	});
	await harness.startSession();
	assert.equal((await harness.invoke(HARD_DENY))?.block, true);

	await harness.commands.get("automode-settings").handler("", harness.context);

	assert.equal(harness.selectCalls[0].options[0], "Permission gate - on");
	assert.equal(
		harness.selectCalls[0].options.some((option) => /Automatic safety decisions/.test(option)),
		false,
	);
	assert.equal(harness.selectCalls[2].options[0], "Permission gate - off");
	assert.equal(await harness.invoke(HARD_DENY), undefined);
	assert.equal(harness.statuses.get("permission-gate"), "permission gate: OFF");
});

test("opens the classifier prompt from the unified settings page", async () => {
	const globalPreferences = { current: "- Keep the prompt route covered." };
	const harness = createHarness({
		hasUI: true,
		mode: "rpc",
		globalPreferences,
		selectResponses: ["View classifier prompt", "Cancel"],
	});

	await harness.startSession();
	await harness.commands.get("automode-settings").handler("", harness.context);

	assert.equal(harness.editorCalls.at(-1).title, "Auto-mode classifier prompt (close without saving)");
	assert.match(harness.editorCalls.at(-1).initialValue, /Keep the prompt route covered/);
});

test("reports and resets command rules from the unified settings page", async () => {
	const globalRules = {
		current: {
			allowedCommands: ["npm test*"],
			disallowedCommands: ["npm publish*"],
		},
	};
	const harness = createHarness({
		hasUI: true,
		mode: "rpc",
		globalRules,
		selectResponses: [
			"Command rules - 1 allowed / 1 denied",
			"Show full rule report",
			"Cancel",
			"Command rules - 1 allowed / 1 denied",
			"Reset current rules",
			"Cancel",
		],
	});

	await harness.startSession();
	const command = harness.commands.get("automode-settings");
	await command.handler("", harness.context);

	const report = harness.notifications.find(({ message }) =>
		message.includes("Permission gate command rules (global)"),
	);
	assert.ok(report);
	assert.match(report.message, /npm test\*/);
	assert.match(report.message, /Hard-deny categories/);

	await command.handler("", harness.context);
	assert.deepEqual(globalRules.current, {
		allowedCommands: [
			"uv run pytest*",
			"rtk uv run pytest*",
			"uv run ruff check*",
			"rtk uv run ruff check*",
			"uv run mypy*",
			"rtk uv run mypy*",
		],
		disallowedCommands: [],
	});
	assert.match(harness.notifications.at(-1).message, /global command rules reset/);
});

test("central settings expose classifier selectors", async () => {
	const globalModeState = { current: undefined };
	const models = [
		{ provider: "github-copilot", id: "gpt-5.6-luna", name: "GPT-5.6 Luna", input: ["text"], reasoning: true },
		{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: true },
	];
	const harness = createHarness({
		hasUI: true,
		models,
		modelChoice: "vertex/gemini/flash - vertex - Gemini Flash",
		thinkingChoice: "medium - supported",
		globalModeState,
	});

	await harness.startSession();
	const command = harness.commands.get("automode-settings");
	assert.equal(command.description, "Open permission-gate settings or configure them directly");
	assert.deepEqual(
		command.getArgumentCompletions("model re").map((item) => item.value),
		["reset"],
	);
	assert.deepEqual(
		command.getArgumentCompletions("thinking ma").map((item) => item.value),
		["max"],
	);

	await command.handler("model", harness.context);
	assert.equal(harness.selectCalls[0].title, "Select the auto-mode classifier model:");
	assert.deepEqual(globalModeState.current.classifierModel, { provider: "vertex", id: "gemini/flash" });

	await command.handler("thinking", harness.context);
	assert.equal(harness.selectCalls[1].title, "Select the auto-mode classifier thinking level:");
	assert.equal(globalModeState.current.classifierThinkingLevel, "medium");
});

test("central settings support direct noninteractive model and thinking forms", async () => {
	const globalModeState = { current: undefined };
	const models = [{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: true }];
	const harness = createHarness({ hasUI: false, mode: "json", models, globalModeState });
	await harness.startSession();
	const command = harness.commands.get("automode-settings");

	await command.handler("model vertex/gemini/flash", harness.context);
	await command.handler("thinking medium", harness.context);
	assert.deepEqual(globalModeState.current.classifierModel, { provider: "vertex", id: "gemini/flash" });
	assert.equal(globalModeState.current.classifierThinkingLevel, "medium");
	assert.equal(harness.selectCalls.length, 0);

	const savedState = { ...globalModeState.current };
	await command.handler("model", harness.context);
	await command.handler("thinking", harness.context);
	assert.equal(harness.selectCalls.length, 0);
	assert.deepEqual(globalModeState.current, savedState);
});

test("configures context history messages via settings dialog and select completions", async () => {
	const globalModeState = { current: undefined };
	const harness = createHarness({
		hasUI: true,
		mode: "rpc",
		globalModeState,
		selectResponses: ["Context history messages - 12", "20 messages", "Cancel"],
	});

	await harness.startSession();
	const command = harness.commands.get("automode-settings");
	const completions = command.getArgumentCompletions("history ");
	assert.ok(completions.some((item) => item.value === "reset"));
	assert.ok(completions.some((item) => item.value === "20"));

	await command.handler("", harness.context);
	assert.equal(globalModeState.current.classifierHistoryMessages, 20);
});

// The specification, not the classifier's blanket allow, makes config writes and IAM critical.
test("new controls are reachable from the unified settings page", async () => {
	const state = { current: undefined };
	const h = createHarness({
		hasUI: true,
		mode: "rpc",
		globalModeState: state,
		selectResponses: [
			"Approval wait - 300 seconds",
			"900",
			"Session intent grants - 0 active",
			"Revoke all",
			"Close",
			"Cancel",
		],
	});
	await h.startSession();
	await h.commands.get("automode-settings").handler("", h.context);
	assert.equal(state.current.approvalWaitSeconds, 900);
	assert.ok(h.selectCalls[0].options.includes("Production patterns"));
	assert.ok(h.selectCalls[0].options.includes("Approval statistics (14 days)"));
	assert.match(h.selectCalls[3].title, /Session intent grants/);
});

test("wait and production settings persist, affect criticality, and statistics are available", async (t) => {
	const state = { current: undefined };
	const h = createHarness({ hasUI: true, choice: "Yes", classifierText: ALLOW, globalModeState: state });
	await h.startSession();
	const settings = h.commands.get("automode-settings");
	await settings.handler("wait 120", h.context);
	assert.equal(state.current.approvalWaitSeconds, 120);
	await settings.handler("wait 12", h.context);
	assert.equal(state.current.approvalWaitSeconds, 120);
	await settings.handler("production customer-*", h.context);
	assert.deepEqual(state.current.productionPatterns, ["customer-*"]);
	await h.startSession();
	await settings.handler("status", h.context);
	assert.match(h.notifications.at(-1).message, /approval wait: 120s/);
	await run(h, "gcloud storage rm gs://customer-dev/item");
	assert.equal(h.approvalRequests.length, 1, "configured production beats the dev marker");
	assert.match(h.selectCalls.at(-1).title, /Environment: production/);
	assert.match(h.approvalRequests[0].tldr, /Environment: production/);
	const agentDir = await mkdtemp(join(tmpdir(), "gate-statistics-"));
	t.after(() => rm(agentDir, { recursive: true, force: true }));
	const previous = process.env.PI_CODING_AGENT_DIR;
	process.env.PI_CODING_AGENT_DIR = agentDir;
	try {
		await settings.handler("statistics", h.context);
		assert.match(h.notifications.at(-1).message, /Approval fatigue summary/);
		assert.match(h.notifications.at(-1).message, /Decisions: 0/);
	} finally {
		if (previous === undefined) delete process.env.PI_CODING_AGENT_DIR;
		else process.env.PI_CODING_AGENT_DIR = previous;
	}
});
