// Covers classifier state behavior.
import assert from "node:assert/strict";
import test from "node:test";
import { createHarness } from "./helpers/gate-harness.mjs";

test("loads persisted auto-mode state with default classifier settings", async () => {
	const globalModeState = { current: { autoModeEnabled: true } };
	const harness = createHarness({
		hasUI: true,
		classifierText: '{"decision":"allow","rationale":"The explicit test command is safe."}',
		globalModeState,
	});

	await harness.startSession();
	const result = await harness.invoke({
		toolName: "bash",
		input: { command: "git reset --hard HEAD~1" },
	});

	assert.equal(result, undefined);
	assert.equal(
		harness.statuses.get("permission-gate"),
		"permission gate: ON (github-copilot/gpt-6-luna, thinking high)",
	);
	assert.deepEqual(globalModeState.current, { autoModeEnabled: true });
});

test("preserves malformed classifier state without default substitution", async () => {
	const globalModeState = {
		current: {
			autoModeEnabled: false,
			classifierModel: { provider: "", id: "" },
			classifierThinkingLevel: "not-a-level",
		},
	};
	const harness = createHarness({ hasUI: true, globalModeState });

	await harness.startSession();
	assert.equal(harness.statuses.get("permission-gate"), "permission gate: OFF");
	await harness.commands.get("automode-settings").handler("status", harness.context);
	assert.match(harness.notifications.at(-1).message, /Permission gate: OFF/);
	assert.match(harness.notifications.at(-1).message, /unavailable classifier model/);
	assert.doesNotMatch(harness.notifications.at(-1).message, /github-copilot\/gpt-6-luna/);
	assert.deepEqual(globalModeState.current, {
		autoModeEnabled: false,
		classifierModel: { provider: "", id: "" },
		classifierThinkingLevel: "not-a-level",
	});

	await harness.commands.get("automode-settings").handler("on", harness.context);
	assert.equal(globalModeState.current.classifierModel, null);
	assert.equal(globalModeState.current.classifierThinkingLevel, "high");
	const result = await harness.invoke({ toolName: "bash", input: { command: "git reset --hard HEAD~1" } });
	assert.equal(result.block, true);
	assert.match(harness.selectCalls.at(-1).title, /unavailable classifier model/);
	assert.equal(harness.classifierCalls.length, 0);
});

test("keeps the global auto-mode state across new sessions, forks, reloads, and tree navigation", async () => {
	const globalModeState = { current: undefined };
	const firstSession = createHarness({ hasUI: true, globalModeState });

	await firstSession.startSession({ type: "session_start", reason: "startup" });
	assert.equal(
		firstSession.statuses.get("permission-gate"),
		"permission gate: ON (github-copilot/gpt-6-luna, thinking high)",
	);

	const nextSession = createHarness({ hasUI: true, globalModeState });
	await nextSession.startSession({ type: "session_start", reason: "fork" });
	assert.equal(
		nextSession.statuses.get("permission-gate"),
		"permission gate: ON (github-copilot/gpt-6-luna, thinking high)",
	);

	await nextSession.startSession({ type: "session_start", reason: "reload" });
	nextSession.handlers.get("session_tree")({}, nextSession.context);
	assert.equal(
		nextSession.statuses.get("permission-gate"),
		"permission gate: ON (github-copilot/gpt-6-luna, thinking high)",
	);

	await nextSession.commands.get("automode-settings").handler("off", nextSession.context);
	const resumedSession = createHarness({ hasUI: true, globalModeState });
	await resumedSession.startSession({ type: "session_start", reason: "resume" });
	assert.equal(resumedSession.statuses.get("permission-gate"), "permission gate: OFF");
});

test("automode toggles and reports its state", async () => {
	const harness = createHarness({ hasUI: true });
	const command = harness.commands.get("automode-settings");

	await command.handler("on", harness.context);
	assert.equal(harness.notifications.at(-1).message.includes("enabled"), true);
	assert.deepEqual(harness.modeEntries()[0].data, {
		autoModeEnabled: true,
		classifierModel: { provider: "github-copilot", id: "gpt-6-luna" },
		classifierThinkingLevel: "high",
		classifierHistoryMessages: 12,
		approvalWaitSeconds: 300,
		productionPatterns: ["prod", "prd", "production"],
	});

	await command.handler("status", harness.context);
	assert.match(harness.notifications.at(-1).message, /Permission gate: ON/);

	await command.handler("off", harness.context);
	assert.match(harness.notifications.at(-1).message, /Permission gate: OFF/);
	assert.equal(harness.statuses.get("permission-gate"), "permission gate: OFF");
});

test("configures, reports, validates, persists, and resets classifier thinking", async () => {
	const globalModeState = { current: undefined };
	const harness = createHarness({
		hasUI: true,
		globalModeState,
		classifierText: '{"decision":"allow","rationale":"The configured classifier level was applied."}',
	});
	const command = harness.commands.get("automode-settings");
	harness.context.thinkingLevel = "medium";

	await harness.startSession();
	await command.handler("thinking max", harness.context);
	assert.equal(harness.context.thinkingLevel, "medium");
	assert.equal(globalModeState.current.classifierThinkingLevel, "max");
	assert.equal(harness.modeEntries().at(-1).data.classifierThinkingLevel, "max");
	assert.match(harness.notifications.at(-1).message, /thinking max -> high/);
	assert.equal(
		harness.statuses.get("permission-gate"),
		"permission gate: ON (github-copilot/gpt-6-luna, thinking max -> high)",
	);

	const persistedAfterSet = { ...globalModeState.current };
	await command.handler("status", harness.context);
	assert.match(harness.notifications.at(-1).message, /thinking max -> high/);
	assert.deepEqual(globalModeState.current, persistedAfterSet);

	await command.handler("thinking invalid", harness.context);
	assert.match(harness.notifications.at(-1).message, /Usage: \/automode-settings thinking/);
	assert.deepEqual(globalModeState.current, persistedAfterSet);
	await command.handler("thinking low extra", harness.context);
	assert.match(harness.notifications.at(-1).message, /Usage: \/automode-settings thinking/);
	assert.deepEqual(globalModeState.current, persistedAfterSet);

	await command.handler("thinking reset", harness.context);
	assert.equal(globalModeState.current.classifierThinkingLevel, "high");
	assert.equal(harness.modeEntries().at(-1).data.classifierThinkingLevel, "high");
	assert.match(harness.notifications.at(-1).message, /thinking high/);
});

test("clamps classifier thinking using Pi's supported-level ordering", async () => {
	const classify = async (model, configuredLevel) => {
		const globalModeState = {
			current: {
				autoModeEnabled: true,
				classifierModel: { provider: model.provider, id: model.id },
				classifierThinkingLevel: configuredLevel,
			},
		};
		const harness = createHarness({
			hasUI: false,
			models: [model],
			globalModeState,
			classifierText: '{"decision":"allow","rationale":"The clamped level was accepted."}',
		});
		await harness.startSession();
		const result = await harness.invoke({ toolName: "bash", input: { command: "git reset --hard HEAD~1" } });
		assert.equal(result, undefined);
		return { options: harness.classifierCalls[0].options, label: harness.decisionEntries()[0].data.model };
	};

	const standard = await classify(
		{ provider: "standard", id: "model", name: "Standard", input: ["text"], reasoning: true },
		"max",
	);
	assert.equal(standard.options.reasoning, "high");
	assert.match(standard.label, /thinking max -> high/);

	const xhigh = await classify(
		{
			provider: "xhigh-provider",
			id: "model",
			name: "XHigh",
			input: ["text"],
			reasoning: true,
			thinkingLevelMap: { xhigh: "xhigh" },
		},
		"max",
	);
	assert.equal(xhigh.options.reasoning, "xhigh");

	const remappedHigh = await classify(
		{
			provider: "remapped-provider",
			id: "model",
			name: "Remapped High",
			input: ["text"],
			reasoning: true,
			thinkingLevelMap: { high: null, xhigh: "xhigh" },
		},
		"high",
	);
	assert.equal(remappedHigh.options.reasoning, "xhigh");

	const max = await classify(
		{
			provider: "max-provider",
			id: "model",
			name: "Max",
			input: ["text"],
			reasoning: true,
			thinkingLevelMap: { max: "max" },
		},
		"max",
	);
	assert.equal(max.options.reasoning, "max");

	const nonReasoning = await classify(
		{ provider: "plain", id: "model", name: "Plain", input: ["text"], reasoning: false },
		"xhigh",
	);
	assert.equal(nonReasoning.options.reasoning, undefined);
	assert.match(nonReasoning.label, /thinking xhigh -> off/);
});

test("persists classifier thinking across sessions", async () => {
	const globalModeState = { current: undefined };
	const models = [
		{ provider: "github-copilot", id: "gpt-6-luna", name: "GPT-6 Luna", input: ["text"], reasoning: true },
		{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: true },
	];
	const first = createHarness({ hasUI: true, models, globalModeState });
	await first.startSession();
	await first.commands.get("automode-settings").handler("thinking medium", first.context);
	assert.equal(globalModeState.current.classifierThinkingLevel, "medium");

	const next = createHarness({
		hasUI: true,
		models,
		globalModeState,
		classifierText: '{"decision":"allow","rationale":"The persisted level was used."}',
	});
	await next.startSession();
	assert.equal(
		next.statuses.get("permission-gate"),
		"permission gate: ON (github-copilot/gpt-6-luna, thinking medium)",
	);
	await next.invoke({ toolName: "bash", input: { command: "git reset --hard HEAD~1" } });
	assert.equal(next.classifierCalls[0].options.reasoning, "medium");
});

test("configures, reports, validates, persists, and resets context history messages", async () => {
	const globalModeState = { current: undefined };
	const harness = createHarness({
		hasUI: true,
		globalModeState,
		classifierText: '{"decision":"allow","rationale":"Context history count configured."}',
	});
	const command = harness.commands.get("automode-settings");
	await harness.startSession();
	assert.equal(globalModeState.current.classifierHistoryMessages, 12);

	await command.handler("history 20", harness.context);
	assert.equal(globalModeState.current.classifierHistoryMessages, 20);
	assert.equal(harness.modeEntries().at(-1).data.classifierHistoryMessages, 20);
	assert.match(harness.notifications.at(-1).message, /20 previous messages/);

	await command.handler("status", harness.context);
	assert.match(harness.notifications.at(-1).message, /context history: 20 messages/);

	await command.handler("history 0", harness.context);
	assert.equal(globalModeState.current.classifierHistoryMessages, 0);
	assert.match(harness.notifications.at(-1).message, /0 previous messages/);

	await command.handler("history invalid", harness.context);
	assert.match(harness.notifications.at(-1).message, /Usage: \/automode-settings history/);
	assert.equal(globalModeState.current.classifierHistoryMessages, 0);

	await command.handler("history 999", harness.context);
	assert.match(harness.notifications.at(-1).message, /Usage: \/automode-settings history/);
	assert.equal(globalModeState.current.classifierHistoryMessages, 0);

	await command.handler("history reset", harness.context);
	assert.equal(globalModeState.current.classifierHistoryMessages, 12);
	assert.match(harness.notifications.at(-1).message, /12 previous messages/);
});

test("passes configured number of previous messages to classifier prompt", async () => {
	const branch = [
		{ type: "message", message: { role: "user", content: [{ type: "text", text: "msg-1" }] } },
		{ type: "message", message: { role: "assistant", content: [{ type: "text", text: "msg-2" }] } },
		{ type: "message", message: { role: "user", content: [{ type: "text", text: "msg-3" }] } },
		{ type: "message", message: { role: "assistant", content: [{ type: "text", text: "msg-4" }] } },
		{ type: "message", message: { role: "user", content: [{ type: "text", text: "msg-5" }] } },
	];
	const globalModeState = {
		current: {
			autoModeEnabled: true,
			classifierModel: { provider: "github-copilot", id: "gpt-6-luna" },
			classifierThinkingLevel: "high",
			classifierHistoryMessages: 2,
		},
	};
	const harness = createHarness({
		hasUI: false,
		branch,
		globalModeState,
		classifierText: '{"decision":"allow","rationale":"Command is safe."}',
	});

	await harness.startSession();
	await harness.invoke({ toolName: "bash", input: { command: "git reset --hard HEAD~1" } });

	const sentPrompt = harness.classifierCalls[0].request.messages[0].content[0].text;
	assert.doesNotMatch(sentPrompt, /msg-1/);
	assert.doesNotMatch(sentPrompt, /msg-2/);
	assert.doesNotMatch(sentPrompt, /msg-3/);
	assert.doesNotMatch(sentPrompt, /msg-4/);
	assert.match(sentPrompt, /msg-5/);
});
