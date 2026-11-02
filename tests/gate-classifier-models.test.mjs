// Covers classifier models behavior.
import assert from "node:assert/strict";
import test from "node:test";
import { createHarness } from "./helpers/gate-harness.mjs";

test("discovers text models for picker and autocomplete, supports slash-containing IDs, and resets", async () => {
	const models = [
		{
			provider: "vertex",
			id: "gemini/flash-2",
			name: "Gemini Flash 2",
			input: ["text"],
			reasoning: false,
		},
		{
			provider: "github-copilot",
			id: "gpt-6-luna",
			name: "GPT-6 Luna",
			input: ["text"],
			reasoning: true,
		},
		{
			provider: "image-provider",
			id: "image-model",
			name: "Image Model",
			input: ["image"],
			reasoning: false,
		},
	];
	const globalModeState = { current: undefined };
	const harness = createHarness({
		hasUI: true,
		models,
		providerDisplayNames: { vertex: "Google Vertex" },
		modelChoice: "vertex/gemini/flash-2 - Google Vertex - Gemini Flash 2",
		globalModeState,
	});

	await harness.startSession();
	const command = harness.commands.get("automode-settings");
	const completions = command.getArgumentCompletions("model ");
	assert.deepEqual(
		completions.slice(0, 2).map((item) => item.value),
		["reset", "github-copilot/gpt-6-luna"],
	);
	assert.ok(completions.some((item) => item.value === "vertex/gemini/flash-2"));
	assert.equal(
		completions.some((item) => item.value === "image-provider/image-model"),
		false,
	);
	assert.match(completions.find((item) => item.value === "vertex/gemini/flash-2").description, /Google Vertex/);
	assert.equal(harness.refreshCalls, 0);

	await command.handler("model", harness.context);
	assert.equal(harness.refreshCalls, 0);
	assert.deepEqual(globalModeState.current.classifierModel, { provider: "vertex", id: "gemini/flash-2" });
	assert.match(harness.notifications.at(-1).message, /vertex\/gemini\/flash-2 \(thinking high -> off\)/);

	await command.handler("model vertex/gemini/flash-2", harness.context);
	assert.equal(harness.refreshCalls, 1);
	assert.deepEqual(globalModeState.current.classifierModel, { provider: "vertex", id: "gemini/flash-2" });

	await command.handler("model reset", harness.context);
	assert.deepEqual(globalModeState.current, {
		autoModeEnabled: true,
		classifierModel: { provider: "github-copilot", id: "gpt-6-luna" },
		classifierThinkingLevel: "high",
		classifierHistoryMessages: 12,
		approvalWaitSeconds: 300,
		productionPatterns: ["prod", "prd", "production"],
	});
});

test("model picker and completions only expose scoped text models", async () => {
	const models = [
		{ provider: "scoped", id: "model", name: "Scoped Model", input: ["text"], reasoning: true },
		{ provider: "registry-only", id: "model", name: "Registry Only", input: ["text"], reasoning: true },
	];
	const harness = createHarness({
		hasUI: true,
		models,
		scopedModels: [{ model: models[0] }],
		globalModeState: { current: undefined },
	});

	await harness.startSession();
	const modelCommand = harness.commands.get("automode-settings");
	assert.deepEqual(
		modelCommand.getArgumentCompletions("model ").map((item) => item.value),
		["reset", "scoped/model"],
	);
	assert.equal(
		modelCommand.getArgumentCompletions("model ").some((item) => item.value.includes("registry-only")),
		false,
	);

	await modelCommand.handler("model", harness.context);
	assert.deepEqual(harness.selectCalls[0].options, ["scoped/model - scoped - Scoped Model"]);
	assert.equal(harness.refreshCalls, 0);
	assert.doesNotMatch(harness.notifications.at(-1).message, /registry-only/);
});

test("warns instead of opening the picker when the session has no scoped models", async () => {
	const harness = createHarness({ hasUI: true, scopedModels: [] });

	await harness.startSession();
	await harness.commands.get("automode-settings").handler("model", harness.context);

	assert.equal(harness.selectCalls.length, 0);
	assert.match(harness.notifications.at(-1).message, /no scoped models/i);
	assert.match(harness.notifications.at(-1).message, /--models/);
});

test("opens the model picker in RPC mode when UI is available", async () => {
	const globalModeState = { current: undefined };
	const harness = createHarness({
		hasUI: true,
		mode: "rpc",
		models: [
			{ provider: "github-copilot", id: "gpt-5.6-luna", name: "GPT-5.6 Luna", input: ["text"], reasoning: true },
			{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: true },
		],
		modelChoice: "vertex/gemini/flash - vertex - Gemini Flash",
		thinkingChoice: "high - supported",
		globalModeState,
	});

	await harness.commands.get("automode-settings").handler("model", harness.context);
	assert.equal(harness.refreshCalls, 0);
	assert.deepEqual(globalModeState.current.classifierModel, { provider: "vertex", id: "gemini/flash" });
	await harness.commands.get("automode-settings").handler("thinking", harness.context);
	assert.equal(globalModeState.current.classifierThinkingLevel, "high");
	assert.deepEqual(
		harness.selectCalls.map((call) => call.title),
		["Select the auto-mode classifier model:", "Select the auto-mode classifier thinking level:"],
	);
});

test("autocomplete only suggests valid next classifier-model arguments", async () => {
	const harness = createHarness({
		hasUI: true,
		models: [
			{ provider: "github-copilot", id: "gpt-5.6-luna", name: "GPT-5.6 Luna", input: ["text"], reasoning: true },
			{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: false },
		],
	});
	await harness.startSession();
	const completions = harness.commands.get("automode-settings").getArgumentCompletions;

	assert.deepEqual(
		completions("model re").map((item) => item.value),
		["reset"],
	);
	assert.equal(completions("model reset"), null);
	assert.equal(completions("model reset "), null);
	assert.equal(completions("model github-copilot/gpt-5.6-luna"), null);
	assert.equal(completions("model github-copilot/gpt-5.6-luna "), null);
	assert.equal(completions("model github-copilot/gpt-5.6-luna extra"), null);
	assert.equal(completions("model re extra"), null);
	assert.deepEqual(
		completions("thinking ").map((item) => item.value),
		["off", "minimal", "low", "medium", "high", "xhigh", "max", "reset"],
	);
	assert.deepEqual(
		completions("thinking ma").map((item) => item.value),
		["max"],
	);
	assert.deepEqual(
		completions("thinking re").map((item) => item.value),
		["reset"],
	);
	assert.equal(completions("thinking max"), null);
	assert.equal(completions("thinking max extra"), null);
});

test("rejects a picker in noninteractive mode without changing state", async () => {
	const globalModeState = { current: { autoModeEnabled: true } };
	const harness = createHarness({
		hasUI: false,
		mode: "json",
		globalModeState,
		models: [{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: false }],
	});

	await harness.commands.get("automode-settings").handler("model", harness.context);
	assert.equal(harness.refreshCalls, 0);
	assert.deepEqual(globalModeState.current, { autoModeEnabled: true });
});

test("selects a direct model without changing Pi's active model and persists across sessions", async () => {
	const activeModel = { provider: "active", id: "active-model" };
	const models = [
		{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: false },
		{ provider: "github-copilot", id: "gpt-5.6-luna", name: "GPT-5.6 Luna", input: ["text"], reasoning: true },
	];
	const globalModeState = { current: undefined };
	const first = createHarness({
		hasUI: false,
		models,
		activeModel,
		classifierText: '{"decision":"allow","rationale":"The selected classifier approved the scoped command."}',
		globalModeState,
	});

	await first.startSession();
	await first.commands.get("automode-settings").handler("model vertex/gemini/flash", first.context);
	assert.equal(first.refreshCalls, 1);
	assert.deepEqual(first.registryEvents.slice(-2), ["refresh", "getAvailable"]);
	assert.deepEqual(globalModeState.current.classifierModel, { provider: "vertex", id: "gemini/flash" });
	assert.equal(first.context.model, activeModel);

	const result = await first.invoke({ toolName: "bash", input: { command: "git reset --hard HEAD~1" } });
	assert.equal(result, undefined);
	assert.equal(first.classifierCalls[0].model.provider, "vertex");
	assert.equal(first.classifierCalls[0].model.id, "gemini/flash");
	assert.equal(first.classifierCalls[0].options.reasoning, undefined);
	assert.equal(Object.hasOwn(first.classifierCalls[0].options, "reasoningEffort"), false);
	assert.equal(first.context.model, activeModel);

	const next = createHarness({ hasUI: true, models, activeModel, globalModeState });
	await next.startSession();
	assert.equal(next.statuses.get("permission-gate"), "permission gate: ON (vertex/gemini/flash, thinking high -> off)");
	await next.invoke({ toolName: "bash", input: { command: "git reset --hard HEAD~1" } });
	assert.equal(next.classifierCalls[0].model.provider, "vertex");
	assert.equal(next.classifierCalls[0].model.id, "gemini/flash");
});

test("trims persisted model references before exact canonical matching", async () => {
	const harness = createHarness({
		hasUI: false,
		classifierText: '{"decision":"allow","rationale":"The trimmed model reference resolved exactly."}',
		globalModeState: {
			current: {
				autoModeEnabled: true,
				classifierModel: { provider: "  vertex  ", id: "  gemini/flash  " },
			},
		},
		models: [{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: false }],
	});

	await harness.startSession();
	const result = await harness.invoke({ toolName: "bash", input: { command: "git reset --hard HEAD~1" } });
	assert.equal(result, undefined);
	assert.equal(harness.classifierCalls[0].model.provider, "vertex");
	assert.equal(harness.classifierCalls[0].model.id, "gemini/flash");
});

test("fails closed for a stale selected model without falling back", async () => {
	const harness = createHarness({
		hasUI: false,
		globalModeState: {
			current: {
				autoModeEnabled: true,
				classifierModel: { provider: "vertex", id: "removed/model" },
			},
		},
		models: [
			{ provider: "github-copilot", id: "gpt-5.6-luna", name: "GPT-5.6 Luna", input: ["text"], reasoning: true },
		],
	});

	await harness.startSession();
	const result = await harness.invoke({ toolName: "bash", input: { command: "git reset --hard HEAD~1" } });
	assert.equal(result.block, true);
	assert.match(result.reason, /no approver was reachable/);
	assert.match(
		harness.decisionEntries().at(-1).data.rationale,
		/vertex\/removed\/model \(thinking high -> unavailable\)/,
	);
	assert.equal(harness.classifierCalls.length, 0);
});

test("uses provider.streamSimple with generic options and keyless ambient auth", async () => {
	const selectedModel = {
		provider: "amazon-bedrock",
		id: "claude/ambient",
		name: "Ambient Claude",
		input: ["text"],
		reasoning: true,
		thinkingLevelMap: { xhigh: "xhigh" },
	};
	const activeModel = { provider: "active", id: "active-model" };
	const harness = createHarness({
		hasUI: false,
		useComplete: false,
		activeModel,
		models: [selectedModel],
		globalModeState: {
			current: {
				autoModeEnabled: true,
				classifierModel: { provider: "amazon-bedrock", id: "claude/ambient" },
				classifierThinkingLevel: "xhigh",
			},
		},
		providerAuth: {
			"amazon-bedrock": {
				auth: { headers: { "x-ambient": "true" }, baseUrl: "https://bedrock.example.test" },
				env: { AWS_PROFILE: "test" },
			},
		},
		requestAuth: {
			"amazon-bedrock": { ok: true, headers: { "x-request": "true" }, env: { AWS_REGION: "test-region" } },
		},
		classifierText: '{"decision":"allow","rationale":"Ambient credentials are valid for this test."}',
	});

	await harness.startSession();
	const result = await harness.invoke({ toolName: "bash", input: { command: "git reset --hard HEAD~1" } });
	assert.equal(result, undefined);
	assert.equal(harness.providerCalls.length, 1);
	assert.equal(harness.providerCalls[0].model.provider, selectedModel.provider);
	assert.equal(harness.providerCalls[0].model.id, selectedModel.id);
	assert.equal(harness.providerCalls[0].model.baseUrl, "https://bedrock.example.test");
	assert.equal(harness.providerCalls[0].options.apiKey, undefined);
	assert.equal(harness.providerCalls[0].options.reasoning, "xhigh");
	assert.equal(Object.hasOwn(harness.providerCalls[0].options, "reasoningEffort"), false);
	assert.deepEqual(harness.providerCalls[0].options.headers, { "x-ambient": "true", "x-request": "true" });
	assert.deepEqual(harness.providerCalls[0].options.env, { AWS_PROFILE: "test", AWS_REGION: "test-region" });
	assert.equal(harness.context.model, activeModel);
});

test("prefers model-specific requestAuth baseUrl over providerAuth baseUrl", async () => {
	const selectedModel = {
		provider: "github-copilot",
		id: "gpt-5.6-luna",
		name: "GPT-5.6 Luna",
		input: ["text"],
		reasoning: true,
		baseUrl: "https://api.individual.githubcopilot.com",
	};
	const harness = createHarness({
		hasUI: false,
		useComplete: false,
		models: [selectedModel],
		globalModeState: {
			current: {
				autoModeEnabled: true,
				classifierModel: { provider: "github-copilot", id: "gpt-5.6-luna" },
			},
		},
		providerAuth: {
			"github-copilot": {
				auth: { apiKey: "tok", baseUrl: "https://api.fallback.githubcopilot.com" },
			},
		},
		requestAuth: {
			"github-copilot": {
				ok: true,
				apiKey: "tok",
				baseUrl: "https://api.business.githubcopilot.com",
			},
		},
		classifierText: '{"decision":"allow","rationale":"BaseUrl override verified."}',
	});

	await harness.startSession();
	const result = await harness.invoke({ toolName: "bash", input: { command: "git reset --hard HEAD~1" } });
	assert.equal(result, undefined);
	assert.equal(harness.providerCalls.length, 1);
	assert.equal(harness.providerCalls[0].model.baseUrl, "https://api.business.githubcopilot.com");
});

test("fails closed on an unsuccessful request-auth resolution", async () => {
	const harness = createHarness({
		hasUI: false,
		models: [{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: false }],
		globalModeState: {
			current: {
				autoModeEnabled: true,
				classifierModel: { provider: "vertex", id: "gemini/flash" },
			},
		},
		requestAuth: { vertex: { ok: false, error: "secret-token-must-not-be-shown" } },
	});

	await harness.startSession();
	const result = await harness.invoke({ toolName: "bash", input: { command: "git reset --hard HEAD~1" } });
	assert.equal(result.block, true);
	assert.match(harness.decisionEntries().at(-1).data.rationale, /authentication.*unavailable/i);
	assert.doesNotMatch(JSON.stringify(harness.decisionEntries()), /secret-token/);
	assert.doesNotMatch(result.reason, /secret-token/);
	assert.equal(harness.classifierCalls.length, 0);
});
