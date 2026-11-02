// Provides isolated gate fixtures and test controls.
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPermissionGate } from "../../src/gate.ts";

export function createHarness({
	hasUI = false,
	mode = "tui",
	activeModel = { provider: "active-provider", id: "active-model" },
	choice,
	modelChoice,
	thinkingChoice,
	classifierText = '{"decision":"deny","rationale":"The command is not sufficiently scoped."}',
	classifierError,
	classifierSequence = [],
	beforeClassifier = async () => {},
	useComplete = true,
	models = [
		{
			provider: "github-copilot",
			id: "gpt-6-luna",
			name: "GPT-6 Luna",
			input: ["text"],
			reasoning: true,
		},
	],
	scopedModels = models.map((model) => ({ model })),
	providerDisplayNames = {},
	providerAuth,
	requestAuth,
	refreshError,
	branch = [],
	globalModeState = { current: undefined },
	globalRules = { current: undefined },
	globalPreferences = { current: undefined },
	editedRules,
	editedPreferences,
	ruleSaveChoice = "Apply to this session only",
	selectResponses = [],
	inputValue,
	confirmValue = true,
	approval = async () => undefined,
	// By default, the fast pass returns "deny" without recording a call.
	// Set fastPass to true to record both classifier stages.
	fastPass = false,
	terminalWaits = false,
	openResult = true,
	approvalWaitMs,
	now,
	browserDisabled = false,
	startOff,
} = {}) {
	const approvalRequests = [];
	const messages = [];
	const historyPosts = [];
	const handlers = new Map();
	const commands = new Map();
	const renderers = new Map();
	const entries = [];
	const notifications = [];
	const statuses = new Map();
	const selectCalls = [];
	const editorCalls = [];
	const classifierCalls = [];
	const providerCalls = [];
	let refreshCalls = 0;
	const registryEvents = [];

	const isFastPass = (request) => request.messages[0].content[0].text.includes("FAST PASS");
	const nextClassifierResponse = (request) => {
		if (!fastPass && isFastPass(request)) {
			return {
				content: [{ type: "text", text: '{"decision":"deny","rationale":"Deferred to the deep pass."}' }],
				stopReason: "stop",
			};
		}
		if (classifierSequence.length > 0) {
			const next = classifierSequence.shift();
			if (next instanceof Error) throw next;
			return { content: [{ type: "text", text: next.text ?? "" }], stopReason: next.stopReason ?? "stop" };
		}
		if (classifierError) throw classifierError;
		const text = classifierText;
		return {
			content: [{ type: "text", text }],
			stopReason: "stop",
		};
	};

	const providers = new Map();
	for (const model of models) {
		if (providers.has(model.provider)) continue;
		providers.set(model.provider, {
			id: model.provider,
			name: providerDisplayNames[model.provider] ?? model.provider,
			streamSimple(selectedModel, request, options) {
				if (fastPass || !isFastPass(request)) providerCalls.push({ model: selectedModel, request, options });
				return { result: async () => nextClassifierResponse(request) };
			},
		});
	}

	const defaultProviderAuth = (provider) =>
		providerAuth?.[provider] ?? { auth: { apiKey: "test-token", headers: {} }, env: {} };
	const defaultRequestAuth = (model) =>
		requestAuth?.[model.provider] ?? { ok: true, apiKey: "test-token", headers: {}, env: {} };

	const pi = {
		sendMessage(message, options) {
			messages.push({ message, options });
		},
		on(eventName, handler) {
			handlers.set(eventName, handler);
		},
		registerCommand(name, definition) {
			commands.set(name, definition);
		},
		registerEntryRenderer(name, renderer) {
			renderers.set(name, renderer);
		},
		appendEntry(type, data) {
			entries.push({ type, data });
			if (type === "permission-gate-mode") {
				branch.push({ type: "custom", customType: type, data });
			}
		},
	};

	const context = {
		cwd: "/tmp/project",
		mode,
		model: activeModel,
		hasUI,
		scopedModels,
		signal: undefined,
		sessionManager: {
			getBranch: () => branch,
		},
		modelRegistry: {
			refresh() {
				refreshCalls += 1;
				registryEvents.push("refresh");
				if (refreshError) return Promise.reject(refreshError);
				return Promise.resolve();
			},
			getAvailable() {
				registryEvents.push("getAvailable");
				return models;
			},
			getProvider(provider) {
				return providers.get(provider);
			},
			getProviderDisplayName(provider) {
				return providerDisplayNames[provider] ?? provider;
			},
			async getApiKeyAndHeaders(model) {
				return defaultRequestAuth(model);
			},
			async getProviderAuth(provider) {
				return defaultProviderAuth(provider);
			},
		},
		isProjectTrusted() {
			return false;
		},
		ui: {
			async select(title, options, selectOptions) {
				selectCalls.push({ title, options, signal: selectOptions?.signal });
				if (title === "Save permission gate rules:") return ruleSaveChoice;
				if (title === "Select the auto-mode classifier model:") return modelChoice ?? options[0];
				if (title === "Select the auto-mode classifier thinking level:") return thinkingChoice ?? options[0];
				if (terminalWaits) {
					// Like the real terminal dialog: no answer until the user answers or the gate cancels it.
					return new Promise((resolve) => selectOptions?.signal?.addEventListener("abort", () => resolve(undefined)));
				}
				if (selectResponses.length > 0) return selectResponses.shift();
				return choice;
			},
			async input(_title, _placeholder) {
				return inputValue;
			},
			async confirm() {
				return confirmValue;
			},
			async editor(title, initialValue) {
				editorCalls.push({ title, initialValue });
				if (title.startsWith("Edit auto-mode classifier preference notes")) return editedPreferences;
				return editedRules;
			},
			notify(message, level) {
				notifications.push({ message, level });
			},
			setStatus(id, text) {
				statuses.set(id, text);
			},
		},
	};

	const complete = async (model, request, options) => {
		if (fastPass || !isFastPass(request)) classifierCalls.push({ model, request, options });
		await beforeClassifier(request);
		return nextClassifierResponse(request);
	};

	createPermissionGate(pi, {
		startOff,
		approvalWaitMs,
		now,
		...(useComplete ? { complete } : {}),
		openApprovalPage: async () => openResult,
		postHistory: async (entry) => {
			historyPosts.push(entry);
		},
		requestApproval: browserDisabled
			? undefined
			: async (request, signal, lifecycle) => {
					approvalRequests.push(request);
					return approval(request, signal, lifecycle);
				},
		loadGlobalModeState: async () => globalModeState.current,
		saveGlobalModeState: async (state) => {
			globalModeState.current = { ...state };
		},
		loadGlobalRules: async () => globalRules.current,
		saveGlobalRules: async (config) => {
			globalRules.current = {
				allowedCommands: [...config.allowedCommands],
				disallowedCommands: [...config.disallowedCommands],
			};
		},
		loadAutoModePreferences: async () => globalPreferences.current,
		saveAutoModePreferences: async (preferences) => {
			globalPreferences.current = preferences;
		},
	});

	return {
		handlers,
		messages,
		commands,
		entries,
		renderers,
		notifications,
		statuses,
		selectCalls,
		approvalRequests,
		historyPosts,
		editorCalls,
		classifierCalls,
		providerCalls,
		get refreshCalls() {
			return refreshCalls;
		},
		registryEvents,
		context,
		decisionEntries() {
			return entries.filter((entry) => entry.type === "permission-gate-decision");
		},
		modeEntries() {
			return entries.filter((entry) => entry.type === "permission-gate-mode");
		},
		startSession(event = { type: "session_start", reason: "startup" }) {
			return handlers.get("session_start")(event, context);
		},
		invoke(event) {
			return handlers.get("tool_call")(event, context);
		},
	};
}

// Hard-deny command, built at runtime so the source text does not trip a live gate.
export const HARD_DENY = { toolName: "bash", input: { command: ["rm", "-rf", "/"].join(" ") } };

export const autoState = () => ({ current: { autoModeEnabled: true } });
export const ALLOW = '{"decision":"allow","risk":"low","rationale":"Routine project work."}';
export const DENY = '{"decision":"deny","risk":"medium","rationale":"The target is unclear."}';
export const run = (harness, command) => harness.invoke({ toolName: "bash", input: { command } });

export async function scriptProject(t, content = "print('version A')\n") {
	const dir = await mkdtemp(join(tmpdir(), "gate-script-flow-"));
	t.after(() => rm(dir, { recursive: true, force: true }));
	await writeFile(join(dir, "main.py"), content);
	return dir;
}
