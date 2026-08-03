import assert from "node:assert/strict";
import test from "node:test";

import {
  createPermissionGate,
  hardDenyReasons,
  matchedReasons,
  parseAutoModeDecision,
} from "../extensions/permission-gate.ts";

function createHarness({
  hasUI = false,
  mode = "tui",
  activeModel = { provider: "active-provider", id: "active-model" },
  choice,
  modelChoice,
  thinkingChoice,
  classifierText = '{"decision":"deny","rationale":"The command is not sufficiently scoped."}',
  classifierTexts,
  classifierError,
  useComplete = true,
  models = [
    {
      provider: "github-copilot",
      id: "gpt-5.6-luna",
      name: "GPT-5.6 Luna",
      input: ["text"],
      reasoning: true,
    },
  ],
  scopedModels = models.map((model) => ({ model })),
  providerDisplayNames = {},
  providerAuth,
  requestAuth,
  refreshError,
  webSearchAvailable = false,
  webSearchRegistered = webSearchAvailable,
  webSearchExtensionPath = webSearchAvailable ? "test-web-search.ts" : undefined,
  webEvidence = "web evidence: package documentation and security advisories",
  branch = [],
  globalModeState = { current: undefined },
  globalRules = { current: undefined },
  editedRules,
  ruleSaveChoice = "Apply to this session only",
} = {}) {
  const handlers = new Map();
  const commands = new Map();
  const renderers = new Map();
  const entries = [];
  const notifications = [];
  const statuses = new Map();
  const selectCalls = [];
  const classifierCalls = [];
  const providerCalls = [];
  const execCalls = [];
  let classifierCallIndex = 0;
  let refreshCalls = 0;
  const registryEvents = [];

  const nextClassifierResponse = () => {
    if (classifierError) throw classifierError;
    const text = classifierTexts?.[classifierCallIndex++] ?? classifierText;
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
        providerCalls.push({ model: selectedModel, request, options });
        return { result: async () => nextClassifierResponse() };
      },
    });
  }

  const defaultProviderAuth = (provider) => providerAuth?.[provider] ?? { auth: { apiKey: "test-token", headers: {} }, env: {} };
  const defaultRequestAuth = (model) => requestAuth?.[model.provider] ?? { ok: true, apiKey: "test-token", headers: {}, env: {} };

  const pi = {
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
    getActiveTools() {
      return webSearchAvailable ? ["web_search"] : [];
    },
    getAllTools() {
      return webSearchRegistered ? [{ name: "web_search", sourceInfo: { path: "test-web-search.ts" } }] : [];
    },
    async exec(command, args, options) {
      execCalls.push({ command, args, options });
      const stdout = [
        JSON.stringify({ type: "tool_execution_start", toolName: "web_search", toolCallId: "test-web-call" }),
        JSON.stringify({
          type: "tool_execution_end",
          toolName: "web_search",
          toolCallId: "test-web-call",
          isError: false,
          result: {
            content: [{ type: "text", text: webEvidence }],
            details: {
              model: "test-web",
              depth: "short",
              sourceCount: 1,
              sources: [{ url: "https://example.test/source" }],
            },
            isError: false,
          },
        }),
      ].join("\n");
      return { stdout, stderr: "", code: 0, killed: false };
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
      find(provider, modelId) {
        return models.find((model) => model.provider === provider && model.id === modelId);
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
      async select(title, options) {
        selectCalls.push({ title, options });
        if (title === "Save permission gate rules:") return ruleSaveChoice;
        if (title === "Select the auto-mode classifier model:") return modelChoice ?? options[0];
        if (title === "Select the auto-mode classifier thinking level:") return thinkingChoice ?? options[0];
        return choice;
      },
      async editor() {
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
    classifierCalls.push({ model, request, options });
    return nextClassifierResponse();
  };

  createPermissionGate(pi, {
    ...(useComplete ? { complete } : {}),
    webSearchExtensionPath,
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
  });

  return {
    handlers,
    commands,
    entries,
    renderers,
    notifications,
    statuses,
    selectCalls,
    classifierCalls,
    providerCalls,
    execCalls,
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

test("recognizes soft and hard permission rules", () => {
  assert.deepEqual(matchedReasons("rm -rf /tmp/example"), ["recursive/forced rm"]);
  assert.deepEqual(hardDenyReasons("rm -rf /tmp/example"), []);
  assert.deepEqual(matchedReasons("rtk uv run pytest"), []);
  assert.deepEqual(matchedReasons("rtk uv run ruff check ."), []);
  assert.deepEqual(matchedReasons("rtk uv run mypy"), []);
  assert.ok(matchedReasons("uv run python script.py").includes("package execution or publish"));
  assert.deepEqual(matchedReasons("npm install ruff"), []);
  assert.deepEqual(matchedReasons("rm -rf build", undefined, "/tmp/project"), []);
  assert.deepEqual(matchedReasons("find build -type f -delete", undefined, "/tmp/project"), []);
  assert.ok(matchedReasons("rm -rf ../outside", undefined, "/tmp/project").includes("recursive/forced rm"));
  assert.ok(matchedReasons("find . -delete", undefined, "/tmp/project").includes("find delete"));
  assert.ok(matchedReasons("rtk uv run pytest && rm -rf /tmp/example").includes("recursive/forced rm"));
  assert.ok(hardDenyReasons("rm -rf /").includes("recursive delete of a system or home root"));
  assert.ok(hardDenyReasons('rm -rf "${HOME}"').includes("recursive delete of a system or home root"));
  assert.ok(hardDenyReasons("rm -rf /{etc,usr}").includes("unresolved recursive delete target"));
  assert.ok(hardDenyReasons('rm -rf "$(printf /)"').includes("unresolved recursive delete target"));
  assert.ok(hardDenyReasons('dd if=/dev/zero of="/dev/disk2"').includes("disk device overwrite"));
  assert.ok(hardDenyReasons("git push origin main --force").includes("forced push to a protected branch"));
  assert.ok(hardDenyReasons('BRANCH=main; git push -f origin "$BRANCH"').includes("unresolved forced push target"));
});

test("parses strict and fenced auto-mode decisions", () => {
  assert.deepEqual(parseAutoModeDecision('{"decision":"allow","rationale":"Scoped temporary cleanup."}'), {
    decision: "allow",
    rationale: "Scoped temporary cleanup.",
  });
  assert.deepEqual(parseAutoModeDecision('{"decision":"deny","needs_web_search":true,"search_query":"package safety","rationale":"Need current package information."}'), {
    decision: "deny",
    rationale: "Need current package information.",
    needsWebSearch: true,
    searchQuery: "package safety",
  });
  assert.equal(parseAutoModeDecision("```json\n{\"decision\":\"deny\",\"rationale\":\"Unclear target.\"}\n```"), undefined);
  assert.equal(parseAutoModeDecision('{"decision":"allow","rationale":"ok","extra":"reject this"}'), undefined);
  assert.equal(parseAutoModeDecision('{"decision":"allow"}'), undefined);
  assert.equal(parseAutoModeDecision("not JSON"), undefined);
});

test("edits allowed and disallowed command patterns through /permission-rules", async () => {
  const globalRules = { current: undefined };
  const harness = createHarness({
    hasUI: true,
    globalRules,
    editedRules: JSON.stringify({
      allowedCommands: ["uv run python*", "rm -rf *"],
      disallowedCommands: ["npm install evil*"],
    }),
    ruleSaveChoice: "Save as global default",
  });

  await harness.startSession();
  await harness.commands.get("permission-rules").handler("edit", harness.context);
  assert.deepEqual(globalRules.current, {
    allowedCommands: ["uv run python*", "rm -rf *"],
    disallowedCommands: ["npm install evil*"],
  });

  assert.equal(
    await harness.invoke({ toolName: "bash", input: { command: "uv run python script.py" } }),
    undefined,
  );
  const disallowed = await harness.invoke({
    toolName: "bash",
    input: { command: "npm install evil-package" },
  });
  assert.equal(disallowed.block, true);
  assert.equal(harness.decisionEntries().at(-1).data.source, "user-rule");

  const hardDenied = await harness.invoke({
    toolName: "bash",
    input: { command: "rm -rf /" },
  });
  assert.equal(hardDenied.block, true);
  assert.equal(harness.decisionEntries().at(-1).data.source, "hard-deny");
  assert.equal(harness.classifierCalls.length, 0);
});

test("ignores non-bash tool calls", async () => {
  const harness = createHarness();

  const result = await harness.invoke({
    toolName: "read",
    input: { path: "/tmp/example.txt" },
  });

  assert.equal(result, undefined);
  assert.equal(harness.classifierCalls.length, 0);
});

test("allows safe bash commands", async () => {
  const harness = createHarness({ hasUI: false });

  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "printf 'hello\\n'" },
  });

  assert.equal(result, undefined);
  assert.equal(harness.entries.length, 0);
});

test("allows local verification commands without the classifier", async () => {
  const harness = createHarness({ hasUI: false });
  await harness.startSession();

  for (const command of [
    "rtk uv run pytest",
    "rtk uv run ruff check .",
    "rtk uv run mypy",
    "rm -rf build",
    "find build -type f -delete",
    "npm install ruff",
    "uv pip install ruff",
  ]) {
    const result = await harness.invoke({
      toolName: "bash",
      input: { command },
    });

    assert.equal(result, undefined, command);
  }

  assert.equal(harness.classifierCalls.length, 0);
  assert.equal(harness.decisionEntries().length, 0);
});

test("blocks dangerous commands without a UI when auto mode is off", async () => {
  const harness = createHarness({ hasUI: false });

  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "rm -rf /tmp/example" },
  });

  assert.equal(result.block, true);
  assert.match(result.reason, /recursive\/forced rm/);
  assert.match(result.reason, /no UI for confirmation/);
});

test("blocks a dangerous command when the user selects No", async () => {
  const harness = createHarness({ hasUI: true, choice: "No" });

  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "git reset --hard HEAD" },
  });

  assert.deepEqual(result, { block: true, reason: "Blocked by user" });
});

test("allows a dangerous command when the user selects Yes", async () => {
  const harness = createHarness({ hasUI: true, choice: "Yes" });

  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "sudo -n true" },
  });

  assert.equal(result, undefined);
});

test("hard-denies catastrophic commands without calling the model", async () => {
  const harness = createHarness({ hasUI: true, choice: "Yes" });

  const result = await harness.invoke({
    toolName: "bash",
    input: { command: 'dd if=/dev/zero of="/dev/disk2"' },
  });

  assert.equal(result.block, true);
  assert.match(result.reason, /Non-negotiable safety rule/);
  assert.equal(harness.classifierCalls.length, 0);
  assert.equal(harness.decisionEntries()[0].data.source, "hard-deny");
});

test("auto mode approves a soft-deny command with the configured model", async () => {
  const harness = createHarness({
    hasUI: true,
    classifierText: '{"decision":"allow","rationale":"The target is a scoped temporary directory."}',
  });

  await harness.commands.get("automode").handler("on", harness.context);
  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "rm -rf /tmp/example" },
  });

  assert.equal(result, undefined);
  assert.equal(harness.classifierCalls.length, 1);
  assert.equal(harness.classifierCalls[0].model.id, "gpt-5.6-luna");
  assert.equal(harness.classifierCalls[0].options.reasoning, "high");
  assert.equal(harness.decisionEntries()[0].data.status, "approved");
  assert.equal(harness.decisionEntries()[0].data.source, "auto-model");
  assert.match(harness.decisionEntries()[0].data.model, /github-copilot\/gpt-5\.6-luna \(thinking high\)/);
  assert.equal(harness.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-5.6-luna, thinking high, web on)");
});

test("auto mode can request web verification before the final decision", async () => {
  const harness = createHarness({
    hasUI: true,
    webSearchAvailable: true,
    classifierTexts: [
      '{"decision":"deny","needs_web_search":true,"search_query":"is this package runner safe?","rationale":"The package identity needs verification."}',
      '{"decision":"allow","rationale":"The web evidence confirms this is a scoped local package operation."}',
    ],
  });

  await harness.commands.get("automode").handler("on", harness.context);
  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "npx example-package --token example-value-123 --help" },
  });

  assert.equal(result, undefined);
  assert.equal(harness.classifierCalls.length, 2);
  assert.equal(harness.execCalls.length, 1);
  assert.deepEqual(harness.execCalls[0].args.slice(0, 4), ["--no-extensions", "--extension", "test-web-search.ts", "--no-session"]);
  assert.match(harness.classifierCalls[1].request.messages[0].content[0].text, /web evidence: package documentation/);
  assert.equal(harness.decisionEntries()[0].data.status, "approved");
  assert.match(harness.decisionEntries()[0].data.webQuery, /example-package/);
  assert.doesNotMatch(harness.decisionEntries()[0].data.webQuery, /example-value-123/);
});

test("auto mode blocks when requested web verification is registered but inactive", async () => {
  const harness = createHarness({
    hasUI: true,
    webSearchAvailable: false,
    webSearchRegistered: true,
    classifierText: '{"decision":"allow","needs_web_search":true,"search_query":"unknown package","rationale":"The package identity needs verification."}',
  });

  await harness.commands.get("automode").handler("on", harness.context);
  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "npx unknown-package --help" },
  });

  assert.equal(result.block, true);
  assert.match(result.reason, /web_search tool is not available/);
  assert.equal(harness.execCalls.length, 0);
});

test("auto mode blocks a denied soft-deny command and records the rationale", async () => {
  const harness = createHarness({
    hasUI: true,
    classifierText: '{"decision":"deny","rationale":"Privilege escalation is not necessary for the stated task."}',
  });

  await harness.commands.get("automode").handler("on", harness.context);
  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "sudo -n true" },
  });

  assert.equal(result.block, true);
  assert.match(result.reason, /Privilege escalation is not necessary/);
  assert.equal(harness.decisionEntries()[0].data.status, "blocked");
  assert.equal(harness.decisionEntries()[0].data.source, "auto-model");
});

test("auto mode fails closed when classification fails", async () => {
  const harness = createHarness({
    hasUI: true,
    classifierError: new Error("classifier unavailable"),
  });

  await harness.commands.get("automode").handler("on", harness.context);
  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "sudo -n true" },
  });

  assert.equal(result.block, true);
  assert.match(result.reason, /classifier unavailable/);
  assert.equal(harness.decisionEntries()[0].data.status, "blocked");
});

test("loads legacy globally persisted auto-mode state and uses the default classifier", async () => {
  const globalModeState = { current: { autoModeEnabled: true, webVerificationEnabled: false } };
  const harness = createHarness({
    hasUI: true,
    classifierText: '{"decision":"allow","rationale":"The explicit test command is safe."}',
    globalModeState,
  });

  await harness.startSession();
  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "sudo -n true" },
  });

  assert.equal(result, undefined);
  assert.equal(harness.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-5.6-luna, thinking high, web off)");
  assert.deepEqual(globalModeState.current, { autoModeEnabled: true, webVerificationEnabled: false });
});

test("preserves booleans and exposes malformed classifier state without default substitution", async () => {
  const globalModeState = {
    current: {
      autoModeEnabled: false,
      webVerificationEnabled: false,
      classifierModel: { provider: "", id: "" },
      classifierThinkingLevel: "not-a-level",
    },
  };
  const harness = createHarness({ hasUI: true, globalModeState });

  await harness.startSession();
  assert.equal(harness.statuses.get("permission-gate"), undefined);
  await harness.commands.get("automode").handler("status", harness.context);
  assert.match(harness.notifications.at(-1).message, /auto mode is OFF/);
  assert.match(harness.notifications.at(-1).message, /web verification is OFF/);
  assert.match(harness.notifications.at(-1).message, /unavailable classifier model/);
  assert.doesNotMatch(harness.notifications.at(-1).message, /github-copilot\/gpt-5\.6-luna/);
  assert.deepEqual(globalModeState.current, {
    autoModeEnabled: false,
    webVerificationEnabled: false,
    classifierModel: { provider: "", id: "" },
    classifierThinkingLevel: "not-a-level",
  });

  await harness.commands.get("automode").handler("on", harness.context);
  assert.equal(globalModeState.current.classifierModel, null);
  assert.equal(globalModeState.current.classifierThinkingLevel, "high");
  const result = await harness.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
  assert.equal(result.block, true);
  assert.match(result.reason, /unavailable classifier model/);
  assert.equal(harness.classifierCalls.length, 0);
});

test("keeps the global auto-mode state across new sessions, forks, reloads, and tree navigation", async () => {
  const globalModeState = { current: undefined };
  const firstSession = createHarness({ hasUI: true, globalModeState });

  await firstSession.startSession({ type: "session_start", reason: "startup" });
  assert.equal(firstSession.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-5.6-luna, thinking high, web on)");
  await firstSession.commands.get("automode").handler("web off", firstSession.context);

  const nextSession = createHarness({ hasUI: true, globalModeState });
  await nextSession.startSession({ type: "session_start", reason: "fork" });
  assert.equal(nextSession.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-5.6-luna, thinking high, web off)");

  await nextSession.startSession({ type: "session_start", reason: "reload" });
  nextSession.handlers.get("session_tree")({}, nextSession.context);
  assert.equal(nextSession.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-5.6-luna, thinking high, web off)");

  await nextSession.commands.get("automode").handler("off", nextSession.context);
  const resumedSession = createHarness({ hasUI: true, globalModeState });
  await resumedSession.startSession({ type: "session_start", reason: "resume" });
  assert.equal(resumedSession.statuses.get("permission-gate"), undefined);
});

test("automode toggles and reports its state", async () => {
  const harness = createHarness({ hasUI: true });
  const command = harness.commands.get("automode");

  await command.handler("on", harness.context);
  assert.equal(harness.notifications.at(-1).message.includes("enabled"), true);
  assert.deepEqual(harness.modeEntries()[0].data, {
    autoModeEnabled: true,
    webVerificationEnabled: true,
    classifierModel: { provider: "github-copilot", id: "gpt-5.6-luna" },
    classifierThinkingLevel: "high",
  });

  await command.handler("web off", harness.context);
  assert.match(harness.notifications.at(-1).message, /web verification disabled/);
  assert.equal(harness.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-5.6-luna, thinking high, web off)");

  await command.handler("status", harness.context);
  assert.match(harness.notifications.at(-1).message, /is ON/);
  assert.match(harness.notifications.at(-1).message, /web verification is OFF/);

  await command.handler("off", harness.context);
  assert.match(harness.notifications.at(-1).message, /disabled/);
  assert.equal(harness.statuses.get("permission-gate"), undefined);
});

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
      id: "gpt-5.6-luna",
      name: "GPT-5.6 Luna",
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
  const command = harness.commands.get("automode");
  const completions = command.getArgumentCompletions("model ");
  assert.deepEqual(completions.slice(0, 2).map((item) => item.value), ["reset", "github-copilot/gpt-5.6-luna"]);
  assert.ok(completions.some((item) => item.value === "vertex/gemini/flash-2"));
  assert.equal(completions.some((item) => item.value === "image-provider/image-model"), false);
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
    webVerificationEnabled: true,
    classifierModel: { provider: "github-copilot", id: "gpt-5.6-luna" },
    classifierThinkingLevel: "high",
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
  const modelCommand = harness.commands.get("automode-model");
  assert.deepEqual(modelCommand.getArgumentCompletions("").map((item) => item.value), ["reset", "scoped/model"]);
  assert.equal(modelCommand.getArgumentCompletions("").some((item) => item.value.includes("registry-only")), false);

  await modelCommand.handler("", harness.context);
  assert.deepEqual(harness.selectCalls[0].options, ["scoped/model - scoped - Scoped Model"]);
  assert.equal(harness.refreshCalls, 0);
  assert.doesNotMatch(harness.notifications.at(-1).message, /registry-only/);
});

test("warns instead of opening the picker when the session has no scoped models", async () => {
  const harness = createHarness({ hasUI: true, scopedModels: [] });

  await harness.startSession();
  await harness.commands.get("automode-model").handler("", harness.context);

  assert.equal(harness.selectCalls.length, 0);
  assert.match(harness.notifications.at(-1).message, /no scoped models/i);
  assert.match(harness.notifications.at(-1).message, /--models/);
});

test("registers discoverable classifier selector commands and keeps aliases", async () => {
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
  const modelCommand = harness.commands.get("automode-model");
  const thinkingCommand = harness.commands.get("automode-thinking");
  assert.equal(modelCommand.description, "Choose the auto-mode classifier model");
  assert.equal(thinkingCommand.description, "Configure the auto-mode classifier thinking level");
  assert.deepEqual(modelCommand.getArgumentCompletions("re").map((item) => item.value), ["reset"]);
  assert.deepEqual(thinkingCommand.getArgumentCompletions("ma").map((item) => item.value), ["max"]);

  await modelCommand.handler("", harness.context);
  assert.equal(harness.selectCalls[0].title, "Select the auto-mode classifier model:");
  assert.deepEqual(globalModeState.current.classifierModel, { provider: "vertex", id: "gemini/flash" });

  await thinkingCommand.handler("", harness.context);
  assert.equal(harness.selectCalls[1].title, "Select the auto-mode classifier thinking level:");
  assert.equal(globalModeState.current.classifierThinkingLevel, "medium");

  const alias = createHarness({
    hasUI: true,
    models,
    modelChoice: "vertex/gemini/flash - vertex - Gemini Flash",
    thinkingChoice: "low - supported",
    globalModeState: { current: undefined },
  });
  await alias.startSession();
  await alias.commands.get("automode").handler("model", alias.context);
  await alias.commands.get("automode").handler("thinking low", alias.context);
  assert.deepEqual(alias.selectCalls.map((call) => call.title), ["Select the auto-mode classifier model:"]);
  assert.equal(alias.modeEntries().at(-1).data.classifierThinkingLevel, "low");
});

test("dedicated classifier selector commands support direct noninteractive forms", async () => {
  const globalModeState = { current: undefined };
  const models = [
    { provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: true },
  ];
  const harness = createHarness({ hasUI: false, mode: "json", models, globalModeState });
  await harness.startSession();

  await harness.commands.get("automode-model").handler("vertex/gemini/flash", harness.context);
  await harness.commands.get("automode-thinking").handler("medium", harness.context);
  assert.deepEqual(globalModeState.current.classifierModel, { provider: "vertex", id: "gemini/flash" });
  assert.equal(globalModeState.current.classifierThinkingLevel, "medium");
  assert.equal(harness.selectCalls.length, 0);

  const savedState = { ...globalModeState.current };
  await harness.commands.get("automode-model").handler("", harness.context);
  await harness.commands.get("automode-thinking").handler("", harness.context);
  assert.equal(harness.selectCalls.length, 0);
  assert.deepEqual(globalModeState.current, savedState);
});
test("configures, reports, validates, persists, and resets classifier thinking", async () => {
  const globalModeState = { current: undefined };
  const harness = createHarness({
    hasUI: true,
    globalModeState,
    classifierText: '{"decision":"allow","rationale":"The configured classifier level was applied."}',
  });
  const command = harness.commands.get("automode");
  harness.context.thinkingLevel = "medium";

  await harness.startSession();
  await command.handler("thinking max", harness.context);
  assert.equal(harness.context.thinkingLevel, "medium");
  assert.equal(globalModeState.current.classifierThinkingLevel, "max");
  assert.equal(harness.modeEntries().at(-1).data.classifierThinkingLevel, "max");
  assert.match(harness.notifications.at(-1).message, /thinking max -> high/);
  assert.equal(harness.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-5.6-luna, thinking max -> high, web on)");

  const persistedAfterSet = { ...globalModeState.current };
  await command.handler("thinking", harness.context);
  assert.match(harness.notifications.at(-1).message, /configured as max and effective as high/);
  assert.deepEqual(globalModeState.current, persistedAfterSet);

  await command.handler("thinking invalid", harness.context);
  assert.match(harness.notifications.at(-1).message, /Usage: \/automode thinking/);
  assert.deepEqual(globalModeState.current, persistedAfterSet);
  await command.handler("thinking low extra", harness.context);
  assert.match(harness.notifications.at(-1).message, /Usage: \/automode thinking/);
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
        webVerificationEnabled: false,
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
    const result = await harness.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
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
    { provider: "github-copilot", id: "gpt-5.6-luna", name: "GPT-5.6 Luna", input: ["text"], reasoning: true },
    { provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: true },
  ];
  const first = createHarness({ hasUI: true, models, globalModeState });
  await first.startSession();
  await first.commands.get("automode").handler("thinking medium", first.context);
  assert.equal(globalModeState.current.classifierThinkingLevel, "medium");

  const next = createHarness({
    hasUI: true,
    models,
    globalModeState,
    classifierText: '{"decision":"allow","rationale":"The persisted level was used."}',
  });
  await next.startSession();
  assert.equal(next.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-5.6-luna, thinking medium, web on)");
  await next.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
  assert.equal(next.classifierCalls[0].options.reasoning, "medium");
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

  await harness.commands.get("automode-model").handler("", harness.context);
  assert.equal(harness.refreshCalls, 0);
  assert.deepEqual(globalModeState.current.classifierModel, { provider: "vertex", id: "gemini/flash" });
  await harness.commands.get("automode-thinking").handler("", harness.context);
  assert.equal(globalModeState.current.classifierThinkingLevel, "high");
  assert.deepEqual(harness.selectCalls.map((call) => call.title), [
    "Select the auto-mode classifier model:",
    "Select the auto-mode classifier thinking level:",
  ]);
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
  const completions = harness.commands.get("automode").getArgumentCompletions;

  assert.deepEqual(completions("model re").map((item) => item.value), ["reset"]);
  assert.equal(completions("model reset"), null);
  assert.equal(completions("model reset "), null);
  assert.equal(completions("model github-copilot/gpt-5.6-luna"), null);
  assert.equal(completions("model github-copilot/gpt-5.6-luna "), null);
  assert.equal(completions("model github-copilot/gpt-5.6-luna extra"), null);
  assert.equal(completions("model re extra"), null);
  assert.deepEqual(completions("thinking ").map((item) => item.value), [
    "off",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
    "max",
    "reset",
  ]);
  assert.deepEqual(completions("thinking ma").map((item) => item.value), ["max"]);
  assert.deepEqual(completions("thinking re").map((item) => item.value), ["reset"]);
  assert.equal(completions("thinking max"), null);
  assert.equal(completions("thinking max extra"), null);
});

test("rejects a picker in noninteractive mode without changing state", async () => {
  const globalModeState = { current: { autoModeEnabled: true, webVerificationEnabled: true } };
  const harness = createHarness({
    hasUI: false,
    mode: "json",
    globalModeState,
    models: [{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: false }],
  });

  await harness.commands.get("automode").handler("model", harness.context);
  assert.equal(harness.refreshCalls, 0);
  assert.deepEqual(globalModeState.current, { autoModeEnabled: true, webVerificationEnabled: true });
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
  await first.commands.get("automode").handler("model vertex/gemini/flash", first.context);
  assert.equal(first.refreshCalls, 1);
  assert.deepEqual(first.registryEvents.slice(-2), ["refresh", "getAvailable"]);
  assert.deepEqual(globalModeState.current.classifierModel, { provider: "vertex", id: "gemini/flash" });
  assert.equal(first.context.model, activeModel);

  const result = await first.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
  assert.equal(result, undefined);
  assert.equal(first.classifierCalls[0].model.provider, "vertex");
  assert.equal(first.classifierCalls[0].model.id, "gemini/flash");
  assert.equal(first.classifierCalls[0].options.reasoning, undefined);
  assert.equal(Object.hasOwn(first.classifierCalls[0].options, "reasoningEffort"), false);
  assert.equal(first.context.model, activeModel);

  const next = createHarness({ hasUI: true, models, activeModel, globalModeState });
  await next.startSession();
  assert.equal(next.statuses.get("permission-gate"), "auto mode: ON (vertex/gemini/flash, thinking high -> off, web on)");
  await next.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
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
        webVerificationEnabled: true,
        classifierModel: { provider: "  vertex  ", id: "  gemini/flash  " },
      },
    },
    models: [{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: false }],
  });

  await harness.startSession();
  const result = await harness.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
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
        webVerificationEnabled: true,
        classifierModel: { provider: "vertex", id: "removed/model" },
      },
    },
    models: [{ provider: "github-copilot", id: "gpt-5.6-luna", name: "GPT-5.6 Luna", input: ["text"], reasoning: true }],
  });

  await harness.startSession();
  const result = await harness.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
  assert.equal(result.block, true);
  assert.match(result.reason, /vertex\/removed\/model \(thinking high -> unavailable\)/);
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
        webVerificationEnabled: false,
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
  const result = await harness.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
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

test("fails closed on an unsuccessful request-auth resolution", async () => {
  const harness = createHarness({
    hasUI: false,
    models: [{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: false }],
    globalModeState: {
      current: {
        autoModeEnabled: true,
        webVerificationEnabled: true,
        classifierModel: { provider: "vertex", id: "gemini/flash" },
      },
    },
    requestAuth: { vertex: { ok: false, error: "secret-token-must-not-be-shown" } },
  });

  await harness.startSession();
  const result = await harness.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
  assert.equal(result.block, true);
  assert.match(result.reason, /authentication.*unavailable/i);
  assert.doesNotMatch(result.reason, /secret-token/);
  assert.equal(harness.classifierCalls.length, 0);
});

test("uses the selected classifier for both calls around fixed web verification", async () => {
  const models = [
    { provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: true },
    { provider: "github-copilot", id: "gpt-5.6-luna", name: "GPT-5.6 Luna", input: ["text"], reasoning: true },
  ];
  const harness = createHarness({
    hasUI: true,
    models,
    webSearchAvailable: true,
    globalModeState: {
      current: {
        autoModeEnabled: true,
        webVerificationEnabled: true,
        classifierModel: { provider: "vertex", id: "gemini/flash" },
        classifierThinkingLevel: "max",
      },
    },
    classifierTexts: [
      '{"decision":"deny","needs_web_search":true,"search_query":"package safety","rationale":"The package identity needs verification."}',
      '{"decision":"allow","rationale":"The web evidence supports this bounded operation."}',
    ],
  });

  await harness.startSession();
  const result = await harness.invoke({ toolName: "bash", input: { command: "npx example-package --help" } });
  assert.equal(result, undefined);
  assert.equal(harness.classifierCalls.length, 2);
  assert.deepEqual(harness.classifierCalls.map((call) => `${call.model.provider}/${call.model.id}`), [
    "vertex/gemini/flash",
    "vertex/gemini/flash",
  ]);
  assert.equal(harness.classifierCalls[0].options.reasoning, "high");
  assert.equal(harness.classifierCalls[1].options.reasoning, "high");
  assert.match(harness.decisionEntries()[0].data.model, /thinking max -> high/);
  assert.equal(harness.execCalls[0].args[harness.execCalls[0].args.indexOf("--model") + 1], "github-copilot/gpt-5.6-luna");
  assert.equal(harness.execCalls[0].args[harness.execCalls[0].args.indexOf("--thinking") + 1], "high");
});
