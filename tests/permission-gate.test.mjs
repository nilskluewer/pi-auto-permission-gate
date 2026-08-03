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
  choice,
  classifierText = '{"decision":"deny","rationale":"The command is not sufficiently scoped."}',
  classifierTexts,
  classifierError,
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
  const classifierCalls = [];
  const execCalls = [];
  let classifierCallIndex = 0;

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
    mode: "tui",
    hasUI,
    signal: undefined,
    sessionManager: {
      getBranch: () => branch,
    },
    modelRegistry: {
      find(provider, modelId) {
        assert.equal(provider, "github-copilot");
        assert.equal(modelId, "gpt-5.6-luna");
        return { provider, id: modelId };
      },
      async getApiKeyAndHeaders() {
        return { ok: true, apiKey: "test-token", headers: {}, env: {} };
      },
      async getProviderAuth() {
        return { auth: { apiKey: "test-token", headers: {} }, env: {} };
      },
    },
    isProjectTrusted() {
      return false;
    },
    ui: {
      async select(title) {
        if (title === "Save permission gate rules:") return ruleSaveChoice;
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
    if (classifierError) throw classifierError;
    const text = classifierTexts?.[classifierCallIndex++] ?? classifierText;
    return {
      content: [{ type: "text", text }],
      stopReason: "stop",
    };
  };

  createPermissionGate(pi, {
    complete,
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
    classifierCalls,
    execCalls,
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
  assert.equal(harness.classifierCalls[0].options.reasoningEffort, "high");
  assert.equal(harness.decisionEntries()[0].data.status, "approved");
  assert.equal(harness.decisionEntries()[0].data.source, "auto-model");
  assert.match(harness.decisionEntries()[0].data.model, /github-copilot\/gpt-5\.6-luna \(high\)/);
  assert.equal(harness.statuses.get("permission-gate"), "auto mode: ON (gpt-5.6-luna, high, web on)");
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

test("loads globally persisted auto-mode state on session start", async () => {
  const harness = createHarness({
    hasUI: true,
    classifierText: '{"decision":"allow","rationale":"The explicit test command is safe."}',
    globalModeState: { current: { autoModeEnabled: true, webVerificationEnabled: false } },
  });

  await harness.startSession();
  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "sudo -n true" },
  });

  assert.equal(result, undefined);
  assert.equal(harness.statuses.get("permission-gate"), "auto mode: ON (gpt-5.6-luna, high, web off)");
});

test("keeps the global auto-mode state across new sessions, forks, reloads, and tree navigation", async () => {
  const globalModeState = { current: undefined };
  const firstSession = createHarness({ hasUI: true, globalModeState });

  await firstSession.startSession({ type: "session_start", reason: "startup" });
  assert.equal(firstSession.statuses.get("permission-gate"), "auto mode: ON (gpt-5.6-luna, high, web on)");
  await firstSession.commands.get("automode").handler("web off", firstSession.context);

  const nextSession = createHarness({ hasUI: true, globalModeState });
  await nextSession.startSession({ type: "session_start", reason: "fork" });
  assert.equal(nextSession.statuses.get("permission-gate"), "auto mode: ON (gpt-5.6-luna, high, web off)");

  await nextSession.startSession({ type: "session_start", reason: "reload" });
  nextSession.handlers.get("session_tree")({}, nextSession.context);
  assert.equal(nextSession.statuses.get("permission-gate"), "auto mode: ON (gpt-5.6-luna, high, web off)");

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
  assert.deepEqual(harness.modeEntries()[0].data, { autoModeEnabled: true, webVerificationEnabled: true });

  await command.handler("web off", harness.context);
  assert.match(harness.notifications.at(-1).message, /web verification disabled/);
  assert.equal(harness.statuses.get("permission-gate"), "auto mode: ON (gpt-5.6-luna, high, web off)");

  await command.handler("status", harness.context);
  assert.match(harness.notifications.at(-1).message, /is ON/);
  assert.match(harness.notifications.at(-1).message, /web verification is OFF/);

  await command.handler("off", harness.context);
  assert.match(harness.notifications.at(-1).message, /disabled/);
  assert.equal(harness.statuses.get("permission-gate"), undefined);
});
