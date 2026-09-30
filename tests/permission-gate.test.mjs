import assert from "node:assert/strict";
import test from "node:test";

import {
  buildAutoModePrompt,
  createPermissionGate,
  hardDenyReasons,
  matchedReasons,
  parseAutoModeDecision,
} from "../extensions/permission-gate.ts";

test("user command patterns match regex metacharacters literally", () => {
  const rules = { allowedCommands: ["npx foo.bar+baz"], disallowedCommands: [] };
  assert.deepEqual(matchedReasons("npx foo.bar+baz", rules), []);
  assert.deepEqual(matchedReasons("npx fooXbar+baz", rules), ["package runner"]);
});

function createHarness({
  hasUI = false,
  mode = "tui",
  activeModel = { provider: "active-provider", id: "active-model" },
  choice,
  modelChoice,
  thinkingChoice,
  classifierText = '{"decision":"deny","rationale":"The command is not sufficiently scoped."}',
  classifierError,
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
} = {}) {
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

  const nextClassifierResponse = () => {
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
      async select(title, options) {
        selectCalls.push({ title, options });
        if (title === "Save permission gate rules:") return ruleSaveChoice;
        if (title === "Select the auto-mode classifier model:") return modelChoice ?? options[0];
        if (title === "Select the auto-mode classifier thinking level:") return thinkingChoice ?? options[0];
        if (selectResponses.length > 0) return selectResponses.shift();
        return choice;
      },
      async input(title, placeholder) {
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
    classifierCalls.push({ model, request, options });
    return nextClassifierResponse();
  };

  createPermissionGate(pi, {
    ...(useComplete ? { complete } : {}),
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
    commands,
    entries,
    renderers,
    notifications,
    statuses,
    selectCalls,
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

test("recognizes soft and hard permission rules", () => {
  assert.deepEqual(matchedReasons("rm -rf /tmp/example"), ["recursive/forced rm"]);
  assert.deepEqual(hardDenyReasons("rm -rf /tmp/example"), []);
  assert.deepEqual(matchedReasons("rtk uv run pytest"), []);
  assert.deepEqual(matchedReasons("rtk uv run ruff check ."), []);
  assert.deepEqual(matchedReasons("rtk uv run mypy"), []);
  assert.ok(matchedReasons("uv run python script.py").includes("package execution or publish"));
  assert.deepEqual(matchedReasons("npm install ruff"), []);
  assert.ok(matchedReasons("rm -rf build", undefined, "/tmp/project").includes("recursive/forced rm"));
  assert.deepEqual(matchedReasons("find build -type f -delete", undefined, "/tmp/project"), []);
  assert.ok(matchedReasons("rm -rf ../outside", undefined, "/tmp/project").includes("recursive/forced rm"));
  assert.ok(matchedReasons("find . -delete", undefined, "/tmp/project").includes("find delete"));
  assert.ok(matchedReasons("rtk uv run pytest && rm -rf /tmp/example").includes("recursive/forced rm"));
  assert.ok(hardDenyReasons("rm -rf /").includes("recursive delete of a system or home root"));
});

test("file deletions from the reported session are not hard-denied", async () => {
  const project = "/Users/A200048/GitLab/AISE/skill-workspace";
  const references = "skills/snowflake-query/references";
  const python = "/Users/A200048/GitLab/AISE/lea-goldhamster/lea/.venv/bin/python";
  const commands = [
    `set -e
cd ${project}
test "$(git branch --show-current)" = feat/snowflake-query-skill
test -z "$(git status --porcelain)"
launchctl bootout gui/$(id -u)/com.a200048.skill-workspace.autocommit
git rm ${references}/lea.md ${references}/root.md
${python} /Users/A200048/.pi/agent/skills/snowflake-query/scripts/test_run_query.py
${python.replace(/python$/, "ruff")} check --select E4,E7,E9,F,I skills/snowflake-query/scripts
${python.replace(/python$/, "ruff")} format --check skills/snowflake-query/scripts
if rg -n -i '\\b(lea|root|aise|a_user|databaseconnection)\\b' skills/snowflake-query --glob '*.md' --glob '*.py'; then
  printf 'Unexpected repository-specific reference\\n'; exit 1
fi
git diff --cached --check
git diff --cached --stat
git commit -m 'refactor(skills): remove repository-specific Snowflake adapters'
git push origin feat/snowflake-query-skill`,
    `/bin/rm ${project}/${references}/lea.md ${project}/${references}/root.md`,
  ];
  const harness = createHarness({
    classifierText: '{"decision":"allow","rationale":"Delete only the two requested files."}',
  });
  await harness.startSession();
  for (const command of commands) {
    assert.deepEqual(hardDenyReasons(command), [], command);
    assert.equal(await harness.invoke({ toolName: "bash", input: { command } }), undefined, command);
  }
  assert.equal(harness.classifierCalls.length, 1);
  assert.equal(harness.decisionEntries()[0].data.source, "auto-model");
});

test("rm recursion rules match option tokens, not paths or the next command", () => {
  for (const command of [
    "rm /Users/me/project/snowflake-query/file.md /Users/me/project/other.md",
    "git rm snowflake-query/file.md\n/usr/bin/true",
    "rm --force /Users/me/project/file.md",
    "rm file.md\n--recursive /",
    "rm -r build\n/usr/bin/true",
    'rm snowflake-query/file.md "$file"',
    "rm --force '$file'",
  ]) {
    assert.deepEqual(hardDenyReasons(command), [], command);
  }
  for (const command of [
    "rm --force /Users/me/project/file.md",
    "rm file.md\n--recursive /",
    "rm /Users/me/project/snowflake-query/file.md /Users/me/project/other.md",
  ]) {
    assert.equal(matchedReasons(command).includes("recursive/forced rm"), false, command);
  }
  for (const option of ["-r", "-rf", "-fr", "-R", "--recursive", '"-rf"', "'--recursive'"]) {
    const command = `/bin/rm ${option} /`;
    assert.ok(hardDenyReasons(command).includes("recursive delete of a system or home root"), command);
    assert.ok(matchedReasons(command).includes("recursive/forced rm"), command);
    assert.ok(hardDenyReasons(`rm ${option} "$unknown"`).includes("unresolved recursive delete target"));
    assert.ok(matchedReasons(`rm build ${option}; true`).includes("recursive/forced rm"));
  }
});

test("recursive rm always needs the classifier", () => {
  const cwd = "/Users/me/project";
  for (const command of [
    "rm -rf build",
    "rm -rf /tmp/example",
    'rm -rf "/private/tmp/lea-gitleaks"',
    "rm -r dist",
    "rm --recursive dist",
  ]) {
    assert.ok(matchedReasons(command, undefined, cwd).includes("recursive/forced rm"), command);
    // User allow patterns cannot skip the classifier for recursive rm.
    const rules = { allowedCommands: ["rm *"], disallowedCommands: [] };
    assert.ok(matchedReasons(command, rules, cwd).includes("recursive/forced rm"), command);
  }
  // Temp targets are not hard-denied, so they reach the classifier.
  assert.deepEqual(hardDenyReasons("rm -rf /private/tmp/lea-gitleaks"), []);
  assert.ok(hardDenyReasons("rm -rf /private/tmp/../etc").includes("recursive delete of a system or home root"));

  // mktemp variables are resolved for the hard-deny layer, so the classifier decides
  // (real blocked commands from error reports).
  for (const command of [
    'tmpdir=$(mktemp -d) && PI_CODING_AGENT_DIR="$tmpdir" node x.mjs; rm -rf "$tmpdir"',
    "set +e\nTMP_CACHE=$(mktemp -d /tmp/ty-uv-cache.XXXXXX)\ntrap 'rm -rf \"$TMP_CACHE\"' EXIT\nuvx ty",
    'tmp=$(mktemp -d /tmp/root-review-XXXX); printf x > "$tmp/a.py"; rm -rf "${tmp}"',
    'rm -rf "$TMPDIR/build"',
  ]) {
    assert.deepEqual(hardDenyReasons(command), [], command);
  }
  // Reassignment, expansion tricks, globs, and escapes keep the hard deny.
  for (const command of [
    'tmp=$(mktemp -d); tmp=/; rm -rf "$tmp"',
    'tmp=$(mktemp -d); read tmp; rm -rf "$tmp"',
    'tmp=$(mktemp -d); rm -rf "${tmp:-/}"',
    'tmp=$(mktemp -d); rm -rf "$tmp"/*',
    'tmp=$(mktemp -d); rm -rf "$tmp/../.."',
    'TMPDIR=/ rm -rf "$TMPDIR"',
    'dir=$(pwd); rm -rf "$dir"',
  ]) {
    assert.ok(hardDenyReasons(command).length > 0, command);
  }
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
  assert.equal(parseAutoModeDecision('{"decision":"deny","unexpected":"extra","rationale":"Reject unknown fields."}'), undefined);
  assert.equal(parseAutoModeDecision("```json\n{\"decision\":\"deny\",\"rationale\":\"Unclear target.\"}\n```"), undefined);
  assert.equal(parseAutoModeDecision('{"decision":"allow","rationale":"ok","extra":"reject this"}'), undefined);
  assert.equal(parseAutoModeDecision('{"decision":"allow"}'), undefined);
  assert.equal(parseAutoModeDecision("not JSON"), undefined);
});

test("edits allowed and disallowed command patterns from unified settings", async () => {
  const globalRules = { current: undefined };
  const harness = createHarness({
    hasUI: true,
    mode: "rpc",
    globalRules,
    editedRules: JSON.stringify({
      allowedCommands: ["uv run python*", "rm -rf *"],
      disallowedCommands: ["npm install evil*"],
    }),
    ruleSaveChoice: "Save as global default",
    selectResponses: [
      "Command rules - 6 allowed / 0 denied",
      "Edit command patterns",
      "Cancel",
    ],
  });

  await harness.startSession();
  await harness.commands.get("automode-settings").handler("", harness.context);
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
    input: { command: "rm -rf ../example" },
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

test("injects persisted auto-mode preference notes into classifier prompts", async () => {
  const globalPreferences = { current: "- Keep operations inside the current project whenever possible." };
  const harness = createHarness({
    hasUI: false,
    globalPreferences,
    classifierText: '{"decision":"allow","rationale":"The user preference permits this bounded operation."}',
  });

  await harness.startSession();
  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "rm -rf ../example" },
  });

  assert.equal(result, undefined);
  assert.match(harness.classifierCalls[0].request.systemPrompt, /Keep operations inside the current project/);
  assert.match(harness.classifierCalls[0].request.messages[0].content[0].text, /<auto_mode_preferences>/);
  assert.match(harness.classifierCalls[0].request.messages[0].content[0].text, /Keep operations inside the current project/);
});

test("adds preference notes and edits the preference file through commands", async () => {
  const globalPreferences = { current: "- Existing preference" };
  const harness = createHarness({
    hasUI: true,
    globalPreferences,
    editedPreferences: "- Edited preference",
  });

  await harness.startSession();
  await harness.commands.get("automode-settings").handler("preferences Prefer read-only checks before mutations", harness.context);
  assert.match(globalPreferences.current, /Existing preference/);
  assert.match(globalPreferences.current, /Prefer read-only checks before mutations/);

  await harness.commands.get("automode-settings").handler("preferences", harness.context);
  assert.equal(globalPreferences.current, "- Edited preference");
  assert.equal(harness.editorCalls.at(-1).title, "Edit auto-mode classifier preference notes");
  assert.equal(harness.editorCalls.at(-1).initialValue.includes("Prefer read-only checks"), true);
});

test("shows the classifier prompt with injected preferences", async () => {
  const globalPreferences = { current: "- Always deny production changes." };
  const harness = createHarness({ hasUI: true, globalPreferences });

  await harness.startSession();
  await harness.commands.get("automode-settings").handler("prompt", harness.context);

  const promptEditor = harness.editorCalls.at(-1);
  assert.equal(promptEditor.title, "Auto-mode classifier prompt (close without saving)");
  assert.match(promptEditor.initialValue, /SYSTEM PROMPT/);
  assert.match(promptEditor.initialValue, /Always deny production changes/);
  assert.match(promptEditor.initialValue, /USER PROMPT TEMPLATE/);
  assert.match(promptEditor.initialValue, /<auto_mode_preferences>/);
  assert.match(buildAutoModePrompt(globalPreferences.current), /Always deny production changes/);
});

test("auto mode approves a soft-deny command with the configured model", async () => {
  const harness = createHarness({
    hasUI: true,
    classifierText: '{"decision":"allow","rationale":"The target is a scoped sibling directory."}',
  });

  await harness.commands.get("automode-settings").handler("on", harness.context);
  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "rm -rf ../example" },
  });

  assert.equal(result, undefined);
  assert.equal(harness.classifierCalls.length, 1);
  assert.equal(harness.classifierCalls[0].model.id, "gpt-6-luna");
  assert.equal(harness.classifierCalls[0].options.reasoning, "high");
  assert.equal(harness.decisionEntries()[0].data.status, "approved");
  assert.equal(harness.decisionEntries()[0].data.source, "auto-model");
  assert.match(harness.decisionEntries()[0].data.model, /github-copilot\/gpt-6-luna \(thinking high\)/);
  assert.equal(harness.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-6-luna, thinking high)");
});

test("auto mode blocks a denied soft-deny command and records the rationale", async () => {
  const harness = createHarness({
    hasUI: true,
    classifierText: '{"decision":"deny","rationale":"Privilege escalation is not necessary for the stated task."}',
  });

  await harness.commands.get("automode-settings").handler("on", harness.context);
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

  await harness.commands.get("automode-settings").handler("on", harness.context);
  const result = await harness.invoke({
    toolName: "bash",
    input: { command: "sudo -n true" },
  });

  assert.equal(result.block, true);
  assert.match(result.reason, /classifier unavailable/);
  assert.equal(harness.decisionEntries()[0].data.status, "blocked");
});

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
    input: { command: "sudo -n true" },
  });

  assert.equal(result, undefined);
  assert.equal(harness.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-6-luna, thinking high)");
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
  assert.equal(harness.statuses.get("permission-gate"), undefined);
  await harness.commands.get("automode-settings").handler("status", harness.context);
  assert.match(harness.notifications.at(-1).message, /auto mode is OFF/);
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
  const result = await harness.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
  assert.equal(result.block, true);
  assert.match(result.reason, /unavailable classifier model/);
  assert.equal(harness.classifierCalls.length, 0);
});

test("keeps the global auto-mode state across new sessions, forks, reloads, and tree navigation", async () => {
  const globalModeState = { current: undefined };
  const firstSession = createHarness({ hasUI: true, globalModeState });

  await firstSession.startSession({ type: "session_start", reason: "startup" });
  assert.equal(firstSession.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-6-luna, thinking high)");

  const nextSession = createHarness({ hasUI: true, globalModeState });
  await nextSession.startSession({ type: "session_start", reason: "fork" });
  assert.equal(nextSession.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-6-luna, thinking high)");

  await nextSession.startSession({ type: "session_start", reason: "reload" });
  nextSession.handlers.get("session_tree")({}, nextSession.context);
  assert.equal(nextSession.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-6-luna, thinking high)");

  await nextSession.commands.get("automode-settings").handler("off", nextSession.context);
  const resumedSession = createHarness({ hasUI: true, globalModeState });
  await resumedSession.startSession({ type: "session_start", reason: "resume" });
  assert.equal(resumedSession.statuses.get("permission-gate"), undefined);
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
  });

  await command.handler("status", harness.context);
  assert.match(harness.notifications.at(-1).message, /is ON/);

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
  assert.deepEqual(completions.slice(0, 2).map((item) => item.value), ["reset", "github-copilot/gpt-6-luna"]);
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
    classifierModel: { provider: "github-copilot", id: "gpt-6-luna" },
    classifierThinkingLevel: "high",
    classifierHistoryMessages: 12,
  });
});

test("registers only the current auto-mode settings command", () => {
  const harness = createHarness();
  assert.deepEqual([...harness.commands.keys()], ["automode-settings"]);
});

test("central auto-mode settings command groups configuration", async () => {
  const harness = createHarness({ hasUI: true, editedPreferences: "- Prefer bounded changes" });
  const command = harness.commands.get("automode-settings");

  await harness.startSession();
  await command.handler("status", harness.context);
  assert.match(harness.notifications.at(-1).message, /auto mode is ON/);

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
    selectResponses: [
      "Classifier preferences - 1 note",
      "Edit preference notes",
      "Cancel",
    ],
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
    selectResponses: [
      "Command rules - 1 allowed / 1 denied",
      "Allowed - npm test*",
      "Cancel",
    ],
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

test("toggles auto mode from the unified settings page", async () => {
  const globalModeState = { current: { autoModeEnabled: false } };
  const harness = createHarness({
    hasUI: true,
    mode: "rpc",
    globalModeState,
    selectResponses: [
      "Automatic safety decisions - off",
      "on",
      "Cancel",
    ],
  });

  await harness.startSession();
  await harness.commands.get("automode-settings").handler("", harness.context);

  assert.equal(globalModeState.current.autoModeEnabled, true);
  assert.deepEqual(harness.selectCalls.map((call) => call.title), [
    "Permission Gate Settings",
    "Automatic safety decisions",
    "Permission Gate Settings",
  ]);
  assert.match(harness.notifications.at(-1).message, /auto mode enabled/);
});

test("opens the classifier prompt from the unified settings page", async () => {
  const globalPreferences = { current: "- Keep the prompt route covered." };
  const harness = createHarness({
    hasUI: true,
    mode: "rpc",
    globalPreferences,
    selectResponses: [
      "View classifier prompt",
      "Cancel",
    ],
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

  const report = harness.notifications.find(({ message }) => message.includes("Permission gate command rules (global)"));
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
  assert.deepEqual(modelCommand.getArgumentCompletions("model ").map((item) => item.value), ["reset", "scoped/model"]);
  assert.equal(modelCommand.getArgumentCompletions("model ").some((item) => item.value.includes("registry-only")), false);

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
  assert.deepEqual(command.getArgumentCompletions("model re").map((item) => item.value), ["reset"]);
  assert.deepEqual(command.getArgumentCompletions("thinking ma").map((item) => item.value), ["max"]);

  await command.handler("model", harness.context);
  assert.equal(harness.selectCalls[0].title, "Select the auto-mode classifier model:");
  assert.deepEqual(globalModeState.current.classifierModel, { provider: "vertex", id: "gemini/flash" });

  await command.handler("thinking", harness.context);
  assert.equal(harness.selectCalls[1].title, "Select the auto-mode classifier thinking level:");
  assert.equal(globalModeState.current.classifierThinkingLevel, "medium");
});

test("central settings support direct noninteractive model and thinking forms", async () => {
  const globalModeState = { current: undefined };
  const models = [
    { provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: true },
  ];
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
  assert.equal(harness.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-6-luna, thinking max -> high)");

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
  assert.equal(next.statuses.get("permission-gate"), "auto mode: ON (github-copilot/gpt-6-luna, thinking medium)");
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

  await harness.commands.get("automode-settings").handler("model", harness.context);
  assert.equal(harness.refreshCalls, 0);
  assert.deepEqual(globalModeState.current.classifierModel, { provider: "vertex", id: "gemini/flash" });
  await harness.commands.get("automode-settings").handler("thinking", harness.context);
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
  const completions = harness.commands.get("automode-settings").getArgumentCompletions;

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
  await harness.invoke({ toolName: "bash", input: { command: "sudo -n true" } });

  const sentPrompt = harness.classifierCalls[0].request.messages[0].content[0].text;
  assert.doesNotMatch(sentPrompt, /msg-1/);
  assert.doesNotMatch(sentPrompt, /msg-2/);
  assert.doesNotMatch(sentPrompt, /msg-3/);
  assert.match(sentPrompt, /msg-4/);
  assert.match(sentPrompt, /msg-5/);
});

test("configures context history messages via settings dialog and select completions", async () => {
  const globalModeState = { current: undefined };
  const harness = createHarness({
    hasUI: true,
    mode: "rpc",
    globalModeState,
    selectResponses: [
      "Context history messages - 12",
      "20 messages",
      "Cancel",
    ],
  });

  await harness.startSession();
  const command = harness.commands.get("automode-settings");
  const completions = command.getArgumentCompletions("history ");
  assert.ok(completions.some((item) => item.value === "reset"));
  assert.ok(completions.some((item) => item.value === "20"));

  await command.handler("", harness.context);
  assert.equal(globalModeState.current.classifierHistoryMessages, 20);
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

  const result = await first.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
  assert.equal(result, undefined);
  assert.equal(first.classifierCalls[0].model.provider, "vertex");
  assert.equal(first.classifierCalls[0].model.id, "gemini/flash");
  assert.equal(first.classifierCalls[0].options.reasoning, undefined);
  assert.equal(Object.hasOwn(first.classifierCalls[0].options, "reasoningEffort"), false);
  assert.equal(first.context.model, activeModel);

  const next = createHarness({ hasUI: true, models, activeModel, globalModeState });
  await next.startSession();
  assert.equal(next.statuses.get("permission-gate"), "auto mode: ON (vertex/gemini/flash, thinking high -> off)");
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
  const result = await harness.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
  assert.equal(result, undefined);
  assert.equal(harness.providerCalls.length, 1);
  assert.equal(harness.providerCalls[0].model.baseUrl, "https://api.business.githubcopilot.com");
});

test("classifier prompt reinforces strict json schema output directive", async () => {
  const harness = createHarness({
    hasUI: false,
    globalModeState: {
      current: {
        autoModeEnabled: true,
        classifierModel: { provider: "github-copilot", id: "gpt-6-luna" },
      },
    },
    classifierText: '{"decision":"allow","rationale":"Safe inspect command."}',
  });

  await harness.startSession();
  await harness.invoke({ toolName: "bash", input: { command: "sudo -n true" } });

  assert.equal(harness.classifierCalls.length, 1);
  const promptText = harness.classifierCalls[0].request.messages[0].content[0].text;
  assert.match(promptText, /Return exactly one JSON object and no markdown or extra text\./);
  assert.match(promptText, /\{"decision":"allow"\|"deny","rationale":"short explanation"\}/);
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
  const result = await harness.invoke({ toolName: "bash", input: { command: "sudo -n true" } });
  assert.equal(result.block, true);
  assert.match(result.reason, /authentication.*unavailable/i);
  assert.doesNotMatch(result.reason, /secret-token/);
  assert.equal(harness.classifierCalls.length, 0);
});
