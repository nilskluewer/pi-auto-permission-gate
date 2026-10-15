import assert from "node:assert/strict";
import test from "node:test";
import { visibleWidth } from "@earendil-works/pi-tui";
import { initTheme } from "@earendil-works/pi-coding-agent";
import { openPermissionSettings } from "../permission-gate-settings.ts";

initTheme("dark", false);

const state = {
  autoModeEnabled: false,
  classifierModel: "provider/model",
  classifierModelOptions: [{ value: "provider/model", label: "Model" }],
  classifierThinking: "low",
  classifierThinkingOptions: [{ value: "low", label: "Low" }],
  classifierHistoryMessages: 3,
  classifierHistoryMessageOptions: [{ value: "3", label: "3 messages" }],
  ruleScope: "global",
  allowedCommands: [],
  disallowedCommands: [],
  preferences: "",
};
const mainLabels = [
  "Automatic safety decisions - off",
  "Classifier model - provider/model",
  "Classifier thinking - low",
  "Context history messages - 3",
  "Command rules - 0 allowed / 0 denied",
  "Classifier preferences - none",
  "View classifier prompt",
  "Destructive Command Guard (DCG) - off",
  "Cancel",
];

async function rpc(responses, view = state) {
  const calls = [];
  const result = await openPermissionSettings({
    mode: "rpc", hasUI: true,
    ui: {
      async select(title, options) {
        calls.push({ title, options });
        return responses.shift();
      },
      custom() { assert.fail("RPC must not use custom terminal UI"); },
      input() { assert.fail("Binary dialogs belong to the main gate"); },
      confirm() { assert.fail("Settings must not add an approval UI"); },
    },
  }, view);
  return { result, calls };
}

const actions = [
  ["off", { type: "dcg-mode", value: "off" }],
  ["observe", { type: "dcg-mode", value: "observe" }],
  ["enforce", { type: "dcg-mode", value: "enforce" }],
  ["Configure trusted binary", { type: "dcg-binary" }],
  ["Show DCG status", { type: "dcg-status" }],
];
for (const [label, action] of actions) {
  test(`RPC DCG ${label} returns a main-gate action`, async () => {
    const view = structuredClone(state);
    const { result, calls } = await rpc([mainLabels[7], label], view);
    assert.deepEqual(result, action);
    assert.deepEqual(calls[0].options, mainLabels);
    assert.deepEqual(calls[1].options, [...actions.map(([label]) => label), "Cancel"]);
    assert.match(calls[1].title, /Mode: off/);
    assert.match(calls[1].title, /Trusted absolute binary path: not configured/);
    assert.match(calls[1].title, /SHA-256: not configured/);
    assert.match(calls[1].title, /Status: not configured/);
    assert.match(calls[1].title, /Observe never blocks solely on DCG/);
    assert.match(calls[1].title, /failures require human review or block without UI/);
    assert.deepEqual(view, state);
  });
}

test("RPC shows the supplied binary, hash, mode and status without claiming verification", async () => {
  const view = { ...state, dcgMode: "observe", dcgBinaryPath: "/opt/trusted/dcg", dcgSha256: "ab".repeat(32), dcgStatus: "Enforcement unavailable: policy isolation unverified" };
  const { result, calls } = await rpc(["Destructive Command Guard (DCG) - observe", "Show DCG status"], view);
  assert.deepEqual(result, { type: "dcg-status" });
  for (const value of [view.dcgBinaryPath, view.dcgSha256, view.dcgStatus]) assert.ok(calls[1].title.includes(value));
  assert.match(calls[1].title, /main gate validates/);
});

test("RPC cancellation and unknown DCG selections return no action", async () => {
  for (const selected of [undefined, "Cancel", "unexpected"]) {
    assert.equal((await rpc([mainLabels[7], selected])).result, undefined);
  }
  assert.equal((await rpc(["Cancel"])).result, undefined);
});

test("original RPC settings retain their action behavior and ordering", async () => {
  const cases = [
    [0, "on", { type: "auto-mode", value: "on" }],
    [1, "Model", { type: "classifier-model", value: "provider/model" }],
    [2, "Low", { type: "classifier-thinking", value: "low" }],
    [3, "3 messages", { type: "history-messages", value: 3 }],
    [4, "Edit command patterns", { type: "command-rules", value: "edit" }],
    [5, "Add a preference note", { type: "preferences", value: "add" }],
    [6, undefined, { type: "prompt" }],
  ];
  for (const [index, selection, action] of cases) {
    const { result, calls } = await rpc([mainLabels[index], selection]);
    assert.deepEqual(result, action);
    assert.deepEqual(calls[0].options, mainLabels);
  }
});

const down = "\u001b[B";
const enter = "\r";
const escape = "\u001b";
const theme = { fg: (_color, text) => text, bold: (text) => text };
async function tui(drive, view = state) {
  return openPermissionSettings({
    mode: "tui", hasUI: true,
    ui: {
      custom(factory) {
        return new Promise((resolve) => {
          const component = factory({ requestRender() {} }, theme, {}, resolve);
          drive(component);
        });
      },
      select() { assert.fail("TUI must use existing components"); },
    },
  }, view);
}
function openDcg(component) {
  for (let index = 0; index < 7; index++) component.handleInput(down);
  component.handleInput(enter);
}
for (const [index, [label, action]] of actions.entries()) {
  test(`TUI DCG ${label} returns the same action as RPC`, async () => {
    const result = await tui((component) => {
      openDcg(component);
      const text = component.render(100).join("\n");
      assert.match(text, /Mode: off/);
      assert.match(text, /SHA-256: not configured/);
      assert.match(text, /Status: not configured/);
      assert.match(text, /Observe never blocks solely on DCG/);
      for (const width of [24, 60, 100]) {
        for (const line of component.render(width)) assert.ok(visibleWidth(line) <= width);
      }
      component.invalidate();
      for (let n = 0; n < index; n++) component.handleInput(down);
      component.handleInput(enter);
    });
    assert.deepEqual(result, action);
  });
}

test("TUI escaping the DCG subpage returns to unchanged settings", async () => {
  const result = await tui((component) => {
    const original = component.render(100).join("\n");
    assert.ok(original.indexOf("View classifier prompt") < original.indexOf("Destructive Command Guard"));
    openDcg(component);
    component.handleInput(escape);
    assert.match(component.render(100).join("\n"), /Permission Gate Settings/);
    component.handleInput(escape);
  });
  assert.equal(result, undefined);
});

test("TUI original settings still return their actions", async () => {
  assert.deepEqual(await tui((component) => component.handleInput(enter)), { type: "auto-mode", value: "on" });
  assert.deepEqual(await tui((component) => {
    for (let index = 0; index < 6; index++) component.handleInput(down);
    component.handleInput(enter);
  }), { type: "prompt" });
});

test("no UI returns without invoking any dialogs", async () => {
  const ui = new Proxy({}, { get() { assert.fail("No UI must not access dialogs"); } });
  assert.equal(await openPermissionSettings({ mode: "print", hasUI: false, ui }, state), undefined);
});
