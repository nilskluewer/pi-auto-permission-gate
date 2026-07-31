import assert from "node:assert/strict";
import test from "node:test";

import permissionGate from "../extensions/permission-gate.ts";

function createHarness({ hasUI = false, choice } = {}) {
  let toolCallHandler;

  permissionGate({
    on(eventName, handler) {
      assert.equal(eventName, "tool_call");
      toolCallHandler = handler;
    },
  });

  return async (event) =>
    toolCallHandler(event, {
      hasUI,
      ui: {
        select: async () => choice,
      },
    });
}

test("ignores non-bash tool calls", async () => {
  const invoke = createHarness();

  const result = await invoke({
    toolName: "read",
    input: { path: "/tmp/example.txt" },
  });

  assert.equal(result, undefined);
});

test("allows safe bash commands", async () => {
  const invoke = createHarness({ hasUI: false });

  const result = await invoke({
    toolName: "bash",
    input: { command: "printf 'hello\\n'" },
  });

  assert.equal(result, undefined);
});

test("blocks dangerous commands without a UI", async () => {
  const invoke = createHarness({ hasUI: false });

  const result = await invoke({
    toolName: "bash",
    input: { command: "rm -rf /tmp/example" },
  });

  assert.equal(result.block, true);
  assert.match(result.reason, /recursive\/forced rm/);
  assert.match(result.reason, /no UI for confirmation/);
});

test("blocks a dangerous command when the user selects No", async () => {
  const invoke = createHarness({ hasUI: true, choice: "No" });

  const result = await invoke({
    toolName: "bash",
    input: { command: "git push --force origin main" },
  });

  assert.deepEqual(result, { block: true, reason: "Blocked by user" });
});

test("allows a dangerous command when the user selects Yes", async () => {
  const invoke = createHarness({ hasUI: true, choice: "Yes" });

  const result = await invoke({
    toolName: "bash",
    input: { command: "sudo -n true" },
  });

  assert.equal(result, undefined);
});

test("blocks an unconfirmed or dismissed selection", async () => {
  const invoke = createHarness({ hasUI: true });

  const result = await invoke({
    toolName: "bash",
    input: { command: "find . -delete" },
  });

  assert.deepEqual(result, { block: true, reason: "Blocked by user" });
});
