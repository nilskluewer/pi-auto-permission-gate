import assert from "node:assert/strict";
import test from "node:test";
import registerGate, { NO_GATE_FLAG } from "../extensions/permission-gate.ts";

// Loads the real extension with a minimal pi and returns the registered tool_call handlers.
function load(flag) {
	const handlers = new Map();
	const pi = {
		registerFlag() {},
		getFlag: (name) => (name === NO_GATE_FLAG ? flag : undefined),
		on: (event, handler) => handlers.set(event, [...(handlers.get(event) ?? []), handler]),
		registerCommand() {}, registerEntryRenderer() {}, appendEntry() {}, sendMessage() {},
	};
	registerGate(pi);
	return handlers;
}

// A context that records every access: an active gate reads it, an inactive gate does not.
function recordingCtx() {
	const touched = [];
	const ctx = new Proxy({}, { get: (_t, prop) => (touched.push(prop), undefined) });
	return { ctx, touched };
}

async function runToolCall(handlers) {
	const { ctx, touched } = recordingCtx();
	const results = [];
	for (const h of handlers.get("tool_call") ?? []) {
		try { results.push(await h({ toolName: "bash", input: { command: "rm -rf /tmp/x" } }, ctx)); } catch { results.push("threw"); }
	}
	return { results, touched };
}

test("--no-permission-gate inside the sandbox: every gate handler is a no-op", async () => {
	process.env.SPI = "1";
	const { results, touched } = await runToolCall(load(true));
	assert.ok(results.length > 0);
	assert.ok(results.every((r) => r === undefined));
	assert.deepEqual(touched, []);
});

test("--no-permission-gate outside the sandbox: the gate stays on", async () => {
	delete process.env.SPI;
	const { touched } = await runToolCall(load(true));
	assert.ok(touched.length > 0);
});

test("without the flag the gate is on, also in the sandbox", async () => {
	process.env.SPI = "1";
	const { touched } = await runToolCall(load(false));
	assert.ok(touched.length > 0);
	delete process.env.SPI;
});
