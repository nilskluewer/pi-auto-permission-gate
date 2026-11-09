import assert from "node:assert/strict";
import test from "node:test";
import { ALLOW, createHarness, run } from "./helpers/gate-harness.mjs";

const models = [
	{ provider: "vertex", id: "gemini/flash", name: "Gemini Flash", input: ["text"], reasoning: false },
	{ provider: "image-provider", id: "image", name: "Image Model", input: ["image"], reasoning: false },
];

// Pi defines an empty session scope as unrestricted, not as an empty catalogue.
test("fresh settings allow a picker switch without a configured session scope", async () => {
	const state = { current: undefined };
	const h = createHarness({
		hasUI: true,
		models,
		scopedModels: [],
		globalModeState: state,
		classifierText: ALLOW,
	});
	await h.startSession();
	const command = h.commands.get("automode-settings");
	assert.deepEqual(
		command.getArgumentCompletions("model ").map((item) => item.value),
		["reset", "vertex/gemini/flash"],
	);
	await command.handler("model", h.context);
	assert.deepEqual(h.selectCalls[0].options, ["vertex/gemini/flash - vertex - Gemini Flash"]);
	assert.deepEqual(state.current.classifierModel, { provider: "vertex", id: "gemini/flash" });
	assert.equal(h.refreshCalls, 0);
	await run(h, "git reset --hard HEAD~1");
	assert.equal(h.classifierCalls[0].model.id, "gemini/flash");

	const next = createHarness({ hasUI: true, models, scopedModels: [], globalModeState: state });
	await next.startSession();
	assert.match(next.statuses.get("permission-gate"), /vertex\/gemini\/flash/);
});

test("unified settings expose and persist models with an unrestricted session scope", async () => {
	const state = { current: undefined };
	const h = createHarness({ hasUI: true, mode: "rpc", models, scopedModels: [], globalModeState: state });
	await h.startSession();
	let calls = 0;
	h.context.ui.select = async (title, options) => {
		h.selectCalls.push({ title, options });
		calls += 1;
		if (calls === 1) return options.find((option) => option.startsWith("Classifier model - "));
		if (calls === 2) {
			assert.ok(options.includes("vertex/gemini/flash"));
			assert.ok(!options.some((option) => option.includes("image-provider")));
			return "vertex/gemini/flash";
		}
		return "Cancel";
	};
	await h.commands.get("automode-settings").handler("", h.context);
	assert.deepEqual(state.current.classifierModel, { provider: "vertex", id: "gemini/flash" });
});

test("an explicit scope without text models does not expose models outside that scope", async () => {
	const state = { current: undefined };
	const h = createHarness({
		hasUI: true,
		models,
		scopedModels: [{ model: models[1] }],
		globalModeState: state,
	});
	await h.startSession();
	const saved = structuredClone(state.current);
	const command = h.commands.get("automode-settings");
	assert.deepEqual(
		command.getArgumentCompletions("model ").map((item) => item.value),
		["reset"],
	);
	await command.handler("model", h.context);
	assert.equal(h.selectCalls.length, 0);
	assert.deepEqual(state.current, saved);
});

test("cancelling an unrestricted model picker does not change settings", async () => {
	const state = { current: undefined };
	const h = createHarness({ hasUI: true, models, scopedModels: [], globalModeState: state });
	await h.startSession();
	const saved = structuredClone(state.current);
	h.context.ui.select = async () => undefined;
	await h.commands.get("automode-settings").handler("model", h.context);
	assert.deepEqual(state.current, saved);
	assert.equal(h.modeEntries().length, 0);
});
