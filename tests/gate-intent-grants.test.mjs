// Covers intent grants behavior.
import assert from "node:assert/strict";
import test from "node:test";
import { createHarness, run, scriptProject } from "./helpers/gate-harness.mjs";

// Spec oracles: soft gaps reach the classifier; only the human can grant an intent.
// These checks reject a blanket gap prompt, unscoped grants, and cross-session reuse.
test("intent approvals cover only their paths, reasons, non-critical commands, and session", async (t) => {
	const dir = await scriptProject(t);
	const h = createHarness({
		hasUI: true,
		terminalWaits: true,
		approval: async () => ({ status: "approved", scope: "intent" }),
	});
	h.context.cwd = dir;
	await h.startSession();
	assert.equal(await run(h, "python main.py"), undefined);
	const first = h.decisionEntries().at(-1).data;
	assert.equal(first.scope, "intent");
	assert.ok(first.grantId);
	assert.equal(await run(h, "python main.py"), undefined);
	assert.equal(h.approvalRequests.length, 1);
	assert.equal(h.decisionEntries().at(-1).data.source, "intent-grant");
	assert.equal(h.decisionEntries().at(-1).data.grantId, first.grantId);
	await run(h, "uv run python main.py");
	assert.equal(h.approvalRequests.length, 2, "extra reason must prompt");
	await run(h, "sudo python main.py");
	assert.equal(h.approvalRequests.length, 3, "critical must prompt");
	h.context.cwd = "/tmp/another-project";
	await run(h, "python main.py");
	assert.equal(h.approvalRequests.length, 4, "other directory must prompt");
	h.context.cwd = dir;
	await h.startSession({ type: "session_start", reason: "switch" });
	await run(h, "python main.py");
	assert.equal(h.approvalRequests.length, 5, "new session must prompt");
});

test("a config-directory intent covers later writes there, but not another config directory", async () => {
	const h = createHarness({
		hasUI: true,
		terminalWaits: true,
		approval: async () => ({ status: "approved", scope: "intent" }),
	});
	await h.startSession();
	await run(h, "printf a > ~/.config/gcp-agent/a");
	assert.equal(h.decisionEntries().at(-1).data.scope, "intent");
	await run(h, "printf b > ~/.config/gcp-agent/b");
	assert.equal(h.approvalRequests.length, 1);
	assert.equal(h.decisionEntries().at(-1).data.source, "intent-grant");
	await run(h, "printf c > ~/.config/other/c");
	assert.equal(h.approvalRequests.length, 2);
});

test("edited intents cannot widen the human proposal", async () => {
	const h = createHarness({
		hasUI: true,
		terminalWaits: true,
		approval: async (request) => ({
			status: "approved",
			scope: "intent",
			intent: {
				...request.intentProposal,
				targets: ["path:/", "exec:python3"],
			},
		}),
	});
	await h.startSession();
	await run(h, "python3 -c 'print(1)'");
	assert.equal(h.decisionEntries().at(-1).data.scope, "once");
	assert.match(h.decisionEntries().at(-1).data.rationale, /narrow|widen|once/i);
	await run(h, "python3 -c 'print(1)'");
	assert.equal(h.approvalRequests.length, 2);
});

test("an edited intent cannot remove all executable restrictions", async () => {
	const h = createHarness({
		hasUI: true,
		terminalWaits: true,
		approval: async (request) => ({
			status: "approved",
			scope: "intent",
			intent: {
				...request.intentProposal,
				targets: request.intentProposal.targets.filter((target) => target.startsWith("path:")),
			},
		}),
	});
	await h.startSession();
	await run(h, "python3 -c 'print(1)'");
	assert.equal(h.decisionEntries().at(-1).data.scope, "once");
	assert.match(h.decisionEntries().at(-1).data.rationale, /narrow|once/i);
	await run(h, "node -e 'console.log(1)'");
	assert.equal(h.approvalRequests.length, 2, "dropping exec targets must not grant other interpreters");
});

test("terminal grants, revoke-one, revoke-all, and shutdown have session-only effects", async (t) => {
	const dir = await scriptProject(t);
	const h = createHarness({ hasUI: true });
	h.context.cwd = dir;
	let revoke = false;
	h.context.ui.select = async (_title, options) => {
		if (options.includes("Revoke all")) {
			if (!revoke) {
				revoke = true;
				return options[0];
			}
			return "Close";
		}
		return options.find((option) => option.startsWith("Yes, for this session:")) ?? "Yes";
	};
	await h.startSession();
	await run(h, "python main.py");
	assert.equal(h.decisionEntries().at(-1).data.scope, "intent");
	await run(h, "python main.py");
	assert.equal(h.classifierCalls.length, 1);
	await h.commands.get("automode-settings").handler("grants", h.context);
	await run(h, "python main.py");
	assert.equal(h.classifierCalls.length, 2, "revoked grant cannot cover a call");
	let all = false;
	h.context.ui.select = async (_title, options) => {
		if (!options.includes("Revoke all")) {
			return options.find((option) => option.startsWith("Yes, for this session:")) ?? "Yes";
		}
		if (all) return "Close";
		all = true;
		return "Revoke all";
	};
	await h.commands.get("automode-settings").handler("grants", h.context);
	await run(h, "python main.py");
	assert.equal(h.classifierCalls.length, 3);
	await h.handlers.get("session_shutdown")({}, h.context);
	await run(h, "python main.py");
	assert.equal(h.classifierCalls.length, 4, "shutdown clears grants");
});

test("recursive rm cannot run under a session intent", async () => {
	const h = createHarness({
		hasUI: true,
		terminalWaits: true,
		approval: async () => ({ status: "approved", scope: "intent" }),
	});
	await h.startSession();
	await run(h, "rm -rf /tmp/example");
	await run(h, "rm -rf /tmp/example");
	assert.equal(h.approvalRequests[0].intentProposal, undefined);
	assert.equal(h.decisionEntries().at(-1).data.scope, "once");
	assert.equal(h.classifierCalls.length, 2);
});
