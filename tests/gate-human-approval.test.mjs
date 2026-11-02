// Covers human approval behavior.
import assert from "node:assert/strict";
import test from "node:test";
import { ALLOW, autoState, createHarness, DENY, run } from "./helpers/gate-harness.mjs";

test("blocks classifier-denied commands without an approver", async () => {
	const harness = createHarness({ hasUI: false });

	const result = await harness.invoke({
		toolName: "bash",
		input: { command: "rm -rf ../example" },
	});

	assert.equal(result.block, true);
	assert.match(result.reason, /recursive\/forced rm/);
	assert.match(result.reason, /no approver was reachable/);
});

test("blocks a dangerous command when the user selects No", async () => {
	const harness = createHarness({ hasUI: true, choice: "No" });

	const result = await harness.invoke({
		toolName: "bash",
		input: { command: "git reset --hard HEAD" },
	});

	assert.equal(result.block, true);
	assert.match(result.reason, /the user did not approve/);
});

test("allows a dangerous command when the user selects Yes", async () => {
	const harness = createHarness({ hasUI: true, choice: "Yes" });

	const result = await harness.invoke({
		toolName: "bash",
		input: { command: "git reset --hard HEAD~1" },
	});

	assert.equal(result, undefined);
});

test("the browser queue decides, with a TLDR, a recommendation, and the user's note", async () => {
	const harness = createHarness({
		hasUI: true,
		terminalWaits: true,
		globalModeState: autoState(),
		classifierText: DENY,
		approval: async () => ({ status: "denied", note: "Use a feature branch instead." }),
	});
	await harness.startSession();
	const result = await run(harness, "git reset --hard HEAD~1");
	assert.equal(result.block, true);
	assert.match(result.reason, /Note from the user: Use a feature branch instead\./);
	assert.doesNotMatch(result.reason, /The target is unclear/);
	const request = harness.approvalRequests[0];
	assert.equal(request.kind, "command");
	assert.equal(request.tldr, "The target is unclear.");
	assert.equal(request.recommendation, "deny");
	assert.equal(request.risk, "medium");
	assert.equal(request.cwd, "/tmp/project");
	assert.deepEqual(request.reasons, ["git reset hard"]);

	const approved = createHarness({
		hasUI: true,
		terminalWaits: true,
		globalModeState: autoState(),
		classifierText: DENY,
		approval: async () => ({ status: "approved" }),
	});
	await approved.startSession();
	assert.equal(await run(approved, "git reset --hard HEAD~1"), undefined);
	assert.equal(approved.decisionEntries().at(-1).data.status, "approved");
	assert.match(approved.decisionEntries().at(-1).data.rationale, /You approved the command in the browser/);
});

test("the terminal and the browser race, and the first answer cancels the other", async () => {
	let browserSignal;
	const harness = createHarness({
		hasUI: true,
		choice: "Yes",
		globalModeState: autoState(),
		classifierText: DENY,
		approval: (_request, signal) => {
			browserSignal = signal;
			return new Promise((resolve) => signal.addEventListener("abort", () => resolve({ status: "cancelled" })));
		},
	});
	await harness.startSession();
	assert.equal(await run(harness, "git reset --hard HEAD~1"), undefined);
	assert.equal(browserSignal.aborted, true);
});

test("critical commands always reach a human, even when the classifier allows them", async () => {
	const gcloud = createHarness({
		hasUI: true,
		terminalWaits: true,
		fastPass: true,
		globalModeState: autoState(),
		classifierText: ALLOW,
		approval: async () => ({ status: "approved" }),
	});
	await gcloud.startSession();
	assert.equal(await run(gcloud, "gcloud run deploy api --region europe-west1"), undefined);
	assert.equal(gcloud.approvalRequests.length, 1);
	assert.equal(gcloud.approvalRequests[0].risk, "critical");
	assert.equal(gcloud.approvalRequests[0].recommendation, "approve");
	// Critical commands skip the fast pass.
	assert.equal(gcloud.classifierCalls.length, 1);
	assert.doesNotMatch(gcloud.classifierCalls[0].request.messages[0].content[0].text, /FAST PASS/);

	const classifierCritical = createHarness({
		hasUI: true,
		terminalWaits: true,
		globalModeState: autoState(),
		classifierText: '{"decision":"allow","risk":"critical","rationale":"Deletes a folder outside the project."}',
		approval: async () => ({ status: "denied" }),
	});
	await classifierCritical.startSession();
	const result = await run(classifierCritical, "rm -rf /tmp/other-project/build");
	assert.equal(result?.block, true);
	assert.equal(classifierCritical.approvalRequests[0].risk, "critical");

	const noApprover = createHarness({ hasUI: false, globalModeState: autoState(), classifierText: ALLOW });
	await noApprover.startSession();
	assert.equal((await run(noApprover, "terraform apply -auto-approve")).block, true);
});

test("pushes and merges are not critical when the classifier allows them", async () => {
	const harness = createHarness({
		hasUI: true,
		fastPass: true,
		globalModeState: autoState(),
		classifierSequence: [{ text: ALLOW }],
	});
	await harness.startSession();
	assert.equal(await run(harness, "git push --force-with-lease origin feat/edit"), undefined);
	assert.equal(harness.approvalRequests.length, 0);
});

test("repeated denials start a lockdown that a human can lift", async () => {
	const harness = createHarness({
		hasUI: true,
		globalModeState: autoState(),
		classifierText: DENY,
		selectResponses: ["No", "No", "No", "Yes, and lift lockdown"],
	});
	await harness.startSession();
	assert.equal((await run(harness, "git reset --hard HEAD~1")).block, true);
	assert.equal((await run(harness, "git reset --hard HEAD~2")).block, true);
	const third = await run(harness, "git reset --hard HEAD~3");
	assert.match(third.reason, /every command now needs the user's approval/);
	assert.match(harness.notifications.at(-1).message, /lockdown/i);

	// In lockdown even a harmless command needs the human.
	const callsBefore = harness.classifierCalls.length;
	assert.equal(await run(harness, "echo hello"), undefined);
	assert.equal(harness.classifierCalls.length, callsBefore);
	assert.match(harness.selectCalls.at(-1).title, /Lockdown/);
	assert.deepEqual(harness.selectCalls.at(-1).options, ["No", "Yes", "Yes, and lift lockdown", "Redirect…"]);

	// The human lifted it, so harmless commands run freely again.
	const selectsBefore = harness.selectCalls.length;
	assert.equal(await run(harness, "echo hello"), undefined);
	assert.equal(harness.selectCalls.length, selectsBefore);
});

test("an approval resets the count of denials in a row", async () => {
	const harness = createHarness({
		hasUI: true,
		globalModeState: autoState(),
		classifierText: DENY,
		selectResponses: ["No", "No", "Yes", "No", "No"],
	});
	await harness.startSession();
	for (let index = 0; index < 5; index += 1) await run(harness, `git reset --hard HEAD~${index + 1}`);
	assert.doesNotMatch(harness.notifications.map((entry) => entry.message).join("\n"), /lockdown/i);
});

test("/approvals opens the browser page and reports when it is unavailable", async () => {
	const ok = createHarness({ hasUI: true });
	await ok.commands.get("approvals").handler("", ok.context);
	assert.match(ok.notifications.at(-1).message, /Opened the approval queue/);
	const down = createHarness({ hasUI: true, openResult: false });
	await down.commands.get("approvals").handler("", down.context);
	assert.match(down.notifications.at(-1).message, /unavailable/);
	assert.equal(down.notifications.at(-1).level, "warning");
});
