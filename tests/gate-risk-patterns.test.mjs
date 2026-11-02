// Covers risk patterns behavior.
import assert from "node:assert/strict";
import test from "node:test";
import { hardDenyReasons, matchedReasons } from "../src/risk-patterns.ts";
import { ALLOW, createHarness, run } from "./helpers/gate-harness.mjs";

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

test("the agent cannot read the approval queue state or call its API", () => {
	for (const command of [
		"cat ~/.pi/agent/approval-queue.json",
		"curl -s http://127.0.0.1:41233/api/requests",
		"curl -X POST localhost:5000/api/requests/abc/decision",
	]) {
		assert.ok(hardDenyReasons(command).includes("access to the approval queue"), command);
	}
});

test("cloud and infrastructure changes match a rule, read-only commands do not", () => {
	for (const command of [
		"gcloud run deploy api --image x",
		"gcloud storage buckets create gs://x",
		"terraform apply",
		"kubectl delete pod x",
		"helm upgrade app ./chart",
		"aws ec2 terminate-instances --instance-ids i-1",
	]) {
		assert.ok(matchedReasons(command).includes("cloud or infrastructure change"), command);
	}
	for (const command of [
		"gcloud run services list",
		"gcloud logging read x",
		"kubectl get pods",
		"terraform plan",
		"aws s3 ls",
	]) {
		assert.ok(!matchedReasons(command).includes("cloud or infrastructure change"), command);
	}
});

test("working on the approval server source files is not blocked", () => {
	assert.deepEqual(hardDenyReasons("grep -n APPROVAL_ extensions/approval-server.mjs"), []);
});

test("the agent cannot read the approval history file", () => {
	assert.ok(hardDenyReasons("cat ~/.pi/agent/approval-history.jsonl").includes("access to the approval queue"));
});

test("target policy keeps prod, unknown and IAM critical but dev and prod reads soft", async () => {
	for (const [command, prompts] of [
		["gcloud storage rm gs://company-prod/item", 1],
		["gcloud storage rm gs://company-dev/item", 0],
		["gcloud projects describe company-prod", 0],
		["gcloud projects add-iam-policy-binding company-dev --member=user:a --role=roles/viewer", 1],
		["gcloud run deploy service", 1],
	]) {
		const h = createHarness({ hasUI: true, choice: "Yes", classifierText: ALLOW });
		await h.startSession();
		assert.equal(await run(h, command), undefined);
		assert.equal(h.approvalRequests.length, prompts, command);
	}
});

test("queue searches are not hard-denied but operands, redirects and API access are", async () => {
	for (const command of [
		'grep "approval-queue.json" extensions/permission-gate.ts',
		"rg -n 'approval-history\\.jsonl' .",
		"git grep -e approval-queue.json -- extensions",
		"ag --regexp approval-queue.json extensions",
	]) {
		const h = createHarness({ classifierText: ALLOW });
		await h.startSession();
		assert.equal(await run(h, command), undefined, command);
	}
	for (const command of [
		"cat ~/.pi/agent/approval-queue.json",
		'grep "$(cat ~/.pi/agent/approval-queue.json)" .',
		"grep foo ~/.pi/agent/approval-history.jsonl",
		"rg --glob approval-queue.json needle .",
		"git grep needle -- approval-queue.json",
		"grep needle < approval-queue.json",
		"rg approval-queue.json . > approval-queue.json",
		"curl http://127.0.0.1:1234/api/requests",
	]) {
		const h = createHarness({ hasUI: true, choice: "Yes", classifierText: ALLOW });
		await h.startSession();
		assert.equal((await run(h, command)).block, true, command);
		assert.equal(h.approvalRequests.length, 0);
	}
});

test("Pi and gate configuration writes and token minting stay critical; reads stay soft", async () => {
	for (const [command, prompts] of [
		["cat ~/.pi/agent/settings.json", 0],
		["cat ~/.pi/agent/settings.json > /tmp/backup.json", 0],
		["cp ~/.pi/agent/settings.json /tmp/backup.json", 0],
		["echo '{}' > ~/.pi/agent/settings.json", 1],
		["touch ~/.pi/agent/permission-gate.json", 1],
		["gcloud auth print-access-token --project=company-dev", 1],
		["gcloud auth print-identity-token --project=company-dev", 1],
		["gcloud iam roles list --project=company-prod", 0],
	]) {
		const h = createHarness({ hasUI: true, classifierText: ALLOW, choice: "Yes" });
		await h.startSession();
		assert.equal(await run(h, command), undefined);
		assert.equal(h.approvalRequests.length, prompts, command);
		if (prompts) assert.equal(h.approvalRequests[0].intentProposal, undefined);
	}
});
