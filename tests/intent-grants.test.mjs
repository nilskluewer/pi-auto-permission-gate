import assert from "node:assert/strict";
import test from "node:test";
import {
	commandAccess,
	commandExecutables,
	createIntentStore,
	grantCovers,
	isNarrowerOrEqual,
	proposeIntent,
} from "../src/intent-grants.ts";

const entry = (path, role = "file") => ({ path, role });
const proposal = {
	label: "write via python3 in /tmp/work/",
	access: "write",
	reasons: ["script", "sensitive path"],
	targets: ["exec:python3", "path:/tmp/work/"],
};
const input = {
	command: "python3 /tmp/work/run.py",
	reasons: ["script"],
	paths: [entry("/tmp/work", "working directory"), entry("/tmp/work/run.py")],
};
// Oracle: /tmp/pg-fatigue-contracts.md, Module B. Negative controls reject
// ignored pipeline segments, write-as-read errors, prefix collisions and session leaks.
test("extracts every segment executable and skips launchers and assignments", () => {
	assert.deepEqual(
		commandExecutables(
			"A=1 env -u OLD B=2 rtk uv run --python 3.12 python3 x.py | grep x && command /usr/bin/cat x; exec timeout -s TERM 5s nice -n 10 nohup time stdbuf -oL /bin/ls\n(printf x)",
		),
		["python3", "grep", "cat", "ls", "printf"],
	);
	assert.deepEqual(commandExecutables(""), []);
	assert.deepEqual(commandExecutables("A=1"), []);
	assert.deepEqual(commandExecutables("cat < input > output | grep x"), ["cat", "grep"]);
	assert.deepEqual(commandExecutables("env --chdir /tmp/work -- cat x"), ["cat"]);
	assert.deepEqual(commandExecutables("cat x & python3 run.py"), ["cat", "python3"]);
});

test("known reads remain read-only across pipelines and launchers", () => {
	for (const command of [
		"cat x | grep y",
		"env A=1 ls -la",
		"head x; tail y",
		"rg x . && wc -l x",
		"jq '.a' x",
		"sort x | uniq | cut -f1",
		"awk '{print $1}' x",
		"sed -n '1p' x",
		"find . -type f",
		"stat x; file x; du .; df .; pwd",
		"echo hello",
		"printf '%s' hello > /dev/null",
		"git status",
		"git log -n 2",
		"git diff",
		"git show HEAD",
		"git branch --list",
		"git branch --list 'feature/*'",
		"cat x 2>&1",
		"aws --profile dev ec2 describe-instances",
		"kubectl --context dev get pods",
		"gcloud projects list",
		"aws s3api get-object --bucket dev --key x /dev/null",
		"kubectl get pods",
		"kubectl logs pod",
	])
		assert.equal(commandAccess(command), "read", command);
});

test("writes, unknown commands, hidden execution and dangerous read options fail toward write", () => {
	for (const command of [
		"",
		"python3 -c 'print(1)'",
		"cat x | tee y",
		"echo x > out",
		"ls >> out",
		"echo x &> out",
		"cat x 2> error",
		"sed -i s/a/b/ x",
		"sed --in-place=.bak s/a/b/ x",
		"awk -i inplace '{print}' x",
		"find . -delete",
		"find . -exec rm {} +",
		"find . -execdir echo {} ';'",
		"git branch -D old",
		"git branch -m old new",
		"git checkout main",
		"gcloud run deploy api",
		"aws s3 rm s3://dev/x",
		"kubectl delete pod dev",
		'echo "$(rm x)"',
		"cat `touch x`",
		"echo hello; touch x",
		"jq --run-tests tests",
		"sort -o out in",
		"sed 'w output' input",
		"awk 'BEGIN {system(\"touch x\")}'",
		"git -c alias.status='!touch x' status",
		"aws --profile get s3api delete-object --bucket dev --key x",
		"aws s3api upload-part --bucket get --key x",
		"kubectl rollout restart get",
		"gcloud compute disks resize get",
		"rg --pre 'touch x' pattern .",
		"sort --compress-program=touch x",
		"uniq input output",
		"file -C",
		"awk -f script.awk input",
		"sed 's@x@touch x@e' input",
		"sed 'w/tmp/out' input",
	])
		assert.equal(commandAccess(command), "write", command);
});

test("proposes collapsed, resolved directory targets, all executables and bounded labels", () => {
	const result = proposeIntent({
		command: "cat /tmp/work/sub/a | grep x",
		cwd: "/tmp/work",
		grantableReasons: ["sensitive path"],
		paths: [entry("/tmp/work", "working directory"), entry("/tmp/work/sub/a"), entry("/tmp/work/else", "directory")],
		home: "/home/me",
	});
	assert.deepEqual(result.targets, ["exec:cat", "exec:grep", "path:/tmp/work/"]);
	assert.equal(result.access, "read");
	assert.deepEqual(result.reasons, ["sensitive path"]);
	assert.match(result.label, /read via cat, grep in \/tmp\/work\//);
	const home = proposeIntent({
		command: "python3 run.py",
		cwd: "/home/me/.config/gcp-agent",
		grantableReasons: ["script"],
		paths: [entry("/home/me/.config/gcp-agent", "working directory")],
		home: "/home/me",
	});
	assert.match(home.label, /~\/\.config\/gcp-agent\//);
	assert.equal(home.access, "write");
	const merged = proposeIntent({
		command: "cat x",
		cwd: "/tmp/work",
		grantableReasons: ["script"],
		paths: [entry("/tmp/work", "working directory, argument")],
	});
	assert.deepEqual(merged.targets, ["exec:cat", "path:/tmp/work/"]);
	const long = proposeIntent({
		command: "cat x",
		cwd: `/tmp/${"x".repeat(200)}`,
		grantableReasons: ["script"],
		paths: [entry(`/tmp/${"x".repeat(200)}`, "directory")],
	});
	assert.ok(long.label.length <= 160);
});

test("never proposes root, home, unresolved paths, empty reasons or no executable", () => {
	const base = { command: "cat x", cwd: "/tmp/work", grantableReasons: ["script"], paths: [], home: "/home/me" };
	for (const paths of [
		[entry("/", "directory")],
		[entry("/home/me", "working directory")],
		[entry("/home/me/file")],
		[{ path: "$FILE", role: "file", unresolved: true }],
	])
		assert.equal(proposeIntent({ ...base, paths }), undefined);
	assert.equal(proposeIntent({ ...base, grantableReasons: [] }), undefined);
	assert.equal(proposeIntent({ ...base, command: "A=1" }), undefined);
});

test("proposal edits may narrow, never widen reasons, access or directory boundaries", () => {
	assert.equal(isNarrowerOrEqual(proposal, proposal), true);
	const spaced = { ...proposal, targets: ["exec:my tool", "path:/tmp/work/"] };
	assert.equal(isNarrowerOrEqual(spaced, spaced), true);
	assert.equal(
		isNarrowerOrEqual(
			{ ...proposal, access: "read", reasons: ["script"], targets: ["exec:python3", "path:/tmp/work/sub/"] },
			proposal,
		),
		true,
	);
	for (const change of [
		{ reasons: [] },
		{ reasons: ["extra"] },
		{ targets: [] },
		{ targets: ["exec:bash"] },
		{ targets: ["path:/tmp/work-other/"] },
		{ targets: ["path:/tmp/work/../other/"] },
		{ targets: ["path:/tmp/"] },
		{ label: "" },
		{ label: "x".repeat(161) },
		{ access: "invalid" },
	])
		assert.equal(isNarrowerOrEqual({ ...proposal, ...change }, proposal), false, JSON.stringify(change));
	assert.equal(isNarrowerOrEqual(proposal, { ...proposal, access: "read" }), false);
});

test("matching requires every reason, executable, path role and compatible access", () => {
	assert.equal(grantCovers(proposal, input), true);
	for (const change of [
		{ reasons: [] },
		{ reasons: ["extra"] },
		{ reasons: ["script", "extra"] },
		{ command: "python3 run.py | bash" },
		{ paths: [entry("/tmp/work-other/file")] },
		{ paths: [entry("/tmp/work/../other/file")] },
		{ paths: [entry("/tmp", "working directory"), ...input.paths] },
		{ paths: [{ ...input.paths[0], unresolved: true }] },
	])
		assert.equal(grantCovers(proposal, { ...input, ...change }), false, JSON.stringify(change));
	assert.equal(grantCovers({ ...proposal, access: "read" }, input), false);
	assert.equal(
		grantCovers(
			{ ...proposal, access: "read", targets: ["path:/tmp/work/", "exec:cat"] },
			{ ...input, command: "cat /tmp/work/run.py" },
		),
		true,
	);
	assert.equal(grantCovers({ ...proposal, targets: ["path:/tmp/work/"] }, input), true);
	assert.equal(grantCovers(proposal, { ...input, paths: [entry("/tmp/work", "directory")] }), true);
});

test("store isolates sessions, revokes grants, clears selectively and does not leak mutable state", () => {
	let serial = 0;
	const store = createIntentStore({ now: () => 123, randomId: () => `grant-${++serial}` });
	const first = store.add("one", proposal);
	const second = store.add("two", proposal);
	assert.equal(first.createdAt, 123);
	assert.equal(first.id, "grant-1");
	assert.equal(store.match("one", input).id, first.id);
	assert.equal(store.match("three", input), undefined);
	assert.equal(store.list().length, 2);
	assert.equal(store.list("one").length, 1);
	first.reasons.push("extra");
	store.list("one")[0].targets.push("path:/");
	assert.equal(store.match("one", { ...input, reasons: ["extra"] }), undefined);
	assert.equal(store.match("one", { ...input, paths: [entry("/etc/passwd")] }), undefined);
	assert.equal(store.revoke(first.id), true);
	assert.equal(store.revoke(first.id), false);
	assert.equal(store.match("one", input), undefined);
	store.add("one", proposal);
	store.clear("one");
	assert.deepEqual(
		store.list().map((g) => g.id),
		[second.id],
	);
	store.clear();
	assert.deepEqual(store.list(), []);
});
