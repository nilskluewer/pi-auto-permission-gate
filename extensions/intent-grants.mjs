import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { basename, dirname, resolve, sep } from "node:path";
import { shellWords } from "./command-inspection.mjs";

const ASSIGNMENT = /^[A-Za-z_]\w*=/;
const SEPARATOR = /^[;&|()\n]$/;
const LAUNCHERS = new Set(["env", "rtk", "command", "exec", "timeout", "nice", "nohup", "time", "stdbuf"]);
const OPTION_ARGUMENTS = {
	env: new Set(["-u", "--unset", "-C", "--chdir", "--argv0"]),
	exec: new Set(["-a"]), timeout: new Set(["-s", "--signal", "-k", "--kill-after"]),
	nice: new Set(["-n", "--adjustment"]), time: new Set(["-f", "--format", "-o", "--output"]),
	stdbuf: new Set(["-i", "-o", "-e", "--input", "--output", "--error"]),
	uv: new Set(["--python", "--project", "--directory", "--package", "--with", "--with-editable", "--with-requirements", "--extra", "--group", "--index", "--index-url"]),
};

function executableIndex(words) {
	let i = 0;
	while (i < words.length) {
		if (ASSIGNMENT.test(words[i])) { i++; continue; }
		const name = basename(words[i]);
		if (!LAUNCHERS.has(name) && name !== "uv") return i;
		i++;
		if (name === "uv" && words[i] === "run") i++;
		while (i < words.length && words[i].startsWith("-")) {
			const option = words[i++];
			if (option === "--") break;
			if (OPTION_ARGUMENTS[name]?.has(option)) i++;
		}
		if (name === "uv" && words[i] === "run") { i++; continue; }
		if (name === "timeout" && /^\d+(?:\.\d+)?[smhd]?$/.test(words[i] ?? "")) i++;
	}
	return -1;
}

function commandSegments(command) {
	const segments = [];
	let current = [];
	const flush = () => { if (current.length) segments.push(current); current = []; };
	const words = shellWords(command);
	for (let i = 0; i < words.length; i++) {
		const word = words[i];
		if (SEPARATOR.test(word)) { flush(); continue; }
		if (/^\d+$/.test(word) && /^[<>]$/.test(words[i + 1] ?? "")) continue;
		if (/^[<>]$/.test(word)) {
			while (words[i + 1] === word) i++;
			if (words[i + 1] === "&") i++;
			i++;
			continue;
		}
		current.push(word);
	}
	flush();
	return segments;
}

export function commandExecutables(command) {
	return commandSegments(command).flatMap((words) => {
		const index = executableIndex(words);
		return index < 0 ? [] : [basename(words[index])];
	});
}

const SIMPLE_READS = new Set(["cat", "ls", "head", "tail", "grep", "rg", "wc", "jq", "sort", "uniq", "cut", "stat", "file", "du", "df", "pwd", "echo", "printf"]);

const CLOUD_VALUE_FLAGS = new Set(["--project", "--project-id", "--account", "--configuration", "--impersonate-service-account", "--billing-project", "--verbosity", "--format", "--filter", "--limit", "--profile", "--region", "--endpoint-url", "--output", "--query", "--ca-bundle", "--cli-read-timeout", "--cli-connect-timeout", "--context", "--namespace", "-n", "--kubeconfig", "--cluster", "--user", "--server", "--token", "--request-timeout"]);
const CLOUD_SWITCHES = new Set(["--quiet", "-q", "--debug", "--no-paginate", "--no-sign-request", "--no-verify-ssl", "--no-cli-pager", "--log-http", "--help", "-h"]);
const GCLOUD_GROUPS = new Set("projects organizations folders services service-management run jobs executions revisions compute instances disks images snapshots networks subnetworks firewall-rules routes addresses regions zones machine-types instance-groups managed unmanaged templates storage buckets objects iam service-accounts keys roles container clusters node-pools artifacts repositories docker images tags builds triggers logging logs sinks metrics monitoring policies sql databases users backups pubsub topics subscriptions secrets versions functions app versions config configurations auth scheduler tasks queues spanner databases instances bigtable firestore operations redis memorystore dns managed-zones record-sets endpoints deploy releases targets workflows dataproc dataflow billing accounts resource-manager".split(" "));

function cloudReadOnly(name, args) {
	const positional = [];
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (arg.startsWith("-")) {
			if (arg.includes("=")) continue;
			if (CLOUD_VALUE_FLAGS.has(arg)) { i++; continue; }
			if (CLOUD_SWITCHES.has(arg)) continue;
			return false;
		}
		positional.push(arg);
		if (name === "aws" && positional.length < 2) continue;
		if (arg === "get-credentials") return false;
		if (/^(?:list|describe|get|read|logs)(?:-|$)/.test(arg)) return true;
		if (name !== "gcloud" || !GCLOUD_GROUPS.has(arg)) return false;
	}
	return false;
}

function readOnlySegment(words) {
	const index = executableIndex(words);
	if (index < 0) return false;
	const name = basename(words[index]);
	const args = words.slice(index + 1);
	// Launcher options can write too.
	if (words.slice(0, index).some((word) => /^(?:-o|--output)(?:=|$)/.test(word)) && words.slice(0, index).some((word) => basename(word) === "time")) return false;
	if (name === "tee") return false;
	if (name === "sort" && args.some((arg) => /^-.*o|^--(?:output|compress-program)(?:=|$)/.test(arg))) return false;
	if (name === "rg" && args.some((arg) => /^--(?:pre|hostname-bin)(?:=|$)/.test(arg))) return false;
	if (name === "file" && args.some((arg) => /^-[^-]*C|^--compile$/.test(arg))) return false;
	if (name === "uniq") {
		let files = 0;
		for (let i = 0; i < args.length; i++) {
			if (/^(?:-[fsw]|--skip-fields|--skip-chars|--check-chars)$/.test(args[i])) { i++; continue; }
			if (!args[i].startsWith("-") || args[i] === "-") files++;
		}
		if (files > 1) return false;
	}
	if (name === "jq" && args.includes("--run-tests")) return false;
	if (SIMPLE_READS.has(name)) return true;
	if (name === "awk") return !args.some((arg) => /^-[fil]|^--(?:inplace|file|include|load)(?:=|$)/.test(arg) || /\bsystem\s*\(|\bgetline\b|[>|]/.test(arg));
	if (name === "sed") {
		if (args.some((arg) => /^-(?:[^-]*i)|^--in-place(?:=|$)|^--file(?:=|$)|^-f/.test(arg))) return false;
		// External programs and output commands are not read-only sed scripts.
		return !args.some((arg) => /\b[wer](?:\s|\/|$)|(?:^|[;\n}])\s*(?:[\d,$]+\s*)?[wer](?:\s|\/|$)|[;}]\s*e\b|[^\w\s][a-z]*[ew][a-z]*(?:\s|$)/.test(arg));
	}
	if (name === "find") return !args.some((arg) => /^-(?:delete|exec|execdir|ok|okdir|fprint|fprint0|fprintf|fls)$/.test(arg));
	if (name === "git") {
		if (!/^(?:status|log|diff|show|branch)$/.test(args[0] ?? "")) return false;
		if (args.some((arg) => /^(?:--output|--ext-diff|--textconv)(?:=|$)/.test(arg))) return false;
		if (args[0] !== "branch") return true;
		const branchArgs = args.slice(1);
		if (branchArgs.some((arg) => /^-[^-]*[dDmMcCf]|^--(?:delete|move|copy|force|edit-description|set-upstream-to|unset-upstream)(?:=|$)/.test(arg))) return false;
		return branchArgs.some((arg) => /^(?:--list|--contains|--no-contains|--merged|--no-merged|--points-at)(?:=|$)/.test(arg)) || branchArgs.every((arg) => arg.startsWith("-"));
	}
	if (["gcloud", "aws", "kubectl"].includes(name)) return cloudReadOnly(name, args);
	return false;
}

function hasExpansion(command) {
	let quote = "";
	for (let i = 0; i < command.length; i++) {
		const char = command[i];
		if (char === "\\" && quote !== "'") { i++; continue; }
		if (quote === "'") { if (char === "'") quote = ""; continue; }
		if (char === "'" && !quote) { quote = "'"; continue; }
		if (char === '"') { quote = quote ? "" : '"'; continue; }
		if (char === "$" || char === "`") return true;
	}
	return quote !== "";
}

export function commandAccess(command) {
	// Expansions and shell programs need classifier review, not a read grant.
	if (hasExpansion(command) || /<<|\b(?:source|eval)\b/.test(command)) return "write";
	const words = shellWords(command);
	for (let i = 0; i < words.length; i++) {
		if (words[i] !== ">") continue;
		while (words[i + 1] === ">") i++;
		if (words[i + 1] === "&" && /^(?:\d+|-)$/.test(words[i + 2] ?? "")) { i += 2; continue; }
		if (words[i + 1] !== "/dev/null") return "write";
	}
	const segments = commandSegments(command);
	return segments.length > 0 && segments.every(readOnlySegment) ? "read" : "write";
}

const directory = (path) => { const result = resolve(path); return result.endsWith(sep) ? result : result + sep; };
function inside(path, parent) {
	const resolved = resolve(path), base = resolve(parent);
	return resolved === base || resolved.startsWith(directory(base));
}
const pathTargets = (targets) => targets.filter((target) => target.startsWith("path:")).map((target) => target.slice(5));
const copy = (proposal) => ({ ...proposal, reasons: [...proposal.reasons], targets: [...proposal.targets] });

export function proposeIntent({ command, cwd, grantableReasons, paths, home = homedir() }) {
	if (!grantableReasons.length || paths.some((entry) => entry.unresolved)) return undefined;
	const executables = [...new Set(commandExecutables(command))];
	if (!executables.length) return undefined;
	const directories = [...new Set(paths.map((entry) => {
		const path = resolve(cwd, entry.path);
		const roles = entry.role.split(", ");
		return directory(roles.includes("working directory") || roles.includes("directory") ? path : dirname(path));
	}))];
	if (directories.some((path) => resolve(path) === sep || resolve(path) === resolve(home))) return undefined;
	const collapsed = directories.filter((path) => !directories.some((other) => other !== path && inside(path, other)));
	const access = commandAccess(command);
	const display = collapsed.map((path) => inside(path, home) ? "~/" + path.slice(directory(home).length) : path);
	const label = `${access} via ${executables.join(", ")} in ${display.join(", ") || directory(cwd)}`.slice(0, 160);
	return { label, access, reasons: [...new Set(grantableReasons)], targets: [...executables.map((name) => `exec:${name}`), ...collapsed.map((path) => `path:${path}`)] };
}

function validProposal(proposal) {
	return proposal && typeof proposal.label === "string" && proposal.label.trim().length > 0 && proposal.label.length <= 160 &&
		["read", "write"].includes(proposal.access) && Array.isArray(proposal.reasons) && proposal.reasons.length > 0 &&
		proposal.reasons.every((reason) => typeof reason === "string" && reason.length > 0) &&
		Array.isArray(proposal.targets) && proposal.targets.length > 0 && proposal.targets.every((target) => typeof target === "string" && /^(?:path:\/|exec:[^/]+$)/.test(target));
}

export function isNarrowerOrEqual(edited, original) {
	if (!validProposal(edited) || !validProposal(original)) return false;
	if (edited.access === "write" && original.access !== "write") return false;
	// No executable targets means unrestricted executables, not an empty set.
	if (original.targets.some((target) => target.startsWith("exec:")) && !edited.targets.some((target) => target.startsWith("exec:"))) return false;
	if (!edited.reasons.every((reason) => original.reasons.includes(reason))) return false;
	return edited.targets.every((target) => target.startsWith("path:")
		? pathTargets(original.targets).some((parent) => inside(target.slice(5), parent))
		: original.targets.includes(target));
}

export function grantCovers(grant, { command, reasons, paths }) {
	if (!validProposal(grant) || !reasons.length || !reasons.every((reason) => grant.reasons.includes(reason))) return false;
	if (commandAccess(command) !== "read" && grant.access !== "write") return false;
	const directories = pathTargets(grant.targets);
	if (paths.some((entry) => entry.unresolved || !directories.some((parent) => inside(entry.path, parent)))) return false;
	const execTargets = grant.targets.filter((target) => target.startsWith("exec:"));
	return !execTargets.length || commandExecutables(command).every((name) => execTargets.includes(`exec:${name}`));
}

export function createIntentStore({ now = Date.now, randomId = randomUUID } = {}) {
	const grants = new Map();
	return {
		add(sessionId, proposal) {
			const grant = { ...copy(proposal), id: randomId(), sessionId, createdAt: now() };
			grants.set(grant.id, grant);
			return copy(grant);
		},
		match(sessionId, input) {
			const grant = [...grants.values()].find((candidate) => candidate.sessionId === sessionId && grantCovers(candidate, input));
			return grant ? copy(grant) : undefined;
		},
		list(sessionId) { return [...grants.values()].filter((grant) => sessionId === undefined || grant.sessionId === sessionId).map(copy); },
		revoke(id) { return grants.delete(id); },
		clear(sessionId) {
			if (sessionId === undefined) grants.clear();
			else for (const [id, grant] of grants) if (grant.sessionId === sessionId) grants.delete(id);
		},
	};
}
