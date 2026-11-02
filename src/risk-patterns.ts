import { homedir } from "node:os";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { commandAccess } from "./command-access.ts";
import { SHELL_CONTROL_CHARACTERS, evaluateUserCommandRules, splitSimpleSegments } from "./command-rules.ts";
import { getAgentConfigDirectory } from "./config-paths.ts";
import { DEFAULT_COMMAND_RULE_CONFIG } from "./constants.ts";
import { isAccessChange } from "./criticality.ts";
import { codeReviewReasons, shellWords } from "./shell-words.ts";
import { unique } from "./text.ts";
import { type CommandRuleConfig, type DangerousPattern } from "./types.ts";

// Recursive rm always needs the classifier (or the user when auto mode is off):
// neither user allow patterns nor scoped-deletion shortcuts can skip it.
export const CLASSIFIER_REQUIRED_REASON = "recursive/forced rm";
const PATH_GLOB_CHARACTERS = /[*?[\]{}]/;
const FIND_NARROWING_PREDICATES = new Set([
	"-atime",
	"-ctime",
	"-empty",
	"-group",
	"-iname",
	"-ipath",
	"-iregex",
	"-links",
	"-maxdepth",
	"-mindepth",
	"-mtime",
	"-name",
	"-newer",
	"-newermt",
	"-path",
	"-perm",
	"-regex",
	"-size",
	"-type",
	"-user",
]);

function isSafeRelativeDeletionTarget(target: string, cwd: string, allowCurrentDirectory: boolean): boolean {
	if (
		!target ||
		target.startsWith("/") ||
		target.startsWith("~") ||
		target.startsWith("$") ||
		/^[A-Za-z]:[\\/]/.test(target)
	) {
		return false;
	}
	if (PATH_GLOB_CHARACTERS.test(target)) return false;

	const normalizedSegments = target.replace(/^\.\/+/, "").split(/[\\/]/);
	if (!allowCurrentDirectory && normalizedSegments.length === 1 && normalizedSegments[0] === "") return false;
	if (normalizedSegments.some((segment) => segment === ".." || segment === ".git")) return false;

	const projectRoot = resolve(cwd);
	const resolvedTarget = resolve(projectRoot, target);
	const relativeTarget = relative(projectRoot, resolvedTarget);
	return (
		Boolean(relativeTarget) &&
		relativeTarget !== ".." &&
		!relativeTarget.startsWith(`..${sep}`) &&
		!relativeTarget.startsWith(sep)
	);
}

function isScopedFindDeleteCommand(command: string, cwd: string): boolean {
	if (SHELL_CONTROL_CHARACTERS.test(command) || PATH_GLOB_CHARACTERS.test(command)) return false;
	const tokens = command
		.trim()
		.split(/[ \t]+/)
		.filter(Boolean);
	if (tokens.shift()?.toLowerCase() !== "find" || tokens.includes("-exec") || tokens.includes("-execdir")) return false;
	if (!tokens.includes("-delete")) return false;

	const expressionStart = tokens.findIndex(
		(token) => token.startsWith("-") || token === "!" || token === "(" || token === ")",
	);
	if (expressionStart <= 0) return false;

	const roots = tokens.slice(0, expressionStart);
	const hasNarrowingPredicate = tokens.some((token) => FIND_NARROWING_PREDICATES.has(token));
	return roots.length > 0 && roots.every((root) => isSafeRelativeDeletionTarget(root, cwd, hasNarrowingPredicate));
}

export const dangerousPatterns: DangerousPattern[] = [
	// File deletion / destructive filesystem traversal
	{
		name: "recursive/forced rm",
		pattern: /\brm\b(?=[^\n;&|]*[ \t]+["']?(?:-[a-z]*r[a-z]*|--recursive)["']?(?=[\s;&|]|$))/i,
	},
	{ name: "remove Git metadata", pattern: /\brm\b[^\n;&|]*\s(?:\.git|\.git\/|['"]\.git['"])/i },
	{ name: "find delete", pattern: /\bfind\b[^\n;&|]*\s-delete\b/i },
	{ name: "xargs rm", pattern: /\bxargs\b[^\n;&|]*\brm\b/i },

	// Package execution and publishing can execute third-party code or affect remote state.
	{
		name: "package execution or publish",
		pattern:
			/\b(?:npm|pnpm|yarn|bun|pip|pip3|uv|poetry|cargo|gem|go|brew|apt(?:-get)?|dnf|pacman)\b[^\n;&|]*\b(?:exec|run|dlx|publish)\b/i,
	},
	{ name: "package runner", pattern: /\b(?:npx|pnpm\s+dlx|yarn\s+dlx|bunx|pipx|uvx)\b/i },

	// Target-dependent cloud and infrastructure changes.
	{
		name: "cloud or infrastructure change",
		pattern:
			/\b(?:gcloud|gsutil|aws|az|firebase|wrangler|vercel|flyctl|fly)\b[^\n;&|]*\b(?:deploy|delete|destroy|create|update|patch|submit|import|rm|rb|mb|terminate|set-iam-policy|add-iam-policy-binding|remove-iam-policy-binding|run-instances|start-instance|resize|scale|publish)\b|\b(?:terraform|tofu)\b[^\n;&|]*\b(?:apply|destroy|import|taint)\b|\bpulumi\b[^\n;&|]*\b(?:up|destroy)\b|\bkubectl\b[^\n;&|]*\b(?:apply|delete|create|patch|replace|scale|drain|exec)\b|\bhelm\b[^\n;&|]*\b(?:install|upgrade|uninstall|rollback)\b|\bcdk\b[^\n;&|]*\b(?:deploy|destroy)\b/i,
	},

	// Privilege escalation / permission or ownership foot-guns
	{ name: "sudo", pattern: /\bsudo\b/i },
	{ name: "world-writable permissions", pattern: /\bchmod\b[^\n;&|]*\b777\b/i },
	{ name: "recursive chmod/chown", pattern: /\b(?:chmod|chown)\b[^\n;&|]*\s-R\b/i },
	{ name: "recursive chmod/chown", pattern: /\b(?:chmod|chown)\b[^\n;&|]*\s--recursive\b/i },

	// Disk / partition / filesystem destruction
	{ name: "format filesystem", pattern: /\bmkfs(?:\.[a-z0-9_+-]+)?\b/i },
	{ name: "wipe filesystem signatures", pattern: /\bwipefs\b/i },
	{ name: "disk shred/wipe", pattern: /\b(?:shred|srm)\b/i },
	{ name: "partition editor", pattern: /\b(?:fdisk|parted|gparted|sfdisk|cfdisk)\b/i },
	{
		name: "macOS disk erase",
		pattern: /\bdiskutil\b[^\n;&|]*\b(?:erase|partition|apfs\s+delete|apfs\s+erase)\b/i,
	},
	{ name: "dd writes to disk device", pattern: /\bdd\b[^\n;&|]*\bof=\/dev\//i },

	// Git working tree / repo / history destruction
	{ name: "git reset hard", pattern: /\bgit\b[^\n;&|]*\breset\b[^\n;&|]*\s--hard\b/i },
	{
		name: "git clean forced",
		pattern: /\bgit\b[^\n;&|]*\bclean\b(?=[^\n;&|]*\s-[^\s;&|]*f)[^\n;&|]*/i,
	},
	{
		name: "git force push",
		pattern: /\bgit\b[^\n;&|]*\bpush\b[^\n;&|]*\s--(?:force|force-with-lease|mirror)\b/i,
	},
	{ name: "git force push", pattern: /\bgit\b[^\n;&|]*\bpush\b[^\n;&|]*\s-[^\s;&|]*f[^\s;&|]*\b/i },
	{ name: "git branch force-delete", pattern: /\bgit\b[^\n;&|]*\bbranch\b[^\n;&|]*\s-D\b/i },
	{ name: "git tag delete", pattern: /\bgit\b[^\n;&|]*\btag\b[^\n;&|]*\s-d\b/i },
	{ name: "git remove files", pattern: /\bgit\b[^\n;&|]*\brm\b/i },
	{ name: "git checkout all files", pattern: /\bgit\b[^\n;&|]*\bcheckout\b[^\n;&|]*\s--\s+(?:\.|\*)\b/i },
	{
		name: "git restore all files",
		pattern: /\bgit\b[^\n;&|]*\brestore\b[^\n;&|]*(?:\s\.\b|\s:\/\b|\s--source\b)/i,
	},
	{ name: "git reflog expiry", pattern: /\bgit\b[^\n;&|]*\breflog\b[^\n;&|]*\bexpire\b/i },
	{
		name: "git aggressive prune/gc",
		pattern: /\bgit\b[^\n;&|]*\b(?:gc|prune)\b[^\n;&|]*(?:--prune=(?:now|all)|--expire\s+now|--expire=now)/i,
	},

	// Containers / volumes can destroy local databases and development state
	{
		name: "docker prune/remove volumes",
		pattern: /\bdocker\b[^\n;&|]*\b(?:system\s+prune|volume\s+(?:rm|prune)|container\s+prune|image\s+prune)\b/i,
	},
	{
		name: "docker compose remove volumes",
		pattern: /\bdocker\s+compose\b[^\n;&|]*\bdown\b[^\n;&|]*(?:\s-v\b|\s--volumes\b)/i,
	},

	// Running remote scripts can do anything with current user permissions
	{
		name: "downloaded script execution",
		pattern: /\b(?:curl|wget)\b[^\n;&|]*(?:\|\s*(?:sh|bash|zsh)\b|\b(?:sh|bash|zsh)\s*<\s*\()/i,
	},
];

// rm options must be whole tokens, not hyphens inside paths. Use horizontal
// whitespace before options and targets so matches cannot cross command lines.
// These operations are never delegated to a language model.
// The list is deliberately small and reserved for catastrophic targets where an
// automatic approval would be unsafe even with clear-looking surrounding context.
export const hardDenyPatterns: DangerousPattern[] = [
	{
		// The agent must never read the queue state or call the approval API itself.
		name: "access to the approval queue",
		pattern: /approval-queue\.json|approval-history\.jsonl|(?:127\.0\.0\.1|localhost):\d+\/api\/(?:requests|events)/i,
	},
	{
		name: "recursive delete of a system or home root",
		pattern:
			/\brm\b[^\n;&|]*[ \t]+["']?(?:--recursive|-[a-z]*r[a-z]*)["']?(?=[\s;&|]|$)[^\n;&|]*[ \t]+["']?(?!\/private\/tmp\/(?![^\s"';&|]*\.\.)[^\s"';&|])(?:\/|~|\$HOME|\$\{HOME\}|\/(?:Users|home|root|System|Applications|Library|etc|usr|var|bin|sbin|opt|private|Volumes))(?:["']?(?:\s|$)|\/)/i,
	},
	{
		name: "unresolved recursive delete target",
		pattern:
			/\brm\b(?=[^\n;&|]*[ \t]+["']?(?:--recursive|-[a-z]*r[a-z]*)["']?(?=[\s;&|]|$))(?=[^\n;&|]*(?:\$\(|\$\{|\$[A-Za-z_]|\$['"]|~[A-Za-z]|[`*?[\]]|\{[^}]*,))[^\n;&|]*/i,
	},
	{ name: "filesystem format or signature wipe", pattern: /\b(?:mkfs(?:\.[a-z0-9_+-]+)?|wipefs)\b/i },
	{ name: "disk device overwrite", pattern: /\bdd\b[^\n;&|]*\bof\s*=\s*["']?\/dev\//i },
	{
		name: "macOS disk erase or partition",
		pattern: /\bdiskutil\b[^\n;&|]*\b(?:erase|partition|apfs\s+delete|apfs\s+erase)\b/i,
	},
	{
		name: "forced push to a protected branch",
		pattern:
			/\bgit\b[^\n;&|]*\bpush\b[^\n;&|]*(?:--force(?:-with-lease)?|-[^\s;&|]*f[^\s;&|]*)\b[^\n;&|]*\b(?:main|master|production|prod)\b/i,
	},
	{
		name: "forced push to a protected branch",
		pattern:
			/\bgit\b[^\n;&|]*\bpush\b[^\n;&|]*\b(?:main|master|production|prod)\b[^\n;&|]*(?:--force(?:-with-lease)?|-[^\s;&|]*f[^\s;&|]*)\b/i,
	},
	{
		name: "unresolved forced push target",
		pattern:
			/\bgit\b(?=[^\n;&|]*\bpush\b)(?=[^\n;&|]*(?:--force(?:-with-lease)?|-[^\s;&|]*f[^\s;&|]*))(?=[^\n;&|]*(?:\$\(|\$\{|\$[A-Za-z_]|\$['"]|~[A-Za-z]|[`*?[\]]|\{[^}]*,))[^\n;&|]*/i,
	},
];

export function matchedReasons(
	command: string,
	rules: CommandRuleConfig = DEFAULT_COMMAND_RULE_CONFIG,
	cwd?: string,
): string[] {
	const reasons = unique([
		...dangerousPatterns.filter(({ pattern }) => pattern.test(command)).map(({ name }) => name),
		...codeReviewReasons(command),
	]);
	if (isAccessChange(command) && !reasons.includes("cloud or infrastructure change"))
		reasons.push("cloud or infrastructure change");
	if (
		commandAccess(command) === "write" &&
		shellWords(command).some((word, index, words) => {
			const operand = word
				.replace(/^--?[\w-]+=/, "")
				.replace(/^~(?=\/)/, homedir())
				.replace(/^\$\{?HOME\}?(?=\/)/, homedir());
			if (!/[/]|\.json$|automode-preferences\.md$/.test(operand) || /\s/.test(operand)) return false;
			const path = resolve(cwd ?? process.cwd(), operand);
			const agent = resolve(getAgentConfigDirectory());
			const configName =
				/^(?:(?:settings|models|keybindings|mcp)\.json|permission-gate[^/]*|automode-preferences\.md)$/;
			const sensitive =
				path === agent ||
				(dirname(path) === agent && configName.test(basename(path))) ||
				(/(?:^|\/)\.pi\//.test(path) && configName.test(basename(path)) && basename(dirname(path)) === ".pi");
			if (!sensitive) return false;
			if (words[index - 1] === ">") return true;
			const start = words.slice(0, index).findLastIndex((w) => /^[;&|()\n]$/.test(w)) + 1;
			const endOffset = words.slice(index + 1).findIndex((w) => /^[;&|()\n<>]$/.test(w));
			const end = endOffset < 0 ? words.length : index + 1 + endOffset;
			const executable = basename(words[start] ?? "");
			if (["cat", "head", "tail", "grep", "rg", "ag", "echo", "printf", "jq"].includes(executable)) return false;
			if (executable === "cp" && index < end - 1) return false;
			return true;
		})
	)
		reasons.push("Pi or gate configuration write");
	if (
		reasons.includes(CLASSIFIER_REQUIRED_REASON) ||
		isAccessChange(command) ||
		reasons.includes("Pi or gate configuration write")
	)
		return reasons;
	// A literal single-quoted string cannot expand or hide another shell command.
	if (reasons.length === 0 && command.trim() && splitSimpleSegments(command.replace(/'[^']*'/g, "''")) === undefined)
		reasons.push("shell syntax requires classifier assessment");
	if (evaluateUserCommandRules(command, rules)?.decision === "allow") return [];
	if (cwd && isScopedFindDeleteCommand(command, cwd)) return reasons.filter((reason) => reason !== "find delete");
	return reasons;
}

const TEMPORARY_PLACEHOLDER = "/tmp/permission-gate-temporary";

// Treat $TMPDIR and variables assigned once from `$(mktemp ...)` as resolved temp paths,
// so `tmp=$(mktemp -d); ...; rm -rf "$tmp"` is not hard-denied. The soft rules and the
// classifier still review the full command. Any reassignment, parameter expansion, or
// `..` after the variable keeps it unresolved.
function resolveTemporaryVariables(command: string): string {
	const names = new Set(["TMPDIR"]);
	for (const match of command.matchAll(/(?<![\w$])([A-Za-z_]\w*)=["']?\$\(\s*mktemp\b[^)]*\)["']?/g))
		names.add(match[1]);

	let resolved = command;
	for (const name of names) {
		const bareWords = command.match(new RegExp(`(?<![\\w\${/.-])${name}\\b`, "g"))?.length ?? 0;
		if (bareWords !== (name === "TMPDIR" ? 0 : 1)) continue;
		if (new RegExp(`\\$\\{${name}[^}]`).test(command)) continue;
		resolved = resolved.replace(
			new RegExp(`\\$(?:\\{${name}\\}|${name}\\b)(?![^\\s"';&|]*\\.\\.)`, "g"),
			TEMPORARY_PLACEHOLDER,
		);
	}
	return resolved;
}

function accessesApprovalQueue(command: string): boolean {
	if (/(?:127\.0\.0\.1|localhost):\d+\/api\/(?:requests|events)/i.test(command)) return true;
	const words = shellWords(command);
	const skipped = new Set<number>();
	// Never exempt an operand that can execute a command substitution.
	const skipPattern = (index: number) => {
		if (!/\$\(|`/.test(words[index] ?? "")) skipped.add(index);
	};
	for (let start = 0; start < words.length; start++) {
		if (start > 0 && !/^[;&|()\n]$/.test(words[start - 1])) continue;
		let i = start;
		if (basename(words[i] ?? "") === "git" && words[i + 1] === "grep") i++;
		if (!["grep", "rg", "ag"].includes(basename(words[i] ?? ""))) continue;
		let patternFound = false;
		let positionalOnly = false;
		for (i++; i < words.length && !/^[;&|()\n]$/.test(words[i]); i++) {
			const word = words[i];
			if (/^[<>]$/.test(word)) {
				i++;
				continue;
			}
			if (!positionalOnly && word === "--") {
				positionalOnly = true;
				continue;
			}
			if (!positionalOnly && /^(?:-e|--regexp)$/.test(word)) {
				if (words[i + 1] !== undefined) skipPattern(++i);
				patternFound = true;
				continue;
			}
			if (!positionalOnly && /^(?:--regexp=|-e.+)/.test(word)) {
				skipPattern(i);
				patternFound = true;
				continue;
			}
			if (
				!positionalOnly &&
				/^(?:-[ABCmfgjt]|--(?:after-context|before-context|context|max-count|file|glob|iglob|type|type-not|threads|encoding|pre|include|exclude|exclude-dir))$/.test(
					word,
				)
			) {
				if (word === "-f" || word === "--file") patternFound = true;
				i++;
				continue;
			}
			if (!positionalOnly && word.startsWith("-")) continue;
			if (!patternFound) {
				skipPattern(i);
				patternFound = true;
			}
		}
	}
	return words.some((word, i) => !skipped.has(i) && /approval-queue\.json|approval-history\.jsonl/i.test(word));
}

export function hardDenyReasons(command: string): string[] {
	const resolved = resolveTemporaryVariables(command);
	return unique(
		hardDenyPatterns
			.filter(({ name, pattern }) =>
				name === "access to the approval queue" ? accessesApprovalQueue(command) : pattern.test(resolved),
			)
			.map(({ name }) => name),
	);
}
