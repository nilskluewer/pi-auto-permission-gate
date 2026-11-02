import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { dirname, resolve, sep } from "node:path";
import { commandAccess, commandExecutables } from "./command-access.ts";
import type { InspectedPath } from "./command-inspection.ts";

export { commandAccess, commandExecutables } from "./command-access.ts";

export interface IntentProposal {
	label: string;
	access: "read" | "write";
	reasons: string[];
	targets: string[];
}
export interface IntentGrant extends IntentProposal {
	id: string;
	sessionId: string;
	createdAt: number;
}
interface GrantInput {
	command: string;
	reasons: string[];
	paths: Pick<InspectedPath, "path" | "unresolved">[];
}
interface ProposalInput {
	command: string;
	cwd: string;
	grantableReasons: string[];
	paths: Pick<InspectedPath, "path" | "role" | "unresolved">[];
	home?: string;
}
export interface IntentStore {
	add(sessionId: string, proposal: IntentProposal): IntentGrant;
	match(sessionId: string, input: GrantInput): IntentGrant | undefined;
	list(sessionId?: string): IntentGrant[];
	revoke(id: string): boolean;
	clear(sessionId?: string): void;
}

const directory = (path: string): string => {
	const result = resolve(path);
	return result.endsWith(sep) ? result : result + sep;
};
function inside(path: string, parent: string): boolean {
	const resolved = resolve(path),
		base = resolve(parent);
	return resolved === base || resolved.startsWith(directory(base));
}
const pathTargets = (targets: string[]): string[] =>
	targets.filter((target) => target.startsWith("path:")).map((target) => target.slice(5));
const copy = <T extends IntentProposal>(proposal: T): T => ({
	...proposal,
	reasons: [...proposal.reasons],
	targets: [...proposal.targets],
});

export function proposeIntent({
	command,
	cwd,
	grantableReasons,
	paths,
	home = homedir(),
}: ProposalInput): IntentProposal | undefined {
	if (!grantableReasons.length || paths.some((entry) => entry.unresolved)) return undefined;
	const executables = [...new Set(commandExecutables(command))];
	if (!executables.length) return undefined;
	const directories = [
		...new Set(
			paths.map((entry) => {
				const path = resolve(cwd, entry.path);
				const roles = entry.role.split(", ");
				return directory(roles.includes("working directory") || roles.includes("directory") ? path : dirname(path));
			}),
		),
	];
	if (directories.some((path) => resolve(path) === sep || resolve(path) === resolve(home))) return undefined;
	const collapsed = directories.filter((path) => !directories.some((other) => other !== path && inside(path, other)));
	const access = commandAccess(command);
	const display = collapsed.map((path) => (inside(path, home) ? `~/${path.slice(directory(home).length)}` : path));
	const label = `${access} via ${executables.join(", ")} in ${display.join(", ") || directory(cwd)}`.slice(0, 160);
	return {
		label,
		access,
		reasons: [...new Set(grantableReasons)],
		targets: [...executables.map((name) => `exec:${name}`), ...collapsed.map((path) => `path:${path}`)],
	};
}

function validProposal(proposal: unknown): proposal is IntentProposal {
	const value = proposal as Partial<Record<keyof IntentProposal, unknown>> | null | undefined;
	return Boolean(
		value &&
			typeof value.label === "string" &&
			value.label.trim().length > 0 &&
			value.label.length <= 160 &&
			(value.access === "read" || value.access === "write") &&
			Array.isArray(value.reasons) &&
			value.reasons.length > 0 &&
			value.reasons.every((reason) => typeof reason === "string" && reason.length > 0) &&
			Array.isArray(value.targets) &&
			value.targets.length > 0 &&
			value.targets.every((target) => typeof target === "string" && /^(?:path:\/|exec:[^/]+$)/.test(target)),
	);
}

export function isNarrowerOrEqual(edited: unknown, original: unknown): boolean {
	if (!validProposal(edited) || !validProposal(original)) return false;
	if (edited.access === "write" && original.access !== "write") return false;
	// No executable targets means unrestricted executables, not an empty set.
	if (
		original.targets.some((target) => target.startsWith("exec:")) &&
		!edited.targets.some((target) => target.startsWith("exec:"))
	)
		return false;
	if (!edited.reasons.every((reason) => original.reasons.includes(reason))) return false;
	return edited.targets.every((target) =>
		target.startsWith("path:")
			? pathTargets(original.targets).some((parent) => inside(target.slice(5), parent))
			: original.targets.includes(target),
	);
}

export function grantCovers(grant: unknown, { command, reasons, paths }: GrantInput): boolean {
	if (!validProposal(grant) || !reasons.length || !reasons.every((reason) => grant.reasons.includes(reason)))
		return false;
	if (commandAccess(command) !== "read" && grant.access !== "write") return false;
	const directories = pathTargets(grant.targets);
	if (paths.some((entry) => entry.unresolved || !directories.some((parent) => inside(entry.path, parent))))
		return false;
	const execTargets = grant.targets.filter((target) => target.startsWith("exec:"));
	return !execTargets.length || commandExecutables(command).every((name) => execTargets.includes(`exec:${name}`));
}

export function createIntentStore({
	now = Date.now,
	randomId = randomUUID,
}: {
	now?: () => number;
	randomId?: () => string;
} = {}): IntentStore {
	const grants = new Map<string, IntentGrant>();
	return {
		add(sessionId, proposal) {
			const grant = { ...copy(proposal), id: randomId(), sessionId, createdAt: now() };
			grants.set(grant.id, grant);
			return copy(grant);
		},
		match(sessionId, input) {
			const grant = [...grants.values()].find(
				(candidate) => candidate.sessionId === sessionId && grantCovers(candidate, input),
			);
			return grant ? copy(grant) : undefined;
		},
		list(sessionId) {
			return [...grants.values()].filter((grant) => sessionId === undefined || grant.sessionId === sessionId).map(copy);
		},
		revoke(id) {
			return grants.delete(id);
		},
		clear(sessionId) {
			if (sessionId === undefined) grants.clear();
			else for (const [id, grant] of grants) if (grant.sessionId === sessionId) grants.delete(id);
		},
	};
}
