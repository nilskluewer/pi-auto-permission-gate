import { DEFAULT_COMMAND_RULE_CONFIG } from "./constants.ts";
import type { CommandRuleConfig } from "./types.ts";

// User-editable command patterns use shell-style '*' and '?' wildcards.
// Shell control syntax is never accepted by an allow pattern; hard-deny rules
// remain non-overridable even when a user adds a broad allow pattern.
export const SHELL_CONTROL_CHARACTERS = /[\r\n;&|<>$`()\\]/;

function commandGlobToRegExp(pattern: string): RegExp {
	let source = "^";
	for (const character of pattern) {
		if (character === "*") source += "[\\s\\S]*";
		else if (character === "?") source += "[\\s\\S]";
		else source += character.replace(/[\\^$.+()[\]{}|]/g, "\\$&");
	}
	return new RegExp(`${source}$`, "i");
}

function matchesCommandPattern(command: string, pattern: string, allowShellControl: boolean): boolean {
	const normalizedPattern = pattern.trim();
	if (!normalizedPattern || normalizedPattern.includes("\n") || normalizedPattern.includes("\r")) return false;
	if (!allowShellControl && SHELL_CONTROL_CHARACTERS.test(command)) return false;
	return commandGlobToRegExp(normalizedPattern).test(command.trim());
}

function matchesAnyCommandPattern(command: string, patterns: string[], allowShellControl: boolean): string | undefined {
	return patterns.find((pattern) => matchesCommandPattern(command, pattern, allowShellControl));
}

// Splits a compound command (`cd x && uv run y | tail`) into simple segments so an allow pattern
// can match each one. Returns undefined for anything that can hide a second command or
// change meaning at runtime: command substitution, heredocs, subshells, escapes, or file
// redirects. Only `2>&1` and redirects to /dev/null are accepted.
export function splitSimpleSegments(command: string): string[] | undefined {
	const SAFE_REDIRECT = /^(?:>&\d|>>?\s*\/dev\/null)(?![\w./-])/;
	const segments: string[] = [];
	let current = "";
	let quote: "'" | '"' | undefined;
	for (let i = 0; i < command.length; i += 1) {
		const char = command[i];
		const rest = command.slice(i);
		if (char === "\\" || char === "\r" || char === "`") return undefined;
		if (quote === "'") {
			if (char === "'") quote = undefined;
			current += char;
			continue;
		}
		if (char === "$" && command[i + 1] === "(") return undefined;
		if (quote === '"') {
			if (char === '"') quote = undefined;
			current += char;
			continue;
		}
		if (char === "'" || char === '"') {
			quote = char;
			current += char;
			continue;
		}
		if (char === "(" || char === ")") return undefined;
		if (char === ">" || char === "<") {
			const redirect = SAFE_REDIRECT.exec(rest);
			if (!redirect) return undefined;
			current += redirect[0];
			i += redirect[0].length - 1;
			continue;
		}
		if (char === "\n" || char === ";" || char === "|" || char === "&") {
			// `&&` and `||` are two characters, a lone `&` is a background operator.
			if ((char === "&" || char === "|") && command[i + 1] === char) i += 1;
			segments.push(current);
			current = "";
			continue;
		}
		current += char;
	}
	if (quote) return undefined;
	segments.push(current);
	const trimmed = segments.map((segment) => segment.trim()).filter(Boolean);
	return trimmed.length > 0 ? trimmed : undefined;
}

// Segments with no side effects beyond the shell state or reading, which need no allow pattern.
const TRIVIAL_SEGMENT = /^(?:cd(?:\s+[^\s]+)?|(?:tail|head|wc|sleep)(?:\s+[\w./:=+-]+)*)$/;

function findAllowedPattern(command: string, patterns: string[]): string | undefined {
	if (!SHELL_CONTROL_CHARACTERS.test(command)) return matchesAnyCommandPattern(command, patterns, false);

	const segments = splitSimpleSegments(command);
	if (!segments) return undefined;
	let matched: string | undefined;
	for (const segment of segments) {
		if (TRIVIAL_SEGMENT.test(segment)) continue;
		const pattern = matchesAnyCommandPattern(segment, patterns, true);
		if (!pattern) return undefined;
		matched ??= pattern;
	}
	return matched;
}

export function evaluateUserCommandRules(
	command: string,
	config: CommandRuleConfig,
): { decision: "allow" | "deny"; pattern: string } | undefined {
	const deniedPattern = matchesAnyCommandPattern(command, config.disallowedCommands, true);
	if (deniedPattern) return { decision: "deny", pattern: deniedPattern };

	const allowedPattern = findAllowedPattern(command, config.allowedCommands);
	if (allowedPattern) return { decision: "allow", pattern: allowedPattern };
	return undefined;
}

export function cloneDefaultCommandRuleConfig(): CommandRuleConfig {
	return {
		allowedCommands: [...DEFAULT_COMMAND_RULE_CONFIG.allowedCommands],
		disallowedCommands: [...DEFAULT_COMMAND_RULE_CONFIG.disallowedCommands],
	};
}
