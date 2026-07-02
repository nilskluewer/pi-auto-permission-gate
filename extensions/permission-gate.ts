/**
 * Permission Gate Extension
 *
 * Prompts for confirmation before running potentially dangerous bash commands.
 * In non-interactive mode, matching commands are blocked by default.
 *
 * Focus areas:
 * - Commands that can destroy the local machine or user data
 * - Commands that can irreversibly damage a Git repository/history
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

type DangerousPattern = {
	name: string;
	pattern: RegExp;
};

const dangerousPatterns: DangerousPattern[] = [
	// File deletion / destructive filesystem traversal
	{ name: "recursive/forced rm", pattern: /\brm\b(?=[^\n;&|]*\s-(?:[^\s;&|]*[rR][^\s;&|]*[fF]?|[^\s;&|]*[fF][^\s;&|]*[rR])\b|[^\n;&|]*\s--recursive\b)/i },
	{ name: "remove Git metadata", pattern: /\brm\b[^\n;&|]*\s(?:\.git|\.git\/|['"]\.git['"])/i },
	{ name: "find delete", pattern: /\bfind\b[^\n;&|]*\s-delete\b/i },
	{ name: "xargs rm", pattern: /\bxargs\b[^\n;&|]*\brm\b/i },

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
	{ name: "macOS disk erase", pattern: /\bdiskutil\b[^\n;&|]*\b(?:erase|partition|apfs\s+delete|apfs\s+erase)\b/i },
	{ name: "dd writes to disk device", pattern: /\bdd\b[^\n;&|]*\bof=\/dev\//i },

	// Git working tree / repo / history destruction
	{ name: "git reset hard", pattern: /\bgit\b[^\n;&|]*\breset\b[^\n;&|]*\s--hard\b/i },
	{ name: "git clean forced", pattern: /\bgit\b[^\n;&|]*\bclean\b(?=[^\n;&|]*\s-[^\s;&|]*f)[^\n;&|]*/i },
	{ name: "git force push", pattern: /\bgit\b[^\n;&|]*\bpush\b[^\n;&|]*\s--(?:force|force-with-lease|mirror)\b/i },
	{ name: "git force push", pattern: /\bgit\b[^\n;&|]*\bpush\b[^\n;&|]*\s-[^\s;&|]*f[^\s;&|]*\b/i },
	{ name: "git branch force-delete", pattern: /\bgit\b[^\n;&|]*\bbranch\b[^\n;&|]*\s-D\b/i },
	{ name: "git tag delete", pattern: /\bgit\b[^\n;&|]*\btag\b[^\n;&|]*\s-d\b/i },
	{ name: "git remove files", pattern: /\bgit\b[^\n;&|]*\brm\b/i },
	{ name: "git checkout all files", pattern: /\bgit\b[^\n;&|]*\bcheckout\b[^\n;&|]*\s--\s+(?:\.|\*)\b/i },
	{ name: "git restore all files", pattern: /\bgit\b[^\n;&|]*\brestore\b[^\n;&|]*(?:\s\.\b|\s:\/\b|\s--source\b)/i },
	{ name: "git reflog expiry", pattern: /\bgit\b[^\n;&|]*\breflog\b[^\n;&|]*\bexpire\b/i },
	{ name: "git aggressive prune/gc", pattern: /\bgit\b[^\n;&|]*\b(?:gc|prune)\b[^\n;&|]*(?:--prune=(?:now|all)|--expire\s+now|--expire=now)/i },

	// Containers / volumes can destroy local databases and development state
	{ name: "docker prune/remove volumes", pattern: /\bdocker\b[^\n;&|]*\b(?:system\s+prune|volume\s+(?:rm|prune)|container\s+prune|image\s+prune)\b/i },
	{ name: "docker compose remove volumes", pattern: /\bdocker\s+compose\b[^\n;&|]*\bdown\b[^\n;&|]*(?:\s-v\b|\s--volumes\b)/i },

	// Running remote scripts can do anything with current user permissions
	{ name: "downloaded script execution", pattern: /\b(?:curl|wget)\b[^\n;&|]*(?:\|\s*(?:sh|bash|zsh)\b|\b(?:sh|bash|zsh)\s*<\s*\()/i },
];

function matchedReasons(command: string): string[] {
	return dangerousPatterns.filter(({ pattern }) => pattern.test(command)).map(({ name }) => name);
}

function preview(command: string): string {
	const maxLength = 1200;
	return command.length > maxLength ? `${command.slice(0, maxLength)}\n… (truncated)` : command;
}

export default function (pi: ExtensionAPI) {
	pi.on("tool_call", async (event, ctx) => {
		if (event.toolName !== "bash") return undefined;

		const command = typeof event.input.command === "string" ? event.input.command : "";
		const reasons = matchedReasons(command);
		if (reasons.length === 0) return undefined;

		const reason = `Potentially dangerous command blocked/needs confirmation: ${[...new Set(reasons)].join(", ")}`;

		if (!ctx.hasUI) {
			return { block: true, reason: `${reason} (no UI for confirmation)` };
		}

		const choice = await ctx.ui.select(
			`⚠️ Dangerous bash command detected\n\nReasons: ${[...new Set(reasons)].join(", ")}\n\n${preview(command)}\n\nAllow this command to run?`,
			["No", "Yes"],
		);

		if (choice !== "Yes") {
			return { block: true, reason: "Blocked by user" };
		}

		return undefined;
	});
}
