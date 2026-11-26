import { basename } from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { formatPaths } from "./command-inspection.ts";
import { createApprovalComponent, type TerminalApprovalView } from "./terminal-approval-component.ts";
import type { ApprovalRequest } from "./types.ts";

export async function selectTerminalApproval(
	ctx: Pick<ExtensionContext, "mode" | "ui" | "cwd">,
	request: Pick<
		ApprovalRequest,
		"tldr" | "risk" | "recommendation" | "environment" | "paths" | "pathNotes" | "command"
	>,
	options: string[],
	signal: AbortSignal,
): Promise<string | undefined> {
	if (signal.aborted) return undefined;
	const project = `Project: ${basename(ctx.cwd)} — ${ctx.cwd}`;
	const noteCount = (request.pathNotes ?? []).length;
	const view: TerminalApprovalView = {
		summary: `Execution summary: ${request.tldr}`,
		facts: [
			`Recommended: ${request.recommendation} · Permission gate: ${request.risk.toUpperCase()} risk`,
			...(request.environment ? [`Environment: ${request.environment}`] : []),
			project,
			`Static references only; ${noteCount} inspection note${noteCount === 1 ? "" : "s"} in Files and paths.`,
		].join("\n"),
		details: [
			{
				label: "Files and paths",
				text: [
					project,
					formatPaths(request.paths),
					"Static references only; runtime code can construct additional paths.",
					...(request.pathNotes ?? []),
				].join("\n"),
			},
			{
				label: "Command / inline code",
				text: `Execution summary: ${request.tldr}\n\n${request.command}`,
			},
		],
	};

	if (ctx.mode === "tui") {
		let cancel: (() => void) | undefined;
		try {
			const result = await ctx.ui.custom<string | null>(
				(tui, theme, keybindings, done) => {
					cancel = () => done(null);
					signal.addEventListener("abort", cancel, { once: true });
					if (signal.aborted) cancel();
					return createApprovalComponent(tui, theme, keybindings, view, options, done);
				},
				{ blocked: { kind: "permission", message: "Allow this command to run?" } },
			);
			return signal.aborted ? undefined : (result ?? undefined);
		} finally {
			if (cancel) signal.removeEventListener("abort", cancel);
		}
	}

	// RPC clients support dialogs, but not custom terminal components.
	const detailOptions = view.details.map((detail) => `Show ${detail.label.toLowerCase()}…`);
	while (!signal.aborted) {
		const choice = await ctx.ui.select(
			`${view.summary}\n${view.facts}\n\nAllow this command to run? (You can also answer in the browser queue.)`,
			[...options, ...detailOptions],
			{ signal },
		);
		if (signal.aborted) return undefined;
		const detailIndex = detailOptions.indexOf(choice ?? "");
		if (detailIndex < 0) return choice;
		await ctx.ui.select(`${view.details[detailIndex].label}\n\n${view.details[detailIndex].text}`, ["Back"], {
			signal,
		});
	}
	return undefined;
}
