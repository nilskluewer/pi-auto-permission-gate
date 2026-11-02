import { basename, join } from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createApprovalRequester } from "./approval-client.ts";
import { formatPaths } from "./command-inspection.ts";
import { getAgentConfigDirectory } from "./config-paths.ts";
import { APPROVAL_STATE_FILENAME, LATE_ANSWER_WINDOW_MS } from "./constants.ts";
import type { GateState } from "./gate-state.ts";
import { preview } from "./text.ts";
import type { ApprovalOutcome, ApprovalRequest, ApprovalRequester, HumanDecision } from "./types.ts";

function getApprovalRequester(gate: GateState): ApprovalRequester | undefined {
	if (gate.dependencies.requestApproval) return gate.dependencies.requestApproval;
	if (process.env.PI_PERMISSION_GATE_BROWSER === "0") return undefined;
	gate.requestApproval ??= createApprovalRequester(join(getAgentConfigDirectory(), APPROVAL_STATE_FILENAME));
	return gate.requestApproval;
}

// Asks the human in the shared browser queue and in the terminal at the same time.
// The first answer wins and cancels the other. Without any reachable approver the result is
// "unavailable", which the caller treats as a block.

export function askHuman(
	gate: GateState,
	ctx: ExtensionContext,
	request: Pick<
		ApprovalRequest,
		| "kind"
		| "command"
		| "risk"
		| "tldr"
		| "recommendation"
		| "reasons"
		| "model"
		| "paths"
		| "pathNotes"
		| "intentProposal"
		| "environment"
	>,
	onLateOutcome: (outcome: ApprovalOutcome, shownAt: number) => void,
): Promise<HumanDecision> {
	if (ctx.signal?.aborted) return Promise.resolve({ approved: false, cancelled: true });
	const requester = ctx.hasUI ? getApprovalRequester(gate) : undefined;
	if (!ctx.hasUI)
		return Promise.resolve({
			approved: false,
			unavailable: true,
			scope: "once",
			recommendation: request.recommendation,
		});

	const terminal = new AbortController();
	const browser = new AbortController();
	const park = new AbortController();
	gate.pendingApprovals.add(browser);
	const shownAt = gate.now();
	const generation = gate.sessionGeneration;
	return new Promise<HumanDecision>((resolve) => {
		let settled = false;
		let browserAvailable = Boolean(requester);
		let answerers = 0;
		let timer: ReturnType<typeof setTimeout> | undefined;
		const cleanupBrowser = () => {
			gate.pendingApprovals.delete(browser);
			ctx.signal?.removeEventListener("abort", onOuterAbort);
		};
		const settle = (decision: HumanDecision) => {
			if (settled) return;
			settled = true;
			ctx.signal?.removeEventListener("abort", onOuterAbort);
			clearTimeout(timer);
			terminal.abort();
			if (decision.status !== "expired") {
				browser.abort();
				cleanupBrowser();
			} else if (!requester) cleanupBrowser();
			resolve({
				...decision,
				shownAt,
				...(decision.status === "expired" || decision.unavailable || decision.cancelled
					? {}
					: { answeredAt: gate.now() }),
				scope: decision.scope ?? "once",
				recommendation: request.recommendation,
			});
		};
		const onOuterAbort = () => {
			browser.abort();
			settle({ approved: false, cancelled: true });
			cleanupBrowser();
		};
		ctx.signal?.addEventListener("abort", onOuterAbort, { once: true });
		browser.signal.addEventListener(
			"abort",
			() => {
				settle({ approved: false, cancelled: true });
				cleanupBrowser();
			},
			{ once: true },
		);
		const answererGone = () => {
			answerers--;
			if (!answerers) settle({ approved: false, unavailable: true });
		};
		const waitMs = gate.dependencies.approvalWaitMs ?? gate.approvalWaitSeconds * 1000;
		timer = setTimeout(() => {
			settle({
				approved: false,
				status: "expired",
				note: browserAvailable
					? "The user is away; continue with other work that does not need this command, or end the turn and ask in plain text. If the user answers later, a message follows."
					: "The user is away; continue with other work that does not need this command, or end the turn and ask in plain text. Without the browser channel, late answers are not possible.",
			});
			park.abort();
		}, waitMs);

		if (requester) {
			answerers++;
			void requester(
				{
					...request,
					ttlMs: waitMs + LATE_ANSWER_WINDOW_MS,
					tldr: request.environment ? `${request.tldr} Environment: ${request.environment}.` : request.tldr,
					sessionId: gate.gateSessionId,
					sessionLabel: basename(ctx.cwd) || ctx.cwd,
					cwd: ctx.cwd,
				},
				browser.signal,
				{
					parkSignal: park.signal,
					onLateOutcome: (outcome) => {
						if (park.signal.aborted && generation === gate.sessionGeneration && !browser.signal.aborted)
							onLateOutcome(outcome, shownAt);
					},
				},
			)
				.then((outcome) => {
					if (settled) return;
					if (!outcome) {
						browserAvailable = false;
						return answererGone();
					}
					if (outcome.status === "cancelled") return settle({ approved: false, cancelled: true, via: "browser" });
					if (outcome.status === "expired")
						return settle({
							approved: false,
							status: "expired",
							note: "The user is away; continue with other work or end the turn and ask in plain text.",
							via: "browser",
						});
					const note = outcome.note?.trim();
					// Invalid redirects fail closed, never count as a useful steering answer.
					if (outcome.status === "redirected" && !note)
						return settle({ approved: false, note: "Redirect needs an instruction.", via: "browser" });
					settle({
						approved: outcome.status === "approved",
						status: outcome.status === "redirected" ? "redirected" : undefined,
						note,
						scope: outcome.scope === "intent" ? "intent" : "once",
						intent: outcome.intent,
						historyId: outcome.historyId,
						liftLockdown: outcome.scope === "session" && request.kind === "lockdown",
						via: "browser",
					});
				})
				.catch(() => {
					browserAvailable = false;
					if (!settled) answererGone();
				})
				.finally(cleanupBrowser);
		}

		answerers++;
		const intentOption = request.intentProposal ? `Yes, for this session: ${request.intentProposal.label}` : undefined;
		const options = [
			"No",
			"Yes",
			...(request.kind === "lockdown" ? ["Yes, and lift lockdown"] : []),
			...(intentOption ? [intentOption] : []),
			"Redirect…",
		];
		const title = [
			`Execution summary: ${request.tldr}`,
			`Recommended: ${request.recommendation}`,
			`Permission gate: ${request.risk.toUpperCase()} risk`,
			...(request.environment ? [`Environment: ${request.environment}`] : []),
			"",
			`Project: ${basename(ctx.cwd)} — ${ctx.cwd}`,
			"",
			"Files and paths:",
			formatPaths(request.paths),
			"Static references only; runtime code can construct additional paths.",
			...(request.pathNotes ?? []),
			"",
			preview(request.command),
			"",
			"Allow this command to run? (You can also answer in the browser queue.)",
		].join("\n");
		void (async () => {
			while (!settled) {
				const choice = await ctx.ui.select(title, options, { signal: terminal.signal });
				if (settled) return;
				if (terminal.signal.aborted) return settle({ approved: false, cancelled: true });
				if (choice === "Redirect…") {
					const note = await ctx.ui.input("Redirect: what should the agent do instead?", "", {
						signal: terminal.signal,
					});
					if (settled) return;
					if (note === undefined) return settle({ approved: false, via: "terminal" });
					if (!note.trim()) continue;
					return settle({ approved: false, status: "redirected", note: note.trim(), via: "terminal" });
				}
				return settle({
					approved:
						choice === "Yes" ||
						choice === "Yes, and lift lockdown" ||
						(intentOption !== undefined && choice === intentOption),
					scope: intentOption !== undefined && choice === intentOption ? "intent" : "once",
					liftLockdown: choice === "Yes, and lift lockdown",
					via: "terminal",
				});
			}
		})().catch(() => {
			if (!settled) answererGone();
		});
		if (ctx.signal?.aborted) onOuterAbort();
	});
}
