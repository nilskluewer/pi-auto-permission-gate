import type { BashToolCallEvent, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { classifyWithModel } from "./classifier.ts";
import { inspectCommand, inspectionIsFresh, inspectionPrompt } from "./command-inspection.ts";
import { evaluateUserCommandRules } from "./command-rules.ts";
import { MAX_CONSECUTIVE_DENIALS, MAX_TOTAL_DENIALS, NO_RETRY_NOTICE } from "./constants.ts";
import { assessCriticality } from "./criticality.ts";
import { refreshAutoModePreferences } from "./gate-controls.ts";
import { notify } from "./gate-display.ts";
import { record } from "./gate-history.ts";
import type { GateState } from "./gate-state.ts";
import { askHuman } from "./human-approval.ts";
import { isNarrowerOrEqual, proposeIntent } from "./intent-grants.ts";
import { CLASSIFIER_REQUIRED_REASON, hardDenyReasons, matchedReasons } from "./risk-patterns.ts";
import { preview, unique } from "./text.ts";
import type { ApprovalOutcome, ApprovalRequest, ApprovalRisk, CommandInspection, DecisionEntry } from "./types.ts";

function snapshotKey(inspection: CommandInspection): string {
	return JSON.stringify([inspectionPrompt(inspection), [...inspection.fingerprints]]);
}

function registerDenial(gate: GateState, ctx: ExtensionContext): boolean {
	if (!gate.gateEnabled) return false;
	gate.consecutiveDenials += 1;
	gate.totalDenials += 1;
	if (gate.lockdown || (gate.consecutiveDenials < MAX_CONSECUTIVE_DENIALS && gate.totalDenials < MAX_TOTAL_DENIALS))
		return false;
	gate.lockdown = true;
	notify(
		ctx,
		`Permission gate lockdown: ${gate.consecutiveDenials} commands in a row and ${gate.totalDenials} in total were blocked. Every command now needs your approval.`,
		"warning",
	);
	return true;
}

function registerApproval(gate: GateState) {
	gate.consecutiveDenials = 0;
}

// The agent gets a generic message only. Classifier text stays with the human, so the agent
// cannot learn the exact boundary and probe around it. A note from the human is passed on.

function denialMessage(what: string, note: string | undefined, lockdownStarted: boolean): string {
	return [
		`Blocked by the permission gate: ${what}.`,
		note ? `Note from the user: ${note}` : "",
		NO_RETRY_NOTICE,
		lockdownStarted ? "Several actions were blocked in a row, so every command now needs the user's approval." : "",
	]
		.filter(Boolean)
		.join(" ");
}

export async function reviewBash(
	gate: GateState,
	event: BashToolCallEvent,
	ctx: ExtensionContext & { signal: AbortSignal },
	cancelled: () => boolean,
) {
	const signal = ctx.signal;
	const command = typeof event.input.command === "string" ? event.input.command : "";
	const hardReasons = hardDenyReasons(command);
	const userRule = evaluateUserCommandRules(command, gate.ruleConfig);
	const reasons = matchedReasons(command, gate.ruleConfig, ctx.cwd);

	if (hardReasons.length > 0) {
		const rationale = `Non-negotiable safety rule matched: ${hardReasons.join(", ")}.`;
		record(gate, ctx, {
			command: preview(command),
			reasons: unique([...reasons, ...hardReasons]),
			status: "blocked",
			source: "hard-deny",
			rationale,
			risk: "critical",
			timestamp: gate.now(),
		});
		const started = registerDenial(gate, ctx);
		return {
			block: true,
			reason: `${rationale} The command was blocked. ${NO_RETRY_NOTICE}${started ? " Every command now needs the user's approval." : ""}`,
		};
	}

	if (userRule?.decision === "deny") {
		const rationale = `User disallowed command pattern matched: ${userRule.pattern}.`;
		record(gate, ctx, {
			command: preview(command),
			reasons: ["user disallowed command"],
			status: "blocked",
			source: "user-rule",
			rationale,
			risk: "medium",
			timestamp: gate.now(),
		});
		const started = registerDenial(gate, ctx);
		return {
			block: true,
			reason: `${rationale} The command was blocked. ${NO_RETRY_NOTICE}${started ? " Every command now needs the user's approval." : ""}`,
		};
	}

	// Inspect every invocation, including commands covered by a human grant.
	if (reasons.length === 0 && !gate.lockdown) return undefined;
	for (let review = 0; review < 3; review++) {
		if (ctx.signal?.aborted)
			return { block: true, reason: "Blocked by the permission gate: the request was cancelled." };
		const inspection = await inspectCommand(command, ctx.cwd);
		if (signal.aborted) return { block: true, reason: "Blocked by the permission gate: the request was cancelled." };
		const display = { paths: inspection.paths, pathNotes: inspection.notes };
		const reviewContext = {
			cwd: ctx.cwd,
			signal: ctx.signal,
			modelRegistry: ctx.modelRegistry,
			sessionManager: ctx.sessionManager,
			inspection,
		};
		const recordReviewed = (entry: DecisionEntry, historyId?: string) => {
			if (!cancelled()) record(gate, ctx, { ...display, ...entry }, historyId);
		};
		const policy = assessCriticality(command, reasons, { productionPatterns: gate.productionPatterns });
		const locked = gate.lockdown;
		const snapshot = snapshotKey(inspection);
		const lateIndex = gate.lateApprovals.findIndex((a) => a.command === command && a.snapshot === snapshot);
		if (!locked && lateIndex >= 0) {
			// Consume before an await so concurrent calls cannot use one approval twice.
			const [approval] = gate.lateApprovals.splice(lateIndex, 1);
			if (!(await inspectionIsFresh(inspection))) continue;
			if (signal.aborted) return { block: true, reason: "Blocked by the permission gate: the request was cancelled." };
			recordReviewed(
				{
					command: preview(command),
					reasons,
					status: "approved",
					source: "human",
					rationale: "The user approved this exact command and inspection snapshot after the short wait.",
					scope: "once",
					note: "late approval",
					via: "browser",
					recommendation: approval.recommendation,
					shownAt: approval.shownAt,
					answeredAt: approval.answeredAt,
					timestamp: gate.now(),
				},
				approval.historyId,
			);
			registerApproval(gate);
			return undefined;
		}
		if (!locked && !policy.critical && !reasons.includes(CLASSIFIER_REQUIRED_REASON)) {
			const grant = gate.intentStore.match(gate.gateSessionId, { command, reasons, paths: inspection.paths });
			if (grant) {
				if (!(await inspectionIsFresh(inspection))) continue;
				if (signal.aborted)
					return { block: true, reason: "Blocked by the permission gate: the request was cancelled." };
				recordReviewed({
					command: preview(command),
					reasons,
					status: "approved",
					source: "intent-grant",
					rationale: `Covered by your session intent: ${grant.label}`,
					scope: "intent",
					grantId: grant.id,
					timestamp: gate.now(),
				});
				registerApproval(gate);
				return undefined;
			}
		}

		let recommendation: ApprovalRequest["recommendation"] = "review";
		let risk: ApprovalRisk = policy.critical ? "critical" : "medium";
		let model: string | undefined;
		let rationale = locked
			? `Lockdown: the agent was blocked ${gate.consecutiveDenials} times in a row. Review this command before it runs.`
			: `Review the command and its effects: ${reasons.join(", ")}.`;
		let failed = false;
		if (!locked) {
			await refreshAutoModePreferences(gate, ctx);
			if (signal.aborted) return { block: true, reason: "Blocked by the permission gate: the request was cancelled." };
			const result = await classifyWithModel(
				command,
				reasons,
				reviewContext,
				gate.dependencies,
				gate.classifierModel,
				gate.classifierThinkingLevel,
				gate.autoModePreferences,
				gate.classifierHistoryMessages,
				policy.critical,
			);
			failed = Boolean(result.failed);
			model = result.model;
			rationale = result.rationale;
			recommendation = failed ? "review" : result.decision === "allow" ? "approve" : "deny";
			risk = policy.critical ? "critical" : (result.risk ?? "medium");
			if (ctx.signal?.aborted) {
				recordReviewed({
					command: preview(command),
					reasons,
					status: "blocked",
					source: "auto-model",
					rationale: "The request was cancelled before the command ran.",
					model,
					recommendation,
					timestamp: gate.now(),
				});
				return { block: true, reason: "Blocked by the permission gate: the request was cancelled." };
			}
			if (!(await inspectionIsFresh(inspection))) continue;
			if (signal.aborted) return { block: true, reason: "Blocked by the permission gate: the request was cancelled." };
			if (!failed && result.decision === "allow" && risk !== "critical") {
				recordReviewed({
					command: preview(command),
					reasons,
					status: "approved",
					source: "auto-model",
					rationale,
					model,
					risk,
					recommendation,
					timestamp: gate.now(),
				});
				registerApproval(gate);
				return undefined;
			}
		}
		const proposal =
			!locked && !policy.critical && risk !== "critical" && !reasons.includes(CLASSIFIER_REQUIRED_REASON)
				? proposeIntent({ command, cwd: ctx.cwd, grantableReasons: policy.grantableReasons, paths: inspection.paths })
				: undefined;
		const generation = gate.sessionGeneration;
		let lateDelivered = false;
		const onLateOutcome = (outcome: ApprovalOutcome, shownAt: number) => {
			if (generation !== gate.sessionGeneration || lateDelivered) return;
			lateDelivered = true;
			let content: string;
			if (outcome.status === "approved") {
				gate.lateApprovals.push({
					command,
					snapshot,
					recommendation,
					shownAt,
					answeredAt: gate.now(),
					scope: "once",
					historyId: outcome.historyId,
				});
				content = `The user approved this command after the wait: ${command}\nYou may run the exact command again. This is a single-use approval for the same inspection snapshot; changed code needs a new assessment.`;
			} else if (outcome.status === "redirected" && outcome.note?.trim()) {
				content = `The user redirected you: ${outcome.note.trim()}. Follow this instruction instead of running the command.`;
			} else if (outcome.status === "denied") {
				content = `The user denied the command: ${command}. ${NO_RETRY_NOTICE}`;
			} else return;
			gate.pi.sendMessage(
				{ customType: "permission-gate-late-answer", content, display: true },
				{ triggerTurn: true, deliverAs: "followUp" },
			);
		};
		const human = await askHuman(
			gate,
			ctx,
			{
				...display,
				kind: locked ? "lockdown" : "command",
				command,
				risk,
				tldr: failed ? `${rationale} Please review the command yourself.` : rationale,
				recommendation,
				reasons: reasons.length ? reasons : ["lockdown"],
				model,
				intentProposal: proposal,
				environment: policy.environment,
			},
			onLateOutcome,
		);
		if (ctx.signal?.aborted || human.cancelled || generation !== gate.sessionGeneration)
			return { block: true, reason: "Blocked by the permission gate: the request was cancelled." };
		if (human.approved && !(await inspectionIsFresh(inspection))) continue;
		if (ctx.signal?.aborted || generation !== gate.sessionGeneration)
			return { block: true, reason: "Blocked by the permission gate: the request was cancelled." };

		let grantId: string | undefined;
		if (human.approved && human.scope === "intent") {
			const intent = human.intent ?? proposal;
			if (proposal && intent && isNarrowerOrEqual(intent, proposal)) {
				grantId = gate.intentStore.add(gate.gateSessionId, intent).id;
			} else {
				human.scope = "once";
				human.fallbackNote = "The edited intent was not narrower than the proposal; approved once only.";
			}
		}
		const status = human.status ?? (human.approved ? "approved" : "blocked");
		recordReviewed(
			{
				command: preview(command),
				reasons: reasons.length ? reasons : ["lockdown"],
				status,
				source: "human",
				rationale: [
					rationale,
					human.unavailable
						? "No approver was reachable, so the command was blocked."
						: status === "expired"
							? human.note
							: status === "redirected"
								? `You redirected the agent: ${human.note}`
								: `You ${human.approved ? "approved" : "denied"} the command ${human.via === "browser" ? "in the browser" : "in the terminal"}.`,
					human.fallbackNote,
				]
					.filter(Boolean)
					.join(" "),
				model,
				risk,
				via: human.via,
				timestamp: gate.now(),
				recommendation,
				shownAt: human.shownAt,
				answeredAt: human.answeredAt,
				scope: human.scope ?? "once",
				grantId,
				note: human.note,
			},
			human.historyId,
		);
		if (human.approved) {
			if (human.liftLockdown) {
				gate.lockdown = false;
				gate.totalDenials = 0;
			}
			registerApproval(gate);
			return undefined;
		}
		if (status === "redirected")
			return {
				block: true,
				reason: `The user redirected you: ${human.note}. Follow this instruction instead of running the command.`,
			};
		if (status === "expired")
			return {
				block: true,
				reason: human.note ?? "The user is away; continue with other work or end the turn and ask in plain text.",
			};
		const started = locked ? false : registerDenial(gate, ctx);
		return {
			block: true,
			reason: denialMessage(
				human.unavailable
					? `no approver was reachable (${reasons.join(", ")})`
					: locked
						? "lockdown is active"
						: `the user did not approve this action (${reasons.join(", ")})`,
				human.note,
				started,
			),
		};
	}
	if (signal.aborted) return { block: true, reason: "Blocked by the permission gate: the request was cancelled." };
	const rationale = "Inspected files kept changing during review; the command was not run.";
	record(gate, ctx, {
		command: preview(command),
		reasons,
		status: "blocked",
		source: "auto-model",
		rationale,
		timestamp: gate.now(),
	});
	const started = registerDenial(gate, ctx);
	return {
		block: true,
		reason: `${rationale} ${NO_RETRY_NOTICE}${started ? " Every command now needs the user's approval." : ""}`,
	};
}
