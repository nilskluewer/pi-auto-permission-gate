import { basename, join } from "node:path";
import { type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createHistoryReporter } from "./approval-client.ts";
import { getAgentConfigDirectory } from "./config-paths.ts";
import { APPROVAL_STATE_FILENAME } from "./constants.ts";
import { recordDecision } from "./gate-display.ts";
import { type GateState } from "./gate-state.ts";
import { type DecisionEntry, type HistoryEntry } from "./types.ts";

function toHistoryEntry(gate: GateState, ctx: ExtensionContext, entry: DecisionEntry, historyId?: string): HistoryEntry {
	return {
		...(historyId ? { id: historyId } : {}),
		sessionId: gate.gateSessionId,
		sessionLabel: basename(ctx.cwd) || ctx.cwd,
		cwd: ctx.cwd,
		command: entry.command,
		risk: entry.risk ?? "low",
		tldr: entry.rationale,
		status: entry.status === "blocked" ? "denied" : entry.status,
		recommendation: entry.recommendation,
		shownAt: entry.shownAt,
		answeredAt: entry.answeredAt,
		scope: entry.scope,
		grantId: entry.grantId,
		note: entry.note,
		source:
			entry.source === "auto-model"
				? "auto"
				: entry.source === "user-rule"
					? "rule"
					: entry.source === "human"
						? "human"
						: entry.source === "intent-grant"
							? "grant"
							: "hard-deny",
		...(entry.via ? { via: entry.via } : {}),
		reasons: entry.reasons,
		...(entry.paths ? { paths: entry.paths, pathNotes: entry.pathNotes } : {}),
		...(entry.model ? { model: entry.model } : {}),
		ts: entry.timestamp,
	};
}

function reportHistory(gate: GateState, ctx: ExtensionContext, entry: DecisionEntry, historyId?: string): void {
	if (!ctx.hasUI || (entry.via === "browser" && !historyId)) return;
	if (gate.dependencies.postHistory) {
		void gate.dependencies.postHistory(toHistoryEntry(gate, ctx, entry, historyId));
		return;
	}
	if (gate.dependencies.requestApproval || process.env.PI_PERMISSION_GATE_BROWSER === "0") return;
	gate.historyReporter ??= createHistoryReporter(join(getAgentConfigDirectory(), APPROVAL_STATE_FILENAME));
	void gate.historyReporter(toHistoryEntry(gate, ctx, entry, historyId));
}
// Records the decision in the session and reports it to the browser history.

export function record(gate: GateState, ctx: ExtensionContext, entry: DecisionEntry, historyId?: string): void {
	recordDecision(gate.pi, entry);
	reportHistory(gate, ctx, entry, historyId);
}
