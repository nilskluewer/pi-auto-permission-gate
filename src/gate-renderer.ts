import { Text } from "@earendil-works/pi-tui";
import { DECISION_ENTRY_TYPE } from "./constants.ts";
import { type GateState } from "./gate-state.ts";
import { type DecisionEntry } from "./types.ts";

export function registerDecisionRenderer(gate: GateState): void {
	gate.pi.registerEntryRenderer(DECISION_ENTRY_TYPE, (entry, { expanded }, theme) => {
		const data = entry.data as Partial<DecisionEntry> | undefined;
		if (!data || typeof data.command !== "string") return new Text("Permission Gate decision", 0, 0);

		const approved = data.status === "approved";
		const title = `Permission Gate: ${(data.status ?? "blocked").toUpperCase()}`;
		const source =
			data.source === "auto-model"
				? "auto model"
				: data.source === "user-rule"
					? "user rule"
					: data.source === "human"
						? "you"
						: data.source === "intent-grant"
							? "intent grant"
							: "hard deny";
		const color = approved
			? "success"
			: data.status === "redirected"
				? "accent"
				: data.status === "expired"
					? "warning"
					: "error";
		const lines = [
			`${theme.fg(color, theme.bold(title))} ${theme.fg("dim", `via ${source}`)}`,
			`${theme.fg("dim", `Command: ${data.command}`)}`,
			`${theme.fg("dim", `Matched: ${(data.reasons ?? []).join(", ")}`)}`,
			`Reason: ${data.rationale ?? "No rationale provided."}`,
		];

		const facts: string[] = [];
		if (data.recommendation) facts.push(`Recommended: ${data.recommendation}`);
		if (data.scope) facts.push(`Scope: ${data.scope === "intent" ? "intent grant" : "once"}`);
		if (typeof data.shownAt === "number" && typeof data.answeredAt === "number")
			facts.push(`Answered after ${Math.max(0, (data.answeredAt - data.shownAt) / 1000).toFixed(1)} s`);
		else if (data.status === "expired") facts.push("No answer");
		if (facts.length > 0) lines.push(theme.fg("dim", facts.join(" · ")));
		if (data.note) lines.push(`Note: ${data.note}`);
		if (expanded && data.grantId) lines.push(theme.fg("dim", `Grant: ${data.grantId}`));
		if (expanded && data.model) lines.push(theme.fg("dim", `Model: ${data.model}`));
		return new Text(lines.join("\n"), 0, 0);
	});

}
