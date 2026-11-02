import { join } from "node:path";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { findAvailableClassifierModel, formatClassifierModelLabel } from "./classifier-models.ts";
import {
	handleClassifierHistoryCommand,
	handleClassifierModelCommand,
	handleClassifierThinkingCommand,
} from "./commands-model.ts";
import { handleAutoModePreferencesCommand, handleAutoModePromptCommand } from "./commands-preferences.ts";
import { getAgentConfigDirectory } from "./config-paths.ts";
import { APPROVAL_WAIT_CHOICES, AUTO_MODE_SETTINGS_COMMAND } from "./constants.ts";
import { formatFatigueSummary, readSessionDecisions, summarizeDecisions } from "./fatigue-summary.ts";
import { persistMode, refreshStatus, setGate, syncAvailableClassifierModels } from "./gate-controls.ts";
import { notify } from "./gate-display.ts";
import type { GateState } from "./gate-state.ts";
import { unique } from "./text.ts";

export async function handleAutoModeSettingsCommand(
	gate: GateState,
	args: string,
	ctx: ExtensionContext,
): Promise<void> {
	const rawValue = String(args ?? "").trim();
	const parts = rawValue.split(/\s+/).filter(Boolean);
	const first = parts[0]?.toLowerCase() ?? "";

	if (first === "wait") {
		const selected =
			parts[1] ??
			(ctx.hasUI ? await ctx.ui.select("Approval wait (seconds)", APPROVAL_WAIT_CHOICES.map(String)) : undefined);
		if (parts.length > 2 || !selected || !APPROVAL_WAIT_CHOICES.map(String).includes(selected)) {
			notify(ctx, `Usage: /${AUTO_MODE_SETTINGS_COMMAND} wait [${APPROVAL_WAIT_CHOICES.join("|")}]`, "warning");
			return;
		}
		gate.approvalWaitSeconds = Number(selected);
		await persistMode(gate, ctx);
		notify(ctx, `Approval wait: ${gate.approvalWaitSeconds} seconds.`, "info");
		return;
	}
	if (first === "production") {
		const edited =
			parts.length > 1
				? parts.slice(1).join(" ")
				: ctx.hasUI
					? await ctx.ui.editor(
							"Production patterns (one per line; * and ? wildcards)",
							gate.productionPatterns.join("\n"),
						)
					: undefined;
		if (edited === undefined) return;
		gate.productionPatterns = unique(edited.split(/[\s,]+/).filter(Boolean));
		await persistMode(gate, ctx);
		notify(
			ctx,
			`Production patterns: ${gate.productionPatterns.join(", ") || "(none; unknown targets remain critical)"}`,
			"info",
		);
		return;
	}
	if (first === "grants") {
		if (!ctx.hasUI) return;
		while (true) {
			const grants = gate.intentStore.list(gate.gateSessionId);
			const choices = grants.map((grant) => `${grant.id}: ${grant.label} — ${grant.targets.join(", ")}`);
			const choice = await ctx.ui.select(`Session intent grants (${gate.gateSessionId}) — select to revoke`, [
				...choices,
				"Revoke all",
				"Close",
			]);
			if (!choice || choice === "Close") return;
			if (choice === "Revoke all") gate.intentStore.clear(gate.gateSessionId);
			else {
				const index = choices.indexOf(choice);
				if (index < 0) return;
				gate.intentStore.revoke(grants[index].id);
			}
		}
	}
	if (first === "statistics") {
		const range = { from: gate.now() - 14 * 24 * 60 * 60 * 1000 };
		try {
			const decisions = await readSessionDecisions(join(getAgentConfigDirectory(), "sessions"), range);
			notify(ctx, formatFatigueSummary(summarizeDecisions(decisions), range), "info");
		} catch (error) {
			notify(ctx, `Could not read approval statistics: ${String(error)}`, "error");
		}
		return;
	}
	if (first === "model") {
		await handleClassifierModelCommand(gate, parts.slice(1).join(" "), ctx);
		return;
	}
	if (first === "thinking") {
		await handleClassifierThinkingCommand(gate, parts.slice(1).join(" "), ctx);
		return;
	}
	if (first === "history") {
		await handleClassifierHistoryCommand(gate, parts.slice(1).join(" "), ctx);
		return;
	}
	if (first === "prompt") {
		if (parts.length !== 1) {
			notify(ctx, `Usage: /${AUTO_MODE_SETTINGS_COMMAND} prompt`, "warning");
			return;
		}
		await handleAutoModePromptCommand(gate, ctx);
		return;
	}
	if (first === "preferences") {
		await handleAutoModePreferencesCommand(gate, parts.slice(1).join(" "), ctx);
		return;
	}

	const value = rawValue.toLowerCase();
	if (value === "on" || value === "enable" || value === "enabled") {
		await setGate(gate, ctx, "on");
		return;
	} else if (value === "off" || value === "disable" || value === "disabled") {
		await setGate(gate, ctx, "off");
		return;
	} else if (value === "status" || !value) {
		syncAvailableClassifierModels(gate, ctx);
		const selected = findAvailableClassifierModel(gate.availableClassifierModels, gate.classifierModel);
		notify(
			ctx,
			`Permission gate: ${gate.autoModeEnabled ? "ON" : "OFF"}; classifier model is ${formatClassifierModelLabel(gate.classifierModel, selected, gate.classifierThinkingLevel)}; context history: ${gate.classifierHistoryMessages} message${gate.classifierHistoryMessages === 1 ? "" : "s"}; approval wait: ${gate.approvalWaitSeconds}s; production patterns: ${gate.productionPatterns.join(", ")}; active grants: ${gate.intentStore.list(gate.gateSessionId).length}.`,
			"info",
		);
		refreshStatus(gate, ctx);
		return;
	} else {
		notify(
			ctx,
			`Usage: /${AUTO_MODE_SETTINGS_COMMAND} [on|off|status|model [provider/model-id|reset]|thinking [level|reset]|history [count|reset]|prompt|preferences [text|list|clear]|wait [seconds]|production [patterns]|grants|statistics]`,
			"warning",
		);
		return;
	}
}
