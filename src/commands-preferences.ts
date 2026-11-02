import { type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { buildAutoModePrompt } from "./classifier-prompt.ts";
import { getAutoModePreferencesPath } from "./config-paths.ts";
import { AUTO_MODE_SETTINGS_COMMAND } from "./constants.ts";
import { persistAutoModePreferences, refreshAutoModePreferences } from "./gate-controls.ts";
import { notify } from "./gate-display.ts";
import { type GateState } from "./gate-state.ts";
import { appendAutoModePreference } from "./persistence.ts";

export async function handleAutoModePromptCommand(gate: GateState, ctx: ExtensionContext): Promise<void> {
	await refreshAutoModePreferences(gate, ctx);
	const prompt = buildAutoModePrompt(gate.autoModePreferences, gate.classifierHistoryMessages);
	if (ctx.hasUI) {
		await ctx.ui.editor("Auto-mode classifier prompt (close without saving)", prompt);
		return;
	}
	notify(ctx, prompt, "info");
}

export async function handleAutoModePreferencesCommand(gate: GateState, args: string, ctx: ExtensionContext): Promise<void> {
	await refreshAutoModePreferences(gate, ctx);
	const rawValue = String(args ?? "").trim();
	if (!rawValue) {
		if (!ctx.hasUI) {
			notify(
				ctx,
				`/${AUTO_MODE_SETTINGS_COMMAND} preferences needs an interactive UI without text. Use /${AUTO_MODE_SETTINGS_COMMAND} preferences <text> or edit ${getAutoModePreferencesPath()} directly.`,
				"warning",
			);
			return;
		}

		let edited: string | undefined;
		try {
			edited = await ctx.ui.editor("Edit auto-mode classifier preference notes", gate.autoModePreferences);
		} catch (error) {
			notify(
				ctx,
				`Permission gate: preference editor failed: ${error instanceof Error ? error.message : String(error)}`,
				"error",
			);
			return;
		}
		if (edited === undefined) return;

		if (!(await persistAutoModePreferences(gate, ctx, edited))) return;
		notify(ctx, `Auto-mode classifier preferences saved to ${getAutoModePreferencesPath()}.`, "info");
		return;
	}

	const lowered = rawValue.toLowerCase();
	if (lowered === "list") {
		const prompt = gate.autoModePreferences || "(no auto-mode preferences configured)";
		if (ctx.hasUI) await ctx.ui.editor("Auto-mode classifier preference notes (close without saving)", prompt);
		else notify(ctx, prompt, "info");
		return;
	}
	if (lowered === "clear") {
		if (!(await persistAutoModePreferences(gate, ctx, ""))) return;
		notify(ctx, "Auto-mode classifier preferences cleared.", "info");
		return;
	}

	const nextPreferences = appendAutoModePreference(gate.autoModePreferences, rawValue);
	if (!(await persistAutoModePreferences(gate, ctx, nextPreferences))) return;
	notify(ctx, `Added an auto-mode classifier preference note to ${getAutoModePreferencesPath()}.`, "info");
}
