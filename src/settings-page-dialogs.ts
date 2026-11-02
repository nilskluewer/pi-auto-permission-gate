import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
	formatPreferenceCount,
	GATE_OFF_DESCRIPTION,
	type PermissionSettingsAction,
	type PermissionSettingsView,
} from "./settings-page-model.ts";

export async function openPermissionSettingsWithDialogs(
	ctx: Pick<ExtensionContext, "ui">,
	state: PermissionSettingsView,
): Promise<PermissionSettingsAction | undefined> {
	const cancel = "Cancel";
	const gateOption = `Permission gate - ${state.gateEnabled ? "on" : "off"}`;
	const mainOptions = [
		gateOption,
		`Classifier model - ${state.classifierModel}`,
		`Classifier thinking - ${state.classifierThinking}`,
		`Context history messages - ${state.classifierHistoryMessages}`,
		`Command rules - ${state.allowedCommands.length} allowed / ${state.disallowedCommands.length} denied`,
		`Classifier preferences - ${formatPreferenceCount(state.preferences)}`,
		"View classifier prompt",
		"Production patterns",
		`Approval wait - ${state.approvalWaitSeconds ?? 300} seconds`,
		`Session intent grants - ${state.activeGrantCount ?? 0} active`,
		"Approval statistics (14 days)",
		cancel,
	];

	const choice = await ctx.ui.select("Permission Gate Settings", mainOptions);
	if (!choice || choice === cancel) return undefined;
	if (choice === gateOption) {
		const selected = await ctx.ui.select(`Permission gate. ${GATE_OFF_DESCRIPTION}`, [
			state.gateEnabled ? "on" : "off",
			state.gateEnabled ? "off" : "on",
			cancel,
		]);
		if (!selected || selected === cancel) return undefined;
		return { type: "gate", value: selected as "on" | "off" };
	}
	const index = mainOptions.indexOf(choice);
	if (index === 1) {
		const selected = await ctx.ui.select("Select the auto-mode classifier model", [
			...state.classifierModelOptions.map((option) => option.label),
			cancel,
		]);
		if (!selected || selected === cancel) return undefined;
		const option = state.classifierModelOptions.find((item) => item.label === selected);
		return option && option.value !== "info:no-models" ? { type: "classifier-model", value: option.value } : undefined;
	}
	if (index === 2) {
		const selected = await ctx.ui.select("Select the auto-mode classifier thinking level", [
			...state.classifierThinkingOptions.map((option) => option.label),
			cancel,
		]);
		if (!selected || selected === cancel) return undefined;
		const option = state.classifierThinkingOptions.find((item) => item.label === selected);
		return option ? { type: "classifier-thinking", value: option.value } : undefined;
	}
	if (index === 3) {
		const selected = await ctx.ui.select("Select the number of context history messages for the classifier", [
			...state.classifierHistoryMessageOptions.map((option) => option.label),
			cancel,
		]);
		if (!selected || selected === cancel) return undefined;
		const option = state.classifierHistoryMessageOptions.find((item) => item.label === selected);
		if (!option) return undefined;
		const parsed = Number.parseInt(option.value, 10);
		return Number.isNaN(parsed) ? undefined : { type: "history-messages", value: parsed };
	}
	if (index === 4) return openRulesWithDialogs(ctx, state, cancel);
	if (index === 5) return openPreferencesWithDialogs(ctx, state, cancel);
	if (index === 6) return { type: "prompt" };
	if (index === 7) return { type: "production-patterns" };
	if (index === 8) {
		const seconds = await ctx.ui.select("Approval wait (seconds)", ["60", "120", "300", "600", "900", "1800", cancel]);
		return seconds && seconds !== cancel ? { type: "approval-wait", value: Number(seconds) } : undefined;
	}
	if (index === 9) return { type: "intent-grants" };
	if (index === 10) return { type: "statistics" };
	return undefined;
}

async function openRulesWithDialogs(
	ctx: Pick<ExtensionContext, "ui">,
	state: PermissionSettingsView,
	cancel: string,
): Promise<PermissionSettingsAction | undefined> {
	const visibleRules = [
		...state.allowedCommands.map((pattern) => `Allowed - ${pattern}`),
		...state.disallowedCommands.map((pattern) => `Denied - ${pattern}`),
	];
	const selected = await ctx.ui.select(`Command rules (${state.ruleScope})`, [
		...(visibleRules.length > 0 ? visibleRules : ["No user-defined command patterns"]),
		"Edit command patterns",
		"Show full rule report",
		"Reset current rules",
		cancel,
	]);
	if (!selected || selected === cancel || selected === "No user-defined command patterns") return undefined;
	if (selected === "Edit command patterns" || selected.startsWith("Allowed - ") || selected.startsWith("Denied - ")) {
		return { type: "command-rules", value: "edit" };
	}
	if (selected === "Show full rule report") return { type: "command-rules", value: "list" };
	if (selected === "Reset current rules") return { type: "command-rules", value: "reset" };
	return undefined;
}

async function openPreferencesWithDialogs(
	ctx: Pick<ExtensionContext, "ui">,
	state: PermissionSettingsView,
	cancel: string,
): Promise<PermissionSettingsAction | undefined> {
	const selected = await ctx.ui.select(`Classifier preferences (${formatPreferenceCount(state.preferences)})`, [
		...(state.preferences ? ["View current preference notes"] : ["No classifier preferences configured"]),
		"Edit preference notes",
		"Add a preference note",
		"Clear preference notes",
		cancel,
	]);
	if (!selected || selected === cancel || selected === "No classifier preferences configured") return undefined;
	if (selected === "View current preference notes") return { type: "preferences", value: "list" };
	if (selected === "Edit preference notes") return { type: "preferences", value: "edit" };
	if (selected === "Add a preference note") return { type: "preferences", value: "add" };
	if (selected === "Clear preference notes") return { type: "preferences", value: "clear" };
	return undefined;
}
