import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
	canonicalClassifierModelId,
	findAvailableClassifierModel,
	formatClassifierModelLabel,
	formatClassifierThinkingLevel,
	getClassifierThinkingChoices,
	getModelDescription,
} from "./classifier-models.ts";
import {
	handleClassifierHistoryCommand,
	handleClassifierModelCommand,
	handleClassifierThinkingCommand,
} from "./commands-model.ts";
import { handleAutoModePreferencesCommand, handleAutoModePromptCommand } from "./commands-preferences.ts";
import { handlePermissionRulesCommand } from "./commands-rules.ts";
import { handleAutoModeSettingsCommand } from "./commands-settings.ts";
import {
	AUTO_MODE_MODEL_ID,
	AUTO_MODE_MODEL_PROVIDER,
	CLASSIFIER_HISTORY_CHOICES,
	DEFAULT_CLASSIFIER_HISTORY_MESSAGES,
} from "./constants.ts";
import {
	refreshAutoModePreferences,
	setGate,
	syncAvailableClassifierModels,
	syncScopedClassifierModels,
} from "./gate-controls.ts";
import type { GateState } from "./gate-state.ts";
import {
	openPermissionSettings,
	type PermissionSettingsAction,
	type PermissionSettingsOption,
} from "./settings-page.ts";

function getPermissionSettingsModelOptions(gate: GateState): PermissionSettingsOption[] {
	const options: PermissionSettingsOption[] = [
		{
			value: "reset",
			label: "Reset to default classifier",
			description: `${AUTO_MODE_MODEL_PROVIDER}/${AUTO_MODE_MODEL_ID}`,
		},
	];
	if (gate.scopedClassifierModels.length === 0) {
		options.push({
			value: "info:no-models",
			label: "No scoped models available",
			description: "Configure Pi's --models option or enabledModels setting to choose a model.",
		});
		return options;
	}
	const currentModelId = gate.classifierModel ? canonicalClassifierModelId(gate.classifierModel) : undefined;
	options.push(
		...gate.scopedClassifierModels.map((model) => ({
			value: model.canonicalId,
			label: model.canonicalId === currentModelId ? `${model.canonicalId} (current)` : model.canonicalId,
			description: getModelDescription(model),
		})),
	);
	return options;
}

function getPermissionSettingsThinkingOptions(gate: GateState): PermissionSettingsOption[] {
	const selected = findAvailableClassifierModel(gate.availableClassifierModels, gate.classifierModel);
	return getClassifierThinkingChoices(selected?.model, gate.classifierThinkingLevel).map((choice) => {
		const separator = choice.indexOf(" - ");
		const value = separator >= 0 ? choice.slice(0, separator) : choice;
		const description = separator >= 0 ? choice.slice(separator + 3) : undefined;
		return {
			value,
			label: value === gate.classifierThinkingLevel ? `${value} (current)` : value,
			description,
		};
	});
}

function getPermissionSettingsHistoryOptions(gate: GateState): PermissionSettingsOption[] {
	const options: PermissionSettingsOption[] = CLASSIFIER_HISTORY_CHOICES.map((n) => ({
		value: String(n),
		label: n === gate.classifierHistoryMessages ? `${n} messages (current)` : `${n} messages`,
		description: `Send the last ${n} messages from the conversation`,
	}));
	options.push({
		value: String(DEFAULT_CLASSIFIER_HISTORY_MESSAGES),
		label: `reset (${DEFAULT_CLASSIFIER_HISTORY_MESSAGES} messages)`,
		description: "Restore the default history message limit",
	});
	return options;
}

function buildPermissionSettingsView(gate: GateState, ctx: ExtensionContext) {
	syncAvailableClassifierModels(gate, ctx);
	syncScopedClassifierModels(gate, ctx);
	const selected = findAvailableClassifierModel(gate.availableClassifierModels, gate.classifierModel);
	return {
		autoModeEnabled: gate.autoModeEnabled,
		classifierModel: formatClassifierModelLabel(gate.classifierModel, selected, gate.classifierThinkingLevel),
		classifierModelOptions: getPermissionSettingsModelOptions(gate),
		classifierThinking: formatClassifierThinkingLevel(gate.classifierThinkingLevel, selected?.model),
		classifierThinkingOptions: getPermissionSettingsThinkingOptions(gate),
		classifierHistoryMessages: gate.classifierHistoryMessages,
		classifierHistoryMessageOptions: getPermissionSettingsHistoryOptions(gate),
		ruleScope: gate.ruleScope,
		allowedCommands: gate.ruleConfig.allowedCommands,
		disallowedCommands: gate.ruleConfig.disallowedCommands,
		preferences: gate.autoModePreferences,
		productionPatterns: gate.productionPatterns,
		approvalWaitSeconds: gate.approvalWaitSeconds,
		activeGrantCount: gate.intentStore.list(gate.gateSessionId).length,
	};
}

async function handlePermissionSettingsAction(
	gate: GateState,
	action: PermissionSettingsAction,
	ctx: ExtensionContext,
): Promise<void> {
	switch (action.type) {
		case "gate":
			await setGate(gate, ctx, action.value);
			return;
		case "production-patterns":
			await handleAutoModeSettingsCommand(gate, "production", ctx);
			return;
		case "approval-wait":
			await handleAutoModeSettingsCommand(gate, `wait ${action.value}`, ctx);
			return;
		case "intent-grants":
			await handleAutoModeSettingsCommand(gate, "grants", ctx);
			return;
		case "statistics":
			await handleAutoModeSettingsCommand(gate, "statistics", ctx);
			return;
		case "classifier-model":
			await handleClassifierModelCommand(gate, action.value, ctx);
			return;
		case "classifier-thinking":
			await handleClassifierThinkingCommand(gate, action.value, ctx);
			return;
		case "history-messages":
			await handleClassifierHistoryCommand(gate, String(action.value), ctx);
			return;
		case "command-rules":
			await handlePermissionRulesCommand(gate, action.value, ctx);
			return;
		case "preferences":
			if (action.value === "add") {
				const note = await ctx.ui.input("Add an auto-mode classifier preference note:", "");
				if (note?.trim()) await handleAutoModePreferencesCommand(gate, note, ctx);
				return;
			}
			if (action.value === "edit") {
				await handleAutoModePreferencesCommand(gate, "", ctx);
				return;
			}
			if (action.value === "clear") {
				const confirmed = await ctx.ui.confirm(
					"Clear classifier preferences?",
					"All user-authored auto-mode preference notes will be removed.",
				);
				if (!confirmed) return;
			}
			await handleAutoModePreferencesCommand(gate, action.value, ctx);
			return;
		case "prompt":
			await handleAutoModePromptCommand(gate, ctx);
			return;
	}
}

export async function handlePermissionSettingsCommand(gate: GateState, ctx: ExtensionContext): Promise<void> {
	if (!ctx.hasUI) {
		await handleAutoModeSettingsCommand(gate, "", ctx);
		return;
	}

	while (true) {
		await refreshAutoModePreferences(gate, ctx);
		const action = await openPermissionSettings(ctx, buildPermissionSettingsView(gate, ctx));
		if (!action) return;
		await handlePermissionSettingsAction(gate, action, ctx);
	}
}
