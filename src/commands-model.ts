import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
	classifierModelDisplayId,
	cloneClassifierModelReference,
	findAvailableClassifierModel,
	formatClassifierModelLabel,
	formatClassifierThinkingLevel,
	getClassifierThinkingChoices,
	getModelDescription,
	isClassifierThinkingLevel,
} from "./classifier-models.ts";
import {
	AUTO_MODE_SETTINGS_COMMAND,
	CLASSIFIER_HISTORY_CHOICES,
	DEFAULT_CLASSIFIER_HISTORY_MESSAGES,
	DEFAULT_CLASSIFIER_MODEL,
	DEFAULT_CLASSIFIER_THINKING_LEVEL,
	MAX_CLASSIFIER_HISTORY_MESSAGES,
	MIN_CLASSIFIER_HISTORY_MESSAGES,
	NO_SCOPED_CLASSIFIER_MODELS_WARNING,
} from "./constants.ts";
import {
	canPromptForSelection,
	persistMode,
	refreshAvailableClassifierModels,
	refreshStatus,
	syncAvailableClassifierModels,
	syncScopedClassifierModels,
} from "./gate-controls.ts";
import { notify } from "./gate-display.ts";
import type { GateState } from "./gate-state.ts";
import type { AvailableClassifierModel } from "./types.ts";

export async function handleClassifierModelCommand(
	gate: GateState,
	args: string,
	ctx: ExtensionContext,
): Promise<void> {
	const parts = String(args ?? "")
		.trim()
		.split(/\s+/)
		.filter(Boolean);
	if (parts.length === 0) {
		if (!canPromptForSelection(ctx)) {
			notify(
				ctx,
				`Choosing a classifier model requires interactive mode. Use /${AUTO_MODE_SETTINGS_COMMAND} model provider/model-id instead.`,
				"warning",
			);
			return;
		}

		syncScopedClassifierModels(gate, ctx);
		const models = gate.scopedClassifierModels;
		if (models.length === 0) {
			notify(ctx, NO_SCOPED_CLASSIFIER_MODELS_WARNING, "warning");
			return;
		}

		const choices = models.map((model) => `${model.canonicalId} - ${getModelDescription(model)}`);
		const choice = await ctx.ui.select("Select the auto-mode classifier model:", choices);
		if (!choice) return;
		const selectedIndex = choices.indexOf(choice);
		const selected = selectedIndex >= 0 ? models[selectedIndex] : models.find((model) => model.canonicalId === choice);
		if (!selected) {
			notify(ctx, "Permission gate: the selected classifier model is no longer available.", "warning");
			return;
		}
		gate.classifierModel = { provider: selected.model.provider, id: selected.model.id };
		await persistMode(gate, ctx);
		refreshStatus(gate, ctx);
		notify(
			ctx,
			`Permission gate classifier model set to ${formatClassifierModelLabel(gate.classifierModel, selected, gate.classifierThinkingLevel)}.`,
			"info",
		);
		return;
	}

	if (parts.length !== 1) {
		notify(ctx, `Usage: /${AUTO_MODE_SETTINGS_COMMAND} model [provider/model-id|reset]`, "warning");
		return;
	}

	const modelArgument = parts[0];
	if (modelArgument.toLowerCase() === "reset") {
		gate.classifierModel = cloneClassifierModelReference(DEFAULT_CLASSIFIER_MODEL);
		syncAvailableClassifierModels(gate, ctx);
		await persistMode(gate, ctx);
		refreshStatus(gate, ctx);
		notify(
			ctx,
			`Permission gate classifier model reset to ${formatClassifierModelLabel(gate.classifierModel, findAvailableClassifierModel(gate.availableClassifierModels, gate.classifierModel), gate.classifierThinkingLevel)}.`,
			"info",
		);
		return;
	}

	let models: AvailableClassifierModel[];
	try {
		models = await refreshAvailableClassifierModels(gate, ctx);
	} catch {
		notify(ctx, "Permission gate could not discover classifier models after refreshing Pi's model registry.", "error");
		return;
	}
	const selected = models.find((model) => model.canonicalId === modelArgument);
	if (!selected) {
		notify(
			ctx,
			`Permission gate classifier model ${modelArgument} is not an available authenticated text-capable model.`,
			"warning",
		);
		return;
	}
	gate.classifierModel = { provider: selected.model.provider, id: selected.model.id };
	await persistMode(gate, ctx);
	refreshStatus(gate, ctx);
	notify(
		ctx,
		`Permission gate classifier model set to ${formatClassifierModelLabel(gate.classifierModel, selected, gate.classifierThinkingLevel)}.`,
		"info",
	);
}

export async function handleClassifierThinkingCommand(
	gate: GateState,
	args: string,
	ctx: ExtensionContext,
): Promise<void> {
	const parts = String(args ?? "")
		.trim()
		.split(/\s+/)
		.filter(Boolean);
	if (parts.length === 0 && !canPromptForSelection(ctx)) {
		notify(
			ctx,
			`Choosing a classifier thinking level requires interactive mode. Use /${AUTO_MODE_SETTINGS_COMMAND} thinking <level> instead.`,
			"warning",
		);
		return;
	}

	syncAvailableClassifierModels(gate, ctx);
	const selected = findAvailableClassifierModel(gate.availableClassifierModels, gate.classifierModel);
	if (parts.length === 0) {
		const choices = getClassifierThinkingChoices(selected?.model, gate.classifierThinkingLevel);
		const choice = await ctx.ui.select("Select the auto-mode classifier thinking level:", choices);
		if (!choice) return;
		const requestedThinkingLevel = choice.split(" - ", 1)[0]?.trim().toLowerCase();
		const nextThinkingLevel =
			requestedThinkingLevel === "reset"
				? DEFAULT_CLASSIFIER_THINKING_LEVEL
				: requestedThinkingLevel && isClassifierThinkingLevel(requestedThinkingLevel)
					? requestedThinkingLevel
					: undefined;
		if (!nextThinkingLevel) {
			notify(ctx, "Permission gate: the selected thinking level is no longer available.", "warning");
			return;
		}
		gate.classifierThinkingLevel = nextThinkingLevel;
	} else {
		if (parts.length !== 1) {
			notify(
				ctx,
				`Usage: /${AUTO_MODE_SETTINGS_COMMAND} thinking [off|minimal|low|medium|high|xhigh|max|reset]`,
				"warning",
			);
			return;
		}

		const requestedThinkingLevel = parts[0].toLowerCase();
		const nextThinkingLevel =
			requestedThinkingLevel === "reset"
				? DEFAULT_CLASSIFIER_THINKING_LEVEL
				: isClassifierThinkingLevel(requestedThinkingLevel)
					? requestedThinkingLevel
					: undefined;
		if (!nextThinkingLevel) {
			notify(
				ctx,
				`Usage: /${AUTO_MODE_SETTINGS_COMMAND} thinking [off|minimal|low|medium|high|xhigh|max|reset]`,
				"warning",
			);
			return;
		}
		gate.classifierThinkingLevel = nextThinkingLevel;
	}

	syncAvailableClassifierModels(gate, ctx);
	await persistMode(gate, ctx);
	refreshStatus(gate, ctx);
	notify(
		ctx,
		`Permission gate classifier for ${classifierModelDisplayId(gate.classifierModel)} is ${formatClassifierThinkingLevel(gate.classifierThinkingLevel, findAvailableClassifierModel(gate.availableClassifierModels, gate.classifierModel)?.model)}.`,
		"info",
	);
}

export async function handleClassifierHistoryCommand(
	gate: GateState,
	args: string,
	ctx: ExtensionContext,
): Promise<void> {
	const parts = String(args ?? "")
		.trim()
		.split(/\s+/)
		.filter(Boolean);
	if (parts.length === 0 && !canPromptForSelection(ctx)) {
		notify(
			ctx,
			`Choosing context history message count requires interactive mode. Use /${AUTO_MODE_SETTINGS_COMMAND} history <number> instead.`,
			"warning",
		);
		return;
	}

	if (parts.length === 0) {
		const choices = CLASSIFIER_HISTORY_CHOICES.map(
			(n) => `${n} message${n === 1 ? "" : "s"}${n === gate.classifierHistoryMessages ? " (current)" : ""}`,
		);
		choices.push(`reset - Restore ${DEFAULT_CLASSIFIER_HISTORY_MESSAGES} (default)`);
		const choice = await ctx.ui.select("Select the number of context history messages for the classifier:", choices);
		if (!choice) return;
		if (choice.startsWith("reset")) {
			gate.classifierHistoryMessages = DEFAULT_CLASSIFIER_HISTORY_MESSAGES;
		} else {
			const count = Number.parseInt(choice, 10);
			if (Number.isNaN(count)) return;
			gate.classifierHistoryMessages = count;
		}
	} else {
		if (parts.length !== 1) {
			notify(
				ctx,
				`Usage: /${AUTO_MODE_SETTINGS_COMMAND} history [0-${MAX_CLASSIFIER_HISTORY_MESSAGES}|reset]`,
				"warning",
			);
			return;
		}

		const requested = parts[0].toLowerCase();
		if (requested === "reset") {
			gate.classifierHistoryMessages = DEFAULT_CLASSIFIER_HISTORY_MESSAGES;
		} else {
			const count = Number.parseInt(requested, 10);
			if (
				Number.isNaN(count) ||
				count < MIN_CLASSIFIER_HISTORY_MESSAGES ||
				count > MAX_CLASSIFIER_HISTORY_MESSAGES ||
				String(count) !== requested
			) {
				notify(
					ctx,
					`Usage: /${AUTO_MODE_SETTINGS_COMMAND} history [0-${MAX_CLASSIFIER_HISTORY_MESSAGES}|reset]`,
					"warning",
				);
				return;
			}
			gate.classifierHistoryMessages = count;
		}
	}

	await persistMode(gate, ctx);
	notify(
		ctx,
		`Permission gate classifier context history set to ${gate.classifierHistoryMessages} previous message${gate.classifierHistoryMessages === 1 ? "" : "s"}.`,
		"info",
	);
}
