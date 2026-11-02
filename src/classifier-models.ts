import {
	CLASSIFIER_HISTORY_CHOICES,
	CLASSIFIER_THINKING_LEVELS,
	DEFAULT_CLASSIFIER_HISTORY_MESSAGES,
} from "./constants.ts";
import type {
	AvailableClassifierModel,
	ClassifierModelReference,
	ClassifierThinkingLevel,
	CommandCompletion,
	RegistryModel,
} from "./types.ts";

export function cloneClassifierModelReference(
	reference: ClassifierModelReference | null,
): ClassifierModelReference | null {
	return reference ? { provider: reference.provider, id: reference.id } : null;
}

export function parseClassifierModelReference(value: unknown): ClassifierModelReference | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const candidate = value as Partial<ClassifierModelReference>;
	if (typeof candidate.provider !== "string" || typeof candidate.id !== "string") return undefined;
	const provider = candidate.provider.trim();
	const id = candidate.id.trim();
	if (!provider || !id) return undefined;
	return { provider, id };
}

export function canonicalClassifierModelId(reference: ClassifierModelReference): string {
	return `${reference.provider}/${reference.id}`;
}

export function classifierModelDisplayId(reference: ClassifierModelReference | null): string {
	return reference ? canonicalClassifierModelId(reference) : "unavailable classifier model";
}

export function findAvailableClassifierModel(
	availableModels: readonly AvailableClassifierModel[],
	reference: ClassifierModelReference | null,
): AvailableClassifierModel | undefined {
	return reference
		? availableModels.find((model) => model.canonicalId === canonicalClassifierModelId(reference))
		: undefined;
}

export function isClassifierThinkingLevel(value: string): value is ClassifierThinkingLevel {
	return (CLASSIFIER_THINKING_LEVELS as readonly string[]).includes(value);
}

function getSupportedClassifierThinkingLevels(model: RegistryModel): ClassifierThinkingLevel[] {
	if (model.reasoning !== true) return ["off"];
	return CLASSIFIER_THINKING_LEVELS.filter((level) => {
		const mapped = model.thinkingLevelMap?.[level];
		if (mapped === null) return false;
		if (level === "xhigh" || level === "max") return mapped !== undefined;
		return true;
	});
}

export function clampClassifierThinkingLevel(
	model: RegistryModel,
	configured: ClassifierThinkingLevel,
): ClassifierThinkingLevel {
	const availableLevels = getSupportedClassifierThinkingLevels(model);
	if (availableLevels.includes(configured)) return configured;

	const requestedIndex = CLASSIFIER_THINKING_LEVELS.indexOf(configured);
	for (let index = requestedIndex; index < CLASSIFIER_THINKING_LEVELS.length; index += 1) {
		const candidate = CLASSIFIER_THINKING_LEVELS[index];
		if (availableLevels.includes(candidate)) return candidate;
	}
	for (let index = requestedIndex - 1; index >= 0; index -= 1) {
		const candidate = CLASSIFIER_THINKING_LEVELS[index];
		if (availableLevels.includes(candidate)) return candidate;
	}
	return availableLevels[0] ?? "off";
}

function effectiveClassifierThinkingLevel(
	model: RegistryModel | undefined,
	configured: ClassifierThinkingLevel,
): ClassifierThinkingLevel | "unavailable" {
	return model ? clampClassifierThinkingLevel(model, configured) : "unavailable";
}

export function formatClassifierThinkingLevel(
	configured: ClassifierThinkingLevel,
	model: RegistryModel | undefined,
): string {
	const effective = effectiveClassifierThinkingLevel(model, configured);
	return configured === effective ? `thinking ${configured}` : `thinking ${configured} -> ${effective}`;
}

function filterTextModels(models: readonly unknown[]): RegistryModel[] {
	const uniqueModels = new Map<string, RegistryModel>();
	for (const candidate of models) {
		if (!candidate || typeof candidate !== "object") continue;
		const model = candidate as RegistryModel;
		if (
			typeof model.provider !== "string" ||
			model.provider === "" ||
			typeof model.id !== "string" ||
			model.id === "" ||
			!Array.isArray(model.input) ||
			!model.input.includes("text")
		) {
			continue;
		}
		const canonicalId = canonicalClassifierModelId(model);
		if (!uniqueModels.has(canonicalId)) uniqueModels.set(canonicalId, model);
	}

	return [...uniqueModels.values()].sort((left, right) => {
		const leftId = canonicalClassifierModelId(left);
		const rightId = canonicalClassifierModelId(right);
		return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
	});
}

export function getAvailableClassifierModels(ctx: {
	modelRegistry: { getAvailable: () => readonly unknown[] };
}): RegistryModel[] {
	try {
		return filterTextModels(ctx.modelRegistry.getAvailable());
	} catch {
		return [];
	}
}

function describeClassifierModels(
	models: readonly unknown[],
	getProviderDisplayName: (provider: string) => string,
): AvailableClassifierModel[] {
	return filterTextModels(models).map((model) => ({
		model,
		canonicalId: canonicalClassifierModelId(model),
		providerDisplayName: getProviderDisplayName(model.provider),
		modelName: model.name || model.id,
	}));
}

export function cacheAvailableClassifierModels(ctx: {
	modelRegistry: {
		getAvailable: () => readonly unknown[];
		getProviderDisplayName: (provider: string) => string;
	};
}): AvailableClassifierModel[] {
	return describeClassifierModels(ctx.modelRegistry.getAvailable(), (provider) =>
		ctx.modelRegistry.getProviderDisplayName(provider),
	);
}

export function cacheScopedClassifierModels(ctx: {
	scopedModels: readonly { model: unknown }[];
	modelRegistry: { getProviderDisplayName: (provider: string) => string };
}): AvailableClassifierModel[] {
	return describeClassifierModels(
		ctx.scopedModels.map((scoped) => scoped.model),
		(provider) => ctx.modelRegistry.getProviderDisplayName(provider),
	);
}

export function formatClassifierModelLabel(
	reference: ClassifierModelReference | null,
	availableModel: AvailableClassifierModel | RegistryModel | undefined,
	configuredThinkingLevel: ClassifierThinkingLevel,
): string {
	const model = availableModel && "model" in availableModel ? availableModel.model : availableModel;
	return `${classifierModelDisplayId(reference)} (${formatClassifierThinkingLevel(configuredThinkingLevel, model)})`;
}

export function getModelDescription(model: AvailableClassifierModel): string {
	return `${model.providerDisplayName} - ${model.modelName}`;
}

export function getClassifierThinkingChoices(
	model: RegistryModel | undefined,
	configured: ClassifierThinkingLevel,
): string[] {
	const supportedLevels = model ? getSupportedClassifierThinkingLevels(model) : [];
	const levels = model
		? [...supportedLevels, ...CLASSIFIER_THINKING_LEVELS.filter((level) => !supportedLevels.includes(level))]
		: [...CLASSIFIER_THINKING_LEVELS];

	const choices = levels.map((level) => {
		const details = model
			? supportedLevels.includes(level)
				? `supported${level === configured ? "; current" : ""}`
				: `unsupported; effective ${clampClassifierThinkingLevel(model, level)}${level === configured ? "; current" : ""}`
			: `model unavailable${level === configured ? "; current" : ""}`;
		return `${level} - ${details}`;
	});
	choices.push("reset - Restore high (default)");
	return choices;
}

function getClassifierThinkingCompletions(argumentPrefix: string): CommandCompletion[] | null {
	const prefix = argumentPrefix.trimStart();
	const tokens = prefix.split(/\s+/).filter(Boolean);
	const trailingSpace = /\s$/.test(argumentPrefix);
	if (tokens.length > 1) return null;

	const query = tokens[0]?.toLowerCase() ?? "";
	const thinkingItems = CLASSIFIER_THINKING_LEVELS.map((level) => ({
		value: level,
		label: level,
		description: `Classifier thinking level: ${level}`,
	}));
	const resetItem = { value: "reset", label: "reset", description: "Restore the default classifier thinking level" };
	if (isClassifierThinkingLevel(query) || query === "reset") return null;
	if (tokens.length === 0 || trailingSpace) return [...thinkingItems, resetItem];
	return [
		...thinkingItems.filter((item) => item.value.startsWith(query)),
		...(resetItem.value.startsWith(query) ? [resetItem] : []),
	];
}

function getClassifierModelArgumentCompletions(
	argumentPrefix: string,
	availableModels: readonly AvailableClassifierModel[],
): CommandCompletion[] | null {
	const prefix = argumentPrefix.trimStart();
	const tokens = prefix.split(/\s+/).filter(Boolean);
	const trailingSpace = /\s$/.test(argumentPrefix);
	if (tokens.length > 1) return null;

	const query = tokens[0] ?? "";
	const lowerQuery = query.toLowerCase();
	const resetItem = { value: "reset", label: "reset", description: "Restore the default classifier model" };
	const completedModel = availableModels.some((model) => model.canonicalId === query);
	if (completedModel || lowerQuery === "reset") return null;

	const modelItems = availableModels
		.filter((model) => model.canonicalId.toLowerCase().startsWith(lowerQuery))
		.map((model) => ({
			value: model.canonicalId,
			label: model.canonicalId,
			description: getModelDescription(model),
		}));
	if (tokens.length === 0 || trailingSpace) return [resetItem, ...modelItems];
	return [...(resetItem.value.startsWith(lowerQuery) ? [resetItem] : []), ...modelItems];
}

export function getClassifierModelCompletions(
	argumentPrefix: string,
	availableModels: readonly AvailableClassifierModel[],
): CommandCompletion[] | null {
	const prefix = argumentPrefix.trimStart();
	const tokens = prefix.split(/\s+/).filter(Boolean);
	const trailingSpace = /\s$/.test(argumentPrefix);
	const subcommands = [
		{ value: "on", label: "on", description: "Enable auto mode" },
		{ value: "off", label: "off", description: "Disable auto mode" },
		{ value: "status", label: "status", description: "Show auto mode and classifier status" },
		{ value: "model", label: "model", description: "Choose the auto-mode classifier model" },
		{ value: "thinking", label: "thinking", description: "Configure classifier thinking level" },
		{ value: "history", label: "history", description: "Configure number of previous messages sent to classifier" },
		{ value: "prompt", label: "prompt", description: "Show the classifier prompt" },
		{ value: "preferences", label: "preferences", description: "Edit classifier preference notes" },
		{ value: "wait", label: "wait", description: "Configure the short approval wait" },
		{ value: "production", label: "production", description: "Edit production target patterns" },
		{ value: "grants", label: "grants", description: "List and revoke this session's intent grants" },
		{ value: "statistics", label: "statistics", description: "Show approval fatigue statistics for 14 days" },
	];

	if (tokens.length === 0 || (tokens.length === 1 && !trailingSpace)) {
		const query = tokens[0]?.toLowerCase() ?? "";
		return subcommands.filter((item) => item.value.startsWith(query));
	}

	const action = tokens[0]?.toLowerCase();
	if (action === "thinking") {
		if (tokens.length > 2) return null;
		const thinkingPrefix = tokens.length === 1 ? "" : `${tokens[1]}${trailingSpace ? " " : ""}`;
		return getClassifierThinkingCompletions(thinkingPrefix);
	}
	if (action === "history") {
		if (tokens.length > 2) return null;
		const historyPrefix = (tokens.length === 1 ? "" : (tokens[1] ?? "")).toLowerCase();
		const historyItems: CommandCompletion[] = CLASSIFIER_HISTORY_CHOICES.map((n) => ({
			value: String(n),
			label: String(n),
			description: `${n} previous messages`,
		}));
		const resetItem: CommandCompletion = {
			value: "reset",
			label: "reset",
			description: `Restore default (${DEFAULT_CLASSIFIER_HISTORY_MESSAGES} messages)`,
		};
		if (tokens.length === 1 && trailingSpace) return [resetItem, ...historyItems];
		return [
			...(resetItem.value.startsWith(historyPrefix) ? [resetItem] : []),
			...historyItems.filter((item) => item.value.startsWith(historyPrefix)),
		];
	}
	if (action !== "model") return null;
	if (tokens.length > 2) return null;

	const modelPrefix = tokens.length === 1 ? "" : `${tokens[1]}${trailingSpace ? " " : ""}`;
	return getClassifierModelArgumentCompletions(modelPrefix, availableModels);
}
