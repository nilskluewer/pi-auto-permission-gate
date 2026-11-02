import {
	clampClassifierThinkingLevel,
	formatClassifierModelLabel,
	getAvailableClassifierModels,
} from "./classifier-models.ts";
import {
	buildAutoModeSystemPrompt,
	buildClassifierPrompt,
	extractText,
	parseAutoModeDecision,
} from "./classifier-prompt.ts";
import { CLASSIFIER_TIMEOUT_MS, DEFAULT_CLASSIFIER_HISTORY_MESSAGES } from "./constants.ts";
import { truncate } from "./text.ts";
import type {
	ApprovalRisk,
	ClassifierComplete,
	ClassifierContext,
	ClassifierModelReference,
	ClassifierResponse,
	ClassifierThinkingLevel,
	CommandInspection,
	ParsedAutoDecision,
	PermissionGateDependencies,
	RegistryModel,
} from "./types.ts";

function createProviderComplete(provider: unknown): ClassifierComplete {
	return async (model, context, options) => {
		if (!provider || typeof provider !== "object") {
			throw new Error("The configured classifier provider is not available.");
		}

		const streamSimple = (
			provider as {
				streamSimple?: (
					model: unknown,
					context: unknown,
					options: unknown,
				) => { result: () => Promise<ClassifierResponse> };
			}
		).streamSimple;
		if (typeof streamSimple !== "function") {
			throw new Error("The configured classifier provider cannot stream simple responses.");
		}
		return streamSimple.call(provider, model, context, options).result();
	};
}

export type ClassifierAuth = {
	apiKey?: string;
	headers?: Record<string, string | null>;
	env?: Record<string, string>;
	baseUrl?: string;
};

// Two stages, like Claude Code auto mode. Stage 1 is a fast pass without reasoning that errs
// toward "deny". Only "allow" ends there. Everything else goes to stage 2 with reasoning.
// The reasoning budget counts against maxTokens, so stage 2 gets a large budget and one retry
// without reasoning when the first try returns no text (stopReason "length").
export type ClassifierAttempt = { fastPass: boolean; reasoning: ClassifierThinkingLevel; maxTokens: number };
export type ClassifierOutcome = { decision: ParsedAutoDecision } | { failure: string };

async function requestClassifierDecision(
	complete: ClassifierComplete,
	model: RegistryModel,
	auth: ClassifierAuth,
	effectiveThinkingLevel: ClassifierThinkingLevel,
	command: string,
	reasons: string[],
	ctx: {
		cwd: string;
		signal?: AbortSignal;
		sessionManager: { getBranch: () => unknown[] };
		inspection?: CommandInspection;
	},
	preferences: string,
	historyMessages = DEFAULT_CLASSIFIER_HISTORY_MESSAGES,
	skipFastPass = false,
): Promise<ClassifierOutcome> {
	const failures: string[] = [];

	const attempt = async ({
		fastPass,
		reasoning,
		maxTokens,
	}: ClassifierAttempt): Promise<ParsedAutoDecision | undefined> => {
		if (ctx.signal?.aborted) return undefined;
		try {
			const response = await complete(
				model,
				{
					systemPrompt: buildAutoModeSystemPrompt(preferences),
					messages: [
						{
							role: "user",
							content: [
								{
									type: "text",
									text: buildClassifierPrompt(command, reasons, ctx, preferences, historyMessages, fastPass),
								},
							],
							timestamp: Date.now(),
						},
					],
				},
				{
					...(auth.apiKey ? { apiKey: auth.apiKey } : {}),
					...(auth.headers ? { headers: auth.headers } : {}),
					...(auth.env ? { env: auth.env } : {}),
					...(reasoning !== "off" ? { reasoning } : {}),
					maxTokens,
					timeoutMs: CLASSIFIER_TIMEOUT_MS,
					signal: ctx.signal,
					cacheRetention: "none",
				},
			);
			if (ctx.signal?.aborted) return undefined;
			if (response.stopReason !== "stop") {
				const detail = response.errorMessage ? `: ${truncate(response.errorMessage, 200)}` : "";
				failures.push(`stop reason "${response.stopReason ?? "unknown"}"${detail}`);
				return undefined;
			}
			const decision = parseAutoModeDecision(extractText(response.content));
			if (!decision) failures.push("response was not the expected JSON decision");
			return decision;
		} catch (error) {
			failures.push(truncate(error instanceof Error ? error.message : String(error), 200));
			return undefined;
		}
	};

	if (!skipFastPass) {
		const fast = await attempt({ fastPass: true, reasoning: "off", maxTokens: 2048 });
		if (fast?.decision === "allow" && fast.risk !== "critical") return { decision: fast };
	}

	const deep = await attempt({ fastPass: false, reasoning: effectiveThinkingLevel, maxTokens: 8192 });
	if (deep) return { decision: deep };
	if (effectiveThinkingLevel !== "off" && !ctx.signal?.aborted) {
		const retry = await attempt({ fastPass: false, reasoning: "off", maxTokens: 4096 });
		if (retry) return { decision: retry };
	}
	return { failure: ctx.signal?.aborted ? "cancelled" : failures.slice(-2).join("; then ") };
}

export async function classifyWithModel(
	command: string,
	reasons: string[],
	ctx: ClassifierContext,
	dependencies: PermissionGateDependencies,
	classifierModel: ClassifierModelReference | null,
	classifierThinkingLevel: ClassifierThinkingLevel,
	preferences: string,
	classifierHistoryMessages = DEFAULT_CLASSIFIER_HISTORY_MESSAGES,
	skipFastPass = false,
): Promise<{
	decision: "allow" | "deny";
	risk?: ApprovalRisk;
	rationale: string;
	model?: string;
	// True when no classifier decision was obtained (config, auth, provider, or output failure).
	failed?: boolean;
}> {
	const registry = ctx.modelRegistry;
	const availableModels = getAvailableClassifierModels(ctx);
	const model = classifierModel
		? availableModels.find(
				(candidate) => candidate.provider === classifierModel.provider && candidate.id === classifierModel.id,
			)
		: undefined;
	const modelLabel = formatClassifierModelLabel(classifierModel, model, classifierThinkingLevel);
	if (!classifierModel || !model) {
		return {
			decision: "deny",
			failed: true,
			rationale: `Auto mode classifier model ${modelLabel} is not available.`,
			model: modelLabel,
		};
	}
	const effectiveThinkingLevel = clampClassifierThinkingLevel(model, classifierThinkingLevel);

	const provider = registry.getProvider(classifierModel.provider);
	if (!dependencies.complete && !provider) {
		return {
			decision: "deny",
			failed: true,
			rationale: `Auto mode classifier provider ${classifierModel.provider} is not available.`,
			model: modelLabel,
		};
	}

	let auth: ClassifierAuth;
	try {
		// The public registry API exposes provider auth and request auth separately, so merge both resolutions here.
		ctx.signal?.throwIfAborted();
		const providerAuth = await registry.getProviderAuth(classifierModel.provider);
		ctx.signal?.throwIfAborted();
		if (!providerAuth) {
			return {
				decision: "deny",
				failed: true,
				rationale: `Classifier authentication for ${modelLabel} is unavailable.`,
				model: modelLabel,
			};
		}

		const modelRequestAuth = await registry.getApiKeyAndHeaders(
			model as Parameters<typeof registry.getApiKeyAndHeaders>[0],
		);
		ctx.signal?.throwIfAborted();
		if (!modelRequestAuth.ok) {
			return {
				decision: "deny",
				failed: true,
				rationale: `Classifier authentication for ${modelLabel} is unavailable.`,
				model: modelLabel,
			};
		}

		const headers = { ...(providerAuth.auth.headers ?? {}), ...(modelRequestAuth.headers ?? {}) };
		const env = { ...(providerAuth.env ?? {}), ...(modelRequestAuth.env ?? {}) };
		const effectiveBaseUrl = modelRequestAuth.baseUrl ?? providerAuth.auth.baseUrl;
		auth = {
			...(providerAuth.auth.apiKey || modelRequestAuth.apiKey
				? { apiKey: modelRequestAuth.apiKey ?? providerAuth.auth.apiKey }
				: {}),
			...(Object.keys(headers).length > 0 ? { headers } : {}),
			...(Object.keys(env).length > 0 ? { env } : {}),
			...(effectiveBaseUrl ? { baseUrl: effectiveBaseUrl } : {}),
		};
	} catch {
		return {
			decision: "deny",
			failed: true,
			rationale: `Classifier authentication for ${modelLabel} is unavailable.`,
			model: modelLabel,
		};
	}

	try {
		const complete = dependencies.complete ?? createProviderComplete(provider);
		const effectiveModel = auth.baseUrl ? { ...model, baseUrl: auth.baseUrl } : model;
		const result = await requestClassifierDecision(
			complete,
			effectiveModel,
			auth,
			effectiveThinkingLevel,
			command,
			reasons,
			ctx,
			preferences,
			classifierHistoryMessages,
			skipFastPass,
		);
		if ("failure" in result) {
			return {
				decision: "deny",
				failed: true,
				rationale: `The classifier returned no valid decision (${result.failure}).`,
				model: modelLabel,
			};
		}
		return { ...result.decision, model: modelLabel };
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return {
			decision: "deny",
			failed: true,
			rationale: `Auto mode classification failed, so the command was blocked: ${truncate(message, 300)}`,
			model: modelLabel,
		};
	}
}
