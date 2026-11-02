import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { CONFIG_DIR_NAME } from "@earendil-works/pi-coding-agent";
import {
	cloneClassifierModelReference,
	isClassifierThinkingLevel,
	parseClassifierModelReference,
} from "./classifier-models.ts";
import { normalizeAutoModePreferences } from "./classifier-prompt.ts";
import { getAutoModePreferencesPath, getGlobalModeStatePath, getGlobalRulesPath } from "./config-paths.ts";
import {
	APPROVAL_WAIT_CHOICES,
	DEFAULT_APPROVAL_WAIT_SECONDS,
	DEFAULT_CLASSIFIER_HISTORY_MESSAGES,
	DEFAULT_CLASSIFIER_MODEL,
	DEFAULT_CLASSIFIER_THINKING_LEVEL,
	DEFAULT_COMMAND_RULE_CONFIG,
	DEFAULT_MODE_STATE,
	MAX_CLASSIFIER_HISTORY_MESSAGES,
	MIN_CLASSIFIER_HISTORY_MESSAGES,
	RULES_FILE_NAME,
} from "./constants.ts";
import { DEFAULT_PRODUCTION_PATTERNS } from "./criticality.ts";
import { notify } from "./gate-display.ts";
import { dangerousPatterns, hardDenyPatterns } from "./risk-patterns.ts";
import { truncate, unique } from "./text.ts";
import { type CommandRuleConfig, type ModeState, type PermissionGateDependencies } from "./types.ts";

function parseClassifierHistoryMessages(value: unknown): number | undefined {
	if (typeof value !== "number" || !Number.isInteger(value)) return undefined;
	if (value < MIN_CLASSIFIER_HISTORY_MESSAGES || value > MAX_CLASSIFIER_HISTORY_MESSAGES) return undefined;
	return value;
}

function parseModeState(value: unknown): ModeState | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const candidate = value as Partial<ModeState>;
	if (typeof candidate.autoModeEnabled !== "boolean") {
		return undefined;
	}
	const classifierModel =
		candidate.classifierModel === undefined
			? cloneClassifierModelReference(DEFAULT_CLASSIFIER_MODEL)
			: (parseClassifierModelReference(candidate.classifierModel) ?? null);
	const classifierThinkingLevel =
		candidate.classifierThinkingLevel === undefined
			? DEFAULT_CLASSIFIER_THINKING_LEVEL
			: typeof candidate.classifierThinkingLevel === "string" &&
					isClassifierThinkingLevel(candidate.classifierThinkingLevel)
				? candidate.classifierThinkingLevel
				: DEFAULT_CLASSIFIER_THINKING_LEVEL;
	const classifierHistoryMessages =
		candidate.classifierHistoryMessages === undefined
			? DEFAULT_CLASSIFIER_HISTORY_MESSAGES
			: (parseClassifierHistoryMessages(candidate.classifierHistoryMessages) ?? DEFAULT_CLASSIFIER_HISTORY_MESSAGES);
	return {
		autoModeEnabled: candidate.autoModeEnabled,
		classifierModel,
		classifierThinkingLevel,
		classifierHistoryMessages,
		productionPatterns:
			Array.isArray(candidate.productionPatterns) &&
			candidate.productionPatterns.every((p) => typeof p === "string" && p.trim())
				? candidate.productionPatterns.map((pattern) => pattern.trim())
				: [...DEFAULT_PRODUCTION_PATTERNS],
		approvalWaitSeconds: APPROVAL_WAIT_CHOICES.includes(candidate.approvalWaitSeconds ?? 0)
			? candidate.approvalWaitSeconds
			: DEFAULT_APPROVAL_WAIT_SECONDS,
	};
}

async function loadModeStateFromDisk(): Promise<ModeState | undefined> {
	try {
		const raw = await readFile(getGlobalModeStatePath(), "utf8");
		return parseModeState(JSON.parse(raw));
	} catch (error) {
		if (error && typeof error === "object" && (error as { code?: unknown }).code === "ENOENT") {
			return undefined;
		}
		throw error;
	}
}

async function saveModeStateToDisk(state: ModeState): Promise<void> {
	const path = getGlobalModeStatePath();
	const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
	await mkdir(dirname(path), { recursive: true, mode: 0o700 });

	try {
		await writeFile(temporaryPath, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
		await rename(temporaryPath, path);
	} finally {
		await unlink(temporaryPath).catch(() => undefined);
	}
}

async function loadConfiguredModeState(dependencies: PermissionGateDependencies): Promise<ModeState | undefined> {
	const loader = dependencies.loadGlobalModeState ?? loadModeStateFromDisk;
	return parseModeState(await loader());
}

async function saveConfiguredModeState(dependencies: PermissionGateDependencies, state: ModeState): Promise<void> {
	const saver = dependencies.saveGlobalModeState ?? saveModeStateToDisk;
	await saver(state);
}

export async function persistGlobalModeState(dependencies: PermissionGateDependencies, state: ModeState): Promise<boolean> {
	try {
		await saveConfiguredModeState(dependencies, state);
		return true;
	} catch (error) {
		console.warn("[permission-gate] Could not persist global mode state:", error);
		return false;
	}
}

async function loadAutoModePreferencesFromDisk(): Promise<string | undefined> {
	try {
		return normalizeAutoModePreferences(await readFile(getAutoModePreferencesPath(), "utf8"));
	} catch (error) {
		if (error && typeof error === "object" && (error as { code?: unknown }).code === "ENOENT") return undefined;
		throw error;
	}
}

async function saveAutoModePreferencesToDisk(preferences: string): Promise<void> {
	const path = getAutoModePreferencesPath();
	const temporaryPath = `${path}.${process.pid}.${randomUUID()}.tmp`;
	await mkdir(dirname(path), { recursive: true, mode: 0o700 });

	try {
		await writeFile(temporaryPath, `${normalizeAutoModePreferences(preferences)}\n`, { encoding: "utf8", mode: 0o600 });
		await rename(temporaryPath, path);
	} finally {
		await unlink(temporaryPath).catch(() => undefined);
	}
}

export async function loadConfiguredAutoModePreferences(dependencies: PermissionGateDependencies): Promise<string> {
	const loader = dependencies.loadAutoModePreferences ?? loadAutoModePreferencesFromDisk;
	return normalizeAutoModePreferences(await loader());
}

export async function saveConfiguredAutoModePreferences(
	dependencies: PermissionGateDependencies,
	preferences: string,
): Promise<void> {
	const saver = dependencies.saveAutoModePreferences ?? saveAutoModePreferencesToDisk;
	await saver(normalizeAutoModePreferences(preferences));
}

export async function initializeAutoModePreferences(
	dependencies: PermissionGateDependencies,
	ctx: { hasUI: boolean; ui: { notify: (message: string, level: "info" | "warning" | "error") => void } },
): Promise<string> {
	try {
		return await loadConfiguredAutoModePreferences(dependencies);
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		console.warn("[permission-gate] Could not load auto-mode preferences:", error);
		notify(
			ctx,
			`Permission gate could not load auto-mode preferences; using none: ${truncate(message, 300)}`,
			"warning",
		);
		return "";
	}
}

export function appendAutoModePreference(preferences: string, note: string): string {
	const normalizedNote = note.trim();
	if (!normalizedNote) return normalizeAutoModePreferences(preferences);

	const formattedNote = normalizedNote
		.split(/\r?\n/)
		.map((line, index) => `${index === 0 ? "- " : "  "}${line}`)
		.join("\n");
	const existing = normalizeAutoModePreferences(preferences);
	return normalizeAutoModePreferences(existing ? `${existing}\n\n${formattedNote}` : formattedNote);
}

export async function initializeModeState(
	dependencies: PermissionGateDependencies,
	ctx: { hasUI: boolean; ui: { notify: (message: string, level: "info" | "warning" | "error") => void } },
): Promise<ModeState> {
	try {
		const persisted = await loadConfiguredModeState(dependencies);
		if (persisted) return persisted;

		const defaults = { ...DEFAULT_MODE_STATE };
		await saveConfiguredModeState(dependencies, defaults);
		return defaults;
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		console.warn("[permission-gate] Could not load global mode state:", error);
		notify(
			ctx,
			`Permission gate could not load or save global mode settings; using defaults: ${truncate(message, 200)}`,
			"warning",
		);
		return { ...DEFAULT_MODE_STATE };
	}
}

export function cloneDefaultCommandRuleConfig(): CommandRuleConfig {
	return {
		allowedCommands: [...DEFAULT_COMMAND_RULE_CONFIG.allowedCommands],
		disallowedCommands: [...DEFAULT_COMMAND_RULE_CONFIG.disallowedCommands],
	};
}

export function parseCommandRuleConfig(value: unknown): CommandRuleConfig | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const candidate = value as Partial<CommandRuleConfig>;
	if (!Array.isArray(candidate.allowedCommands) || !Array.isArray(candidate.disallowedCommands)) return undefined;
	if (
		candidate.allowedCommands.some((pattern) => typeof pattern !== "string") ||
		candidate.disallowedCommands.some((pattern) => typeof pattern !== "string")
	) {
		return undefined;
	}
	return {
		allowedCommands: unique(candidate.allowedCommands.map((pattern) => pattern.trim()).filter(Boolean)),
		disallowedCommands: unique(candidate.disallowedCommands.map((pattern) => pattern.trim()).filter(Boolean)),
	};
}

async function readCommandRuleConfig(path: string): Promise<CommandRuleConfig | undefined> {
	let raw: string;
	try {
		raw = await readFile(path, "utf8");
	} catch (error) {
		if (error && typeof error === "object" && (error as { code?: unknown }).code === "ENOENT") return undefined;
		throw new Error(`Cannot read ${path}: ${error instanceof Error ? error.message : String(error)}`);
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch (error) {
		throw new Error(`${path} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
	}

	const config = parseCommandRuleConfig(parsed);
	if (!config) throw new Error(`${path} must contain string arrays named allowedCommands and disallowedCommands.`);
	return config;
}

async function loadGlobalRulesFromDisk(): Promise<CommandRuleConfig | undefined> {
	return readCommandRuleConfig(getGlobalRulesPath());
}

async function saveCommandRuleConfig(path: string, config: CommandRuleConfig): Promise<void> {
	await mkdir(dirname(path), { recursive: true, mode: 0o700 });
	await writeFile(path, `${JSON.stringify(config, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

async function loadEffectiveCommandRules(
	dependencies: PermissionGateDependencies,
	ctx: { cwd: string; isProjectTrusted: () => boolean },
): Promise<{ config: CommandRuleConfig; scope: "global" | "project" }> {
	if (dependencies.loadGlobalRules) {
		return {
			config: (await dependencies.loadGlobalRules()) ?? cloneDefaultCommandRuleConfig(),
			scope: "global",
		};
	}

	if (ctx.isProjectTrusted()) {
		const projectConfig = await readCommandRuleConfig(getProjectRulesPath(ctx.cwd));
		if (projectConfig) return { config: projectConfig, scope: "project" };
	}

	return {
		config: (await loadGlobalRulesFromDisk()) ?? cloneDefaultCommandRuleConfig(),
		scope: "global",
	};
}

export async function saveCommandRules(
	dependencies: PermissionGateDependencies,
	scope: "global" | "project",
	cwd: string,
	config: CommandRuleConfig,
): Promise<void> {
	if (scope === "global" && dependencies.saveGlobalRules) {
		await dependencies.saveGlobalRules(config);
		return;
	}
	await saveCommandRuleConfig(scope === "global" ? getGlobalRulesPath() : getProjectRulesPath(cwd), config);
}

export async function initializeCommandRules(
	dependencies: PermissionGateDependencies,
	ctx: {
		cwd: string;
		hasUI: boolean;
		isProjectTrusted: () => boolean;
		ui: { notify: (message: string, level: "info" | "warning" | "error") => void };
	},
): Promise<{ config: CommandRuleConfig; scope: "global" | "project" }> {
	try {
		return await loadEffectiveCommandRules(dependencies, ctx);
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		console.warn("[permission-gate] Could not load command rules:", error);
		notify(
			ctx,
			`Permission gate could not load command rules; using built-in defaults: ${truncate(message, 300)}`,
			"warning",
		);
		return { config: cloneDefaultCommandRuleConfig(), scope: "global" };
	}
}

export function formatCommandRules(config: CommandRuleConfig, scope: string): string {
	const formatList = (patterns: string[]) =>
		patterns.length > 0 ? patterns.map((pattern) => `  - ${pattern}`).join("\n") : "  (none)";
	return [
		`Permission gate command rules (${scope})`,
		"",
		"Allowed command patterns:",
		formatList(config.allowedCommands),
		"",
		"Disallowed command patterns:",
		formatList(config.disallowedCommands),
		"",
		"Patterns use shell-style * and ? wildcards.",
		"Hard-deny safety rules cannot be overridden.",
		"",
		"Built-in soft-deny categories:",
		...unique(dangerousPatterns.map(({ name }) => `  - ${name}`)),
		"",
		"Hard-deny categories:",
		...unique(hardDenyPatterns.map(({ name }) => `  - ${name}`)),
	].join("\n");
}

function getProjectRulesPath(cwd: string): string {
	return join(cwd, CONFIG_DIR_NAME, RULES_FILE_NAME);
}
