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
import { cloneDefaultCommandRuleConfig } from "./command-rules.ts";
import { getAutoModePreferencesPath, getGlobalModeStatePath, getGlobalRulesPath } from "./config-paths.ts";
import {
	APPROVAL_WAIT_CHOICES,
	DEFAULT_APPROVAL_WAIT_SECONDS,
	DEFAULT_CLASSIFIER_HISTORY_MESSAGES,
	DEFAULT_CLASSIFIER_MODEL,
	DEFAULT_CLASSIFIER_THINKING_LEVEL,
	MAX_CLASSIFIER_HISTORY_MESSAGES,
	MIN_CLASSIFIER_HISTORY_MESSAGES,
	RULES_FILE_NAME,
} from "./constants.ts";
import { DEFAULT_PRODUCTION_PATTERNS } from "./criticality.ts";
import { unique } from "./text.ts";
import type { CommandRuleConfig, ModeState, PermissionGateDependencies } from "./types.ts";

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

export async function loadConfiguredModeState(
	dependencies: PermissionGateDependencies,
): Promise<ModeState | undefined> {
	const loader = dependencies.loadGlobalModeState ?? loadModeStateFromDisk;
	return parseModeState(await loader());
}

export async function saveConfiguredModeState(
	dependencies: PermissionGateDependencies,
	state: ModeState,
): Promise<void> {
	const saver = dependencies.saveGlobalModeState ?? saveModeStateToDisk;
	await saver(state);
}

export async function persistGlobalModeState(
	dependencies: PermissionGateDependencies,
	state: ModeState,
): Promise<boolean> {
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

export async function loadEffectiveCommandRules(
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

function getProjectRulesPath(cwd: string): string {
	return join(cwd, CONFIG_DIR_NAME, RULES_FILE_NAME);
}
