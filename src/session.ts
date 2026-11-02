import { cloneClassifierModelReference } from "./classifier-models.ts";
import { cloneDefaultCommandRuleConfig } from "./command-rules.ts";
import { DEFAULT_APPROVAL_WAIT_SECONDS, DEFAULT_CLASSIFIER_HISTORY_MESSAGES, DEFAULT_MODE_STATE } from "./constants.ts";
import { DEFAULT_PRODUCTION_PATTERNS } from "./criticality.ts";
import {
	clearSessionApprovals,
	refreshStatus,
	syncAvailableClassifierModels,
	syncScopedClassifierModels,
} from "./gate-controls.ts";
import { notify } from "./gate-display.ts";
import type { GateState } from "./gate-state.ts";
import {
	loadConfiguredAutoModePreferences,
	loadConfiguredModeState,
	loadEffectiveCommandRules,
	saveConfiguredModeState,
} from "./persistence.ts";
import { truncate } from "./text.ts";
import type { CommandRuleConfig, ModeState, PermissionGateDependencies } from "./types.ts";

export function registerSessionHooks(gate: GateState): void {
	gate.pi.on("session_shutdown", clearSessionApprovals.bind(null, gate));

	gate.pi.on("session_start", async (_event, ctx) => {
		clearSessionApprovals(gate);
		const [restored, loadedRules, loadedPreferences] = await Promise.all([
			initializeModeState(gate.dependencies, ctx),
			initializeCommandRules(gate.dependencies, ctx),
			initializeAutoModePreferences(gate.dependencies, ctx),
		]);
		if (!gate.initialized) {
			gate.gateEnabled = gate.dependencies.startOff?.() ? false : restored.autoModeEnabled;
			gate.initialized = true;
		}
		gate.classifierModel = cloneClassifierModelReference(restored.classifierModel);
		gate.classifierThinkingLevel = restored.classifierThinkingLevel;
		gate.classifierHistoryMessages = restored.classifierHistoryMessages ?? DEFAULT_CLASSIFIER_HISTORY_MESSAGES;
		gate.productionPatterns = restored.productionPatterns ?? [...DEFAULT_PRODUCTION_PATTERNS];
		gate.approvalWaitSeconds = restored.approvalWaitSeconds ?? DEFAULT_APPROVAL_WAIT_SECONDS;
		gate.autoModePreferences = loadedPreferences;
		gate.consecutiveDenials = 0;
		gate.totalDenials = 0;
		gate.lockdown = false;
		gate.ruleConfig = loadedRules.config;
		gate.ruleScope = loadedRules.scope;
		syncAvailableClassifierModels(gate, ctx);
		syncScopedClassifierModels(gate, ctx);
		refreshStatus(gate, ctx);
	});

	gate.pi.on("session_tree", (_event, ctx) => {
		// Mode is a global preference, so navigating a conversation branch must not
		// silently turn auto mode off or restore an obsolete branch-local value.
		syncAvailableClassifierModels(gate, ctx);
		syncScopedClassifierModels(gate, ctx);
		refreshStatus(gate, ctx);
	});
}

// Startup loads fall back to defaults and warn the user, so a broken settings file never blocks the session.

async function initializeModeState(
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

async function initializeCommandRules(
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

async function initializeAutoModePreferences(
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
