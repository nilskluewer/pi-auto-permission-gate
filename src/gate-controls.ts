import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
	cacheAvailableClassifierModels,
	cacheScopedClassifierModels,
	cloneClassifierModelReference,
} from "./classifier-models.ts";
import { normalizeAutoModePreferences } from "./classifier-prompt.ts";
import { notify, persistModeState, setGateStatus } from "./gate-display.ts";
import type { GateState } from "./gate-state.ts";
import {
	loadConfiguredAutoModePreferences,
	persistGlobalModeState,
	saveConfiguredAutoModePreferences,
} from "./persistence.ts";
import { truncate } from "./text.ts";
import type { AvailableClassifierModel, ModeState } from "./types.ts";

export function refreshStatus(gate: GateState, ctx: ExtensionContext): void {
	setGateStatus(
		ctx,
		gate.autoModeEnabled,
		gate.classifierModel,
		gate.classifierThinkingLevel,
		gate.availableClassifierModels,
	);
}

export function clearSessionApprovals(gate: GateState) {
	gate.sessionGeneration += 1;
	gate.intentStore.clear();
	gate.lateApprovals.length = 0;
	for (const controller of gate.activeReviews) controller.abort();
	gate.activeReviews.clear();
	for (const controller of gate.pendingApprovals) controller.abort();
	gate.pendingApprovals.clear();
}

export async function persistMode(
	gate: GateState,
	ctx: {
		hasUI: boolean;
		ui: { notify: (message: string, level: "info" | "warning" | "error") => void };
	},
) {
	const state: ModeState = {
		autoModeEnabled: gate.autoModeEnabled,
		classifierModel: cloneClassifierModelReference(gate.classifierModel),
		classifierThinkingLevel: gate.classifierThinkingLevel,
		classifierHistoryMessages: gate.classifierHistoryMessages,
		productionPatterns: gate.productionPatterns,
		approvalWaitSeconds: gate.approvalWaitSeconds,
	};
	persistModeState(gate.pi, state);
	gate.modeSave = gate.modeSave.then(() => persistGlobalModeState(gate.dependencies, state));
	if (!(await gate.modeSave)) {
		notify(ctx, "Permission gate mode could not be persisted globally.", "warning");
	}
}

export async function setGate(gate: GateState, ctx: ExtensionContext, value: "on" | "off"): Promise<void> {
	gate.autoModeEnabled = value === "on";
	if (!gate.autoModeEnabled) {
		for (const controller of gate.activeReviews) controller.abort(gate.disabledReason);
		clearSessionApprovals(gate);
		gate.consecutiveDenials = 0;
		gate.totalDenials = 0;
		gate.lockdown = false;
	}
	syncAvailableClassifierModels(gate, ctx);
	refreshStatus(gate, ctx);
	await persistMode(gate, ctx);
	notify(
		ctx,
		`Permission gate: ${gate.autoModeEnabled ? "ON" : "OFF"}. ${gate.autoModeEnabled ? "Rules, classifier, and approvals are enabled." : "No checks, classifier, or approvals."}`,
		"info",
	);
}

export async function persistAutoModePreferences(
	gate: GateState,
	ctx: { hasUI: boolean; ui: { notify: (message: string, level: "info" | "warning" | "error") => void } },
	nextPreferences: string,
): Promise<boolean> {
	try {
		await saveConfiguredAutoModePreferences(gate.dependencies, nextPreferences);
		gate.autoModePreferences = normalizeAutoModePreferences(nextPreferences);
		return true;
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		notify(ctx, `Permission gate could not save auto-mode preferences: ${truncate(message, 300)}`, "error");
		return false;
	}
}

export async function refreshAutoModePreferences(
	gate: GateState,
	ctx: {
		hasUI: boolean;
		ui: { notify: (message: string, level: "info" | "warning" | "error") => void };
	},
): Promise<void> {
	// A custom saver without a matching loader is commonly used by embedders and tests.
	// Keep the in-memory value in that case instead of replacing it with the default disk loader.
	if (!gate.dependencies.loadAutoModePreferences && gate.dependencies.saveAutoModePreferences) return;
	try {
		gate.autoModePreferences = await loadConfiguredAutoModePreferences(gate.dependencies);
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		console.warn("[permission-gate] Could not refresh auto-mode preferences:", error);
		notify(ctx, `Permission gate could not refresh auto-mode preferences: ${truncate(message, 300)}`, "warning");
	}
}

export function syncAvailableClassifierModels(
	gate: GateState,
	ctx: {
		modelRegistry: { getAvailable: () => readonly unknown[]; getProviderDisplayName: (provider: string) => string };
	},
): void {
	try {
		gate.availableClassifierModels = cacheAvailableClassifierModels(ctx);
	} catch {
		gate.availableClassifierModels = [];
	}
}

export function syncScopedClassifierModels(
	gate: GateState,
	ctx: {
		scopedModels: readonly { model: unknown }[];
		modelRegistry: { getProviderDisplayName: (provider: string) => string };
	},
): void {
	try {
		gate.scopedClassifierModels = cacheScopedClassifierModels(ctx);
	} catch {
		gate.scopedClassifierModels = [];
	}
}

export async function refreshAvailableClassifierModels(
	gate: GateState,
	ctx: {
		modelRegistry: {
			refresh: () => Promise<unknown>;
			getAvailable: () => readonly unknown[];
			getProviderDisplayName: (provider: string) => string;
		};
	},
): Promise<AvailableClassifierModel[]> {
	await ctx.modelRegistry.refresh();
	gate.availableClassifierModels = cacheAvailableClassifierModels(ctx);
	return gate.availableClassifierModels;
}

export function canPromptForSelection(ctx: Pick<ExtensionContext, "hasUI" | "mode">): boolean {
	return ctx.hasUI && (ctx.mode === "tui" || ctx.mode === "rpc");
}
