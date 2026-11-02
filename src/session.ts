import { cloneClassifierModelReference } from "./classifier-models.ts";
import { DEFAULT_APPROVAL_WAIT_SECONDS, DEFAULT_CLASSIFIER_HISTORY_MESSAGES } from "./constants.ts";
import { DEFAULT_PRODUCTION_PATTERNS } from "./criticality.ts";
import {
	clearSessionApprovals,
	refreshStatus,
	syncAvailableClassifierModels,
	syncScopedClassifierModels,
} from "./gate-controls.ts";
import { type GateState } from "./gate-state.ts";
import { initializeAutoModePreferences, initializeCommandRules, initializeModeState } from "./persistence.ts";

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
			gate.autoModeEnabled = gate.dependencies.startOff?.() ? false : restored.autoModeEnabled;
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
