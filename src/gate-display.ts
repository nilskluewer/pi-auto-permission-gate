import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
	classifierModelDisplayId,
	findAvailableClassifierModel,
	formatClassifierThinkingLevel,
} from "./classifier-models.ts";
import { DECISION_ENTRY_TYPE, MODE_ENTRY_TYPE, STATUS_ID } from "./constants.ts";
import type {
	AvailableClassifierModel,
	ClassifierModelReference,
	ClassifierThinkingLevel,
	DecisionEntry,
	ModeState,
} from "./types.ts";

export function recordDecision(pi: ExtensionAPI, entry: DecisionEntry): void {
	try {
		pi.appendEntry(DECISION_ENTRY_TYPE, entry);
	} catch (error) {
		console.warn("[permission-gate] Could not record decision in the session:", error);
	}
}

export function persistModeState(pi: ExtensionAPI, state: ModeState): void {
	pi.appendEntry(MODE_ENTRY_TYPE, state);
}

export function setGateStatus(
	ctx: { hasUI: boolean; ui: { setStatus: (id: string, text: string | undefined) => void } },
	enabled: boolean,
	classifierModel: ClassifierModelReference | null,
	classifierThinkingLevel: ClassifierThinkingLevel,
	availableModels: readonly AvailableClassifierModel[],
): void {
	if (!ctx.hasUI) return;
	const selectedModel = findAvailableClassifierModel(availableModels, classifierModel);
	const thinking = formatClassifierThinkingLevel(classifierThinkingLevel, selectedModel?.model);
	ctx.ui.setStatus(
		STATUS_ID,
		enabled
			? `permission gate: ON (${classifierModelDisplayId(classifierModel)}, ${thinking})`
			: "permission gate: OFF",
	);
}

export function notify(
	ctx: { hasUI: boolean; ui: { notify: (message: string, level: "info" | "warning" | "error") => void } },
	message: string,
	level: "info" | "warning" | "error",
): void {
	if (ctx.hasUI) ctx.ui.notify(message, level);
}
