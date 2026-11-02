import type { SelectItem } from "@earendil-works/pi-tui";

export type PermissionSettingsAction =
	| { type: "gate"; value: "on" | "off" }
	| { type: "classifier-model"; value: string }
	| { type: "classifier-thinking"; value: string }
	| { type: "history-messages"; value: number }
	| { type: "command-rules"; value: "edit" | "list" | "reset" }
	| { type: "preferences"; value: "edit" | "add" | "list" | "clear" }
	| { type: "production-patterns" }
	| { type: "approval-wait"; value: number }
	| { type: "intent-grants" }
	| { type: "statistics" }
	| { type: "prompt" };

export type PermissionSettingsOption = SelectItem;

export interface PermissionSettingsView {
	autoModeEnabled: boolean;
	classifierModel: string;
	classifierModelOptions: readonly PermissionSettingsOption[];
	classifierThinking: string;
	classifierThinkingOptions: readonly PermissionSettingsOption[];
	classifierHistoryMessages: number;
	classifierHistoryMessageOptions: readonly PermissionSettingsOption[];
	ruleScope: string;
	allowedCommands: readonly string[];
	disallowedCommands: readonly string[];
	preferences: string;
	productionPatterns?: readonly string[];
	approvalWaitSeconds?: number;
	activeGrantCount?: number;
}

export type SettingsTui = { requestRender: () => void };

export const MAX_VISIBLE_SETTINGS = 12;
export const GATE_OFF_DESCRIPTION = "Off: no checks, classifier, or approvals.";

export function formatPreferenceCount(preferences: string): string {
	const lines = preferences
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean);
	if (lines.length === 0) return "none";
	return `${lines.length} note${lines.length === 1 ? "" : "s"}`;
}
