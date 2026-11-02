import { randomUUID } from "node:crypto";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { cloneClassifierModelReference } from "./classifier-models.ts";
import { cloneDefaultCommandRuleConfig } from "./command-rules.ts";
import {
	DEFAULT_APPROVAL_WAIT_SECONDS,
	DEFAULT_CLASSIFIER_HISTORY_MESSAGES,
	DEFAULT_CLASSIFIER_MODEL,
	DEFAULT_CLASSIFIER_THINKING_LEVEL,
} from "./constants.ts";
import { DEFAULT_PRODUCTION_PATTERNS } from "./criticality.ts";
import { createIntentStore } from "./intent-grants.ts";
import type {
	ApprovalRequester,
	AvailableClassifierModel,
	ClassifierModelReference,
	ClassifierThinkingLevel,
	CommandRuleConfig,
	DecisionMeasurements,
	HistoryReporter,
	PermissionGateDependencies,
} from "./types.ts";

export type GateState = {
	pi: ExtensionAPI;
	dependencies: PermissionGateDependencies;
	autoModeEnabled: boolean;
	classifierModel: ClassifierModelReference | null;
	classifierThinkingLevel: ClassifierThinkingLevel;
	classifierHistoryMessages: number;
	autoModePreferences: string;
	productionPatterns: string[];
	approvalWaitSeconds: number;
	initialized: boolean;
	disabledReason: symbol;
	activeReviews: Set<AbortController>;
	now: () => number;
	intentStore: ReturnType<typeof createIntentStore>;
	sessionGeneration: number;
	pendingApprovals: Set<AbortController>;
	lateApprovals: (DecisionMeasurements & { command: string; snapshot: string; historyId?: string })[];
	availableClassifierModels: AvailableClassifierModel[];
	scopedClassifierModels: AvailableClassifierModel[];
	ruleConfig: CommandRuleConfig;
	ruleScope: "global" | "project" | "session";
	consecutiveDenials: number;
	totalDenials: number;
	lockdown: boolean;
	gateSessionId: string;
	modeSave: Promise<boolean>;
	historyReporter: HistoryReporter | undefined;
	requestApproval: ApprovalRequester | undefined;
};

export function createGateState(pi: ExtensionAPI, dependencies: PermissionGateDependencies): GateState {
	const now = dependencies.now ?? Date.now;
	return {
		pi,
		dependencies,
		autoModeEnabled: true,
		classifierModel: cloneClassifierModelReference(DEFAULT_CLASSIFIER_MODEL),
		classifierThinkingLevel: DEFAULT_CLASSIFIER_THINKING_LEVEL,
		classifierHistoryMessages: DEFAULT_CLASSIFIER_HISTORY_MESSAGES,
		autoModePreferences: "",
		productionPatterns: [...DEFAULT_PRODUCTION_PATTERNS],
		approvalWaitSeconds: DEFAULT_APPROVAL_WAIT_SECONDS,
		initialized: false,
		disabledReason: Symbol("permission gate disabled"),
		activeReviews: new Set<AbortController>(),
		now,
		intentStore: createIntentStore({ now }),
		sessionGeneration: 0,
		pendingApprovals: new Set<AbortController>(),
		lateApprovals: [],
		availableClassifierModels: [],
		scopedClassifierModels: [],
		ruleConfig: cloneDefaultCommandRuleConfig(),
		ruleScope: "global",
		consecutiveDenials: 0,
		totalDenials: 0,
		lockdown: false,
		gateSessionId: randomUUID(),
		modeSave: Promise.resolve(true),
		historyReporter: undefined,
		requestApproval: undefined,
	};
}
