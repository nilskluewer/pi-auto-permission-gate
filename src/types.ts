import { type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { type AutocompleteItem } from "@earendil-works/pi-tui";
import { type inspectCommand } from "./command-inspection.ts";
import { type CLASSIFIER_THINKING_LEVELS } from "./constants.ts";

export type IntentProposal = { label: string; access: "read" | "write"; reasons: string[]; targets: string[] };
export type DecisionMeasurements = {
	recommendation?: "approve" | "deny" | "review";
	shownAt?: number;
	answeredAt?: number;
	scope?: "once" | "intent";
	grantId?: string;
	note?: string;
};

export type CommandInspection = Awaited<ReturnType<typeof inspectCommand>>;
export type InspectionDisplay = { paths?: CommandInspection["paths"]; pathNotes?: string[] };

export type ApprovalRisk = "low" | "medium" | "critical";

export type ApprovalRequest = InspectionDisplay & {
	intentProposal?: IntentProposal;
	environment?: string;
	sessionId: string;
	sessionLabel: string;
	cwd: string;
	kind: "command" | "lockdown";
	command: string;
	risk: ApprovalRisk;
	tldr: string;
	recommendation: "approve" | "deny" | "review";
	reasons: string[];
	model?: string;
	ttlMs?: number;
};

export type ApprovalOutcome = {
	status: "approved" | "denied" | "redirected" | "expired" | "cancelled";
	note?: string;
	scope?: "once" | "session" | "intent";
	intent?: IntentProposal;
	// Local correlation for the browser's existing history entry.
	historyId?: string;
};

export type ApprovalLifecycle = { parkSignal: AbortSignal; onLateOutcome: (outcome: ApprovalOutcome) => void };
export type ApprovalRequester = (
	request: ApprovalRequest,
	signal: AbortSignal,
	lifecycle?: ApprovalLifecycle,
) => Promise<ApprovalOutcome | undefined>;

export type QueueState = { port: number; pid: number; sessionToken: string };

export type HistoryEntry = InspectionDisplay &
	DecisionMeasurements & {
		id?: string;
		sessionId: string;
		sessionLabel: string;
		cwd: string;
		command: string;
		risk: ApprovalRisk;
		tldr: string;
		status: "approved" | "denied" | "redirected" | "expired";
		source: "auto" | "human" | "rule" | "hard-deny" | "grant";
		via?: "browser" | "terminal";
		reasons: string[];
		model?: string;
		ts: number;
	};

export type HistoryReporter = (entry: HistoryEntry) => Promise<void>;

export type DangerousPattern = {
	name: string;
	pattern: RegExp;
};

export type ClassifierMessage = {
	role: "user";
	content: [{ type: "text"; text: string }];
	timestamp: number;
};

export type ClassifierResponse = {
	content: unknown;
	stopReason?: string;
	errorMessage?: string;
};

export type ClassifierThinkingLevel = (typeof CLASSIFIER_THINKING_LEVELS)[number];
export type ClassifierReasoningLevel = Exclude<ClassifierThinkingLevel, "off">;

export type ClassifierComplete = (
	model: unknown,
	context: { systemPrompt: string; messages: ClassifierMessage[] },
	options: {
		apiKey?: string;
		headers?: Record<string, string | null>;
		env?: Record<string, string>;
		reasoning?: ClassifierReasoningLevel;
		maxTokens: number;
		timeoutMs: number;
		signal?: AbortSignal;
		cacheRetention: "none";
	},
) => Promise<ClassifierResponse>;

export type ClassifierModelReference = {
	provider: string;
	id: string;
};

export type RegistryModel = {
	provider: string;
	id: string;
	baseUrl?: string;
	name?: string;
	input?: readonly string[];
	reasoning?: boolean;
	thinkingLevelMap?: Partial<Record<ClassifierThinkingLevel, string | null>>;
};

export type AvailableClassifierModel = {
	model: RegistryModel;
	canonicalId: string;
	providerDisplayName: string;
	modelName: string;
};

export type ModeState = {
	autoModeEnabled: boolean;
	// null represents an explicitly malformed persisted model reference.
	classifierModel: ClassifierModelReference | null;
	classifierThinkingLevel: ClassifierThinkingLevel;
	classifierHistoryMessages?: number;
	productionPatterns?: string[];
	approvalWaitSeconds?: number;
};

export type CommandRuleConfig = {
	allowedCommands: string[];
	disallowedCommands: string[];
};

export type ModeStateLoader = () => Promise<ModeState | undefined>;
export type ModeStateSaver = (state: ModeState) => Promise<void>;
export type CommandRuleLoader = () => Promise<CommandRuleConfig | undefined>;
export type CommandRuleSaver = (config: CommandRuleConfig) => Promise<void>;
export type AutoModePreferencesLoader = () => Promise<string | undefined>;
export type AutoModePreferencesSaver = (preferences: string) => Promise<void>;

export type PermissionGateDependencies = {
	/** Read once at the first session_start: true starts with the gate fully off. */
	startOff?: () => boolean;
	approvalWaitMs?: number;
	now?: () => number;
	complete?: ClassifierComplete;
	loadGlobalModeState?: ModeStateLoader;
	saveGlobalModeState?: ModeStateSaver;
	loadGlobalRules?: CommandRuleLoader;
	saveGlobalRules?: CommandRuleSaver;
	loadAutoModePreferences?: AutoModePreferencesLoader;
	saveAutoModePreferences?: AutoModePreferencesSaver;
	// Sends a request to the shared browser approval queue. Returns undefined when the queue is unavailable.
	requestApproval?: ApprovalRequester;
	// Reports decisions to the browser history. Defaults to a no-op when requestApproval is replaced.
	postHistory?: HistoryReporter;
	// Opens the browser page with the queue and the history. Returns false when it is unavailable.
	openApprovalPage?: () => Promise<boolean>;
};

export type ParsedAutoDecision = {
	decision: "allow" | "deny";
	risk: ApprovalRisk;
	rationale: string;
};

export type DecisionSource = "hard-deny" | "auto-model" | "user-rule" | "human" | "intent-grant";
export type DecisionStatus = "approved" | "blocked" | "redirected" | "expired";
export type ClassifierContext = Pick<ExtensionContext, "cwd" | "signal" | "modelRegistry" | "sessionManager"> & {
	inspection?: CommandInspection;
};

export type DecisionEntry = InspectionDisplay &
	DecisionMeasurements & {
		command: string;
		reasons: string[];
		status: DecisionStatus;
		source: DecisionSource;
		rationale: string;
		model?: string;
		risk?: ApprovalRisk;
		// Where a human answered. The queue server logs browser answers itself.
		via?: "browser" | "terminal";
		timestamp: number;
	};

export type HumanDecision = DecisionMeasurements & {
	approved: boolean;
	status?: DecisionStatus;
	intent?: IntentProposal;
	fallbackNote?: string;
	historyId?: string;
	note?: string;
	liftLockdown?: boolean;
	// No approver could be reached (no UI, or the queue and the terminal both failed).
	unavailable?: boolean;
	cancelled?: boolean;
	via?: "browser" | "terminal";
};

export type CommandCompletion = AutocompleteItem;
