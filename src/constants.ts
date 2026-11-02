import { DEFAULT_PRODUCTION_PATTERNS } from "./criticality.ts";
import type { ClassifierModelReference, ClassifierThinkingLevel, CommandRuleConfig, ModeState } from "./types.ts";

export const CLASSIFIER_THINKING_LEVELS = ["off", "minimal", "low", "medium", "high", "xhigh", "max"] as const;
export const AUTO_MODE_SETTINGS_COMMAND = "automode-settings";
export const AUTO_MODE_MODEL_PROVIDER = "github-copilot";
export const AUTO_MODE_MODEL_ID = "gpt-6-luna";
export const DEFAULT_CLASSIFIER_THINKING_LEVEL: ClassifierThinkingLevel = "high";
export const DEFAULT_CLASSIFIER_MODEL: ClassifierModelReference = {
	provider: AUTO_MODE_MODEL_PROVIDER,
	id: AUTO_MODE_MODEL_ID,
};
export const NO_SCOPED_CLASSIFIER_MODELS_WARNING =
	"This session has no scoped models. Configure a session model scope with Pi's --models option or the enabledModels setting before using the model picker.";
export const STATUS_ID = "permission-gate";
export const GATE_COMMAND = "permission-gate";
export const MODE_ENTRY_TYPE = "permission-gate-mode";
export const DECISION_ENTRY_TYPE = "permission-gate-decision";

// The agent waits this long for an answer. After that, the browser request stays open
// for LATE_ANSWER_WINDOW_MS more, so a late answer is always possible.
export const DEFAULT_APPROVAL_WAIT_SECONDS = 300;
export const APPROVAL_WAIT_CHOICES = [60, 120, 300, 600, 900, 1800];
export const LATE_ANSWER_WINDOW_MS = 10 * 60 * 1000;
export const GLOBAL_MODE_STATE_FILENAME = "permission-gate.json";
export const RULES_FILE_NAME = "permission-gate-rules.json";
export const AUTO_MODE_PREFERENCES_FILE_NAME = "automode-preferences.md";
export const DEFAULT_CLASSIFIER_HISTORY_MESSAGES = 12;
export const MIN_CLASSIFIER_HISTORY_MESSAGES = 0;
export const MAX_CLASSIFIER_HISTORY_MESSAGES = 100;
export const CLASSIFIER_HISTORY_CHOICES = [0, 2, 4, 6, 8, 12, 16, 20, 30, 50];

export const DEFAULT_MODE_STATE: ModeState = {
	autoModeEnabled: true,
	classifierModel: { ...DEFAULT_CLASSIFIER_MODEL },
	classifierThinkingLevel: DEFAULT_CLASSIFIER_THINKING_LEVEL,
	classifierHistoryMessages: DEFAULT_CLASSIFIER_HISTORY_MESSAGES,
	productionPatterns: [...DEFAULT_PRODUCTION_PATTERNS],
	approvalWaitSeconds: DEFAULT_APPROVAL_WAIT_SECONDS,
};
export const DEFAULT_COMMAND_RULE_CONFIG: CommandRuleConfig = {
	allowedCommands: [
		"uv run pytest*",
		"rtk uv run pytest*",
		"uv run ruff check*",
		"rtk uv run ruff check*",
		"uv run mypy*",
		"rtk uv run mypy*",
	],
	disallowedCommands: [],
};
export const MAX_PREVIEW_LENGTH = 1200;
export const MAX_RATIONALE_LENGTH = 800;
export const MAX_RECENT_CONTEXT_LENGTH = 6000;
export const MAX_RECENT_MESSAGE_LENGTH = 1200;
export const MAX_AUTO_MODE_PREFERENCES_LENGTH = 8000;
export const CLASSIFIER_TIMEOUT_MS = 90_000;
export const APPROVAL_STATE_FILENAME = "approval-queue.json";
export const MAX_CONSECUTIVE_DENIALS = 3;
export const MAX_TOTAL_DENIALS = 20;
export const NO_RETRY_NOTICE =
	"Do not retry this action in another form (rewording, splitting, scripts, or other tools). If the task needs it, tell the user why in plain text and wait.";
