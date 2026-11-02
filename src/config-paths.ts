import { homedir } from "node:os";
import { join } from "node:path";
import { AUTO_MODE_PREFERENCES_FILE_NAME, GLOBAL_MODE_STATE_FILENAME, RULES_FILE_NAME } from "./constants.ts";

export function getAgentConfigDirectory(): string {
	return process.env.PI_CODING_AGENT_DIR || join(homedir(), ".pi", "agent");
}

export function getGlobalModeStatePath(): string {
	return join(getAgentConfigDirectory(), GLOBAL_MODE_STATE_FILENAME);
}

export function getAutoModePreferencesPath(): string {
	return join(getAgentConfigDirectory(), AUTO_MODE_PREFERENCES_FILE_NAME);
}

export function getGlobalRulesPath(): string {
	return join(getAgentConfigDirectory(), RULES_FILE_NAME);
}
