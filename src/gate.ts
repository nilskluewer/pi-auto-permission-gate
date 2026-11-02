import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerCommands } from "./commands.ts";
import { registerDecisionRenderer } from "./gate-renderer.ts";
import { createGateState } from "./gate-state.ts";
import { registerSessionHooks } from "./session.ts";
import { registerToolCallHook } from "./tool-call.ts";
import type { PermissionGateDependencies } from "./types.ts";

export function createPermissionGate(pi: ExtensionAPI, dependencies: PermissionGateDependencies = {}): void {
	const gate = createGateState(pi, dependencies);
	registerDecisionRenderer(gate);
	registerCommands(gate);
	registerSessionHooks(gate);
	registerToolCallHook(gate);
}
