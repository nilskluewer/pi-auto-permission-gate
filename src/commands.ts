import { join } from "node:path";
import { openApprovalPage } from "./approval-client.ts";
import { getClassifierModelCompletions } from "./classifier-models.ts";
import { handlePermissionSettingsCommand } from "./commands-page.ts";
import { handleAutoModeSettingsCommand } from "./commands-settings.ts";
import { getAgentConfigDirectory } from "./config-paths.ts";
import { APPROVAL_STATE_FILENAME, AUTO_MODE_SETTINGS_COMMAND, GATE_COMMAND } from "./constants.ts";
import { setGate } from "./gate-controls.ts";
import { notify } from "./gate-display.ts";
import type { GateState } from "./gate-state.ts";

export function registerCommands(gate: GateState): void {
	gate.pi.registerCommand(AUTO_MODE_SETTINGS_COMMAND, {
		description: "Open permission-gate settings or configure them directly",
		getArgumentCompletions: (argumentPrefix) =>
			getClassifierModelCompletions(argumentPrefix, gate.scopedClassifierModels),
		handler: async (args, ctx) => {
			const value = String(args ?? "").trim();
			if (!value) {
				await handlePermissionSettingsCommand(gate, ctx);
				return;
			}
			await handleAutoModeSettingsCommand(gate, value, ctx);
		},
	});

	gate.pi.registerCommand(GATE_COMMAND, {
		description: "Turn the permission gate on or off globally: /permission-gate on|off|status",
		getArgumentCompletions: (prefix) =>
			["on", "off", "status"]
				.filter((v) => v.startsWith(prefix.trim().toLowerCase()))
				.map((v) => ({ value: v, label: v })),
		handler: async (args, ctx) => {
			const action = String(args ?? "")
				.trim()
				.toLowerCase();
			if (action === "on" || action === "off") {
				await setGate(gate, ctx, action);
			} else if (!action || action === "status") {
				await handleAutoModeSettingsCommand(gate, "status", ctx);
			} else {
				notify(ctx, "Usage: /permission-gate on|off|status", "warning");
			}
		},
	});

	gate.pi.registerCommand("approvals", {
		description: "Open the approval queue and decision history in the browser",
		handler: async (_args, ctx) => {
			const opened =
				process.env.PI_PERMISSION_GATE_BROWSER === "0"
					? false
					: await (
							gate.dependencies.openApprovalPage ??
							(() => openApprovalPage(join(getAgentConfigDirectory(), APPROVAL_STATE_FILENAME)))
						)();
			notify(
				ctx,
				opened ? "Opened the approval queue and history in the browser." : "The approval queue is unavailable.",
				opened ? "info" : "warning",
			);
		},
	});
}
