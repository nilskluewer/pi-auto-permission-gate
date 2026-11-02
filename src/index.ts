import { type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createPermissionGate } from "./gate.ts";

export const NO_GATE_FLAG = "no-permission-gate";

/** `--no-permission-gate` starts pi with the gate fully off. `/permission-gate on|off` changes it at runtime. */
export default function (pi: ExtensionAPI): void {
	pi.registerFlag(NO_GATE_FLAG, {
		type: "boolean",
		description: "Start with the permission gate fully off (no checks, no approvals).",
	});
	createPermissionGate(pi, { startOff: () => pi.getFlag(NO_GATE_FLAG) === true });
}
