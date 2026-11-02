import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createPermissionGate } from "./gate.ts";

export const NO_GATE_FLAG = "no-permission-gate";
/** Set to "0" to start with the gate off, for launchers that cannot pass CLI flags. */
export const GATE_ENV = "PI_PERMISSION_GATE";

/**
 * `--no-permission-gate` or `PI_PERMISSION_GATE=0` starts pi with the gate fully off.
 * The value is read at session start. `/permission-gate on|off` changes it at runtime.
 */
export function startsOff(flag: unknown, env: NodeJS.ProcessEnv): boolean {
	return flag === true || env[GATE_ENV] === "0";
}

export default function (pi: ExtensionAPI): void {
	pi.registerFlag(NO_GATE_FLAG, {
		type: "boolean",
		description: "Start with the permission gate fully off (no checks, no approvals).",
	});
	createPermissionGate(pi, { startOff: () => startsOff(pi.getFlag(NO_GATE_FLAG), process.env) });
}
