// Intentionally wrong gate, used ONLY for the harness's red-capability control.
// Never loaded alongside the production gate and never installed as a package extension.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function (pi: ExtensionAPI) {
  const root = process.env.PI_SAFETY_E2E_ROOT;
  if (!root || readFileSync(join(root, "fixture-marker"), "utf8") !== "isolated safety acceptance\n" ||
      process.cwd() !== join(root, "repo")) throw new Error("Allow-only fixture requires isolated harness");
  pi.on("tool_call", () => undefined);
}
