import { spawn } from "node:child_process";
import { createReadStream } from "node:fs";
import { lstat, readFile, stat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import type { SafetyFinding } from "./command-safety.ts";

export type DcgMode = "off" | "observe" | "enforce";
export type DcgSettings = { mode: DcgMode; binaryPath?: string; sha256?: string };
export const DEFAULT_DCG_SETTINGS: Readonly<DcgSettings> = Object.freeze({ mode: "off" });
export const SUPPORTED_DCG_VERSION = "0.15.3";
export const DCG_ENFORCEMENT_BLOCKER =
  "DCG 0.15.3 enforcement unavailable: public --config silently falls back and layered ambient policy isolation has not been established; use observe or off";
export type DcgResult =
  | { status: "complete"; decision: "allow" | "deny" | "ask"; findings: SafetyFinding[]; version: string }
  | { status: "incomplete"; reason: string };

const POLICY_PATH = fileURLToPath(new URL("./dcg-policy.toml", import.meta.url));
const POLICY_SHA256 = "b9751732e04e276886490ef1d511ff58f678e3b136c0fd53dd553e7f0256a100";
const INPUT_LIMIT = 1024 * 1024;
const STDOUT_LIMIT = 8 * 1024 * 1024;
const STDERR_LIMIT = 64 * 1024;
const DEADLINE_MS = 5000;
const DRAIN_MS = 150;

export function parseDcgSettings(value: unknown): DcgSettings {
  if (value === undefined) return { ...DEFAULT_DCG_SETTINGS };
  // An absent setting is off. A present but corrupt setting must not silently
  // disable a user's enforcement requirement.
  if (!value || typeof value !== "object" || Array.isArray(value)) return { mode: "enforce" };
  const v = value as Record<string, unknown>;
  const mode = v.mode === "off" || v.mode === "observe" || v.mode === "enforce" ? v.mode : "enforce";
  return {
    mode,
    ...(typeof v.binaryPath === "string" ? { binaryPath: v.binaryPath } : {}),
    ...(typeof v.sha256 === "string" ? { sha256: v.sha256.toLowerCase() } : {}),
  };
}

const incomplete = (reason: string): DcgResult => ({ status: "incomplete", reason });
const digest = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");

// No inherited loader/agent/profile overrides. HOME/XDG remain real in observe:
// this is NOT an isolation mechanism. Enforce is refused even if observe probes pass.
function analyzerEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of ["PATH", "HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "TMPDIR", "SystemRoot", "WINDIR"]) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  return { ...env, NO_COLOR: "1", DCG_HISTORY_DISABLED: "1", DCG_HISTORY_ENABLED: "false",
    DCG_NO_UPDATE_CHECK: "1", DCG_NO_SELF_HEAL: "1" };
}

async function hashBinary(path: string, signal: AbortSignal): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path, { signal })) hash.update(chunk);
  return hash.digest("hex");
}

function parseProtocol(stdout: Buffer, code: number | null, command: string): DcgResult {
  let v: any;
  try { v = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(stdout)); } catch { return incomplete("DCG malformed JSON or UTF-8"); }
  if (!v || typeof v !== "object" || Array.isArray(v)) return incomplete("DCG invalid output object");
  const fields = new Set(["schema_version", "dcg_version", "robot_mode", "command", "decision", "mode", "rule_id", "pack_id",
    "pattern_name", "reason", "explanation", "source", "matched_span", "severity", "allowlist", "agent", "dialect_divergence"]);
  if (Object.keys(v).some(k => !fields.has(k)) || v.schema_version !== 1 ||
      v.dcg_version !== SUPPORTED_DCG_VERSION || v.robot_mode !== true || v.command !== command) {
    return incomplete("DCG unsupported schema/version or command bytes changed");
  }
  if (!v.agent || v.agent.detected !== "pi" || v.agent.trust_level !== "low" || v.agent.detection_method !== "explicit") {
    return incomplete("DCG managed pi profile was not applied");
  }
  if (v.allowlist !== undefined) return incomplete("DCG unexpected allowlist override");
  if (!["allow", "deny", "ask"].includes(v.decision)) return incomplete("DCG unexpected decision");
  if (code !== (v.decision === "allow" ? 0 : 1)) return incomplete("DCG exit/decision mismatch");
  if (v.decision === "allow") {
    if (["mode", "rule_id", "pack_id", "pattern_name", "reason", "explanation", "source", "matched_span", "severity", "dialect_divergence"].some(k => v[k] !== undefined)) {
      return incomplete("DCG allow contains unexpected finding metadata");
    }
    return { status: "complete", decision: "allow", findings: [], version: SUPPORTED_DCG_VERSION };
  }
  if (v.mode !== v.decision || typeof v.rule_id !== "string" || typeof v.pack_id !== "string" ||
      typeof v.pattern_name !== "string" || !v.pattern_name || !/^[a-z][a-z0-9_.-]*$/.test(v.pack_id) ||
      v.rule_id !== `${v.pack_id}:${v.pattern_name}` || !/^[a-zA-Z0-9_.:-]+$/.test(v.rule_id) ||
      typeof v.reason !== "string" || !v.reason || (v.explanation !== undefined && typeof v.explanation !== "string") ||
      !["critical", "high", "medium", "low"].includes(v.severity) || !["pack", "heredoc_ast"].includes(v.source) ||
      (v.matched_span !== undefined && (!Array.isArray(v.matched_span) || v.matched_span.length !== 2 ||
        !v.matched_span.every((n: unknown) => Number.isInteger(n) && Number(n) >= 0) ||
        v.matched_span[0] > v.matched_span[1] || v.matched_span[1] > Buffer.byteLength(command))) ||
      v.dialect_divergence !== undefined) return incomplete("DCG invalid finding schema");
  // Critical severity alone is NOT catastrophic (reset-hard is critical upstream).
  // Local rules retain catastrophic hard blocks; unknown DCG findings need a human.
  const hard = new Set(["core.filesystem:rm-rf-root-home"]);
  const findings: SafetyFinding[] = [{ ruleId: v.rule_id, source: "dcg",
    enforcement: hard.has(v.rule_id) ? "hard-block" : "human-required",
    risk: v.severity === "critical" || v.severity === "high" ? "critical" : v.severity === "low" ? "low" : "medium",
    summary: v.reason }];
  return { status: "complete", decision: v.decision, findings, version: SUPPORTED_DCG_VERSION };
}

/** Analyzer only: command bytes go to stdin, never to a shell or argv.
 * Every call rehashes the selected binary. The user must trust its installation
 * and ancestors. Hash checking cannot prevent concurrent same-user replacement.
 * Deadline bounds setup + direct child + stream drain, not event-loop stalls;
 * no claim that surviving descendants are killed or reaped.
 */
export async function evaluateWithDcg(command: string, cwd: string, settings: DcgSettings, signal?: AbortSignal): Promise<DcgResult> {
  if (signal?.aborted) return incomplete("DCG cancelled");
  if (settings.mode === "off") return incomplete("DCG disabled");
  if (settings.mode === "enforce") return incomplete(DCG_ENFORCEMENT_BLOCKER);
  if (settings.mode !== "observe") return incomplete("DCG invalid mode");
  if (typeof command !== "string" || Buffer.byteLength(command) > INPUT_LIMIT) return incomplete("DCG command exceeds 1 MiB limit");
  const bytes = Buffer.from(command, "utf8");
  if (bytes.toString("utf8") !== command) return incomplete("DCG command is not lossless UTF-8");
  if (!settings.binaryPath || !isAbsolute(settings.binaryPath) || !/^[a-fA-F0-9]{64}$/.test(settings.sha256 ?? "")) {
    return incomplete("DCG requires a user-trusted absolute binary path and SHA256");
  }
  if (!isAbsolute(cwd)) return incomplete("DCG requires an absolute command cwd");

  return new Promise<DcgResult>(resolve => {
    const controller = new AbortController();
    let child: ReturnType<typeof spawn> | undefined;
    let settled = false;
    let drain: ReturnType<typeof setTimeout> | undefined;
    const finish = (result: DcgResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (drain) clearTimeout(drain);
      signal?.removeEventListener("abort", cancel);
      controller.abort();
      if (child && child.exitCode === null && child.signalCode === null) { try { child.kill("SIGKILL"); } catch { /* already gone */ } }
      child?.stdin?.destroy(); child?.stdout?.destroy(); child?.stderr?.destroy();
      resolve(result);
    };
    const cancel = () => finish(incomplete("DCG cancelled"));
    const deadline = setTimeout(() => finish(incomplete("DCG 5 second total deadline exceeded")), DEADLINE_MS);
    signal?.addEventListener("abort", cancel, { once: true });
    if (signal?.aborted) { cancel(); return; }
    void (async () => {
      const binaryPath = settings.binaryPath!;
      const info = await lstat(binaryPath);
      if (!info.isFile() || (info.mode & 0o022) !== 0) throw new Error("binary must be a direct regular file not writable by group/others");
      if (!(await stat(cwd)).isDirectory()) throw new Error("command cwd is not a directory");
      const hash = await hashBinary(binaryPath, controller.signal);
      if (hash !== settings.sha256!.toLowerCase()) throw new Error("binary SHA256 mismatch");
      const policyInfo = await lstat(POLICY_PATH);
      if (!policyInfo.isFile() || (policyInfo.mode & 0o022) !== 0) throw new Error("managed policy is not a trusted regular file");
      const policy = await readFile(POLICY_PATH, { signal: controller.signal });
      if (digest(policy) !== POLICY_SHA256) throw new Error("managed policy SHA256 mismatch");
      if (settled) return;
      child = spawn(binaryPath, ["--robot", "--agent", "pi", "test", "--stdin", "--format", "json", "--dialect", "posix",
        "--config", POLICY_PATH, "--heredoc-scan", "--enforce-budget"],
        { cwd, env: analyzerEnv(), shell: false, stdio: ["pipe", "pipe", "pipe"] });
      let stdoutBytes = 0, stderrBytes = 0;
      const output: Buffer[] = [];
      child.on("error", () => finish(incomplete("DCG subprocess start failed")));
      child.stdin!.on("error", () => finish(incomplete("DCG stdin write failed")));
      child.stdout!.on("error", () => finish(incomplete("DCG stdout read failed")));
      child.stderr!.on("error", () => finish(incomplete("DCG stderr read failed")));
      child.stdout!.on("data", (chunk: Buffer) => {
        stdoutBytes += chunk.length;
        if (stdoutBytes > STDOUT_LIMIT) finish(incomplete("DCG stdout exceeds 8 MiB limit"));
        else output.push(chunk);
      });
      child.stderr!.on("data", (chunk: Buffer) => {
        stderrBytes += chunk.length;
        if (stderrBytes > STDERR_LIMIT) finish(incomplete("DCG stderr exceeds 64 KiB limit"));
      });
      child.on("exit", () => {
        if (settled) return;
        drain = setTimeout(() => finish(incomplete("DCG stream drain deadline exceeded")), DRAIN_MS);
      });
      child.on("close", (code, killed) => {
        if (killed) finish(incomplete(`DCG terminated by ${killed}`));
        else if (stderrBytes) finish(incomplete("DCG unexpected stderr diagnostic (possible config fallback)"));
        else finish(parseProtocol(Buffer.concat(output), code, command));
      });
      // v0.15.3 removes one final LF from stdin. Supply one protocol LF only
      // when needed so its decoded command retains every original byte.
      child.stdin!.end(command.endsWith("\n") ? Buffer.concat([bytes, Buffer.from("\n")]) : bytes);
    })().catch(error => finish(incomplete(`DCG setup failed: ${error instanceof Error ? error.message : "unknown error"}`)));
  });
}
