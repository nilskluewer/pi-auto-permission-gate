#!/usr/bin/env node
// Real installed Pi, offline canned provider, actual built-in bash and production tool_call gate.
// No npm install, real credentials, real developer repository, or real external CLI targets.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { accessSync, constants, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const project = resolve(import.meta.dirname, "..");
const fixtures = join(project, "tests/fixtures/safety-e2e");
const gate = join(project, "extensions/permission-gate.ts");
const timeoutMs = 30_000;
const quote = (value) => "'" + value.replaceAll("'", "'\\''") + "'";
function executable(name) {
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (!dir) continue;
    const path = resolve(dir, name);
    try { accessSync(path, constants.X_OK); return realpathSync(path); } catch {}
  }
  throw new Error(`${name} not found on PATH (requires current installed Pi, Git and bash)`);
}
const piCli = executable("pi");
const git = executable("git");
// Invoke the installed command's resolved JS entry with the current Node, not a hard-coded node path.
assert.match(piCli, /\.(?:[cm]?js|ts)$/, "pi must resolve to its installed JavaScript CLI entry");
const tmp = realpathSync(mkdtempSync(join(tmpdir(), "pi-safety-e2e-")));
const children = new Set();
let serial = 0;
let passed = 0;
const pass = (message) => { passed++; console.log(`ok ${passed} - ${message}`); };

// Allowlist environment rather than inheriting PI_*, model credentials, Git config or shell startup hooks.
function environment(home) {
  return {
    PATH: process.env.PATH ?? `${dirname(process.execPath)}:/usr/bin:/bin`,
    HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"),
    XDG_CACHE_HOME: join(home, ".cache"), TMPDIR: tmp, TMP: tmp, TEMP: tmp,
    LANG: "C.UTF-8", TERM: "dumb", NO_COLOR: "1",
    GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: join(home, "empty-git-config"),
    GIT_TERMINAL_PROMPT: "0", PI_OFFLINE: "1", PI_PERMISSION_GATE_BROWSER: "0",
  };
}
function run(command, args, cwd, env) {
  const result = spawnSync(command, args, { cwd, env, encoding: "utf8", timeout: timeoutMs });
  assert.equal(result.status, 0, `${command} ${args.join(" ")} failed: ${result.error ?? ""}\n${result.stdout}\n${result.stderr}`);
  return result.stdout;
}
function workspace(label) {
  const root = join(tmp, `${++serial}-${label}`);
  const repo = join(root, "repo"), home = join(root, "home"), bin = join(root, "bin");
  for (const path of [repo, home, bin]) mkdirSync(path, { recursive: true });
  writeFileSync(join(root, "fixture-marker"), "isolated safety acceptance\n");
  writeFileSync(join(home, "empty-git-config"), "");
  const env = environment(home);
  const gitRun = (...args) => run(git, args, repo, env);
  gitRun("init", "-q");
  gitRun("config", "user.name", "Safety Fixture");
  gitRun("config", "user.email", "safety-fixture@example.invalid");
  for (const file of ["target.txt", "other.txt", "stash.txt"]) writeFileSync(join(repo, file), `committed ${file}\n`);
  gitRun("add", "--", "target.txt", "other.txt", "stash.txt");
  gitRun("-c", "core.hooksPath=/dev/null", "commit", "-qm", "isolated canary baseline");
  writeFileSync(join(repo, "stash.txt"), "saved stash canary\n");
  gitRun("stash", "push", "-qm", "saved canary", "--", "stash.txt");
  writeFileSync(join(repo, "target.txt"), "dirty target canary\n");
  writeFileSync(join(repo, "other.txt"), "dirty unrelated canary\n");
  const launches = join(root, "launches.jsonl");
  writeFileSync(launches, "");
  // Recording shim delegates to real Git. Absolute executable path avoids login-shell PATH changes.
  writeFileSync(join(bin, "git"), `#!/bin/sh\nprintf '%s\\n' "$*" >> ${quote(launches)}\nexec ${quote(git)} "$@"\n`, { mode: 0o700 });
  writeFileSync(join(bin, "redis-cli"), `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(join(fixtures, "redis-cli.mjs"))} "$@"\n`, { mode: 0o700 });
  const restore = `${quote(join(bin, "git"))} restore -- target.txt`;
  const stash = `${quote(join(bin, "git"))} stash clear`;
  const flush = `${quote(join(bin, "redis-cli"))} FLUSHALL`;
  const actions = {
    restore: { command: restore }, stash: { command: stash }, flush: { command: flush },
    get: { command: `${quote(join(bin, "redis-cli"))} GET fixture-canary` },
    "nested-restore": { command: restore, nested: true },
    "nested-stash": { command: stash, nested: true },
  };
  const actionsPath = join(root, "actions.json");
  writeFileSync(actionsPath, JSON.stringify(actions));
  function snapshot() {
    const stashList = gitRun("stash", "list", "--format=%H %gs");
    return {
      files: Object.fromEntries(["target.txt", "other.txt", "stash.txt"].map((name) => [name, readFileSync(join(repo, name), "utf8")])),
      stash: stashList,
      stashContent: stashList ? gitRun("show", "refs/stash:stash.txt") : null,
      index: gitRun("ls-files", "--stage"), head: gitRun("rev-parse", "HEAD"),
      status: gitRun("status", "--porcelain=v1", "-z"),
    };
  }
  return { root, repo, home, env, launches, actionsPath, actions, snapshot };
}
function lines(path) { return readFileSync(path, "utf8").trim().split("\n").filter(Boolean); }
function unchanged(ws, before) {
  assert.deepEqual(ws.snapshot(), before, "CANARY_CHANGED: a denied call changed Git/file canaries");
  assert.deepEqual(lines(ws.launches), [], "COMMAND_LAUNCHED: denied command reached an executable");
}
function approvedRestore(ws, before, expectedLaunches = 1) {
  const after = ws.snapshot();
  assert.equal(after.files["target.txt"], "committed target.txt\n");
  assert.deepEqual({ ...after, files: { ...after.files, "target.txt": before.files["target.txt"] }, status: before.status }, before,
    "approval changed something other than the named working file");
  assert.equal(after.status, " M other.txt\0", "only named target may lose its dirty status");
  assert.deepEqual(lines(ws.launches), Array(expectedLaunches).fill("restore -- target.txt"));
}
async function start(ws, mode, wrongGate = false, prompt) {
  const agentDir = join(ws.root, `agent-${mode}-${++serial}`);
  mkdirSync(agentDir);
  writeFileSync(join(agentDir, "permission-gate.json"), JSON.stringify({ autoModeEnabled: false, dcg: { mode: "off" } }));
  // Matching allow patterns must not override mandatory human review.
  writeFileSync(join(agentDir, "permission-gate-rules.json"), JSON.stringify({
    allowedCommands: Object.values(ws.actions).map((action) => action.command), disallowedCommands: [],
  }));
  writeFileSync(join(agentDir, "settings.json"), JSON.stringify({
    packages: [], compaction: { enabled: false }, retry: { enabled: false }, cacheWarming: { enabled: false },
  }));
  const audit = join(agentDir, "fixture-audit.jsonl");
  writeFileSync(audit, "");
  const args = [piCli, "--mode", mode, "--offline", "--no-session", "--no-approve",
    "--no-extensions", "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files", "--no-mcp",
    "-e", wrongGate ? join(fixtures, "allow-only.ts") : gate,
    "-e", join(fixtures, "mock-provider.ts"), "--provider", "safety-e2e", "--model", "canned",
    "--thinking", "off", "--tools", "bash,safety_orchestrate"];
  if (prompt) args.push(prompt);
  const child = spawn(process.execPath, args, { cwd: ws.repo, env: { ...ws.env,
    PI_CODING_AGENT_DIR: agentDir, PI_SAFETY_E2E_ROOT: ws.root, PI_SAFETY_E2E_ACTIONS: ws.actionsPath,
    PI_SAFETY_E2E_AUDIT: audit, PI_SAFETY_E2E_LAUNCHES: ws.launches }, stdio: ["pipe", "pipe", "pipe"] });
  children.add(child);
  if (mode !== "rpc") child.stdin.end(); // One-shot Pi reads piped stdin before running prompts.
  const records = [];
  let stderr = "", buffer = "", failure;
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let end;
    while ((end = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, end).replace(/\r$/, ""); buffer = buffer.slice(end + 1);
      if (!line) continue;
      try { records.push(JSON.parse(line)); } catch { failure = new Error(`Non-JSON Pi stdout: ${line}`); }
    }
  });
  child.on("error", (error) => { failure = error; });
  const exit = new Promise((resolveExit) => child.on("close", (code, signal) => {
    children.delete(child); resolveExit({ code, signal });
  }));
  const diagnostics = () => `${stderr}\n${JSON.stringify(records.slice(-8), null, 2)}`;
  async function wait(predicate, from = 0) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (failure) throw failure;
      const record = records.slice(from).find(predicate);
      if (record) return record;
      if (child.exitCode !== null || child.signalCode) throw new Error(`Pi exited unexpectedly\n${diagnostics()}`);
      await sleep(10);
    }
    throw new Error(`Pi ${mode} timeout\n${diagnostics()}`);
  }
  const send = (record) => child.stdin.write(JSON.stringify(record) + "\n");
  async function close() {
    child.stdin.end();
    const timer = setTimeout(() => child.kill("SIGKILL"), 3000);
    try {
      const result = await exit;
      assert.equal(result.code, 0, `Pi did not exit cleanly: ${JSON.stringify(result)}\n${diagnostics()}`);
      assert.equal(buffer.trim(), "", "unterminated Pi JSON record");
      assert.doesNotMatch(stderr, /Failed to load extension|Unknown provider/, diagnostics());
      assert.ok(!records.some((record) => record.type === "extension_error"), diagnostics());
      const providerErrors = records.filter((record) => record.type === "message_end" && record.message?.role === "assistant" &&
        ["error", "aborted"].includes(record.message.stopReason));
      assert.deepEqual(providerErrors, [], diagnostics());
      const entries = lines(audit).map(JSON.parse);
      const startup = entries.find((entry) => entry.type === "startup");
      assert.deepEqual(startup, { type: "startup", mode, hasUI: mode === "rpc", cwd: ws.repo });
      assert.ok(entries.some((entry) => entry.type === "provider" && !entry.followup), "canned model did not run");
    } finally { clearTimeout(timer); }
  }
  return { child, records, wait, send, close, audit, diagnostics };
}
function toolResult(records, nested = false) {
  const result = records.find((record) => record.type === "tool_execution_end" && record.toolName === "bash" &&
    Boolean(record.parentToolCallId) === nested);
  assert.ok(result, `missing ${nested ? "nested " : ""}bash result`);
  return result;
}
function denied(records, nested = false) {
  const result = toolResult(records, nested);
  assert.equal(result.isError, true, "denied bash must be a failed tool result");
  assert.match(JSON.stringify(result.result), /permission gate/i, "unrelated error is not gate denial");
  // Pi announces tool_execution_start before the pre-tool handlers. It is NOT launch evidence;
  // the recording executable and Git/file canaries independently establish absent execution.
}
function emitted(records, action) {
  const calls = records.filter((record) => record.type === "message_end" && record.message?.role === "assistant")
    .flatMap((record) => record.message.content).filter((part) => part.type === "toolCall");
  assert.equal(calls.length, 1, "provider must emit exactly one canned action, no retries");
  assert.equal(calls[0].name, action.nested ? "safety_orchestrate" : "bash");
  assert.deepEqual(calls[0].arguments, { command: action.command });
}
async function jsonCase(action, wrongGate = false) {
  const ws = workspace(`${wrongGate ? "red" : "json"}-${action}`), before = ws.snapshot();
  const client = await start(ws, "json", wrongGate, `safety-e2e:${action}:once`);
  await client.wait((record) => record.type === "agent_settled");
  await client.close();
  emitted(client.records, ws.actions[action]);
  return { ws, before, client };
}
async function rpcRestore(nested) {
  const action = nested ? "nested-restore" : "restore";
  const ws = workspace(`rpc-${action}`), before = ws.snapshot();
  const client = await start(ws, "rpc");
  async function attempt(token, answer) {
    const from = client.records.length;
    client.send({ id: token, type: "prompt", message: `safety-e2e:${action}:${token}` });
    const prompt = await client.wait((record) => record.type === "response" && record.id === token, from);
    assert.equal(prompt.success, true, client.diagnostics());
    const request = await client.wait((record) => record.type === "extension_ui_request" && record.method === "select", from);
    assert.match(request.title, /Permission gate:/);
    assert.ok(request.title.includes(ws.actions[action].command), "approval must identify exact command");
    assert.deepEqual(request.options, ["No", "Yes"]);
    // Before either human answer, not even the command shim may have launched.
    unchanged(ws, before);
    await sleep(100); // Also catch a launch that races the approval card.
    unchanged(ws, before);
    client.send({ type: "extension_ui_response", id: request.id, value: answer });
    await client.wait((record) => record.type === "agent_settled", from);
    const records = client.records.slice(from);
    emitted(records, ws.actions[action]);
    assert.equal(records.filter((record) => record.type === "extension_ui_request" && record.method === "select").length, 1,
      "one action must produce one approval card");
    return records;
  }
  const deniedRecords = await attempt("denial", "No");
  denied(deniedRecords, nested);
  unchanged(ws, before);
  const approved = await attempt("approval", "Yes");
  assert.equal(toolResult(approved, nested).isError, false);
  if (nested) {
    const end = toolResult(approved, true);
    assert.match(end.toolCallId, /^fixture-approval\/\d+$/);
    assert.equal(end.parentToolCallId, "fixture-approval");
  }
  approvedRestore(ws, before);
  // Approval belongs to one call, not this session or command spelling.
  writeFileSync(join(ws.repo, "target.txt"), before.files["target.txt"]);
  writeFileSync(ws.launches, "");
  const again = await attempt("fresh-call", "No");
  denied(again, nested);
  unchanged(ws, before);
  await client.close();
  pass(`RPC ${nested ? "nested " : ""}restore: deny → exact-call approval → fresh call needs approval; only target changes`);
}

try {
  // Other agents may still be creating the production helper modules. Wait, never replace them.
  for (const name of ["command-safety.ts", "dcg.ts", "dcg-policy.toml"]) {
    const deadline = Date.now() + 60_000;
    while (true) {
      try { accessSync(join(project, "extensions", name)); break; } catch {
        if (Date.now() >= deadline) throw new Error(`Missing concurrent helper extensions/${name}`);
        await sleep(250);
      }
    }
  }
  console.log(`safety-e2e: Node ${process.version}; Pi entry ${piCli}`);
  for (const action of ["restore", "stash", "flush", "nested-restore", "nested-stash"]) {
    const { ws, before, client } = await jsonCase(action);
    denied(client.records, Boolean(ws.actions[action].nested));
    unchanged(ws, before);
    assert.ok(!client.records.some((record) => record.type === "extension_ui_request" && record.method === "select"));
    pass(`JSON no-UI ${action}: denied despite matching allow pattern; no launch, files/index/stash unchanged`);
  }
  const safe = await jsonCase("get");
  assert.equal(toolResult(safe.client.records).isError, false);
  assert.deepEqual(safe.ws.snapshot(), safe.before);
  assert.deepEqual(lines(safe.ws.launches).map(JSON.parse), [{ cli: "redis-cli", args: ["GET", "fixture-canary"] }]);
  pass("fake redis-cli GET safe neighbor launches (no database connection)");
  await rpcRestore(false);
  await rpcRestore(true);
  // Non-gating isolated control: independent Git semantics are observable, and denial assertions go red.
  for (const action of ["restore", "stash", "flush", "nested-restore"]) {
    const red = await jsonCase(action, true);
    assert.equal(toolResult(red.client.records, Boolean(red.ws.actions[action].nested)).isError, false,
      "red control must fail because of execution, not startup/schema errors");
    if (action.endsWith("restore")) approvedRestore(red.ws, red.before);
    if (action === "stash") assert.equal(run(git, ["stash", "list"], red.ws.repo, red.ws.env), "");
    if (action === "flush") assert.deepEqual(lines(red.ws.launches).map(JSON.parse), [{ cli: "redis-cli", args: ["FLUSHALL"] }]);
    assert.throws(() => unchanged(red.ws, red.before), action === "flush" ? /COMMAND_LAUNCHED/ : /CANARY_CHANGED/,
      "acceptance invariant failed to detect deliberately non-gating behavior");
    pass(`red-capability ${action}: allow-only fixture executes; ${action === "flush" ? "launch" : "canary"} invariant rejects it`);
  }
  console.log(`safety-e2e ok: ${passed} checks; offline, manual mode, real Pi/built-in bash, isolated canaries.\nLimits: no TUI/browser, live DCG, auto-mode classifier, installed-tarball, cloud/device/database acceptance.`);
} catch (error) {
  console.error(`SAFETY E2E FAIL: ${error.stack ?? error}`);
  process.exitCode = 1;
} finally {
  for (const child of children) child.kill("SIGKILL");
  // Wait for direct Pi processes to close before removing their disposable workspaces.
  await Promise.all([...children].map((child) => new Promise((done) => child.once("close", done))));
  rmSync(tmp, { recursive: true, force: true });
}
