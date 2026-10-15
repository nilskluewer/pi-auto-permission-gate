#!/usr/bin/env node
// Load the installed tarball and the global forwarding layout in real Pi.
// Uses isolated settings, no model calls, and checks gate commands, not just RPC success.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { accessSync, constants, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const tmp = realpathSync(mkdtempSync(join(tmpdir(), "pi-smoke-")));
const children = new Set();
function piEntry() {
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    const path = resolve(dir, "pi");
    try { accessSync(path, constants.X_OK); return realpathSync(path); } catch {}
  }
  throw new Error("Pi must be installed and available on PATH");
}
const cli = piEntry();
const run = (cmd, args) => {
  const result = spawnSync(cmd, args, { cwd: tmp, encoding: "utf8", timeout: 60_000 });
  assert.equal(result.status, 0, `${cmd} failed: ${result.error ?? ""}\n${result.stdout}\n${result.stderr}`);
  return result.stdout.trim();
};
async function load(extensions, agentDir, discover = false) {
  mkdirSync(agentDir, { recursive: true });
  writeFileSync(join(agentDir, "permission-gate.json"), JSON.stringify({ autoModeEnabled: false }));
  const home = join(agentDir, "home"); mkdirSync(home, { recursive: true });
  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: join(home, ".config"),
    TMPDIR: tmp, LANG: "C.UTF-8", TERM: "dumb", NO_COLOR: "1", PI_CODING_AGENT_DIR: agentDir,
    PI_OFFLINE: "1", PI_PERMISSION_GATE_BROWSER: "0" };
  const args = [cli, "--mode", "rpc", "--offline", "--no-session", "--no-approve", "--no-mcp",
    "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files"];
  if (!discover) args.push("--no-extensions");
  for (const extension of extensions) args.push("-e", extension);
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, args, { cwd: tmp, env, stdio: ["pipe", "pipe", "pipe"] });
    children.add(child);
    let pending = "", diagnostics = "", settled = false;
    const finish = (error, commands) => {
      if (settled) return; settled = true; clearTimeout(timer); child.kill(); children.delete(child);
      error ? reject(new Error(`${error}\n${diagnostics.slice(0, 3000)}`)) : resolvePromise(commands);
    };
    const timer = setTimeout(() => finish("Pi did not return get_commands within 30 seconds"), 30_000);
    child.stderr.on("data", (chunk) => { diagnostics += chunk; });
    child.stdout.on("data", (chunk) => {
      pending += chunk;
      for (let i; (i = pending.indexOf("\n")) >= 0;) {
        const line = pending.slice(0, i); pending = pending.slice(i + 1);
        let message; try { message = JSON.parse(line); } catch { continue; }
        if (message.type === "response" && message.command === "get_commands") {
          if (!message.success || diagnostics.includes("Failed to load extension")) return finish("Extension load failed");
          return finish(undefined, message.data?.commands?.map((c) => c.name) ?? []);
        }
      }
    });
    child.on("error", (error) => finish(error.message));
    child.on("exit", () => finish("Pi exited before answering"));
    child.stdin.write(JSON.stringify({ id: "smoke", type: "get_commands" }) + "\n");
  });
}
function checkGate(commands) {
  for (const name of ["automode-settings", "approvals"]) {
    assert.equal(commands.filter((item) => item === name).length, 1, `Gate command ${name} must load exactly once`);
  }
}
try {
  const packed = spawnSync("npm", ["pack", "--silent", "--pack-destination", tmp], { cwd: root, encoding: "utf8", timeout: 60_000 });
  assert.equal(packed.status, 0, packed.stderr);
  const tarball = packed.stdout.trim().split("\n").at(-1);
  writeFileSync(join(tmp, "package.json"), '{"private":true}');
  run("npm", ["install", join(tmp, tarball), "--omit=peer", "--no-audit", "--no-fund", "--silent"]);
  const installed = join(tmp, "node_modules", ...pkg.name.split("/"));
  const extensions = (pkg.pi?.extensions ?? []).map((entry) => join(installed, entry));
  assert.ok(extensions.length, "package.json must declare pi.extensions");
  for (const file of ["extensions/command-safety.ts", "extensions/dcg.ts", "extensions/dcg-policy.toml", "permission-gate-settings.ts"]) {
    assert.ok(readFileSync(join(installed, file)).length, `${file} must be packaged`);
  }
  checkGate(await load(extensions, join(tmp, "packed-agent")));
  console.log("smoke ok: installed tarball loads the gate and all package siblings");

  // Regression for the user's global single-file symlink failure: a forwarding
  // module imports the real entry so Jiti resolves siblings in the complete package.
  const agentDir = join(tmp, "forwarder-agent");
  const extensionDir = join(agentDir, "extensions"); mkdirSync(extensionDir, { recursive: true });
  writeFileSync(join(extensionDir, "permission-gate.ts"), `export { default } from ${JSON.stringify(realpathSync(join(root, "extensions/permission-gate.ts")))};\n`);
  checkGate(await load([], agentDir, true));
  console.log("smoke ok: global forwarding module is discovered and loads the gate exactly once");

  const emptyExtension = join(tmp, "empty-extension.ts");
  writeFileSync(emptyExtension, "export default function () {}\n");
  const commands = await load([emptyExtension], join(tmp, "negative-agent"));
  assert.throws(() => checkGate(commands), /must load exactly once/);
  console.log("smoke ok: command check rejects RPC success without a loaded gate");
} catch (error) {
  console.error("SMOKE FAIL:", error);
  process.exitCode = 1;
} finally {
  for (const child of children) child.kill();
  rmSync(tmp, { recursive: true, force: true });
}
