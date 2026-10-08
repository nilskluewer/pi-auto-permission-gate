#!/usr/bin/env node
// Smoke test: install the packed tarball the way a user gets it, then load it in a real Pi process.
// Catches what repo-local tests cannot: files missing from the tarball, imports that only resolve
// inside the repo, and Pi module-mapping changes. Needs the `pi` binary. Does not call a model.
import { spawn, spawnSync } from "node:child_process"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"

const root = resolve(import.meta.dirname, "..")
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"))
const tmp = mkdtempSync(join(tmpdir(), "pi-smoke-"))
const fail = (message) => {
  console.error("SMOKE FAIL: " + message)
  rmSync(tmp, { recursive: true, force: true })
  process.exit(1)
}
const run = (cmd, args, cwd) => {
  const result = spawnSync(cmd, args, { cwd, encoding: "utf8" })
  if (result.status !== 0) fail([cmd, ...args].join(" ") + "\n" + result.stdout + result.stderr)
  return result.stdout.trim()
}

// 1. Pack and install without peer dependencies: Pi supplies its own packages to extensions.
const tarball = run("npm", ["pack", "--silent", "--pack-destination", tmp], root).split("\n").pop()
writeFileSync(join(tmp, "package.json"), '{"private":true}')
run("npm", ["install", join(tmp, tarball), "--omit=peer", "--no-audit", "--no-fund", "--silent"], tmp)
const installed = join(tmp, "node_modules", ...pkg.name.split("/"))

// 2. Load every declared extension in a real Pi process and ask for its commands.
const extensions = (pkg.pi?.extensions ?? []).map((entry) => join(installed, entry))
if (extensions.length === 0) fail("package.json has no pi.extensions entry")
const args = ["--mode", "rpc", "--offline", "--no-session", "--no-extensions", "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files"]
for (const extension of extensions) args.push("-e", extension)

const child = spawn("pi", args, { cwd: tmp, stdio: ["pipe", "pipe", "pipe"] })
let output = ""
let done = false
const finish = (error) => {
  if (done) return
  done = true
  child.kill()
  if (error) fail(error + "\n" + output.slice(0, 3000))
  console.log("smoke ok: " + pkg.name + " loads in Pi from the packed tarball")
  rmSync(tmp, { recursive: true, force: true })
}
const onData = (chunk) => {
  output += chunk
  for (const line of output.split("\n")) {
    if (!line.trim().startsWith("{")) continue
    try {
      const message = JSON.parse(line)
      if (message.type === "response" && message.command === "get_commands") {
        return finish(message.success ? undefined : "get_commands failed: " + JSON.stringify(message))
      }
    } catch {}
  }
}
child.stdout.on("data", onData)
child.stderr.on("data", onData)
child.on("error", (error) => finish("could not start pi: " + error.message))
child.on("exit", () => finish("pi exited before answering"))
child.stdin.write(JSON.stringify({ id: "smoke", type: "get_commands" }) + "\n")
setTimeout(() => finish("timeout after 60 s"), 60_000).unref()
