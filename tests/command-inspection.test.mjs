import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspectCommand, inspectionIsFresh, inspectionPrompt, groupPaths, codeReviewReasons, INSPECTION_LIMITS } from "../extensions/command-inspection.mjs";

async function project(t, files) {
  const dir = await mkdtemp(join(tmpdir(), "gate-inspection-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  for (const [name, content] of Object.entries(files)) {
    await mkdir(join(dir, name, ".."), { recursive: true });
    await writeFile(join(dir, name), content);
  }
  return dir;
}

// Oracle: the agreed policy requires code evidence, never code execution. A wrong
// implementation that reads only filenames or runs the script fails these checks.
test("collects Python source and local dependencies without running them", async (t) => {
  const dir = await project(t, {
    "scripts/cleanup.py": 'import helper\nfrom pathlib import Path\nPath("must-not-exist.txt").write_text("executed")\n',
    "scripts/helper.py": 'print("local helper")\n',
  });
  const result = await inspectCommand("python scripts/cleanup.py --output build/report.json", dir);
  assert.deepEqual(result.files.map((f) => f.path), [join(dir, "scripts/cleanup.py"), join(dir, "scripts/helper.py")]);
  assert.match(inspectionPrompt(result), /local helper/);
  assert.ok(result.paths.some((p) => p.path === join(dir, "build/report.json")));
  const { access } = await import("node:fs/promises");
  await assert.rejects(access(join(dir, "must-not-exist.txt")));
});

test("reads sourced shell files and nested invoked scripts with cycle protection", async (t) => {
  const dir = await project(t, {
    "run.sh": "source ./helpers.sh\npython ./cleanup.py\n",
    "helpers.sh": "source ./run.sh\n",
    "cleanup.py": 'print("cleanup")\n',
  });
  const result = await inspectCommand("bash run.sh", dir);
  assert.deepEqual(new Set(result.files.map((f) => f.path)), new Set([join(dir, "run.sh"), join(dir, "helpers.sh"), join(dir, "cleanup.py")]));
});

test("resolves JavaScript local imports from the importing file", async (t) => {
  const dir = await project(t, {
    "src/main.mjs": 'import { helper } from "./helper.mjs";\n',
    "src/helper.mjs": "export const helper = 1;\n",
  });
  const result = await inspectCommand("node src/main.mjs", dir);
  assert.equal(result.files.length, 2);
  assert.ok(result.files.some((f) => f.path === join(dir, "src/helper.mjs")));
});

test("resolves Python relative module imports", async (t) => {
  const dir = await project(t, { "pkg/main.py": "from . import helper\n", "pkg/helper.py": "ANSWER = 42\n" });
  const result = await inspectCommand("python pkg/main.py", dir);
  assert.ok(result.files.some((f) => f.path === join(dir, "pkg/helper.py")));
});

test("keeps quoted filenames, option paths, bare existing targets and output paths", async (t) => {
  const dir = await project(t, { "my script.py": "pass\n", "README": "data\n" });
  const result = await inspectCommand("python 'my script.py' --config=config/app.json README > output.txt", dir);
  for (const path of ["my script.py", "config/app.json", "README", "output.txt"]) {
    assert.ok(result.paths.some((p) => p.path === join(dir, path)), path);
  }
});

test("resolves a static cd once, not twice", async (t) => {
  const dir = await project(t, { "sub/run.py": "pass\n" });
  const result = await inspectCommand("cd sub && python run.py", dir);
  assert.equal(result.files[0].path, join(dir, "sub/run.py"));
  assert.ok(!result.paths.some((p) => p.path.includes("/sub/sub")));
});

test("does not invent concrete paths for variables and globs", async (t) => {
  const dir = await project(t, {});
  const result = await inspectCommand('python "$SCRIPT" --output "$OUT/result.json" ./data/*.json', dir);
  assert.equal(result.files.length, 0);
  assert.ok(result.paths.some((p) => p.path === "$SCRIPT" && p.unresolved));
  assert.ok(result.paths.some((p) => p.path === "$OUT/result.json" && p.unresolved));
  assert.match(result.notes.join("\n"), /could not be resolved/);
});

test("missing, oversized, binary and non-regular scripts are explicit limitations", async (t) => {
  const dir = await project(t, { "large.py": "#".repeat(INSPECTION_LIMITS.bytes + 1), "binary.py": Buffer.from([0, 1, 2]) });
  for (const script of ["missing.py", "large.py", "binary.py", "."]) {
    const result = await inspectCommand(`python ${script}`, dir);
    assert.equal(result.files.length, 0);
    assert.match(result.notes.join("\n"), /not inspected/);
  }
});

test("code depth and file budgets are bounded and disclose omissions", async (t) => {
  const files = {};
  for (let i = 0; i < 8; i++) files[`s${i}.sh`] = `source ./s${i + 1}.sh\n`;
  const dir = await project(t, files);
  const result = await inspectCommand("bash s0.sh", dir);
  assert.ok(result.files.length <= INSPECTION_LIMITS.depth + 1);
  assert.match(result.notes.join("\n"), /limit reached/);
});

test("path display budget discloses incomplete lists", async (t) => {
  const dir = await project(t, {});
  const result = await inspectCommand("rm -r " + Array.from({ length: 300 }, (_, i) => `./build/f${i}.txt`).join(" "), dir);
  assert.ok(result.paths.length <= INSPECTION_LIMITS.paths);
  assert.match(result.notes.join("\n"), /path list is incomplete/);
});

test("freshness rejects changed main scripts, dependencies, and newly created missing modules", async (t) => {
  const dir = await project(t, { "main.py": "import helper\n", "helper.py": "VALUE = 1\n" });
  let result = await inspectCommand("python main.py", dir);
  assert.equal(await inspectionIsFresh(result), true);
  await writeFile(join(dir, "helper.py"), "VALUE = 2\n");
  assert.equal(await inspectionIsFresh(result), false);
  result = await inspectCommand("python main.py", dir);
  await writeFile(join(dir, "main.py"), "from .missing import value\n");
  assert.equal(await inspectionIsFresh(result), false);
  result = await inspectCommand("python main.py", dir);
  await writeFile(join(dir, "missing.py"), "value = 3\n");
  assert.equal(await inspectionIsFresh(result), false);
});

test("known secret files and symlinks to them are not sent as source", async (t) => {
  const dir = await project(t, { ".env": "SECRET=value", "main.py": "pass\n" });
  await symlink(join(dir, ".env"), join(dir, "alias.py"));
  for (const script of [".env", "alias.py"]) {
    const result = await inspectCommand(`python ${script}`, dir);
    assert.equal(result.files.length, 0);
    assert.match(result.notes.join("\n"), /Potential secret/);
    assert.doesNotMatch(inspectionPrompt(result), /SECRET=value/);
  }
});

test("inline code imports local modules without treating code text as an invoked filename", async (t) => {
  const dir = await project(t, { "helper.py": "VALUE = 1\n" });
  const result = await inspectCommand("python -c 'import helper\nprint(helper.VALUE)'", dir);
  assert.deepEqual(result.files.map((f) => f.path), [join(dir, "helper.py")]);
});

test("directory compression preserves each full path through directory plus filename", () => {
  const groups = groupPaths([
    { path: "/project/scripts/a.py", role: "script" },
    { path: "/project/scripts/b.py", role: "dependency" },
    { path: "$OUT/result.json", role: "output", unresolved: true },
  ]);
  assert.equal(groups[0].directory, "/project/scripts");
  assert.deepEqual(groups[0].files.map((f) => f.name), ["a.py", "b.py"]);
  assert.equal(groups[1].directory, "Unresolved paths");
});

test("interpreters and direct scripts need assessment, ordinary reads do not", () => {
  for (const command of ["python main.py", "uv run python -c 'print(1)'", "node -e 'console.log(1)'", "bash run.sh", "./run", "source helpers.sh"]) assert.ok(codeReviewReasons(command).length, command);
  for (const command of ["cat main.py", "echo python", "git status", "uv run pytest"]) assert.deepEqual(codeReviewReasons(command), [], command);
});

test("common launcher options do not hide script code", async (t) => {
  const dir = await project(t, { "main.py": "pass\n" });
  for (const command of ["/usr/bin/env python main.py", "env -u HOME python main.py", "uv run --group dev python main.py", "timeout 5 python main.py", "env -S \"python main.py\""]) {
    assert.ok(codeReviewReasons(command).length, command);
    const result = await inspectCommand(command, dir);
    assert.ok(result.files.some((f) => f.path === join(dir, "main.py")), command);
  }
});

test("from-package imports include the package initializer and the local submodule", async (t) => {
  const dir = await project(t, { "main.py": "from pkg import helper\n", "pkg/__init__.py": "pass\n", "pkg/helper.py": "VALUE = 1\n" });
  const result = await inspectCommand("python main.py", dir);
  for (const file of ["main.py", "pkg/__init__.py", "pkg/helper.py"]) assert.ok(result.files.some((f) => f.path === join(dir, file)), file);
});

test("file-count limits disclose omitted scripts without returning partial source", async (t) => {
  const files = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`f${i}.py`, `VALUE = ${i}\n`]));
  const dir = await project(t, files);
  const result = await inspectCommand(Object.keys(files).map((f) => `python ${f}`).join("; "), dir);
  assert.equal(result.files.length, INSPECTION_LIMITS.files);
  assert.match(result.notes.join("\n"), /limit reached/);
});

test("a FIFO script cannot block the inspection worker", async (t) => {
  if (process.platform === "win32") return t.skip("mkfifo requires a POSIX host");
  const dir = await project(t, {});
  const fifo = spawnSync("mkfifo", [join(dir, "blocked.py")]);
  assert.equal(fifo.status, 0);
  const module = new URL("../extensions/command-inspection.mjs", import.meta.url).href;
  const child = spawnSync(process.execPath, ["--input-type=module", "-e", `import {inspectCommand} from ${JSON.stringify(module)}; console.log(JSON.stringify(await inspectCommand("python blocked.py", ${JSON.stringify(dir)})));`], { timeout: 3000, encoding: "utf8" });
  assert.equal(child.error, undefined, "inspection must not hang while opening a named pipe");
  assert.equal(child.status, 0);
  const result = JSON.parse(child.stdout);
  assert.equal(result.files.length, 0);
  assert.match(result.notes.join("\n"), /not a regular file/);
});

test("path-bearing options and file API literals include extensionless names", async (t) => {
  const dir = await project(t, { "main.py": 'from pathlib import Path\nPath("README").read_text()\n' });
  const result = await inspectCommand("python main.py --config CONFIG --input=DATA --output REPORT", dir);
  for (const name of ["CONFIG", "DATA", "REPORT", "README"]) assert.ok(result.paths.some((p) => p.path === join(dir, name)), name);
});

test("long unresolved dependencies cannot create unbounded approval metadata", async (t) => {
  const dir = await project(t, { "main.py": "from ." + "x".repeat(20000) + " import value\n" });
  const result = await inspectCommand("python main.py", dir);
  assert.match(result.notes.join("\n"), /note shortened/);
  assert.ok(Buffer.byteLength(JSON.stringify({ paths: result.paths, pathNotes: result.notes })) < 16 * 1024);
  assert.ok(result.files[0].content.length > 20000, "code itself must not be silently truncated");
});
