import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, chmod, readFile, realpath, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { evaluateWithDcg, parseDcgSettings, DEFAULT_DCG_SETTINGS, DCG_ENFORCEMENT_BLOCKER } from "../extensions/dcg.ts";

// Oracles: section 4 mandates failure != allow, exact input, bounded subprocesses;
// v0.15.3 cli.rs TestOutput (schema 1) and EXIT_DENIED=1 define protocol.
// Falsifiers: actual children emit malformed/mismatched frames, override verdicts,
// leak pipes, hang, change binary bytes, and record argv/stdin (not execution).
const root = await realpath(await mkdtemp(join(tmpdir(), "gate-dcg-test-")));
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
let serial = 0;
async function fake(body = "") {
  const path = join(root, `fake-${serial++}`);
  const record = `${path}.record`;
  const source = `#!${process.execPath}
const fs=require('node:fs');const wire=fs.readFileSync(0,'utf8');
const command=wire.endsWith('\\n')?wire.slice(0,-1):wire;
fs.writeFileSync(${JSON.stringify(record)},JSON.stringify({command,wire,argv:process.argv.slice(2),env:process.env,cwd:process.cwd(),pid:process.pid}));
let frame={schema_version:1,dcg_version:'0.15.3',robot_mode:true,command,decision:'allow',agent:{detected:'pi',trust_level:'low',detection_method:'explicit'}};
let code=0;
${body}
if(frame!==null)process.stdout.write(JSON.stringify(frame));process.exitCode=code;
`;
  await writeFile(path, source, { mode: 0o700 });
  return { settings: { mode: "observe", binaryPath: path, sha256: hash(source) }, record, path };
}
async function run(body, command = "git status") {
  const f = await fake(body);
  return evaluateWithDcg(command, root, f.settings);
}
const deny = `Object.assign(frame,{decision:'deny',mode:'deny',rule_id:'core.git:reset-hard',pack_id:'core.git',pattern_name:'reset-hard',reason:'Discards work',source:'pack',severity:'critical',matched_span:[0,3]});code=1;`;

test("settings are opt-in and preserve invalid enabled configuration for visible failure", () => {
  for (const v of [undefined, { mode: "off" }]) assert.deepEqual(parseDcgSettings(v), DEFAULT_DCG_SETTINGS);
  for (const v of [null, [], "enforce", {}, { mode: "junk" }]) assert.deepEqual(parseDcgSettings(v), { mode: "enforce" });
  assert.deepEqual(parseDcgSettings({ mode: "enforce", binaryPath: "relative", sha256: "ABC", extra: true }), { mode: "enforce", binaryPath: "relative", sha256: "abc" });
});
test("enforce never claims unverified isolation; off launches nothing", async () => {
  const f = await fake();
  assert.deepEqual(await evaluateWithDcg("git status", root, { ...f.settings, mode: "enforce" }), { status: "incomplete", reason: DCG_ENFORCEMENT_BLOCKER });
  assert.equal((await evaluateWithDcg("git status", root, { mode: "off" })).status, "incomplete");
  await assert.rejects(readFile(f.record));
});
test("full UTF8 bytes are stdin only; public API, real cwd, scrubbed overrides", async () => {
  const f = await fake();
  const keys = ["DCG_BYPASS", "DCG_CONFIG", "DCG_DISABLE", "DCG_AGENT", "DCG_POLICY_DEFAULT_MODE", "DCG_HISTORY_ENABLED", "NODE_OPTIONS"];
  const old = keys.map(k => process.env[k]);
  keys.forEach(k => process.env[k] = "malicious");
  try {
    const command = "echo '文'; git reset --hard; $(touch NEVER_EXECUTED)";
    assert.equal((await evaluateWithDcg(command, root, f.settings)).status, "complete");
    const r = JSON.parse(await readFile(f.record, "utf8"));
    assert.equal(r.command, command); assert.equal(r.cwd, root);
    assert.ok(!r.argv.includes(command));
    assert.deepEqual(r.argv.slice(0, 10), ["--robot", "--agent", "pi", "test", "--stdin", "--format", "json", "--dialect", "posix", "--config"]);
    assert.ok(!r.argv.some(a => a.includes("omp")));
    for (const k of keys.filter(k => k !== "DCG_HISTORY_ENABLED")) assert.equal(r.env[k], undefined);
    assert.equal(r.env.DCG_HISTORY_ENABLED, "false"); assert.equal(r.env.DCG_HISTORY_DISABLED, "1");
    await assert.rejects(readFile(join(root, "NEVER_EXECUTED")));
  } finally { keys.forEach((k,i) => old[i] === undefined ? delete process.env[k] : process.env[k] = old[i]); }
});
test("stdin framing preserves original terminal newlines", async () => {
  for (const command of ["git status", "git status\n", "git status\n\n"]) {
    const f = await fake();
    assert.equal((await evaluateWithDcg(command, root, f.settings)).status, "complete");
    const recorded = JSON.parse(await readFile(f.record, "utf8"));
    assert.equal(recorded.command, command);
    assert.equal(recorded.wire, command.endsWith("\n") ? command + "\n" : command);
  }
});

test("deny and ask findings require humans; critical severity is not itself catastrophic", async () => {
  const r = await run(deny);
  assert.equal(r.decision, "deny"); assert.equal(r.findings[0].enforcement, "human-required"); assert.equal(r.findings[0].source, "dcg");
  assert.equal((await run(deny + "frame.decision=frame.mode='ask';")).decision, "ask");
  assert.equal((await run(deny + "frame.pack_id='core.filesystem';frame.pattern_name='rm-rf-root-home';frame.rule_id='core.filesystem:rm-rf-root-home';")).findings[0].enforcement, "hard-block");
});
for (const [name, mutation] of [
  ["malformed JSON", "frame=null;process.stdout.write('{');"],
  ["extra JSON", "process.stdout.write('{}');"],
  ["schema", "frame.schema_version=2;"], ["version", "frame.dcg_version='0.15.4';"],
  ["robot", "frame.robot_mode=false;"], ["command identity", "frame.command+='x';"],
  ["unknown field", "frame.unexpected=true;"], ["profile fallback", "frame.agent.trust_level='medium';"],
  ["allowlist override", "frame.allowlist={layer:'user',reason:'bypass'};"],
  ["warn", "frame.decision='warn';"], ["log", "frame.decision='log';"],
  ["indeterminate", "frame.decision='indeterminate';code=1;"],
  ["allow exit 1", "code=1;"], ["deny exit 0", deny + "code=0;"],
  ["unknown exit", "code=3;"], ["unexpected stderr", "process.stderr.write('config fallback');"],
  ["allow finding", "frame.rule_id='core.git:reset-hard';"],
  ["finding identity", deny + "frame.rule_id='core.git:other';"],
  ["finding severity", deny + "frame.severity='extreme';"],
  ["finding policy", deny + "frame.mode='log';"],
  ["finding span", deny + "frame.matched_span=[0,99999];"],
  ["signal", "process.kill(process.pid,'SIGTERM');"],
]) test(`protocol refuses ${name}`, async () => assert.equal((await run(mutation)).status, "incomplete"));
test("stdout and stderr are byte-bounded", async () => {
  assert.match((await run("frame=null;process.stdout.write(Buffer.alloc(8*1024*1024+1));")).reason, /stdout exceeds/);
  assert.match((await run("frame=null;process.stderr.write(Buffer.alloc(64*1024+1));")).reason, /stderr exceeds/);
});
test("input boundary preserves complete 1MiB, rejects oversize and lossy UTF8", async () => {
  const f = await fake();
  assert.equal((await evaluateWithDcg("x".repeat(1024*1024), root, f.settings)).status, "complete");
  assert.match((await evaluateWithDcg("x".repeat(1024*1024+1), root, f.settings)).reason, /1 MiB/);
  assert.match((await evaluateWithDcg("\ud800", root, f.settings)).reason, /UTF-8/);
});
test("binary is rehashed every call, requires absolute regular trusted path", async () => {
  const f = await fake();
  assert.equal((await evaluateWithDcg("git status", root, f.settings)).status, "complete");
  await writeFile(f.path, "changed");
  assert.match((await evaluateWithDcg("git status", root, f.settings)).reason, /SHA256 mismatch/);
  assert.match((await evaluateWithDcg("git status", root, { ...f.settings, binaryPath: "dcg" })).reason, /absolute/);
  assert.equal((await evaluateWithDcg("git status", root, { ...f.settings, binaryPath: join(root, "missing") })).status, "incomplete");
  await chmod(f.path, 0o777);
  assert.match((await evaluateWithDcg("git status", root, f.settings)).reason, /group\/others/);
});
test("cancellation during setup or analyzer never yields allow", async () => {
  const f = await fake("frame=null;setInterval(()=>{},1000);");
  const before = new AbortController(); before.abort();
  assert.match((await evaluateWithDcg("git status", root, f.settings, before.signal)).reason, /cancelled/);
  const during = new AbortController(); const pending = evaluateWithDcg("git status", root, f.settings, during.signal);
  setTimeout(() => during.abort(), 50);
  assert.match((await pending).reason, /cancelled/);
});
test("5 second deadline kills direct analyzer", async () => {
  const f = await fake("frame=null;setInterval(()=>{},1000);");
  const start = Date.now();
  assert.match((await evaluateWithDcg("git status", root, f.settings)).reason, /deadline/);
  assert.ok(Date.now()-start < 6000);
  const { pid } = JSON.parse(await readFile(f.record, "utf8"));
  await new Promise(resolve => setTimeout(resolve, 100));
  assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
});
test("descendant-held stdout has bounded drain after direct child exit", async () => {
  const start = Date.now();
  const r = await run(`require('node:child_process').spawn(process.execPath,['-e','setTimeout(()=>{},1000)'],{stdio:['ignore',1,2]}).unref();`);
  assert.match(r.reason, /stream drain/); assert.ok(Date.now()-start < 900);
});

test("managed config fault injection rejects missing, malformed, relaxing, replaced and unreadable paths before spawn", async () => {
  const source = await readFile(new URL("../extensions/dcg.ts", import.meta.url), "utf8");
  const f = await fake();
  for (const [name, content] of [["missing", null], ["malformed", "[ broken"], ["relaxing", '[policy]\\ndefault_mode="log"'], ["replaced", ""], ["nonregular", "directory"], ["unreadable", "valid-policy"]]) {
    const dir = join(root, `policy-${name}`); await mkdir(dir);
    const adapter = join(dir, "dcg.ts"); await writeFile(adapter, source);
    const policy = join(dir, "dcg-policy.toml");
    if (content === "directory") await mkdir(policy);
    else if (content !== null) {
      await writeFile(policy, content === "valid-policy" ? await readFile(new URL("../extensions/dcg-policy.toml", import.meta.url)) : content);
      if (name === "unreadable") await chmod(policy, 0o000);
    }
    const isolated = await import(pathToFileURL(adapter).href);
    const result = await isolated.evaluateWithDcg("git status", root, f.settings);
    assert.equal(result.status, "incomplete", name);
    await assert.rejects(readFile(f.record));
  }
});

// Opt-in real release: download archive + GitHub checksum to a temporary directory,
// verify archive hash before extraction; provide extracted binary hash explicitly.
// Verified v0.15.3 aarch64-apple-darwin archive SHA256 (GitHub sidecar):
// 50a1a50762299c7e4b5ebaf3f932f45066c8e7c86a1d5d419b01babd1e2698d7
// Extracted dcg SHA256: deaffef19ab002d7c499479f3b83c5b6cf9d297d2c2c1096b835349c2e31aff8
// No PATH lookup/global installation/network occurs in this test suite.
const realBinary = process.env.DCG_TEST_BINARY;
const realHash = process.env.DCG_TEST_SHA256;
const realSettings = { mode: "observe", binaryPath: realBinary, sha256: realHash };
const real = { skip: !realBinary || !realHash };
const corpus = [
  ["core.git", "git reset --hard", "git status"],
  ["core.filesystem", "rm -rf /", "ls /"],
  ["system.disk", "mkfs.ext4 /dev/sda", "lsblk"],
  ["remote.rsync", "rsync --delete source/ dest/", "rsync --dry-run --delete source/ dest/"],
  ["storage.s3", "aws s3 rm s3://bucket --recursive", "aws s3 ls s3://bucket"],
  ["storage.gcs", "gsutil rm -r gs://bucket", "gsutil ls gs://bucket"],
  ["database.postgresql", "dropdb shared", "psql -c 'SELECT 1'"],
  ["database.mysql", "mysql -e 'DROP DATABASE shared'", "mysql -e 'SELECT 1'"],
  ["database.sqlite", "sqlite3 state.db 'DROP TABLE users'", "sqlite3 state.db 'SELECT 1'"],
  ["database.mongodb", "mongosh --eval 'db.dropDatabase()'", "mongosh --eval 'db.users.find()'"],
  ["database.redis", "redis-cli FLUSHALL", "redis-cli GET example"],
  ["database.snowflake", "snowsql -q 'DROP DATABASE shared'", "snowsql -q 'SELECT 1'"],
  ["database.bigquery", "bq query 'DROP TABLE dataset.users'", "bq query 'SELECT 1'"],
  ["database.supabase", "supabase db reset", "supabase status"],
  ["containers.docker", "docker volume rm state", "docker volume ls"],
  ["containers.compose", "docker compose down --volumes", "docker compose ps"],
  ["containers.podman", "podman volume rm state", "podman volume ls"],
  ["infrastructure.terraform", "terraform state rm aws_instance.example", "terraform state list"],
  ["infrastructure.pulumi", "pulumi destroy", "pulumi stack ls"],
  ["kubernetes.kubectl", "kubectl delete namespace shared", "kubectl get namespaces"],
  ["kubernetes.helm", "helm uninstall shared", "helm list"],
  ["cloud.aws", "aws ec2 terminate-instances --instance-ids i-example", "aws ec2 describe-instances"],
  ["cloud.gcp", "gcloud compute instances delete shared", "gcloud compute instances list"],
  ["cloud.azure", "az group delete --name shared", "az group list"],
];
test("real pinned release: every policy leaf exists", real, async () => {
  assert.equal(hash(await readFile(realBinary)), realHash);
  const r = spawnSync(realBinary, ["--robot", "packs", "--format", "json"], { encoding: "utf8", timeout: 5000 });
  assert.equal(r.status, 0);
  const ids = new Set(JSON.parse(r.stdout).packs.map(p => p.id));
  const policy = await readFile(new URL("../extensions/dcg-policy.toml", import.meta.url), "utf8");
  const leaves = [...policy.matchAll(/"([a-z]+\.[a-z0-9]+)"/g)].map(m => m[1]);
  assert.deepEqual(leaves.sort(), corpus.map(([id]) => id).sort());
  for (const id of leaves) assert.ok(ids.has(id), id);
});
for (const [id, dangerous, safe] of corpus) test(`real release ${id}: destructive/safe neighbor`, real, async () => {
  const d = await evaluateWithDcg(dangerous, root, realSettings);
  assert.equal(d.status, "complete", JSON.stringify(d)); assert.equal(d.decision, "deny", dangerous);
  assert.ok(d.findings[0].ruleId.startsWith(`${id}:`), JSON.stringify(d));
  const s = await evaluateWithDcg(safe, root, realSettings);
  assert.equal(s.status, "complete", JSON.stringify(s)); assert.equal(s.decision, "allow", safe);
});
test("real release: embedded executable vs quoted data, lossless stdin newline handling", real, async () => {
  const embedded = "python -c 'import shutil; shutil.rmtree(\"/home/user/work\")'";
  assert.equal((await evaluateWithDcg(embedded, root, realSettings)).decision, "deny");
  const heredoc = "python <<'PY'\nimport shutil\nshutil.rmtree('/home/user/work')\nPY";
  assert.equal((await evaluateWithDcg(heredoc, root, realSettings)).decision, "deny");
  assert.equal((await evaluateWithDcg("sh -c 'git reset --hard'", root, realSettings)).decision, "deny");
  assert.equal((await evaluateWithDcg("echo 'git reset --hard'", root, realSettings)).decision, "allow");
  assert.equal((await evaluateWithDcg("git status\n", root, realSettings)).decision, "allow");
  assert.equal((await evaluateWithDcg("git status\n\n", root, realSettings)).decision, "allow");
});
test("real release resolves relative SQL input in the command cwd, never executes it", real, async () => {
  await writeFile(join(root, "relative.sql"), "DROP TABLE users;");
  const d = await evaluateWithDcg("psql < relative.sql", root, realSettings);
  assert.equal(d.decision, "deny"); assert.equal(d.findings[0].ruleId, "database.postgresql:drop-table");
  await writeFile(join(root, "relative.sql"), "SELECT 1;");
  assert.equal((await evaluateWithDcg("psql < relative.sql", root, realSettings)).decision, "allow");
  assert.equal(await readFile(join(root, "relative.sql"), "utf8"), "SELECT 1;");
});
test("real release: ambient relaxing config/allowlists do not justify enforce", real, async () => {
  const project = join(root, "ambient-project"); await mkdir(join(project, ".dcg"), { recursive: true });
  await writeFile(join(project, ".dcg.toml"), '[policy]\ndefault_mode="log"\n[packs]\ndisabled=["core.git"]\n');
  await writeFile(join(project, ".dcg", "allowlist.toml"), '[[allow]]\nrule="core.git:reset-hard"\nreason="injected"\n');
  const userHome = join(root, "ambient-home"); await mkdir(join(userHome, ".config", "dcg"), { recursive: true });
  await writeFile(join(userHome, ".config", "dcg", "allowlist.toml"), '[[allow]]\nrule="core.git:reset-hard"\nreason="injected user grant"\n');
  await writeFile(join(userHome, ".config", "dcg", "config.toml"), '[policy]\ndefault_mode="log"\n[agents.pi]\ndisabled_allowlist=false\n');
  const keys = ["DCG_BYPASS", "HOME", "XDG_CONFIG_HOME"]; const old = keys.map(k => process.env[k]);
  process.env.DCG_BYPASS = "1"; process.env.HOME = userHome; process.env.XDG_CONFIG_HOME = join(userHome, ".config");
  try {
    assert.equal((await evaluateWithDcg("git reset --hard", project, realSettings)).decision, "deny");
    assert.match((await evaluateWithDcg("git status", project, { ...realSettings, mode: "enforce" })).reason, /isolation/);
  } finally { keys.forEach((k,i) => old[i] === undefined ? delete process.env[k] : process.env[k] = old[i]); }
});
test("real release config failure oracle: missing/malformed explicit config falls back", real, async () => {
  const bad = join(root, "malformed.toml"); await writeFile(bad, "[ broken");
  for (const config of [bad, join(root, "missing.toml")]) {
    const r = spawnSync(realBinary, ["--robot", "--agent", "pi", "test", "--stdin", "--config", config], { cwd: root, input: "git status", encoding: "utf8", timeout: 5000 });
    assert.equal(r.status, 0); assert.equal(JSON.parse(r.stdout).decision, "allow");
    assert.match(r.stderr, /Failed to load config/);
  }
});
