import { basename, resolve } from "node:path";

/** Findings are policy inputs, not permissions. This module never executes commands. */
export type SafetyFinding = {
  ruleId: string;
  enforcement: "hard-block" | "human-required" | "context";
  risk: "low" | "medium" | "critical";
  summary: string;
  source: "local" | "dcg";
};

type Word = { value: string; dynamic: boolean };
type Token = Word & { op?: boolean; fd?: boolean };
type Invocation = { words: Word[]; redirects: { op: string; target: Word }[]; pipeInput?: Word[] };
type Analysis = { invocations: Invocation[]; embedded: string[]; incomplete: boolean };
const word = (value: string): Word => ({ value, dynamic: false });
const name = (w: Word | undefined) => w ? basename(w.value) : "";
const MAX_COMMAND_BYTES = 128 * 1024;
const MAX_TOKENS = 4096;

/** A deliberately bounded shell lexer, not a shell grammar or expansion engine. */
function lex(command: string): { tokens: Token[]; embedded: string[]; incomplete: boolean } {
  const tokens: Token[] = [], embedded: string[] = [];
  // Linear brace lookahead: repeated '${' / '{' must not rescan suffixes.
  const braceKinds = new Uint8Array(command.length);
  let close = -1, prompt = -1, expansion = -1;
  for (let i = command.length - 1; i >= 0; i--) {
    if (command[i] === "}") { close = i; prompt = expansion = -1; }
    if (command[i] === "@" && command[i + 1] === "P") prompt = i;
    if (command[i] === "," || (command[i] === "." && command[i + 1] === ".")) expansion = i;
    if (command[i] === "{" && close >= 0) braceKinds[i] = 4 | (prompt > i ? 1 : 0) | (expansion > i ? 2 : 0);
  }
  let value = "", dynamic = false, started = false, quote = "", quoted = false, incomplete = false;
  const flush = () => {
    if (started) tokens.push({ value, dynamic });
    value = ""; dynamic = false; started = false; quoted = false;
  };
  for (let i = 0; i < command.length; i++) {
    if (tokens.length >= MAX_TOKENS) return { tokens: [], embedded: [], incomplete: true };
    const c = command[i];
    if (quote === "'") {
      if (c === "'") quote = ""; else value += c;
      continue;
    }
    if (c === "\\") {
      if (i + 1 === command.length) { incomplete = true; continue; }
      const next = command[++i];
      if (next === "\n") continue;
      started = true; quoted = true;
      if (quote === '"' && !['$', '`', '"', '\\'].includes(next)) value += "\\";
      value += next;
      continue;
    }
    if (c === '"') { started = true; quoted = true; quote = quote === '"' ? "" : '"'; continue; }
    if (!quote && c === "'") { started = true; quoted = true; quote = "'"; continue; }
    // Command substitutions execute even in double-quoted data operands.
    if ((c === "$" && command[i + 1] === "(" && command[i + 2] !== "(") || c === "`") {
      started = true; dynamic = true;
      const begin = i, backtick = c === "`";
      let j = i + (backtick ? 1 : 2), depth = 1, q = "";
      const bodyStart = j;
      for (; j < command.length; j++) {
        const x = command[j];
        if (x === "\\") { j++; continue; }
        if (backtick) { if (x === "`") break; continue; }
        if (q) { if (x === q) q = ""; continue; }
        if (x === "#" && (j === bodyStart || /[\s;&|]/.test(command[j - 1]))) {
          while (j < command.length && command[j] !== "\n") j++;
          continue;
        }
        if (x === "'" || x === '"') { q = x; continue; }
        if (x === "(") depth++;
        if (x === ")" && --depth === 0) break;
      }
      if (j >= command.length) incomplete = true;
      else embedded.push(command.slice(bodyStart, j));
      value += command.slice(begin, Math.min(j + 1, command.length));
      i = j; continue;
    }
    if (c === "$" && command[i + 1] === "{" && !(braceKinds[i + 1] & 4)) incomplete = true;
    if (c === "$" && ((command[i + 1] === "(" && command[i + 2] === "(") || (command[i + 1] === "{" && (braceKinds[i + 1] & 1)))) incomplete = true;
    if (c === "$" || (!quote && (/[*?\[\]]/.test(c) || (c === "~" && !started) || (c === "{" && (braceKinds[i] & 2))))) dynamic = true;
    if (!quote && /\s/.test(c)) {
      flush();
      if (c === "\n") tokens.push({ value: ";", dynamic: false, op: true });
      continue;
    }
    if (!quote && c === "#" && !started) {
      while (i < command.length && command[i] !== "\n") i++;
      tokens.push({ value: ";", dynamic: false, op: true });
      continue;
    }
    if (!quote && /[;&|<>()]/.test(c)) {
      const fd = /[<>]/.test(c) && started && !quoted && /^\d+$/.test(value);
      flush();
      let op = c;
      if (command[i + 1] === c && /[&|<>]/.test(c)) op += command[++i];
      else if (/[<>]/.test(c) && /[&|]/.test(command[i + 1] ?? "")) op += command[++i];
      if (op === "<<" || op === "(" || op === ")") incomplete = true;
      tokens.push({ value: op, dynamic: false, op: true, fd });
      if (op === "<<") break; // No fabricated interpretation of heredoc data as invocations.
      continue;
    }
    started = true; value += c;
  }
  if (quote) incomplete = true;
  flush();
  if (tokens.length > MAX_TOKENS) return { tokens: [], embedded: [], incomplete: true };
  return { tokens, embedded, incomplete };
}

function parse(command: string): Analysis {
  const scanned = lex(command);
  const invocations: Invocation[] = [];
  let current: Invocation = { words: [], redirects: [] };
  const flush = () => { if (current.words.length || current.redirects.length) invocations.push(current); current = { words: [], redirects: [] }; };
  for (let i = 0; i < scanned.tokens.length; i++) {
    const t = scanned.tokens[i];
    if (!t.op) { current.words.push(t); continue; }
    if (/^[<>]/.test(t.value)) {
      const target = scanned.tokens[++i];
      if (!target || target.op) { scanned.incomplete = true; continue; }
      if (t.fd) current.words.pop();
      current.redirects.push({ op: t.value, target });
    } else {
      const previous = current.words;
      flush();
      if (t.value === "|") current.pipeInput = previous;
    }
  }
  flush();
  return { invocations, embedded: scanned.embedded, incomplete: scanned.incomplete };
}

type Options = { flags: Map<string, Word | undefined>; entries: [string, Word | undefined][]; positionals: Word[]; unknown: boolean };
/** Consume option operands before interpreting short clusters or dry-run flags. */
function options(args: Word[], takesValue: string[] = [], shortValues = "", optionalValues: string[] = []): Options {
  const flags = new Map<string, Word | undefined>(), positionals: Word[] = [], entries: [string, Word | undefined][] = [];
  const set = (key: string, value?: Word) => { flags.set(key, value); entries.push([key, value]); };
  let end = false, unknown = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i], s = a.value;
    if (end || s === "-" || !s.startsWith("-")) { positionals.push(a); continue; }
    if (s === "--") { end = true; continue; }
    if (s.startsWith("--")) {
      const eq = s.indexOf("="), key = eq < 0 ? s : s.slice(0, eq);
      let operand: Word | undefined;
      if (eq >= 0) operand = { value: s.slice(eq + 1), dynamic: a.dynamic };
      else if (takesValue.includes(key)) operand = args[++i];
      set(key, operand);
      if (takesValue.includes(key) && !operand) unknown = true;
    } else {
      for (let j = 1; j < s.length; j++) {
        const key = s[j];
        if (shortValues.includes(key) || optionalValues.includes(`-${key}`)) {
          const operand = j + 1 < s.length ? { value: s.slice(j + 1), dynamic: a.dynamic } : optionalValues.includes(`-${key}`) ? undefined : args[++i];
          set(`-${key}`, operand);
          if (!operand && !optionalValues.includes(`-${key}`)) unknown = true;
          break;
        }
        set(`-${key}`);
      }
    }
    if (a.dynamic) unknown = true;
  }
  return { flags, entries, positionals, unknown };
}
const has = (o: Options, ...keys: string[]) => keys.some(k => o.flags.has(k));
const operand = (o: Options, ...keys: string[]) => o.entries.findLast(([k, v]) => keys.includes(k) && v !== undefined)?.[1];

function unwrap(input: Word[]): { words: Word[]; incomplete: boolean } {
  let words = input.slice(), incomplete = false;
  for (let depth = 0; depth < 12; depth++) {
    while (/^[A-Za-z_]\w*=/.test(words[0]?.value ?? "")) words.shift();
    const cmd = name(words[0]);
    if (["command", "builtin", "exec", "nohup", "rtk", "busybox", "toybox"].includes(cmd)) {
      words.shift();
      if (cmd === "rtk" && words[0]?.value === "proxy") words.shift();
      while (words[0]?.value.startsWith("-")) {
        const s = words.shift()!.value;
        if (s === "--") break;
        if (cmd === "command" && ["-v", "-V"].includes(s)) return { words: [word("true")], incomplete };
        if (!["-p", "--verbose"].includes(s)) incomplete = true;
      }
      continue;
    }
    if (cmd === "env" || cmd === "sudo" || cmd === "nice" || cmd === "timeout") {
      words.shift();
      while (words.length) {
        const s = words[0].value;
        if (s === "--") { words.shift(); break; }
        if (cmd === "env" && /^[A-Za-z_]\w*=/.test(s)) { words.shift(); continue; }
        if (!s.startsWith("-")) break;
        words.shift();
        if (cmd === "env" && (s.startsWith("--split-string=") || (s.startsWith("-S") && s.length > 2))) {
          const split = s.startsWith("--") ? s.slice(s.indexOf("=") + 1) : s.slice(2);
          incomplete = true;
          words.unshift(...lex(split).tokens.filter(t => !t.op));
          break;
        }
        const values = cmd === "env" ? ["-u", "--unset", "-C", "--chdir", "-S", "--split-string", "-a", "--argv0"] : cmd === "sudo" ? ["-u", "-g", "-h", "-p", "-C", "-D", "--user", "--group", "--chdir"] : cmd === "nice" ? ["-n", "--adjustment"] : ["-k", "--kill-after", "-s", "--signal"];
        if (values.includes(s)) {
          const v = words.shift();
          if (!v || ["-C", "--chdir", "-D"].includes(s)) incomplete = true;
          if (cmd === "env" && ["-S", "--split-string"].includes(s)) {
            incomplete = true;
            if (v) words.unshift(...lex(v.value).tokens.filter(t => !t.op));
          }
        } else if (!(s.includes("=") || ["-i", "--ignore-environment", "-n", "-E", "-H", "-b", "--preserve-status", "--foreground", "-v"].includes(s) || /^-\d+$/.test(s))) incomplete = true;
      }
      if (cmd === "timeout") words.shift(); // duration
      continue;
    }
    return { words, incomplete };
  }
  return { words, incomplete: true };
}

function gitArgs(words: Word[]): { args: Word[]; incomplete: boolean; configs: Word[] } {
  let i = 1, incomplete = false;
  const configs: Word[] = [];
  const config = (key: string, v: Word | undefined) => {
    if ((key === "-c" || key === "--config-env") && v) configs.push({ ...v, dynamic: v.dynamic || key === "--config-env" });
  };
  const values = ["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--super-prefix", "--attr-source"];
  const booleans = ["--bare", "--no-pager", "--paginate", "-p", "-P", "--no-replace-objects", "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs", "--no-optional-locks", "--no-lazy-fetch", "--no-advice"];
  while (i < words.length && words[i].value.startsWith("-")) {
    const s = words[i++].value;
    if (s === "--") break;
    if (["--version", "-v", "--help", "-h"].includes(s)) return { args: [], incomplete, configs };
    if (values.includes(s)) {
      const v = words[i++];
      if (!v) incomplete = true;
      config(s, v);
    } else if (values.some(v => s.startsWith(v + "=") || (v.length === 2 && s.startsWith(v) && s.length > 2))) {
      const key = values.find(v => s.startsWith(v + "=") || (v.length === 2 && s.startsWith(v)))!;
      config(key, { value: s.slice(key.length + (s[key.length] === "=" ? 1 : 0)), dynamic: words[i - 1].dynamic });
    }
    else if (!booleans.includes(s)) incomplete = true;
  }
  return { args: words.slice(i), incomplete, configs };
}

const protectedBranches = new Set(["main", "master", "production", "prod"]);
const shells = /^(?:ba|da|z|k|fi|c|tc)?sh$/;
const interpreters = /^(?:python[\d.]*|node|bun|deno|perl|ruby|php|lua)$/;
const controls = new Set(["if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "function", "{", "}", "!", "eval", "source", ".", "alias", "trap"]);

function gitFindings(args: Word[], add: Add): void {
  const sub = args[0];
  if (!sub) return;
  if (sub.dynamic) { add("shell.incomplete", "human-required", "medium", "Dynamic Git operation needs human review"); return; }
  const rest = args.slice(1);
  const o = options(rest, ["--source", "--pathspec-from-file", "--exclude", "--repo", "--receive-pack", "--exec", "--push-option", "--message"], sub.value === "push" ? "o" : sub.value === "clean" ? "e" : sub.value === "restore" ? "s" : sub.value === "stash" ? "m" : sub.value === "checkout" ? "bB" : sub.value === "switch" ? "cC" : "");
  const known: Record<string, string[]> = {
    reset: ["--soft", "--mixed", "--hard", "--merge", "--keep", "--recurse-submodules", "--no-recurse-submodules", "--pathspec-from-file", "--pathspec-file-nul", "--quiet", "-q", "--patch", "-p", "--no-refresh", "-N", "--intent-to-add"],
    clean: ["-d", "-f", "-i", "-n", "-q", "-e", "-x", "-X", "--force", "--interactive", "--dry-run", "--quiet", "--exclude"],
    stash: ["-m", "--message", "-q", "--quiet", "-u", "--include-untracked", "-a", "--all", "-p", "--patch", "-k", "--keep-index", "--no-keep-index", "-S", "--staged", "--index", "--pathspec-from-file", "--pathspec-file-nul"],
    restore: ["-s", "--source", "-S", "--staged", "-W", "--worktree", "--ours", "--theirs", "--merge", "-m", "--conflict", "--patch", "-p", "--quiet", "-q", "--progress", "--no-progress", "--ignore-unmerged", "--overlay", "--no-overlay", "--ignore-skip-worktree-bits", "--recurse-submodules", "--no-recurse-submodules", "--pathspec-from-file", "--pathspec-file-nul"],
    push: ["-f", "--force", "--no-force", "--force-with-lease", "--no-force-with-lease", "--force-if-includes", "--no-force-if-includes", "--mirror", "--no-mirror", "--all", "--branches", "--tags", "--follow-tags", "--matching", "--delete", "-d", "-u", "--set-upstream", "--repo", "--receive-pack", "--exec", "--push-option", "-o", "--dry-run", "-n", "--porcelain", "--atomic", "--no-atomic", "--signed", "--no-signed", "--recurse-submodules", "--no-recurse-submodules", "--thin", "--no-thin", "--quiet", "-q", "--verbose", "-v", "--progress", "--ipv4", "-4", "--ipv6", "-6", "--no-verify", "--verify", "--prune"],
  };
  if (known[sub.value] && !(sub.value === "stash" && ["list", "show", "push", "create", "store", "branch", "apply", "pop"].includes(o.positionals[0]?.value)) && [...o.flags.keys()].some(k => !known[sub.value].includes(k))) o.unknown = true;
  if (sub.value !== "push" && rest.some(w => w.dynamic)) add("shell.incomplete", "human-required", "medium", "Dynamic Git arguments cannot establish a safe operation");
  if (o.unknown) add("shell.incomplete", "human-required", "medium", "Unresolved Git options need review");
  if (sub.value === "stash" && ["drop", "clear"].includes(o.positionals[0]?.value)) add("git.stash-destruction", "human-required", "medium", "Discard saved stash work");
  if (sub.value === "reset" && has(o, "--hard")) add("git.reset-hard", "human-required", "medium", "Discard working-tree changes with hard reset");
  if (sub.value === "clean" && has(o, "-f", "--force") && !has(o, "-n", "--dry-run")) add("git.clean", "human-required", "medium", "Delete untracked files with forced clean");
  const separator = rest.findIndex(w => w.value === "--");
  if (sub.value === "checkout" && ((separator >= 0 && separator + 1 < rest.length) || has(o, "-f", "--force", "--pathspec-from-file") || (!has(o, "-b", "-B", "--orphan") && o.positionals.length >= 2))) add("git.working-tree-discard", "human-required", "medium", "Checkout replaces working files");
  // -B resets a branch reference, but like -b does NOT itself force dirty-file loss.
  if (sub.value === "switch" && has(o, "-f", "--force", "--discard-changes")) add("git.working-tree-discard", "human-required", "medium", "Switch discards working-file changes");
  if (sub.value === "restore" && (!has(o, "-S", "--staged") || has(o, "-W", "--worktree"))) add("git.working-tree-discard", "human-required", "medium", "Restore discards working-file changes");
  if (sub.value === "rm" && !has(o, "--cached", "-n", "--dry-run")) add("file.delete", "human-required", "medium", "Git removes working files");
  if (sub.value !== "push") return;
  const enabled = (positive: string[], negative: string) => {
    let active = false;
    for (const [key] of o.entries) {
      if (positive.includes(key)) active = true;
      if (key === negative) active = false;
    }
    return active;
  };
  // --force-if-includes alone is documented as a no-op, not a force flag.
  let blanketLease = false;
  const leases: Word[] = [];
  for (const [key, value] of o.entries) {
    if (key === "--no-force-with-lease") { blanketLease = false; leases.length = 0; }
    if (key === "--force-with-lease") {
      if (value) leases.push({ value: value.value.split(":")[0], dynamic: value.dynamic });
      else blanketLease = true;
    }
  }
  const allForced = enabled(["--force", "-f"], "--no-force") || blanketLease || enabled(["--mirror"], "--no-mirror");
  // builtin/push.c assigns argv[0] to repo even when --repo was supplied.
  // That positional repository overrides --repo; it is NEVER itself a refspec.
  const refs = o.positionals.slice(1);
  const forced = refs.filter(r => {
    const s = r.value.replace(/^\+/, ""), dest = s.includes(":") ? s.slice(s.indexOf(":") + 1) : s;
    const fullDest = dest.startsWith("refs/") ? dest : `refs/heads/${dest}`;
    // remote.c apply_cas uses refs.c refname_match, including abbreviated names.
    return allForced || r.value.startsWith("+") || leases.some(l => l.dynamic || !s.includes(":") || [l.value, `refs/${l.value}`, `refs/tags/${l.value}`, `refs/heads/${l.value}`, `refs/remotes/${l.value}`, `refs/remotes/${l.value}/HEAD`].includes(fullDest));
  });
  if (!allForced && !forced.length && !leases.length) return;
  if (leases.length && !forced.length && refs.length && !o.unknown && !refs.some(r => r.dynamic)) return;
  if (!forced.length || has(o, "--all", "--branches", "--mirror", "--matching", "--tags", "--follow-tags") || o.unknown || o.positionals.some(r => r.dynamic)) {
    add("git.force-push-unresolved", "hard-block", "critical", "Forced push needs an explicit literal destination (no tracking-config inference)");
    return;
  }
  for (const ref of forced) {
    const s = ref.value.replace(/^\+/, "");
    const destination = s.includes(":") ? s.slice(s.indexOf(":") + 1) : s;
    const branch = destination.replace(/^refs\/heads\//, "");
    // HEAD and revision expressions without a destination may be resolved through config.
    if (protectedBranches.has(branch)) {
      add("git.force-push-protected", "hard-block", "critical", `Forced update of protected branch ${branch}`);
    } else if (ref.dynamic || !s.includes(":") || !destination || /[\s*?\[\]$~^{}]/.test(destination)) {
      add("git.force-push-unresolved", "hard-block", "critical", "Forced push destination is dynamic or implicit; supply a literal branch");
    } else add("git.force-push", "context", "medium", `Forced update of explicit destination ${destination}`);
  }
}

type Add = (ruleId: string, enforcement: SafetyFinding["enforcement"], risk: SafetyFinding["risk"], summary: string) => void;

function catastrophicPath(w: Word, cwd: string): boolean {
  if (w.dynamic) return /^(?:~|\$(?:HOME|\{HOME\}))/.test(w.value);
  const p = resolve(cwd, w.value), root = resolve(cwd);
  // A scoped relative project target does not become an OS/home root merely
  // because the checkout is under /Users or /home. Deletion still needs a human.
  if (!w.value.startsWith("/") && (p === root || p.startsWith(root + "/"))) {
    return p === "/" || /^\/(?:Users|home)(?:\/[^/]+)?$/.test(p) || /^\/(?:root|System|Applications|Library|etc|usr|var|bin|sbin|opt|private|Volumes)$/.test(p);
  }
  return p === "/" || /^\/(?:Users|home|root|System|Applications|Library|etc|usr|var|bin|sbin|opt|Volumes)(?:\/|$)/.test(p) || (p.startsWith("/private/") && !p.startsWith("/private/tmp/"));
}

/** SQL strings/comments must not turn quoted documentation into DROP statements. */
function sqlStatements(sql: string): string[] {
  return sql.replace(/--[^\n]*|\/\*[\s\S]*?\*\/|'(?:''|\\.|[^'])*'|"(?:""|[^"])*"|`[^`]*`|\$(\w*)\$[\s\S]*?\$\1\$/g, match => /^(?:--|\/\*)/.test(match) ? " " : " __literal__ ").split(";");
}
/** Extract executable CTE bodies and the final DML, not words inside SELECT data. */
function sqlBodies(s: string, depth = 0): { bodies: string[]; incomplete: boolean } {
  if (!/^\s*WITH\b/i.test(s)) return { bodies: [s], incomplete: false };
  if (depth >= 16) return { bodies: [], incomplete: true };
  const bodies: string[] = [];
  let tail = s.replace(/^\s*WITH\s+(?:RECURSIVE\s+)?/i, ""), incomplete = false;
  while (tail) {
    const header = /^\s*(?:\w+)(?:\s*\([^()]*\))?\s+AS\s+(?:(?:NOT\s+)?MATERIALIZED\s+)?\(/i.exec(tail);
    if (!header) return { bodies, incomplete: true };
    let i = header[0].length, balance = 1;
    const start = i;
    for (; i < tail.length && balance; i++) {
      if (tail[i] === "(") balance++;
      if (tail[i] === ")") balance--;
    }
    if (balance) return { bodies, incomplete: true };
    const nested = sqlBodies(tail.slice(start, i - 1), depth + 1);
    bodies.push(...nested.bodies); incomplete ||= nested.incomplete;
    tail = tail.slice(i).trimStart();
    if (tail.startsWith(",")) { tail = tail.slice(1); continue; }
    if (!/^(?:SELECT|DELETE|UPDATE|INSERT|MERGE)\b/i.test(tail)) return { bodies, incomplete: true };
    bodies.push(tail);
    return { bodies, incomplete };
  }
  return { bodies, incomplete: true };
}
function topLevelSql(s: string): string {
  let depth = 0, result = "";
  for (const c of s) {
    if (c === "(") depth++;
    if (!depth) result += c;
    if (c === ")") depth--;
  }
  return result;
}
function tautologicalWhere(body: string): boolean {
  let predicate = /\bWHERE\b([\s\S]*)/i.exec(body)?.[1]?.replace(/\bRETURNING\b[\s\S]*$/i, "").trim() ?? "";
  for (let i = 0; i < 16 && predicate.startsWith("(") && predicate.endsWith(")"); i++) predicate = predicate.slice(1, -1).trim();
  return /^TRUE$/i.test(predicate) || /^(\d+)\s*=\s*\1$/.test(predicate);
}
function destructiveSql(sql: string): boolean {
  return sqlStatements(sql).some(s => sqlBodies(s).bodies.some(body => /^\s*(?:DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|SEQUENCE|FUNCTION|ROLE|USER)|TRUNCATE\b)/i.test(body) || (/^\s*DELETE\s+FROM\b/i.test(body) && (!/\bWHERE\b/i.test(topLevelSql(body)) || tautologicalWhere(body)))));
}
function complexSql(sql: string): boolean {
  return sqlStatements(sql).some(s => sqlBodies(s).incomplete || /^\s*(?:DO|CALL|EXEC(?:UTE)?|BEGIN|DECLARE|CREATE\s+(?:FUNCTION|PROCEDURE|TRIGGER))\b/i.test(s));
}
function destructiveMongo(body: string): boolean {
  const code = sqlStatements(body).join(";");
  return /\.\s*(?:dropDatabase|dropCollection|drop)\s*\(/.test(code) || /\.\s*deleteMany\s*\(\s*\{\s*\}/.test(code) || /\.\s*remove\s*\(\s*\{\s*\}\s*(?:\)|,\s*false\s*\))/.test(code);
}

function operationFindings(cmd: string, args: Word[], cwd: string, add: Add): void {
  if (args.length === 1 && ["--help", "--version"].includes(args[0].value)) return;
  const human = (id: string, summary: string, critical = false) => add(id, "human-required", critical ? "critical" : "medium", summary);
  if (["rm", "unlink", "shred", "srm"].includes(cmd)) {
    const o = options(args);
    if (o.positionals.length) {
      if ((has(o, "-r", "-R", "--recursive") || cmd === "srm") && o.positionals.some(w => w.dynamic || catastrophicPath(w, cwd))) add("file.catastrophic-delete", "hard-block", "critical", "Recursive deletion of system or home data");
      else human("file.delete", `Delete file content with ${cmd}`);
    }
  }
  if (cmd === "truncate") {
    const o = options(args, ["--size", "--reference"], "sr");
    const size = operand(o, "-s", "--size");
    if (has(o, "-r", "--reference") || !size || size.dynamic || !/^\+\d+(?:[KMGTPEmkgtpe]|[KMGTPE]i?B)?$/.test(size.value)) human("file.truncate", "Zero, shrink, or unresolved truncate operation");
  }
  if (cmd === "rsync") {
    // rsync's documented value options (including aliases) consume even '-n'.
    const values = "exclude exclude-from include include-from filter rsh rsync-path log-file out-format max-delete backup-dir suffix files-from password-file info debug stderr confine-root chmod checksum-choice cc block-size max-size min-size max-alloc partial-dir usermap groupmap chown timeout contimeout modify-window temp-dir compare-dest copy-dest link-dest compress-choice zc compress-level zl compress-threads zt skip-compress copy-as address port sockopts outbuf remote-option log-file-format early-input bwlimit stop-after stop-at write-batch only-write-batch read-batch protocol iconv checksum-seed config dparam".split(" ").map(s => `--${s}`);
    const booleans = "verbose quiet no-motd checksum archive recursive inc-recursive i-r no-inc-recursive no-i-r relative no-implied-dirs backup update inplace append append-verify dirs old-dirs old-d mkpath links copy-links copy-unsafe-links safe-links insecure-links munge-links copy-dirlinks keep-dirlinks hard-links perms executability acls xattrs owner group devices copy-devices write-devices specials drop-D times atimes open-noatime crtimes omit-dir-times omit-link-times super fake-super sparse preallocate dry-run whole-file no-whole-file no-W one-file-system existing ignore-non-existing ignore-existing remove-source-files del delete delete-before delete-during delete-delay delete-after delete-excluded ignore-missing-args delete-missing-args ignore-errors force partial delay-updates delay-symlinks prune-empty-dirs numeric-ids ignore-times size-only fuzzy compress cvs-exclude from0 old-args secluded-args protect-args trust-sender blocking-io stats 8-bit-output human-readable progress itemize-changes list-only fsync ipv4 ipv6 version help daemon no-detach".split(" ").map(s => `--${s}`);
    const shorts = "vqcarlptgoDRbu dLl kKHEAXUN OJSnWxIy zCF0s8hiP46V".replace(/ /g, "") + "efBMT@";
    const o = options(args, values, "efBMT@");
    const known = new Set([...values, ...booleans, ...[...shorts].map(s => `-${s}`)]);
    if (o.entries.some(([k]) => !known.has(k)) || args.some(a => a.dynamic) || has(o, "-M", "--remote-option")) o.unknown = true;
    if (([...o.flags.keys()].some(k => k.startsWith("--delete") || k === "--del") || has(o, "--remove-source-files")) && (o.unknown || !has(o, "-n", "--dry-run"))) human("sync.delete", "Rsync deletes destination or source files; preview must be unambiguous", true);
    if (has(o, "--rsync-path", "-e", "--rsh")) human("shell.incomplete", "Custom rsync executable requires review");
  }
  if (cmd === "aws") {
    const o = options(args, ["--profile", "--region", "--endpoint-url", "--output", "--query", "--include", "--exclude", "--cli-input-json", "--cli-input-yaml", "--ca-bundle", "--cli-read-timeout", "--cli-connect-timeout"]);
    const p = o.positionals.map(w => w.value);
    if (p[0] === "s3" && p[1] === "sync" && has(o, "--delete") && !has(o, "--dryrun")) human("sync.delete", "S3 sync deletes destination objects", true);
    else if ((p[0] === "s3" && ["rm", "rb", "mb"].includes(p[1])) || /^(?:delete-|terminate-|create-|put-|update-|run-instances$|start-instances$)/.test(p[1] ?? "")) human("infra.cloud-mutation", "AWS resource mutation", true);
  }
  if (cmd === "gsutil" || cmd === "gcloud") {
    const o = options(args, ["--project", "--account", "--configuration", "--impersonate-service-account", "--exclude"], cmd === "gsutil" ? "opx" : "x");
    const p = o.positionals.map(w => w.value);
    if (cmd === "gsutil" && p[0] === "rsync" && has(o, "-d") && !has(o, "-n")) human("sync.delete", "GCS sync deletes unmatched objects", true);
    else if (cmd === "gcloud" && p[0] === "storage" && p[1] === "rsync" && has(o, "--delete-unmatched-destination-objects") && !has(o, "--dry-run")) human("sync.delete", "GCS sync deletes unmatched objects", true);
    else {
      const mutations = ["delete", "destroy", "deploy", "create", "update", "set-iam-policy", "add-iam-policy-binding", "remove-iam-policy-binding", "rm", "rb", "mb"];
      const action = p.slice(cmd === "gsutil" ? 0 : 1, 4).find(s => [...mutations, "list", "describe", "get", "cat", "ls", "stat", "cp", "rsync"].includes(s));
      if (action && mutations.includes(action)) human("infra.cloud-mutation", "GCP resource mutation", true);
    }
  }
  if (cmd === "redis-cli") {
    const o = options(args, ["--user", "--pass", "--pattern", "--eval", "--cacert", "--cacertdir", "--cert", "--key", "--sni", "--tls-ciphers", "--tls-ciphersuites", "--show-pushes"], "hpnauisdD");
    if (["FLUSHALL", "FLUSHDB"].includes(o.positionals[0]?.value.toUpperCase()) && !has(o, "--scan")) human("database.bulk-delete", "Redis clears database data", true);
    if (has(o, "--eval")) add("database.code", "context", "critical", "Redis script contents are not inspected locally");
  }
  if (cmd === "dropdb") human("database.bulk-delete", "Drop database data", true);
  if (cmd === "supabase") {
    const o = options(args, ["--workdir", "--profile", "--output", "--project-id", "--db-url"], "o");
    if (o.positionals[0]?.value === "db" && o.positionals[1]?.value === "reset") human("database.bulk-delete", "Reset database data", true);
  }
  if (["psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo", "sqlcmd", "bq", "snowsql"].includes(cmd)) {
    const mysql = ["mysql", "mariadb"].includes(cmd);
    const o = options(args, ["--command", "--file", "--execute", "--eval", "--host", "--port", "--username", "--database", "--user"], cmd === "psql" ? "cfhUpdv" : cmd === "sqlite3" ? "" : "efhPuDQq", mysql ? ["-p", "--password"] : []);
    const code = operand(o, "-c", "--command", "-e", "--execute", "--eval", "-Q", "-q");
    const codeKeys = new Set(["-c", "--command", "-e", "--execute", "--eval", "-Q", "-q"]);
    const codes = o.entries.filter(([k, v]) => codeKeys.has(k) && v).map(([, v]) => v!.value);
    if (cmd === "sqlite3") codes.push(...o.positionals.slice(1).map(w => w.value));
    if (cmd === "bq" && o.positionals[0]?.value === "query") codes.push(...o.positionals.slice(1).map(w => w.value));
    for (const body of codes) {
      const mongo = cmd === "mongosh" || cmd === "mongo";
      if (mongo ? destructiveMongo(body) : destructiveSql(body)) human("database.bulk-delete", "Database bulk deletion in executable query", true);
      const stripped = sqlStatements(body).join(";");
      if (mongo ? !/^\s*(?:db\.\w+\.find\s*\([^;]*\)|print\s*\(\s*__literal__\s*\))\s*;?\s*$/.test(stripped) && !destructiveMongo(body) : complexSql(body)) human("database.code", "Complex database inline code is not inspected locally");
    }
    if (code || has(o, "-f", "--file") || codes.length) add("database.code", "context", "medium", "Database query/file may mutate data; files and complex bodies are not inspected locally");
  }
  if (["docker", "podman", "docker-compose", "podman-compose"].includes(cmd)) {
    const o = options(args, ["--host", "--context", "--connection", "--url", "--file", "--project-name", "--env-file", "--profile", "--filter", "--timeout"], "Hcfpt");
    const p = o.positionals.map(w => w.value), compose = cmd.endsWith("-compose") || p[0] === "compose";
    const c = compose && p[0] === "compose" ? p.slice(1) : p;
    if (compose && ((c[0] === "down" && has(o, "-v", "--volumes")) || (c[0] === "rm" && has(o, "-v", "--volumes")))) human("container.persistent-delete", "Compose removes persistent volumes", true);
    if (!compose && ((p[0] === "volume" && ["rm", "remove", "prune"].includes(p[1])) || (p[1] === "prune" && ["system", "container", "image", "network", "builder"].includes(p[0])) || (["rm", "remove"].includes(p[0]) && has(o, "-v", "--volumes")))) human("container.persistent-delete", "Container engine removes state or volumes", true);
  }
  if (["terraform", "tofu", "pulumi", "kubectl", "helm", "az", "cdk"].includes(cmd)) {
    const o = options(args, ["--namespace", "--context", "--cluster", "--kubeconfig", "--user", "--server", "--stack", "--cwd", "--subscription", "--resource-group"], "ns");
    const p = o.positionals.map(w => w.value);
    if (["terraform", "tofu"].includes(cmd) && p[0] === "state" && p[1] === "rm") human("infra.state-remove", "Remove infrastructure state tracking", true);
    else {
      const mutations: Record<string, string[]> = {
        terraform: ["apply", "destroy", "import", "taint"], tofu: ["apply", "destroy", "import", "taint"],
        pulumi: ["up", "destroy", "import"], cdk: ["deploy", "destroy"],
        kubectl: ["apply", "delete", "create", "patch", "replace", "scale", "drain", "exec", "edit", "label", "annotate", "cordon", "uncordon", "taint", "run", "expose", "autoscale", "set"],
        helm: ["install", "upgrade", "uninstall", "rollback"],
        az: ["delete", "create", "update", "deploy"],
      };
      const action = cmd === "az" ? p.slice(1, 4).find(s => [...mutations.az, "show", "list", "get"].includes(s)) : p[0];
      if (action && mutations[cmd].includes(action) || cmd === "kubectl" && p[0] === "rollout" && ["restart", "undo", "pause", "resume"].includes(p[1])) human("infra.mutation", "Infrastructure or cloud mutation", true);
    }
  }
  const disk = /^(?:mkfs(?:\.[\w+-]+)?|wipefs|mdadm|pvremove|vgremove|lvremove|lvreduce|pvresize|dmsetup|dd|diskutil|fdisk|sfdisk|parted|cfdisk)$/;
  if (disk.test(cmd)) {
    if (args.length === 1 && ["--help", "--version"].includes(args[0].value)) return;
    const o = cmd === "wipefs" ? options(args, ["--offset", "--output", "--types"], "oOt") : options(args, ["--size", "--setphysicalvolumesize"], "Lln");
    const p = o.positionals.map(w => w.value);
    let destructive = /^mkfs/.test(cmd) || ["pvremove", "vgremove", "lvremove", "lvreduce"].includes(cmd);
    if (cmd === "wipefs") destructive = has(o, "-a", "--all", "-o", "--offset") && !has(o, "-n", "--no-act", "-h", "--help", "-V", "--version");
    if (cmd === "mdadm") destructive = has(o, "--create", "-C", "--zero-superblock", "--remove", "-r", "--grow", "-G", "--fail", "-f");
    if (cmd === "dmsetup") destructive = ["remove", "remove_all", "wipe_table", "clear"].includes(p[0]);
    if (cmd === "pvresize") destructive = has(o, "--setphysicalvolumesize");
    if (cmd === "dd") destructive = args.some(w => /^of=/.test(w.value) && !(!w.dynamic && /^of=\/dev\/(?:null|stdout|stderr|fd\/\d+)$/.test(w.value)));
    if (cmd === "diskutil") destructive = p.some(s => /^(?:erase|partition)/.test(s) || ["deleteVolume", "deleteContainer"].includes(s));
    if (["fdisk", "sfdisk", "parted", "cfdisk"].includes(cmd)) destructive = !has(o, "-l", "--list") && !p.includes("print");
    if (destructive) {
      const raw = args.some(w => !w.dynamic && /^(?:of=)?\/dev\/(?!null$|zero$|stdout$|stderr$|fd\/)/.test(w.value));
      if (raw || /^mkfs/.test(cmd)) add("disk.destroy", "hard-block", "critical", `Raw-device destruction with ${cmd}`);
      else human("disk.unresolved-destruction", `Destructive disk operation with unresolved target: ${cmd}`, true);
    }
  }
}

function analyze(command: string, cwd: string, depth: number, findings: SafetyFinding[], projection: string[]): void {
  const add: Add = (ruleId, enforcement, risk, summary) => findings.push({ ruleId, enforcement, risk, summary, source: "local" });
  if (depth > 8 || command.length > MAX_COMMAND_BYTES || Buffer.byteLength(command, "utf8") > MAX_COMMAND_BYTES) {
    add("shell.incomplete", "human-required", "critical", "Local shell analysis limit exceeded");
    return; // Never project unparsed input into legacy destructive-text matching.
  }
  const parsed = parse(command);
  if (parsed.incomplete) add("shell.incomplete", "human-required", "medium", "Unsupported or malformed shell syntax needs review");
  for (const body of parsed.embedded) analyze(body, cwd, depth + 1, findings, projection);
  for (const invocation of parsed.invocations) {
    const unwrapped = unwrap(invocation.words), words = unwrapped.words;
    if (unwrapped.incomplete) add("shell.incomplete", "human-required", "medium", "Unsupported execution wrapper needs review");
    const cmd = name(words[0]);
    if (words[0]?.dynamic || (controls.has(cmd) && !(cmd === "trap" && ["-p", "-l"].includes(words[1]?.value)))) add("shell.incomplete", "human-required", "medium", "Dynamic executable or unsupported shell construct needs review");
    for (const r of invocation.redirects) {
      if ([">", ">|"].includes(r.op)) {
        if (!r.target.dynamic && /^\/dev\/(?!null$|stdout$|stderr$|fd\/)/.test(r.target.value)) add("disk.destroy", "hard-block", "critical", "Redirection overwrites a raw device");
        else if (r.target.dynamic || catastrophicPath(r.target, cwd)) add("file.protected-truncate", "human-required", "critical", "Redirection truncates a protected or unresolved path");
        else if (!words.length || [":", "true"].includes(cmd) || (cmd === "printf" && words[1]?.value === "") || (cmd === "cat" && words[1]?.value === "/dev/null")) add("file.truncate", "human-required", "medium", "Shell redirection replaces file content");
      }
    }
    if (!cmd) continue;
    const args = words.slice(1);
    if (/^(?:psql|mysql|mariadb|sqlite3|mongosh|mongo|sqlcmd|redis-cli)$/.test(cmd)) {
      if (invocation.redirects.some(r => r.op === "<")) add("database.code", "context", "medium", "Database input file contents are not inspected locally");
      const directInput = args.some(w => cmd === "psql" ? /^(?:-[cf].*|--(?:command|file)(?:=|$))/.test(w.value) : ["mysql", "mariadb"].includes(cmd) ? /^(?:-e.*|--execute(?:=|$))/.test(w.value) : /^(?:--eval(?:=|$)|-[Qq].*)/.test(w.value));
      const hasRedisCommand = cmd === "redis-cli" && options(args, ["--user", "--pass", "--pattern", "--eval", "--cacert", "--cert", "--key"], "hpnauisdD").positionals.length > 0;
      const hasSqliteCommand = cmd === "sqlite3" && options(args).positionals.length > 1;
      if (invocation.pipeInput && !directInput && !hasRedisCommand && !hasSqliteCommand) {
        const producer = unwrap(invocation.pipeInput).words;
        if (["echo", "printf"].includes(name(producer[0])) && !producer.some(w => w.dynamic)) {
          let data = producer.slice(1).filter(w => !["-n", "-e", "--"].includes(w.value));
          if (name(producer[0]) === "printf" && /^(?:%s(?:\\n|\s)*)+$/.test(data[0]?.value ?? "")) data = data.slice(1);
          if (producer.some(w => w.value === "-e") || (name(producer[0]) === "printf" && /%b|\\\\/.test(producer[1]?.value ?? ""))) add("shell.incomplete", "human-required", "medium", "Escaped database pipeline payload needs review");
          const body = data.map(w => w.value).join(" ");
          if (cmd === "redis-cli" ? /^(?:FLUSHALL|FLUSHDB)\b/im.test(body) : destructiveSql(body)) add("database.bulk-delete", "human-required", "critical", "Destructive database command supplied through a literal pipeline");
          add("database.code", "context", "medium", "Database commands supplied through a pipeline");
          projection.push(body.replace(/\s/g, "\\x20"));
        } else add("shell.incomplete", "human-required", "medium", "Computed database input requires review");
      }
    }
    if (cmd === "cd") {
      const targets = options(args).positionals;
      if (targets.length === 1 && !targets[0].dynamic) cwd = resolve(cwd, targets[0].value);
      else add("shell.incomplete", "human-required", "medium", "Working directory change cannot be established locally");
    }
    if (shells.test(cmd)) {
      const o = options(args, [], "c");
      const body = operand(o, "-c");
      projection.push(cmd + (body ? " -c" : ""));
      if (body && !body.dynamic) analyze(body.value, cwd, depth + 1, findings, projection);
      else add("shell.incomplete", "human-required", "medium", "Shell body or script cannot be established locally");
      continue;
    }
    if (interpreters.test(cmd)) {
      projection.push(cmd); // Interpreter operands are not shell source.
      if (!(args.length === 1 && ["--version", "-V", "--help"].includes(args[0].value))) add("shell.interpreter", "human-required", "medium", "Interpreter code/scripts require review; local analysis does not prove their effects");
      continue;
    }
    if (cmd === "find" && args.some(w => w.value === "-delete")) add("file.delete", "human-required", "medium", "Find deletes matching files");
    if (cmd === "find" && args.some(w => ["-exec", "-execdir", "-ok", "-okdir"].includes(w.value))) {
      add("shell.incomplete", "human-required", "medium", "Find executes commands on computed targets");
      for (let i = 0; i < args.length; i++) if (["-exec", "-execdir", "-ok", "-okdir"].includes(args[i].value)) {
        let end = i + 1;
        while (end < args.length && ![";", "+"].includes(args[end].value)) end++;
        analyze(args.slice(i + 1, end).map(w => w.value).join(" "), cwd, depth + 1, findings, projection);
      }
    }
    if (["xargs", "parallel", "ssh", "watch", "doas", "chrt", "ionice", "taskset", "stdbuf"].includes(cmd) || /\.(?:sh|bash|zsh|py|js|mjs)$/.test(cmd)) add("shell.incomplete", "human-required", "medium", "Computed, remote, or external script execution needs review");
    if (cmd === "eval") projection.push(args.map(w => w.value).join(" "));
    if (cmd === "git") {
      const g = gitArgs(words);
      if (words.some(w => /(?:core\.(?:sshCommand|gitProxy)|(?:ssh|receive|upload)[-\w.]*[Cc]ommand|alias\.)=/.test(w.value)) || g.args.some(w => /^(?:--receive-pack|--exec)(?:=|$)/.test(w.value))) add("shell.incomplete", "human-required", "medium", "Custom Git executable/configuration needs review");
      if (g.incomplete) add("shell.incomplete", "human-required", "medium", "Unsupported Git global options need review");
      if (g.args[0]?.value === "push" && g.configs.some(c => {
        const eq = c.value.indexOf("="), key = (eq < 0 ? c.value : c.value.slice(0, eq)).toLowerCase();
        const value = eq < 0 ? "true" : c.value.slice(eq + 1);
        return /^remote\..*\.(?:push|mirror)$/.test(key) && (c.dynamic || (key.endsWith(".push") ? value.startsWith("+") : !/^(?:false|no|off|0)$/i.test(value)));
      })) add("git.force-push-config", "hard-block", "critical", "Visible Git configuration may force push destinations not established from arguments");
      gitFindings(g.args, add);
      const sub = g.args[0]?.value ?? "";
      const supported = new Set(["stash", "reset", "clean", "checkout", "restore", "push", "rm", "branch", "tag", "reflog", "gc", "prune", "commit", "status", "diff", "log", "show", "rev-parse", "fetch", "add", "switch", "ls-files", "ls-remote", "remote", "config", "help", "version", "describe", "merge", "rebase", "cherry-pick", "init", "clone", "pull", "bisect", "worktree", "cat-file"]);
      if (sub && !supported.has(sub)) add("shell.incomplete", "human-required", "medium", "Git alias/unknown subcommand effects are not inspected locally");
      projection.push("git " + (new Set(["commit", "log", "show", "diff", "status", "add", "config", "help"]).has(sub) ? sub : g.args.map(w => w.value.replace(/\s/g, "\\x20")).join(" ")));
    } else {
      if (/^(?:rm|unlink|truncate|rsync|aws|gcloud|gsutil|redis-cli|dropdb|supabase|psql|mysql|mariadb|sqlite3|mongo|mongosh|docker|podman|docker-compose|podman-compose|terraform|tofu|pulumi|kubectl|helm|az|mdadm|dmsetup|pvremove|vgremove|lvremove|lvreduce|dd)$/.test(cmd) && args.some(w => w.dynamic)) add("shell.incomplete", "human-required", "medium", "Dynamic arguments to a state-changing CLI need review");
      operationFindings(cmd, args, cwd, add);
      const data = new Set(["echo", "printf", "grep", "rg", "egrep", "fgrep", "ag", "true", ":", "test", "["]);
      projection.push(data.has(cmd) ? cmd : words.map(w => w.value.replace(/\s/g, "\\x20")).join(" "));
    }
    for (const r of invocation.redirects) projection.push(r.op + " " + r.target.value);
  }
}

export function evaluateLocalCommand(command: string, cwd: string): SafetyFinding[] {
  const findings: SafetyFinding[] = [];
  analyze(command, cwd, 0, findings, []);
  const unique = new Map<string, SafetyFinding>();
  for (const f of findings) unique.set(`${f.ruleId}:${f.enforcement}:${f.summary}`, f);
  return [...unique.values()];
}

/** Executable projection for legacy hints; NOT a safe-command verdict or shell to execute. */
export function executableCommandText(command: string): string {
  const projection: string[] = [];
  analyze(command, "/", 0, [], projection);
  return projection.join("\n");
}
