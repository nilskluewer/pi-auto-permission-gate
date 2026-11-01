# @nilskluewer/pi-auto-permission-gate

A Pi extension that asks for confirmation before potentially destructive bash commands run.

The extension fails closed for matching commands when Pi has no user interface available.

## Two-minute rules reference

The extension only intercepts model-generated `bash` tool calls.
It does not intercept Pi's direct `!` or `!!` shell commands, and it does not inspect `read`, `write`, `edit`, `grep`, `find`, or `ls` tool calls.

### Decision flow

| Order | Match | Result |
| --- | --- | --- |
| 1 | Hard-deny rule | Block immediately, without the model or a prompt |
| 2 | User `disallowedCommands` pattern | Block immediately |
| 3 | User `allowedCommands` pattern, or no matched rule | Run, except mandatory checks such as recursive `rm`, IAM, and configuration writes |
| 4 | Lockdown | Ask the user for every command |
| 5 | Exact single-use late approval, or a matching non-critical session intent | Run after a fresh inspection |
| 6 | Built-in soft rule with auto mode on | Ask the classifier; a clear non-critical allow runs |
| 7 | Critical, uncertain, denied by classifier, or auto mode off | Ask the user in a UI, or block when no approver exists |

### Command coverage

| Command group | Examples | Default treatment |
| --- | --- | --- |
| Local checks | `uv run pytest`, `rtk uv run ruff check .`, `uv run mypy` | Allowed |
| Package installation, update, removal | `npm install`, `uv pip install`, `cargo add` | Allowed |
| Scoped local deletion | `find build -type f -delete` | Allowed when explicit relative targets stay below the current working directory |
| Recursive rm | `rm -rf build`, `rm -rf /tmp/x`, `rm -rf "$tmp"` after `tmp=$(mktemp -d)` | Always checked by the classifier, or by the user when auto mode is off. Allow patterns cannot skip this check |
| Other deletion | `.git` deletion, parent paths, roots, broad `find . -delete`, `xargs rm` | Checked or hard-blocked |
| Package execution and publishing | `npm run`, `npm exec`, `npx`, `uvx`, `uv run python`, `npm publish` | Checked |
| Privilege and permissions | `sudo`, `chmod 777`, recursive `chmod` or `chown` | Checked |
| Filesystems and disks | `mkfs`, `wipefs`, `shred`, `diskutil`, `dd ... of=/dev/...` | Checked, with catastrophic cases hard-blocked |
| Destructive Git operations | `reset --hard`, `clean -f`, force push, `branch -D`, `tag -d`, `git rm`, aggressive prune | Checked, with protected force pushes hard-blocked |
| Docker state removal | `docker system prune`, volume removal, `compose down -v` | Checked |
| Downloaded scripts | `curl ... \| sh`, `wget ... \| bash` | Checked |
| Interpreter and script execution | `python script.py`, `node -e '...'`, `bash cleanup.sh`, `./cleanup` | Classifier assessment in auto mode; human review otherwise, unless an explicit user allow rule applies |
| Unsupported shell syntax | Command substitutions, heredocs, complex redirects, malformed quoting | Classifier assessment in auto mode, not mandatory human approval merely because local parsing is incomplete |
| Other bash commands | `git status`, `printf`, ordinary project commands | Allowed unless a user rule matches |

Open `/automode-settings` without arguments for the interactive Permission Gate Settings page.
It provides one entry point for auto mode, classifier settings and preferences, command rules, production patterns, the approval wait, active intent grants, and approval statistics.
The command-rules subpage lists the active allowed and disallowed patterns before opening the editor, so user-defined commands are visible instead of being hidden in a separate command.
Hard-deny rules cannot be overridden by an allow pattern.

## What it protects

The gate checks bash tool calls for common destructive or high-impact operations, including:

- Recursive or forced file deletion such as `rm -rf`.
- Removal of Git metadata.
- `find -delete` and `xargs rm` patterns.

Scoped `find -delete` is allowed by default when explicit relative targets stay below the current working directory.
For example, `find build -type f -delete` passes without confirmation.
Recursive `rm` is never allowed without a check: the classifier, or the user when auto mode is off, must approve every `rm -r` or `rm -rf`.
Variables assigned once from `$(mktemp ...)` and `$TMPDIR` are not hard-blocked, so the classifier can approve temp-directory cleanup.
Parent paths, filesystem roots, `.git` metadata, shell expansions, globs, and broad `find . -delete` remain protected.
- Package execution and publishing commands such as `npm run`, `npm publish`, and `npx`.
- `sudo` and recursive `chmod` or `chown` commands.
- World-writable permissions such as `chmod 777`.
- Filesystem formatting, signature wiping, disk wiping, and partition editing.
- `dd` writes directed at device paths under `/dev/`.
- Destructive Git operations such as hard resets, forced pushes, forced branch deletion, and aggressive reflog or object pruning.
- Docker and Docker Compose commands that prune or remove volumes and other development state.
- Downloaded scripts piped into a shell.

Routine package installation, update, and removal commands are allowed by default.
The user-editable rules can add extra command patterns to allow or disallow.
The built-in local verification allowlist includes these commands, with an optional `rtk` prefix:

- `uv run pytest`.
- `uv run ruff check ...`.
- `uv run mypy ...`.

Allow patterns match a chained command (`&&`, `;`, `|`, `2>&1`, `> /dev/null`) only when every segment matches an allow pattern or is a plain `cd`, `tail`, `head`, `wc`, or `sleep`.
Command substitution, heredocs, subshells, escapes, and redirects to files never match an allow pattern.

The checks are intentionally conservative pattern checks rather than a shell parser or a sandbox.
A command that matches a pattern is shown to the user for review, but confirmation does not make the command safe.

## Behavior

In interactive mode, the extension displays the matched reasons and a truncated command preview.
When human review is required, the command runs only after an explicit approval, either once or under a session intent grant.
Hard-deny operations are blocked before this confirmation flow, even when auto mode is off.

In non-interactive, JSON, and print modes, matching commands are blocked because confirmation is unavailable.

Safe commands and non-bash tool calls pass through unchanged.
Intent grants and single-use late approvals stay in memory only. They end on session replacement or shutdown. Every matching tool call gets a fresh inspection.

## User-editable command rules

Use the command-rules page in `/automode-settings` to edit the command rule list in Pi.
The editor accepts shell-style `*` and `?` patterns matched against the complete command.
The editor starts with the built-in local verification allowlist, and saving replaces the two lists with the edited values.

```json
{
  "allowedCommands": [
    "make clean",
    "uv run python -m mypy*"
  ],
  "disallowedCommands": [
    "npm publish*"
  ]
}
```

The precedence is hard-deny rules, user disallowed patterns, user allowed patterns, then the built-in soft-deny rules.
Exception: user allowed patterns cannot skip recursive `rm`, IAM or credential-minting checks, or writes to Pi or gate configuration.
Hard-deny rules cannot be overridden through the editor.

The save menu supports the current session, a global default, or a trusted-project default.
Global rules are stored in `~/.pi/agent/permission-gate-rules.json`.
Project rules are stored in `.pi/permission-gate-rules.json` and override the global rules for that project.

Use the command-rules page in `/automode-settings` to inspect or reset the active rules.

## Auto mode

Auto mode adds a model-backed decision layer for matching commands that are not in the non-negotiable hard-deny list.

Auto mode is enabled by default.
The first session after installation initializes the global setting as enabled.

Use `/automode-settings` as the central settings command.
With no arguments it opens the interactive settings page.
In RPC mode it uses nested selection dialogs, while JSON and print modes retain the non-interactive status behavior.

The same command also supports direct forms:

```text
/automode-settings on|off|status
/automode-settings model [provider/model-id|reset]
/automode-settings thinking [level|reset]
/automode-settings history [count|reset]
/automode-settings prompt
/automode-settings preferences [text|list|clear]
/automode-settings wait [60|120|300|600|900|1800]
/automode-settings production [patterns]
/automode-settings grants
/automode-settings statistics
```

Auto-mode preferences are stored as a user-editable Markdown note file at `~/.pi/agent/automode-preferences.md`, or below `PI_CODING_AGENT_DIR` when that environment variable is set.
Each non-empty note is injected into the classifier's system and user prompts as trusted user-authored policy.
Preferences can refine soft-deny decisions, but they never override hard-deny rules or the classifier's requirement to deny ambiguous commands.
Use `/automode-settings preferences <text>` to append a note, `/automode-settings preferences` to edit the complete note file in the interactive editor, `/automode-settings preferences list` to inspect the notes, or `/automode-settings preferences clear` to remove them.
Use `/automode-settings prompt` to open the complete classifier prompt template, including the currently injected preferences.

Choose the classifier with these central settings commands:

```text
/automode-settings model
/automode-settings model provider/model-id
/automode-settings model reset
```

`/automode-settings model` opens a model selector in TUI and RPC modes.
`/automode-settings model provider/model-id` selects the exact provider and model ID and also works in noninteractive modes.
The provider is the text before the first slash, so model IDs containing additional slashes are supported.
`/automode-settings model reset` restores `github-copilot/gpt-6-luna`.
The picker and model argument completions use only scoped text-capable models from the current Pi session.
Configure a session model scope with Pi's `--models` option or the `enabledModels` setting before using the picker.
Explicit `provider/model-id` arguments still resolve exact current models from Pi's model registry.
The command autocomplete does not expose authentication details.

Configure classifier thinking independently from Pi's active conversation thinking level:

```text
/automode-settings thinking
/automode-settings thinking <off|minimal|low|medium|high|xhigh|max>
/automode-settings thinking reset
```

Configure how many previous conversation messages the classifier receives:

```text
/automode-settings history
/automode-settings history <0-100>
/automode-settings history reset
```

`/automode-settings history` opens a message count selector in TUI and RPC modes.
The default and reset count is `12` messages (within token/length bounds).
Setting `0` sends no previous messages.
The value is persisted globally in `~/.pi/agent/permission-gate.json`.

`/automode-settings thinking` opens a thinking-level selector in TUI and RPC modes.
The selector marks levels supported by the selected classifier and shows the effective clamped level when a level is unsupported.
`/automode-settings thinking` with no UI does not prompt; use an explicit level in noninteractive modes.
The default and reset level is `high`.
Invalid levels and extra arguments are rejected without mutating the global setting.
A picker is rejected in JSON, print, and no-UI modes and does not change the configured model or thinking level.

Explicit provider/model selections are resolved from Pi's model registry after a refresh.
The extension does not maintain a provider allowlist.
Only models whose registry metadata accepts text input are shown in the picker or autocomplete, and provider/model IDs are sorted deterministically.
Provider display names and model names are used only as picker and autocomplete descriptions.

The classifier model and configured/effective thinking level are shown by `/automode-settings status`, the footer status, notifications, and expanded decision entries.
For example, a configured `max` level may be reported as `thinking max -> high` when the selected model supports standard levels but does not advertise `max`.
Pi's model support metadata controls clamping: non-reasoning models use `off`, standard levels through `high` are available unless explicitly mapped to `null`, and `xhigh` and `max` require explicit non-null mappings.
Clamping follows Pi's thinking-level ordering and the effective non-off level is passed to the classifier provider.
Selecting a classifier or classifier thinking level does not change Pi's active model or conversation thinking level, and the extension never calls `pi.setModel()`.

When auto mode is enabled, each soft-deny command is evaluated by the selected classifier in two stages, like Claude Code auto mode.
Stage 1 is a fast pass without reasoning that errs toward "deny". Only an "allow" ends there.
Everything else goes to stage 2 with the configured thinking level. Commands that always need a human skip stage 1.
The classifier is reasoning-blind. It receives the command, matched rules, working directory, the user's own recent messages, the bash commands the agent already ran, and available script-inspection evidence.
Conversation context excludes assistant text and tool output. Inspected source files are a separate, untrusted evidence channel: instructions or approval claims inside them must not control the decision.
The classifier has no direct tools and must return a strict JSON decision: `decision`, `risk` (`low`, `medium`, `critical`), and a one-sentence `rationale` for the human approver.
The decision is recorded in the chat as a session entry showing the command, matched rules, model, outcome, and rationale.
The decision entry is kept out of the model's normal conversation context so it does not create a feedback loop.
Auto-mode settings are persisted globally in `~/.pi/agent/permission-gate.json`, or under `PI_CODING_AGENT_DIR` when that environment variable is set.
The persisted classifier configuration contains only a reference such as `{"provider":"vertex","id":"gemini/flash"}` under `classifierModel` and a `classifierThinkingLevel` such as `"high"`, never a full model or authentication object.
The model reset command persists the default reference and the thinking reset command persists `high`.
The selected reference and configured thinking level are kept across new sessions, resumes, forks, reloads, and tree navigation.

A stale user-selected model never silently falls back to the default classifier.

### Script inspection

Before a command that needs review is assessed, the gate reads statically identifiable invoked scripts and common local dependencies. It does not execute or source them, expand shell expressions, or fetch remote code. Inline code remains part of the command. Common shell invocations, Python imports, and relative JavaScript/TypeScript imports are supported; this is not a complete language parser or a sandbox.

Inspection is bounded: 16 code files, 64 KiB of code in total, dependency depth 4, and a path display budget of 256 entries and 24 KiB of path text. Missing, binary, oversized, sensitive, and unresolved files are disclosed. Known credential paths and secret filenames are excluded from code collection; this is not a general secret scanner. Ordinary external library imports are not inherently grounds for denial, but missing evidence that leaves material uncertainty must reach a human.

Collected source is sent to the configured classifier provider. Source-file bodies are not added to the conversation, approval requests, or history. Only path metadata, inspection limitations, and the decision summary are retained. The exact command remains visible, including any inline code it already contains.

Each call gets a new inspection. The gate rebuilds the evidence after classification and after an approval wait. Changed evidence restarts review; three unstable assessments block the command. This reduces changes between review and execution but does **not** make the check and execution atomic. Intent grants still require fresh evidence on each call. A late approval can be used once, only for the exact command and the same inspection snapshot. Hard blocks and mandatory-human critical rules keep their authority.

### Approval queue

The classifier never blocks a command by itself. It either allows it or sends it to you.
A command goes to you when the classifier says "deny", when its `risk` is `critical`, when target-dependent policy makes it critical, or when classification fails (provider error, cut-off output, malformed JSON, stale model, no authentication). Interpreter execution and unsupported syntax are requests for classifier assessment of the available code, not risks by themselves.
Merges, pushes, and commits are not critical by themselves.

In an interactive session the request is sent to one shared local approval queue and to the terminal at the same time. The first answer wins.
The queue is a small local web server (`127.0.0.1`, random port) that all pi sessions on the machine share, so you watch one browser tab.
The first request starts the server and opens the tab.
Each card shows the project name and full working directory, a visible **Execution summary**, risk, recommendation, exact command, matched rules, and session. The summary describes the execution and its important effects, not just why review was requested.
A collapsed **Files and paths** section groups filenames under each full directory, with roles and code-inspection status. It includes identified inputs, scripts, directories, outputs, and deletion targets. Dynamic references and incomplete inspection are marked explicitly: this is a static list, not a claim to show every runtime access. History details retain the same grouping. Terminal approvals show the project, explanation, and grouped paths as text; when auto mode is off, no model-generated explanation is available.
Critical cards are red and need a second click to approve. You can add a note for the agent when you deny.
The wait defaults to **300 seconds** (5 minutes). If you do not answer, the gate records **expired**, cancels the terminal dialog, and parks the browser request. The command does not run. The agent is told to continue with other work that does not need the command, or end its turn and ask in plain text. The browser request stays answerable for 10 more minutes after the wait ends.

A late browser answer sends a follow-up message to the session. A late approval does not execute anything: it allows the agent to retry the **exact command once**, and only if a new inspection matches the approved code and fingerprints. A late redirect sends your instruction; a late denial tells the agent you denied it. Switching or closing the session discards these permissions and cancels outstanding requests.

Use the Approval wait setting or `/automode-settings wait 600` to change the wait to 60, 120, 300, 600, 900, or 1800 seconds. It is saved as `approvalWaitSeconds` in the global mode settings. Set `PI_PERMISSION_GATE_BROWSER=0` to use only the terminal; after a terminal-only expiry, late answers are not possible.
Without a UI, or when no approver can be reached, the command is blocked.

The same page has a History tab for classifier approvals, hard-denies, rule decisions, grant-covered commands, and human outcomes. Approved, denied, redirected, and expired have separate statuses. Entries can show the recommendation, scope, grant ID, note, and prompt/answer timestamps, in addition to the summary, risk, source, and command. Old entries without the new fields still display.
The history is kept in `approval-history.jsonl` next to the queue state file, the last 500 entries.
Run `/approvals` in pi to open the page.

For a denial, the agent sees a generic refusal and an instruction not to retry it in another form. It does not see the classifier text. Your note, if any, is passed on. A redirect instead returns your instruction without the no-retry notice. Redirects and expiries do not count toward lockdown.
After 3 denials in a row or 20 in total, the gate goes into lockdown: every command needs your approval until you pick "Approve and lift lockdown" in the queue or "Yes, and lift lockdown" in the terminal.
The agent cannot read the queue state file or call the queue API with bash. These commands are hard-denied.
The `read` tool and other tools are not covered by this gate, so treat this as a guard against mistakes, not against a hostile agent.

### Session intent grants

For a non-critical command, the gate can propose a structured intent, such as a write through Python in a named directory. Approve once, or choose **Yes, for this session: <label>** in the terminal / **Approve for session…** in the browser. The browser lets you narrow the target paths, executable targets, and read/write access before approval. An edit that widens the proposal falls back to approval once, with an explanation in the decision record. Only a human answer can create a grant.

A grant covers a later command only when every matched reason, executable, and static path reference fits its scope. This includes the working directory. A read grant cannot authorize a write. Extra reasons, unresolved paths, other directories, critical commands, and lockdown still require normal review. Recursive `rm` never uses an intent grant: each call still needs a classifier assessment or human approval.

Grants belong to one gate session and are not saved to disk. Use **Session intent grants** in `/automode-settings` or `/automode-settings grants` to list their labels and targets and revoke one or all. They are also cleared on session start, replacement, and shutdown. Grant-covered decisions record `source: "intent-grant"` and the grant ID.

### Target-dependent criticality

Cloud and infrastructure writes are critical for **production or unknown environments**. An explicit dev, test, sandbox, or staging target is soft and goes to the classifier. Cloud reads do not become critical merely because the target is production. IAM and credential minting stay critical in every environment. `sudo`, disk wipes, partition editing, and writes to Pi or gate configuration also stay critical. Ordinary reads of that configuration are not critical.

Use **Production patterns** in settings, `/automode-settings production` to edit, or `/automode-settings production prod prd production customer-*` to set patterns directly. The global `productionPatterns` setting defaults to `prod`, `prd`, and `production`. Patterns are case-insensitive shell globs (`*`, `?`) matched against target identifiers and their name segments. Production matches take precedence over dev markers; a target that cannot be classified stays critical. Use `*prod*` if your naming scheme needs substring matching.

### Redirect and measurement

Choose **Redirect…** in either approval channel to give an instruction instead of approval, for example “Use uv instead”. A redirect requires text. Empty terminal input asks again; cancellation denies the command. The command does not run, and the instruction reaches the agent without a safety-denial notice.

Session decisions record optional `recommendation` (`approve`, `deny`, `review`), `shownAt`, `answeredAt`, `scope` (`once`, `intent`), `grantId`, and `note`. Expiry has no `answeredAt` and is not recorded as a denial. These fields keep old session records compatible and separate reaction time from classification time.

Open **Approval statistics** or run `/automode-settings statistics` for the last 14 days. The report reads the agent directory's session files and shows prompts per active UTC hour, denial and redirect rates, expiries, classifier disagreements, and prompts saved by grants. Old blocks that could have been timeouts are kept separate from known denials. This is a decision-based activity measure, not total elapsed work time.

### Hard-deny rules

The following catastrophic operations are blocked without asking the model or you:

- Accessing the approval queue or history files, or calling the queue API. Searching for their filenames with `grep`, `rg`, `ag`, or `git grep` is allowed; actual file operands and redirect targets remain hard-denied.

- Recursive deletion of system or home roots, including unresolved shell expansions or globs.
- Filesystem formatting or filesystem signature wiping.
- Overwriting a device path with `dd`.
- macOS disk erasure or partitioning.
- Forced pushes to protected branch names such as `main`, `master`, `production`, or `prod`.

Package installation, update, and removal commands are not gated by default.
Package execution, package runners, and publishing remain soft-deny matches.

This separation follows the useful part of Claude Code's auto-mode design: deterministic hard denies remain non-negotiable, while lower-confidence safety matches can be classified with context.

Auto mode is a safety aid, not a sandbox or a security boundary.
Do not enable it when the process must be prevented from making any autonomous changes.

## Turn the gate off

The gate can be turned fully off. Then it checks nothing: no hard denies, no command rules, no classifier, no approvals.

- `pi --no-permission-gate` starts pi with the gate off, for example for scheduled automations.
- `/permission-gate off` turns it off in a running pi; `/permission-gate on` turns it on again; `/permission-gate status` shows the state.
- The first row of `/automode-settings`, "Permission gate", does the same.

"Automatic safety decisions: off" is different: it turns off only the classifier. Hard denies and command rules stay, and soft-deny commands then ask for your approval.

The state is for the pi process only; it is not saved. While the gate is off, the footer shows `permission gate: OFF`.

## Install

Install the published package globally:

```bash
pi install npm:@nilskluewer/pi-auto-permission-gate
```

Install directly from GitHub:

```bash
pi install git:github.com/nilskluewer/pi-auto-permission-gate
```

Install from a local checkout:

```bash
pi install /path/to/pi-auto-permission-gate
```

## Development

The extension source is in `extensions/permission-gate.ts`.

Run the unit tests with:

```bash
npm test
```

Inspect the npm tarball without publishing it with:

```bash
npm run pack:dry
```

Load the local package temporarily with:

```bash
pi -e .
```

## License

MIT
