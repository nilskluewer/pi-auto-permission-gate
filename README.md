# @nilskluewer/pi-auto-permission-gate

A Pi extension that asks for confirmation before potentially destructive bash commands run.

The extension fails closed for matching commands when Pi has no user interface available.

## Two-minute rules reference

The extension only intercepts model-generated `bash` tool calls.
It does not intercept Pi's direct `!` or `!!` shell commands, and it does not inspect `read`, `write`, `edit`, `grep`, `find`, or `ls` tool calls.

### Decision flow

| Order | Match | Result |
| --- | --- | --- |
| 1 | No built-in or user rule | Run |
| 2 | Hard-deny rule | Block immediately, without the model or a prompt |
| 3 | User `disallowedCommands` pattern | Block immediately |
| 4 | User `allowedCommands` pattern | Run, unless a hard-deny rule matched |
| 5 | Built-in soft rule with auto mode on | Ask the classifier |
| 6 | Built-in soft rule with auto mode off | Ask the user in a UI, or block when no UI exists |

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
| Other bash commands | `git status`, `printf`, ordinary project commands | Allowed unless a user rule matches |

Open `/automode-settings` without arguments for the interactive Permission Gate Settings page.
It provides one navigable entry point for auto mode, classifier model and thinking, classifier preferences, and command rules.
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

Allow patterns never match shell chaining, redirection, command substitution, or other shell control syntax.

The checks are intentionally conservative pattern checks rather than a shell parser or a sandbox.
A command that matches a pattern is shown to the user for review, but confirmation does not make the command safe.

## Behavior

In interactive mode, the extension displays the matched reasons and a truncated command preview.
The command runs only when the user explicitly selects `Yes`.
Hard-deny operations are blocked before this confirmation flow, even when auto mode is off.

In non-interactive, JSON, and print modes, matching commands are blocked because confirmation is unavailable.

Safe commands and non-bash tool calls pass through unchanged.
Approvals are not persisted, so every matching tool call is reviewed independently.

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
Exception: user allowed patterns cannot skip the check for recursive `rm`.
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

When auto mode is enabled, each soft-deny command is evaluated by the selected classifier.
The classifier receives the command, matched rules, working directory, and a bounded extract of recent user and assistant text.
The classifier has no direct tools and must return a strict JSON decision with a short rationale.
The decision is recorded in the chat as a session entry showing the command, matched rules, model, outcome, and rationale.
The decision entry is kept out of the model's normal conversation context so it does not create a feedback loop.
Auto-mode settings are persisted globally in `~/.pi/agent/permission-gate.json`, or under `PI_CODING_AGENT_DIR` when that environment variable is set.
The persisted classifier configuration contains only a reference such as `{"provider":"vertex","id":"gemini/flash"}` under `classifierModel` and a `classifierThinkingLevel` such as `"high"`, never a full model or authentication object.
The model reset command persists the default reference and the thinking reset command persists `high`.
The selected reference and configured thinking level are kept across new sessions, resumes, forks, reloads, and tree navigation.

Auto mode fails closed if the selected model or provider is unavailable, the selected model becomes stale, authentication fails, the request is cancelled, the response is malformed, or the model is uncertain.
A stale user-selected model never silently falls back to the default classifier.
Malformed persisted classifier references remain observable as unavailable and fail closed until the user selects a model or resets the classifier.

### Hard-deny rules

The following catastrophic operations are blocked without asking the model:

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
