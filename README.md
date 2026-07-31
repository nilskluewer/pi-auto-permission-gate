# @nilskluewer/pi-permission-gate

A Pi extension that asks for confirmation before potentially destructive bash commands run.

The extension fails closed for matching commands when Pi has no user interface available.

## What it protects

The gate checks bash tool calls for common destructive or high-impact operations, including:

- Recursive or forced file deletion such as `rm -rf`.
- Removal of Git metadata.
- `find -delete` and `xargs rm` patterns.
- Package installation and package-runner commands such as `npm install` and `npx`.
- `sudo` and recursive `chmod` or `chown` commands.
- World-writable permissions such as `chmod 777`.
- Filesystem formatting, signature wiping, disk wiping, and partition editing.
- `dd` writes directed at device paths under `/dev/`.
- Destructive Git operations such as hard resets, forced pushes, forced branch deletion, and aggressive reflog or object pruning.
- Docker and Docker Compose commands that prune or remove volumes and other development state.
- Downloaded scripts piped into a shell.

The checks are intentionally conservative pattern checks rather than a shell parser or a sandbox.
A command that matches a pattern is shown to the user for review, but confirmation does not make the command safe.

## Behavior

In interactive mode, the extension displays the matched reasons and a truncated command preview.
The command runs only when the user explicitly selects `Yes`.
Hard-deny operations are blocked before this confirmation flow, even when auto mode is off.

In non-interactive, JSON, and print modes, matching commands are blocked because confirmation is unavailable.

Safe commands and non-bash tool calls pass through unchanged.
Approvals are not persisted, so every matching tool call is reviewed independently.

## Auto mode

Auto mode adds a model-backed decision layer for matching commands that are not in the non-negotiable hard-deny list.

Enable it for the current session with:

```text
/automode
```

The command toggles the mode.
Use `/automode on`, `/automode off`, or `/automode status` for explicit control.
Web verification is enabled by default and can be controlled with `/automode web on` or `/automode web off`.

When auto mode is enabled, each soft-deny command is evaluated by:

```text
github-copilot/gpt-5.6-luna with high reasoning
```

The classifier receives the command, matched rules, working directory, and a bounded extract of recent user and assistant text.
The classifier has no direct tools and must return a strict JSON decision with a short rationale.
When command or package information is unclear, it can request a web verification query.
The extension derives a bounded search query locally from command and package tokens rather than forwarding the recent conversation to the web provider.
It runs that query through the active Pi `web_search` tool in an isolated Pi subprocess that loads only the trusted web-search extension and exposes no shell tool.
The bounded evidence is then sent back to the classifier for a final decision.
The web query and evidence are treated as untrusted data and cannot execute commands.

Web verification requires an active `web_search` tool, for example the companion package `@nilskluewer/pi-vertex-gemini-search`.
The query is sent through the configured Pi web-search provider, so use `/automode web off` when commands or package names should not leave the local environment.

The decision is recorded in the chat as a session entry showing the command, matched rules, model, outcome, and rationale.
The decision entry is kept out of the model's normal conversation context so it does not create a feedback loop.
Auto-mode settings are persisted as session state so `/reload` and session resume retain the explicit mode choice.
New sessions and forks start with auto mode disabled, while tree navigation follows the selected branch's last persisted mode.

Auto mode fails closed if the model is unavailable, authentication fails, the request is cancelled, the response is malformed, requested web verification is unavailable or fails, or the model is uncertain.

### Hard-deny rules

The following catastrophic operations are blocked without asking the model:

- Recursive deletion of system or home roots, including unresolved shell expansions or globs.
- Filesystem formatting or filesystem signature wiping.
- Overwriting a device path with `dd`.
- macOS disk erasure or partitioning.
- Forced pushes to protected branch names such as `main`, `master`, `production`, or `prod`.

Package installation and package-runner commands are soft-deny matches and can trigger web verification.

This separation follows the useful part of Claude Code's auto-mode design: deterministic hard denies remain non-negotiable, while lower-confidence safety matches can be classified with context.

Auto mode is a safety aid, not a sandbox or a security boundary.
Do not enable it when the process must be prevented from making any autonomous changes.

## Install

Install the published package globally:

```bash
pi install npm:@nilskluewer/pi-permission-gate
```

Install directly from GitHub:

```bash
pi install git:github.com/nilskluewer/pi-permission-gate
```

Install from a local checkout:

```bash
pi install /path/to/pi-permission-gate
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
