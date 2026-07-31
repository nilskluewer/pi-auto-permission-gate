# @nilskluewer/pi-permission-gate

A Pi extension that asks for confirmation before potentially destructive bash commands run.

The extension fails closed for matching commands when Pi has no user interface available.

## What it protects

The gate checks bash tool calls for common destructive or high-impact operations, including:

- Recursive or forced file deletion such as `rm -rf`.
- Removal of Git metadata.
- `find -delete` and `xargs rm` patterns.
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

In non-interactive, JSON, and print modes, matching commands are blocked because confirmation is unavailable.

Safe commands and non-bash tool calls pass through unchanged.
Approvals are not persisted, so every matching tool call is reviewed independently.

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
