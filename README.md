# @nilskluewer/pi-permission-gate

A Pi extension that asks for confirmation before potentially destructive bash commands run.

It focuses on common foot-guns such as recursive deletes, `sudo`, forced Git operations,
filesystem formatting, Docker volume pruning, and piping downloaded scripts into shells.

## Install

```bash
pi install npm:@nilskluewer/pi-permission-gate
```

In non-interactive modes, matching commands are blocked by default because no confirmation UI
is available.

## License

MIT
