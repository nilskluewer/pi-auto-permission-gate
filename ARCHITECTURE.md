# Architecture

## One bash tool call

`index.ts → gate.ts` creates one gate and registers commands, rendering, session hooks, and the tool hook.
`tool-call.ts` passes through non-bash calls and all calls while the gate is off.
For an enabled gate, `review.ts` applies this sequence:

1. Compute hard-deny matches, user rules, and matched reasons; block a hard deny first.
2. Block a user disallowed pattern.
3. Return without inspection if no reasons match and lockdown is inactive.
   User allow patterns can remove soft reasons, but not mandatory recursive-rm, IAM, or configuration-write checks.
4. Inspect the command and assess criticality. Lockdown skips reused approvals and the classifier.
5. Outside lockdown, consume an exact late approval for the same inspection snapshot, if present.
6. Otherwise, match a session intent only for non-critical policy without `CLASSIFIER_REQUIRED_REASON`.
7. Otherwise, call the classifier unless lockdown is active.
   A successful allow runs only when the resulting risk is not critical.
8. Ask the human for all remaining cases. No reachable approver means a block.
9. Check freshness before using an approval. Changed evidence restarts review, up to three attempts.

Thus lockdown catches even commands with no matched reason, but hard and user denies still block first.
Human redirects return an instruction rather than permission.
The README Decision flow is the user-facing reference; GLOSSARY defines the decision terms.

## Codemap

Paths below are relative to `src/`. Each line names one module or asset.

### Entry and Pi integration

- `index.ts`: default extension entry.
- `gate.ts`: constructs the gate and registers its integrations.
- `gate-state.ts`: explicit mutable state and dependency injection.
- `tool-call.ts`: event filter and review cancellation.
- `session.ts`: session initialization, reset, and branch status refresh.
- `review.ts`: decision sequence and fresh-evidence retries.
- `human-approval.ts`: races terminal and browser answers and handles late answers.
- `gate-controls.ts`: state changes, persistence requests, model caches, and approval reset.
- `gate-display.ts`: status text, notifications, and Pi custom entries.
- `gate-renderer.ts`: decision entry renderer.
- `gate-history.ts`: sends recorded decisions to Pi and browser history.
- `commands.ts`: command registration and approval-page command.
- `commands-settings.ts`: direct settings arguments and statistics.
- `commands-model.ts`: model, thinking, and context-count handlers.
- `commands-preferences.ts`: preferences and prompt handlers.
- `commands-rules.ts`: command-rule editing and save scope.
- `commands-page.ts`: connects settings actions to handlers.
- `settings-page.ts`: chooses TUI component or dialog UI.
- `settings-page-component.ts`: main TUI settings component.
- `settings-page-dialogs.ts`: selection-dialog settings flow.
- `settings-page-submenus.ts`: TUI selectors and editors.
- `settings-page-model.ts`: settings view and action types.

### Policy and supporting data

- `risk-patterns.ts`: hard-deny patterns and soft matched reasons.
- `command-rules.ts`: wildcard user rules and simple command segments.
- `command-access.ts`: command access and executable classification.
- `shell-words.ts`: shell token approximation and code-review reasons.
- `criticality.ts`: critical operations, environment, and production patterns.
- `intent-grants.ts`: scope proposal, comparison, and in-memory grant store.
- `classifier-prompt.ts`: prompt assembly, preferences normalization, and answer parsing.
- `classifier-models.ts`: model selection, metadata, thinking limits, and completions.
- `constants.ts`: shared defaults, limits, and entry identifiers.
- `text.ts`: bounded display text and unique values.
- `types.ts`: shared TypeScript contracts.

### Inspection and I/O

- `command-inspection.ts`: static path/code inspection, fingerprints, and freshness.
- `inspection-files.ts`: bounded regular-file reads and sensitive-path handling.
- `config-paths.ts`: agent-directory and global file paths.
- `persistence.ts`: settings, preferences, and trusted-project rules.
- `classifier.ts`: provider authentication, requests, timeouts, and result handling.
- `approval-client.ts`: local server discovery, startup, version checks, and HTTP client.
- `fatigue-summary.ts`: reads Pi session decisions and calculates statistics.

### Approval server and browser

- `approval-server/server.mjs`: process entry and state-path argument.
- `approval-server/lifecycle.mjs`: HTTP server construction and shutdown.
- `approval-server/router.mjs`: routes, authentication, and event stream.
- `approval-server/http.mjs`: JSON transport, errors, token checks, and headers.
- `approval-server/queue.mjs`: pending requests, decisions, waiters, and expiry.
- `approval-server/history.mjs`: bounded durable decision history.
- `approval-server/display.mjs`: request display and intent normalization.
- `approval-server/browser.mjs`: platform browser launch and debounce.
- `approval-server/state-file.mjs`: instance discovery and state-file ownership.
- `approval-server/version.mjs`: content-derived server version.
- `approval-server/config.mjs`: server limits and environment settings.
- `approval-server/types.mjs`: JSDoc contracts for the server.
- `approval-server/page.mjs`: page asset assembly.
- `approval-server/page/index.html`: page structure.
- `approval-server/page/styles.css`: page presentation.
- `approval-server/page/cards.js`: approval cards and decisions.
- `approval-server/page/history.js`: history display and filtering.
- `approval-server/page/app.js`: event connection and page controls.
- `approval-server/page/globals.d.ts`: browser-script shared declarations.

## Dependency direction

Entry wiring calls Pi integration; integration calls policy, inspection, and I/O.
Policy uses local helpers and type-only Pi contracts, without Pi runtime values or UI calls.
This is not a strict layered import graph: `classifier-prompt.ts` uses inspection formatting;
`risk-patterns.ts` uses `config-paths.ts` and reads environment-derived paths.
`classifier-models.ts` also accesses registry/session metadata; it is not entirely pure.
`persistence.ts` reads and writes files only; `session.ts` turns load failures into defaults and a user warning.
Shared types also refer to inspection types.
The server imports only its own modules and Node built-ins; it shares contracts with TypeScript through HTTP.

## Processes and protocol

The client starts or reuses a detached Node server bound to an ephemeral port on 127.0.0.1.
Session bearer credentials authorize health, request creation, wait, park, cancellation, history writes, and lifecycle calls.
A separate approver token authorizes browser decisions, history reads, and SSE events.
The browser receives that token in the URL fragment; the token stays out of the state file.
Host checks constrain HTTP requests. Requests use JSON; waits use long polling; browser updates use SSE.
See ADR 0001 for runtime and page-delivery constraints, and router tests for exact protocol behavior.

## State and persistence

The agent directory is `PI_CODING_AGENT_DIR`, or `~/.pi/agent` by default.
It contains global `permission-gate.json` settings, `permission-gate-rules.json` rules,
and `automode-preferences.md` classifier policy notes.
Settings include gate enablement, classifier model/thinking/history count, production patterns, and approval wait.
Trusted project `.pi/permission-gate-rules.json` overrides global rules; a session-only edit stays in memory.
`approval-queue.json` stores server discovery credentials, not pending approvals.
`approval-history.jsonl` stores browser decision history beside that discovery file.
Pi session custom entries record mode and decisions; statistics read decisions from Pi session files.
Session entries do not restore obsolete branch-local mode settings.
GateState holds active reviews, pending controllers, grants, late approvals, model caches, and denial counters.
Session start clears approvals and resets counters/lockdown; shutdown clears approvals.
Turning the gate off also clears approvals and counters. See ADR 0003 for the lifetime decision.

## Scope

There is no shell sandbox or full shell parser here; inspection does not execute the proposed command.
Network I/O in this source is the classifier provider through Pi AI and the localhost approval protocol.
The extension also launches the local server, and the server launches a system browser.
There is no remote approval service or database. Pending server requests are process memory, not durable queue state.
