# Agent guide

This package is a Pi extension that checks each bash tool call before it runs.
Hard-deny rules, user command rules, an LLM classifier, and human approval (terminal or local browser page) decide the result.

## Verify a change

- Run `npm run check` before you hand over a change.
- Use `node --test tests/<name>.test.mjs` for one test file during development.
- Use `npm run smoke` after changes to entry points, imports, packaged assets, or package contents.
- The smoke check needs the `pi` binary; it loads the packed package without a model call.
- Report a blocked or unavailable check with its exact command.
- Add a regression test for each change to a decision or approval result.
- Use `tests/helpers/gate-harness.mjs` for Pi event and UI tests.
- Use `tests/helpers/approval-server.mjs` for approval server tests.
- Test cancellation and unavailable approval paths when you change asynchronous review.

## Keep the boundaries

- Keep `src/index.ts` as the entry point; put registration in `src/gate.ts`.
- Pass the explicit `GateState` to Pi-facing modules.
- Put policy calculations in modules that accept data and return data.
- Keep pure modules free of Pi runtime value imports and `ctx.ui` access.
- Keep filesystem access in inspection or I/O modules.
- Keep approval server runtime modules as `.mjs` with JSDoc types.
- Use only Node built-ins and local modules in that server process.
- Keep browser assets in `src/approval-server/page/`.
- Read ADR 0001 before you change server loading or page asset delivery.
- Import each symbol from the module that owns it; keep imports direct, without barrel re-exports.
- Split a source, test, or script file into cohesive modules before it exceeds 500 lines.
- Write comments about the current system, with a reason that remains useful to future readers.

## Preserve contracts

- Treat user-visible messages, persisted formats, environment variables, and HTTP behavior as contracts.
- Add or update contract tests when you change any of these surfaces.
- Keep classifier rationale in human-facing output; preserve the generic agent denial boundary.
- Keep inspection freshness checks on paths that reuse a human decision.
- Check session cancellation when you add an asynchronous state mutation.
- Read ADR 0003 before you change state lifetime or restoration.
- Read ADR 0004 before you change rule precedence.
- Keep user documentation in README aligned with intentional contract changes.

## Place a change

- To add a risk match, edit `src/risk-patterns.ts` and its rule tests.
- To change user wildcard matching, edit `src/command-rules.ts`.
- To change criticality or production detection, edit `src/criticality.ts`.
- To change inspection evidence, edit `src/command-inspection.ts` or `src/inspection-files.ts`.
- To change intent scope, edit `src/intent-grants.ts`.
- To change classifier text or parsing, edit `src/classifier-prompt.ts`.
- To change provider calls, edit `src/classifier.ts`.
- To add a command, register it in `src/commands.ts` and implement its handler in `commands-*.ts`.
- To add a settings control, use `src/commands-page.ts` and the `settings-page*.ts` modules.
- To change review order, edit `src/review.ts`.
- To change human answer handling, edit `src/human-approval.ts`.
- To change storage, edit `src/persistence.ts`; keep path selection in `src/config-paths.ts`.
- To change browser transport, use `src/approval-client.ts` and `src/approval-server/router.mjs`.

## Read on demand

- Read [ARCHITECTURE.md](ARCHITECTURE.md) before changes across modules or processes.
- Read its state section before you add a stored field or a session hook.
- Read [GLOSSARY.md](GLOSSARY.md) before you name a policy concept or write UI text.
- Read [docs/adr/](docs/adr/) before you change an established boundary.
- Keep each developer fact in one document; link to its owner from other documents.
