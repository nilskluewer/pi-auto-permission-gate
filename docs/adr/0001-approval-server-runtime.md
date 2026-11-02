# 0001: Separate approval server runtime

## Context

Pi loads the extension as TypeScript.
The installed package also needs a server that can run independently of a Pi session.
Node does not strip TypeScript under `node_modules`.
The browser page has a content security policy that permits no external scripts or styles.

## Decision

Run the approval server as a separate Node process.
Keep its runtime modules in plain JavaScript with `.mjs` extensions and JSDoc types.
Use Node built-ins and local modules, without package runtime dependencies.
Read the browser assets and inline them into one HTML response at startup.
Version the server by a hash of every file in `src/approval-server/` (`version.mjs`). The extension replaces a running server that reports another version.

## Consequences

The installed server runs without a TypeScript loader.
The browser source can stay split into small files without extra asset routes.
The browser scripts have a separate, non-strict type-check configuration.
Check the packed runtime with the smoke command in AGENTS.md.
See ARCHITECTURE.md for the module map and protocol.
