# 0002: Explicit gate state

## Context

Commands, session hooks, reviews, and human approval share mutable state.
They must agree on cancellation, configuration, and session ownership.
Those operations span several modules.

## Decision

Construct one `GateState` in `createPermissionGate`.
Pass it explicitly to the modules that register or implement Pi behavior.
Keep injectable services in `PermissionGateDependencies`.
Keep policy functions data-oriented rather than giving them the entire gate.

## Consequences

A reader can find shared fields in one type.
Tests can replace services without replacing the Pi runtime.
Local closures still manage individual requests and callbacks.
The gate object is shared state, not an immutable snapshot.
A caller must check cancellation and session generation before accepting asynchronous results.
See ARCHITECTURE.md for the dependency graph and its exceptions.
