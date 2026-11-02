# 0003: Configuration and permission lifetimes

## Context

Configuration is a user preference across conversations.
A person's permission for inspected code has a smaller scope.
Conversation branch navigation must not restore an obsolete gate switch.

## Decision

Persist gate enablement and classifier configuration globally.
Keep intent grants and exact single-use late approvals in memory for the session.
Use session entries for records rather than branch-local configuration restoration.
Clear approval state on session start, shutdown, and gate disablement.

## Consequences

A new session uses the global configuration but has no reusable human permissions.
A late answer from an old session generation cannot authorize a new session.
Every reused approval requires current inspection evidence.
Persisted decision history is a record, not a permission store.
See ARCHITECTURE.md for file names, additional settings, and reset behavior.
