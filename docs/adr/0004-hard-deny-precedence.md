# 0004: Hard-deny precedence

## Context

User command rules and the classifier can allow commands.
Some built-in matches need a fixed decision while the gate is enabled.
A human approval must not bypass those matches.

## Decision

Return a block for hard-deny matches before applying user-rule outcomes.
Keep that return before inspection reuse, classification, and human approval.
Apply this policy only while the permission gate is enabled.

## Consequences

An allowed-command pattern cannot override a hard deny.
Neither an intent grant nor a classifier allow can reach past that block.
Turning the gate off bypasses the complete review, including hard denies.
Keep precedence covered when adding rule types.
See ARCHITECTURE.md for the full execution sequence.
