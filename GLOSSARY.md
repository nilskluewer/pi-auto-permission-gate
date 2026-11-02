# Permission Gate

The permission gate decides whether a proposed command can run automatically or needs a person's approval.

## Language

**Classifier assessment**:
A model's assessment of a proposed command, its available evidence, and the user's intent. It is not proof of safe execution.
_Avoid_: Safety proof

**Inspection snapshot**:
The code and path evidence available for one permission assessment at a specific point in time.
_Avoid_: Execution trace

**Static path reference**:
A path identified without running the proposed command. It can name an input, code file, directory, or side-effect target; it does not prove which paths execution will access.
_Avoid_: Complete runtime file list

**Human approval**:
A person's permission to run one assessed command, or to allow a stated Intent grant for one session. Approval of one inspection snapshot does not authorize changed code.
_Avoid_: Permanent approval

**Intent grant**:
A person's permission, limited to one session, for a stated, structured set of non-critical commands. It has a defined scope of reasons, targets, and read or write access.
_Avoid_: Blanket approval

**Redirect**:
A human answer that does not run the proposed command and gives the agent an instruction instead. It is steering, not a safety denial.
_Avoid_: Denial with a suggestion

**Permission gate** (`gateEnabled`; stored as `autoModeEnabled` in `permission-gate.json`):
The on/off switch for the complete bash review. Off means that rules, classification, and human approval are bypassed.
_Avoid_: Classifier switch

**Hard deny** (`hardDenyReasons`, `hardDenyPatterns`):
A built-in match that blocks a command without a classifier or human decision while the gate is enabled.
_Avoid_: Soft warning

**Soft rule / matched reason** (`dangerousPatterns`, `matchedReasons`):
A built-in command match that sends a command into review. A matched reason explains why review is needed; it is not itself a final denial.
_Avoid_: Hard block

**User command rule** (`CommandRuleConfig`):
A user wildcard pattern in `allowedCommands` or `disallowedCommands`. It has a session, global, or trusted-project save scope.
_Avoid_: Intent grant

**Classifier / auto mode** (`classifyWithModel`):
The model assessment stage inside the permission gate. Classifier preferences and the classifier prompt keep the `autoMode` prefix (`automode-preferences.md`, `/automode-settings`); use "classifier" in new code.
_Avoid_: Permission gate as a synonym for the classifier alone

**Lockdown** (`lockdown`):
A state reached after repeated blocked commands. It requires human review for commands that are not already blocked by a hard deny or user deny.
_Avoid_: Gate off

**Approval queue / approval server**:
The local Node process and its pending human requests. The queue is process memory; the server also keeps decision history.
_Avoid_: Durable permission store

**Decision entry** (`DecisionEntry`, `permission-gate-decision`):
A record of a reviewed command and its result, source, rationale, and available measurements.
_Avoid_: Approval grant

**Late approval** (`lateApprovals`):
A browser approval received after the agent's wait ends. It can allow one retry of the exact command with the same inspection snapshot in the same session.
_Avoid_: Automatic command execution

**Production pattern** (`productionPatterns`):
A configured pattern used to identify a production target in criticality assessment.
_Avoid_: Production access allowlist

**Criticality** (`assessCriticality`):
The policy assessment of critical operations and environment. Critical policy or a critical classifier risk prevents classifier-only approval.
_Avoid_: Classifier confidence
