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
