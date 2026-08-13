# Q860: Hookify rule engine tool matcher bypass via compile regex

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `compile_regex` via `PreToolUse rule evaluation` and control tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation so that the codebase make a dangerous operation miss the intended rule because tool matching accepts only one representation, breaking the invariant that a matching block rule must reliably deny the protected operation and leading to Unauthorized file read or write outside the user-approved workspace or target scope?

## Target
- File/function: `plugins/hookify/core/rule_engine.py` / `compile_regex`
- Entrypoint: `PreToolUse rule evaluation`
- Attacker controls: tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation
- Exploit idea: Drive `PreToolUse rule evaluation` with attacker-controlled tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation and test whether `compile_regex` changes security behavior in a way that make a dangerous operation miss the intended rule because tool matching accepts only one representation.
- Invariant to test: a matching block rule must reliably deny the protected operation
- Expected Immunefi impact: Unauthorized file read or write outside the user-approved workspace or target scope
- Fast validation: drive the engine with crafted hook JSON and assert dangerous Bash or Edit actions are denied under all equivalent encodings
