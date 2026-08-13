# Q3788: Hookify rule engine tool matcher bypass via compile regex

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `compile_regex` via `PreToolUse rule evaluation` and control tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation so that the codebase make a dangerous operation miss the intended rule because tool matching accepts only one representation, breaking the invariant that tool matcher and condition evaluation must not be bypassable by representation tricks and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/hookify/core/rule_engine.py` / `compile_regex`
- Entrypoint: `PreToolUse rule evaluation`
- Attacker controls: tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation
- Exploit idea: Drive `PreToolUse rule evaluation` with attacker-controlled tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation and test whether `compile_regex` changes security behavior in a way that make a dangerous operation miss the intended rule because tool matching accepts only one representation.
- Invariant to test: tool matcher and condition evaluation must not be bypassable by representation tricks
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: drive the engine with crafted hook JSON and assert dangerous Bash or Edit actions are denied under all equivalent encodings
