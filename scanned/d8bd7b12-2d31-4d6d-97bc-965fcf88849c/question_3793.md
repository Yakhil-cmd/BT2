# Q3793: Hookify rule engine tool matcher bypass via ruleengine extract field

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `RuleEngine._extract_field` via `field extraction from tool_input or hook input` and control tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation so that the codebase make a dangerous operation miss the intended rule because tool matching accepts only one representation, breaking the invariant that tool matcher and condition evaluation must not be bypassable by representation tricks and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/hookify/core/rule_engine.py` / `RuleEngine._extract_field`
- Entrypoint: `field extraction from tool_input or hook input`
- Attacker controls: tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation
- Exploit idea: Drive `field extraction from tool_input or hook input` with attacker-controlled tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation and test whether `RuleEngine._extract_field` changes security behavior in a way that make a dangerous operation miss the intended rule because tool matching accepts only one representation.
- Invariant to test: tool matcher and condition evaluation must not be bypassable by representation tricks
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: drive the engine with crafted hook JSON and assert dangerous Bash or Edit actions are denied under all equivalent encodings
