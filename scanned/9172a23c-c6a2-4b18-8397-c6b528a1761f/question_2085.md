# Q2085: Hookify rule engine tool matcher bypass via ruleengine extract field

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `RuleEngine._extract_field` via `field extraction from tool_input or hook input` and control tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation so that the codebase make a dangerous operation miss the intended rule because tool matching accepts only one representation, breaking the invariant that a matching block rule must reliably deny the protected operation and leading to Cross-repo, cross-session, or wrong-target mutation with real security impact?

## Target
- File/function: `plugins/hookify/core/rule_engine.py` / `RuleEngine._extract_field`
- Entrypoint: `field extraction from tool_input or hook input`
- Attacker controls: tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation
- Exploit idea: Drive `field extraction from tool_input or hook input` with attacker-controlled tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation and test whether `RuleEngine._extract_field` changes security behavior in a way that make a dangerous operation miss the intended rule because tool matching accepts only one representation.
- Invariant to test: a matching block rule must reliably deny the protected operation
- Expected Immunefi impact: Cross-repo, cross-session, or wrong-target mutation with real security impact
- Fast validation: drive the engine with crafted hook JSON and assert dangerous Bash or Edit actions are denied under all equivalent encodings
