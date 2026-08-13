# Q1230: Hookify rule engine tool matcher bypass via ruleengine check condition

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `RuleEngine._check_condition` via `condition evaluation during hook execution` and control tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation so that the codebase make a dangerous operation miss the intended rule because tool matching accepts only one representation, breaking the invariant that a matching block rule must reliably deny the protected operation and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/hookify/core/rule_engine.py` / `RuleEngine._check_condition`
- Entrypoint: `condition evaluation during hook execution`
- Attacker controls: tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation
- Exploit idea: Drive `condition evaluation during hook execution` with attacker-controlled tool_name and tool_input supplied through a normal Bash, Edit, Write, or Stop invocation and test whether `RuleEngine._check_condition` changes security behavior in a way that make a dangerous operation miss the intended rule because tool matching accepts only one representation.
- Invariant to test: a matching block rule must reliably deny the protected operation
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: drive the engine with crafted hook JSON and assert dangerous Bash or Edit actions are denied under all equivalent encodings
