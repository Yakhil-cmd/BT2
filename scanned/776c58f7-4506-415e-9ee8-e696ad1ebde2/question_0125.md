# Q125: Hookify rule loader shadow strict rule via load rule file

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `load_rule_file` via `rule-file parse on hook execution` and control a repo-shipped .claude/hookify.*.local.md file so that the codebase shadow a strict deny rule with a weaker attacker-chosen rule chosen by filename or glob order, breaking the invariant that only intended in-repo rule files should load and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/hookify/core/config_loader.py` / `load_rule_file`
- Entrypoint: `rule-file parse on hook execution`
- Attacker controls: a repo-shipped .claude/hookify.*.local.md file
- Exploit idea: Drive `rule-file parse on hook execution` with attacker-controlled a repo-shipped .claude/hookify.*.local.md file and test whether `load_rule_file` changes security behavior in a way that shadow a strict deny rule with a weaker attacker-chosen rule chosen by filename or glob order.
- Invariant to test: only intended in-repo rule files should load
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: create colliding rule files in a test repo, run the hook loader for each event, and assert which rule instances are actually returned
