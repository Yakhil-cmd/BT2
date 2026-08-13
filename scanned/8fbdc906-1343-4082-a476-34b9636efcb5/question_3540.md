# Q3540: Hookify rule loader shadow strict rule via load rules

## Question
Can an unprivileged attacker while staying inside the public, unprivileged attacker model reach `load_rules` via `PreToolUse rule discovery` and control a repo-shipped .claude/hookify.*.local.md file so that the codebase shadow a strict deny rule with a weaker attacker-chosen rule chosen by filename or glob order, breaking the invariant that disabled or superseded rules must not silently override active block rules and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/hookify/core/config_loader.py` / `load_rules`
- Entrypoint: `PreToolUse rule discovery`
- Attacker controls: a repo-shipped .claude/hookify.*.local.md file
- Exploit idea: Drive `PreToolUse rule discovery` with attacker-controlled a repo-shipped .claude/hookify.*.local.md file and test whether `load_rules` changes security behavior in a way that shadow a strict deny rule with a weaker attacker-chosen rule chosen by filename or glob order.
- Invariant to test: disabled or superseded rules must not silently override active block rules
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: create colliding rule files in a test repo, run the hook loader for each event, and assert which rule instances are actually returned
