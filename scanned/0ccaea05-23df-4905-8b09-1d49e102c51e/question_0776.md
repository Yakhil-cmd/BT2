# Q776: Security-guidance extensibility guidance suppression via load for session

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `load_for_session` via `security-guidance hook startup` and control a repo-shipped .claude/claude-security-guidance.md file so that the codebase inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path, breaking the invariant that repo-controlled guidance must not suppress or weaken built-in security findings and leading to Unauthorized file read or write outside the user-approved workspace or target scope?

## Target
- File/function: `plugins/security-guidance/hooks/extensibility.py` / `load_for_session`
- Entrypoint: `security-guidance hook startup`
- Attacker controls: a repo-shipped .claude/claude-security-guidance.md file
- Exploit idea: Drive `security-guidance hook startup` with attacker-controlled a repo-shipped .claude/claude-security-guidance.md file and test whether `load_for_session` changes security behavior in a way that inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path.
- Invariant to test: repo-controlled guidance must not suppress or weaken built-in security findings
- Expected Immunefi impact: Unauthorized file read or write outside the user-approved workspace or target scope
- Fast validation: place adversarial guidance or pattern files in a repo, load them through normal hook startup, and assert they cannot suppress built-in findings or expand path scope
