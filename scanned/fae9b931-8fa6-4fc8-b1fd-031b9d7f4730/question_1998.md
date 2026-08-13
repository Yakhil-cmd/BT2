# Q1998: Security-guidance extensibility guidance suppression via config paths

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `_config_paths` via `guidance/pattern file discovery` and control a repo-shipped .claude/claude-security-guidance.md file so that the codebase inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path, breaking the invariant that repo-controlled guidance must not suppress or weaken built-in security findings and leading to Cross-repo, cross-session, or wrong-target mutation with real security impact?

## Target
- File/function: `plugins/security-guidance/hooks/extensibility.py` / `_config_paths`
- Entrypoint: `guidance/pattern file discovery`
- Attacker controls: a repo-shipped .claude/claude-security-guidance.md file
- Exploit idea: Drive `guidance/pattern file discovery` with attacker-controlled a repo-shipped .claude/claude-security-guidance.md file and test whether `_config_paths` changes security behavior in a way that inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path.
- Invariant to test: repo-controlled guidance must not suppress or weaken built-in security findings
- Expected Immunefi impact: Cross-repo, cross-session, or wrong-target mutation with real security impact
- Fast validation: place adversarial guidance or pattern files in a repo, load them through normal hook startup, and assert they cannot suppress built-in findings or expand path scope
