# Q2611: Security-guidance extensibility guidance suppression via read config

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `_read_config` via `config file parse for security-patterns` and control a repo-shipped .claude/claude-security-guidance.md file so that the codebase inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path, breaking the invariant that repo-controlled guidance must not suppress or weaken built-in security findings and leading to Security-control bypass that silently disables or routes around blocking, review, or permission boundaries?

## Target
- File/function: `plugins/security-guidance/hooks/extensibility.py` / `_read_config`
- Entrypoint: `config file parse for security-patterns`
- Attacker controls: a repo-shipped .claude/claude-security-guidance.md file
- Exploit idea: Drive `config file parse for security-patterns` with attacker-controlled a repo-shipped .claude/claude-security-guidance.md file and test whether `_read_config` changes security behavior in a way that inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path.
- Invariant to test: repo-controlled guidance must not suppress or weaken built-in security findings
- Expected Immunefi impact: Security-control bypass that silently disables or routes around blocking, review, or permission boundaries
- Fast validation: place adversarial guidance or pattern files in a repo, load them through normal hook startup, and assert they cannot suppress built-in findings or expand path scope
