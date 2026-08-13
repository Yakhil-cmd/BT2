# Q3830: Security-guidance extensibility guidance suppression via load user patterns

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `_load_user_patterns` via `loading security-patterns.{yaml,yml,json}` and control a repo-shipped .claude/claude-security-guidance.md file so that the codebase inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path, breaking the invariant that custom pattern loading must stay confined to intended project files and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/extensibility.py` / `_load_user_patterns`
- Entrypoint: `loading security-patterns.{yaml,yml,json}`
- Attacker controls: a repo-shipped .claude/claude-security-guidance.md file
- Exploit idea: Drive `loading security-patterns.{yaml,yml,json}` with attacker-controlled a repo-shipped .claude/claude-security-guidance.md file and test whether `_load_user_patterns` changes security behavior in a way that inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path.
- Invariant to test: custom pattern loading must stay confined to intended project files
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: place adversarial guidance or pattern files in a repo, load them through normal hook startup, and assert they cannot suppress built-in findings or expand path scope
