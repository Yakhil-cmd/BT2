# Q3954: Security-guidance extensibility guidance suppression via validate pattern

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `_validate_pattern` via `custom pattern validation` and control a repo-shipped .claude/claude-security-guidance.md file so that the codebase inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path, breaking the invariant that custom pattern loading must stay confined to intended project files and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/extensibility.py` / `_validate_pattern`
- Entrypoint: `custom pattern validation`
- Attacker controls: a repo-shipped .claude/claude-security-guidance.md file
- Exploit idea: Drive `custom pattern validation` with attacker-controlled a repo-shipped .claude/claude-security-guidance.md file and test whether `_validate_pattern` changes security behavior in a way that inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path.
- Invariant to test: custom pattern loading must stay confined to intended project files
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: place adversarial guidance or pattern files in a repo, load them through normal hook startup, and assert they cannot suppress built-in findings or expand path scope
