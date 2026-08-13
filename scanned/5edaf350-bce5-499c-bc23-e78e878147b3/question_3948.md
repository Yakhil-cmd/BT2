# Q3948: Security-guidance extensibility guidance suppression via load for session

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `load_for_session` via `security-guidance hook startup` and control a repo-shipped .claude/claude-security-guidance.md file so that the codebase inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path, breaking the invariant that custom pattern loading must stay confined to intended project files and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/extensibility.py` / `load_for_session`
- Entrypoint: `security-guidance hook startup`
- Attacker controls: a repo-shipped .claude/claude-security-guidance.md file
- Exploit idea: Drive `security-guidance hook startup` with attacker-controlled a repo-shipped .claude/claude-security-guidance.md file and test whether `load_for_session` changes security behavior in a way that inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path.
- Invariant to test: custom pattern loading must stay confined to intended project files
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: place adversarial guidance or pattern files in a repo, load them through normal hook startup, and assert they cannot suppress built-in findings or expand path scope
