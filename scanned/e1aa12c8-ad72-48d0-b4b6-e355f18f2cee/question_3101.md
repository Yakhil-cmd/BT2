# Q3101: Security-guidance extensibility guidance suppression via glob match

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `_glob_match` via `include/exclude matching for custom patterns` and control a repo-shipped .claude/claude-security-guidance.md file so that the codebase inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path, breaking the invariant that repo-controlled guidance must not suppress or weaken built-in security findings and leading to Logic-level service disruption caused by bypassing a required guard or misbinding security state?

## Target
- File/function: `plugins/security-guidance/hooks/extensibility.py` / `_glob_match`
- Entrypoint: `include/exclude matching for custom patterns`
- Attacker controls: a repo-shipped .claude/claude-security-guidance.md file
- Exploit idea: Drive `include/exclude matching for custom patterns` with attacker-controlled a repo-shipped .claude/claude-security-guidance.md file and test whether `_glob_match` changes security behavior in a way that inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path.
- Invariant to test: repo-controlled guidance must not suppress or weaken built-in security findings
- Expected Immunefi impact: Logic-level service disruption caused by bypassing a required guard or misbinding security state
- Fast validation: place adversarial guidance or pattern files in a repo, load them through normal hook startup, and assert they cannot suppress built-in findings or expand path scope
