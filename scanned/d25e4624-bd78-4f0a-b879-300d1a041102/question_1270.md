# Q1270: Security-guidance extensibility guidance suppression via validate pattern

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `_validate_pattern` via `custom pattern validation` and control a repo-shipped .claude/claude-security-guidance.md file so that the codebase inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path, breaking the invariant that repo-controlled guidance must not suppress or weaken built-in security findings and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/security-guidance/hooks/extensibility.py` / `_validate_pattern`
- Entrypoint: `custom pattern validation`
- Attacker controls: a repo-shipped .claude/claude-security-guidance.md file
- Exploit idea: Drive `custom pattern validation` with attacker-controlled a repo-shipped .claude/claude-security-guidance.md file and test whether `_validate_pattern` changes security behavior in a way that inject repo-controlled guidance that makes the reviewer skip a real dangerous action or data-exposure path.
- Invariant to test: repo-controlled guidance must not suppress or weaken built-in security findings
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: place adversarial guidance or pattern files in a repo, load them through normal hook startup, and assert they cannot suppress built-in findings or expand path scope
