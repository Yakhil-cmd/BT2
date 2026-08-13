# Q195: Security-guidance main hook warning dedup bypass via record pending warnings

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `record_pending_warnings` via `warning persistence between hooks` and control diff content from normal edits and commits so that the codebase reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake, breaking the invariant that dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/security_reminder_hook.py` / `record_pending_warnings`
- Entrypoint: `warning persistence between hooks`
- Attacker controls: diff content from normal edits and commits
- Exploit idea: Drive `warning persistence between hooks` with attacker-controlled diff content from normal edits and commits and test whether `record_pending_warnings` changes security behavior in a way that reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake.
- Invariant to test: dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: script commit, amend, or push flows against crafted repos and verify stop-hook, commit-review, and push-sweep still surface the dangerous change
