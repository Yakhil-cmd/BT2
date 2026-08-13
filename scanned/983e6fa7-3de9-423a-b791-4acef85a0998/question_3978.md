# Q3978: Security-guidance main hook warning dedup bypass via sweep pending warnings

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `sweep_pending_warnings` via `warning replay on Stop` and control diff content from normal edits and commits so that the codebase reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake, breaking the invariant that warning deduplication and counters must not suppress a new in-scope issue and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/security_reminder_hook.py` / `sweep_pending_warnings`
- Entrypoint: `warning replay on Stop`
- Attacker controls: diff content from normal edits and commits
- Exploit idea: Drive `warning replay on Stop` with attacker-controlled diff content from normal edits and commits and test whether `sweep_pending_warnings` changes security behavior in a way that reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake.
- Invariant to test: warning deduplication and counters must not suppress a new in-scope issue
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: script commit, amend, or push flows against crafted repos and verify stop-hook, commit-review, and push-sweep still surface the dangerous change
