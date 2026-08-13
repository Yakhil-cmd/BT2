# Q3987: Security-guidance main hook warning dedup bypass via handle push sweep posttooluse

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `handle_push_sweep_posttooluse` via `PostToolUse push sweep review` and control diff content from normal edits and commits so that the codebase reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake, breaking the invariant that warning deduplication and counters must not suppress a new in-scope issue and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/security_reminder_hook.py` / `handle_push_sweep_posttooluse`
- Entrypoint: `PostToolUse push sweep review`
- Attacker controls: diff content from normal edits and commits
- Exploit idea: Drive `PostToolUse push sweep review` with attacker-controlled diff content from normal edits and commits and test whether `handle_push_sweep_posttooluse` changes security behavior in a way that reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake.
- Invariant to test: warning deduplication and counters must not suppress a new in-scope issue
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: script commit, amend, or push flows against crafted repos and verify stop-hook, commit-review, and push-sweep still surface the dangerous change
