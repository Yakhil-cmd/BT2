# Q3867: Security-guidance main hook warning dedup bypass via maybe bootstrap agent sdk async

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `_maybe_bootstrap_agent_sdk_async` via `async bootstrap of Agent SDK support` and control diff content from normal edits and commits so that the codebase reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake, breaking the invariant that warning deduplication and counters must not suppress a new in-scope issue and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/security_reminder_hook.py` / `_maybe_bootstrap_agent_sdk_async`
- Entrypoint: `async bootstrap of Agent SDK support`
- Attacker controls: diff content from normal edits and commits
- Exploit idea: Drive `async bootstrap of Agent SDK support` with attacker-controlled diff content from normal edits and commits and test whether `_maybe_bootstrap_agent_sdk_async` changes security behavior in a way that reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake.
- Invariant to test: warning deduplication and counters must not suppress a new in-scope issue
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: script commit, amend, or push flows against crafted repos and verify stop-hook, commit-review, and push-sweep still surface the dangerous change
