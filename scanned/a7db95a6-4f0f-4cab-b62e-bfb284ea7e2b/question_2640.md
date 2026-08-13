# Q2640: Security-guidance main hook warning dedup bypass via resolve amend pre sha

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `_resolve_amend_pre_sha` via `commit amend review anchoring` and control diff content from normal edits and commits so that the codebase reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake, breaking the invariant that dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes and leading to Security-control bypass that silently disables or routes around blocking, review, or permission boundaries?

## Target
- File/function: `plugins/security-guidance/hooks/security_reminder_hook.py` / `_resolve_amend_pre_sha`
- Entrypoint: `commit amend review anchoring`
- Attacker controls: diff content from normal edits and commits
- Exploit idea: Drive `commit amend review anchoring` with attacker-controlled diff content from normal edits and commits and test whether `_resolve_amend_pre_sha` changes security behavior in a way that reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake.
- Invariant to test: dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes
- Expected Immunefi impact: Security-control bypass that silently disables or routes around blocking, review, or permission boundaries
- Fast validation: script commit, amend, or push flows against crafted repos and verify stop-hook, commit-review, and push-sweep still surface the dangerous change
