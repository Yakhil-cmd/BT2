# Q1054: Security-guidance main hook warning dedup bypass via resolve amend pre sha

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `_resolve_amend_pre_sha` via `commit amend review anchoring` and control diff content from normal edits and commits so that the codebase reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake, breaking the invariant that dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes and leading to Unauthorized file read or write outside the user-approved workspace or target scope?

## Target
- File/function: `plugins/security-guidance/hooks/security_reminder_hook.py` / `_resolve_amend_pre_sha`
- Entrypoint: `commit amend review anchoring`
- Attacker controls: diff content from normal edits and commits
- Exploit idea: Drive `commit amend review anchoring` with attacker-controlled diff content from normal edits and commits and test whether `_resolve_amend_pre_sha` changes security behavior in a way that reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake.
- Invariant to test: dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes
- Expected Immunefi impact: Unauthorized file read or write outside the user-approved workspace or target scope
- Fast validation: script commit, amend, or push flows against crafted repos and verify stop-hook, commit-review, and push-sweep still surface the dangerous change
