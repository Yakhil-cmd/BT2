# Q2038: Security-guidance main hook warning dedup bypass via main

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `main` via `security-guidance hook entrypoint` and control diff content from normal edits and commits so that the codebase reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake, breaking the invariant that dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes and leading to Cross-repo, cross-session, or wrong-target mutation with real security impact?

## Target
- File/function: `plugins/security-guidance/hooks/security_reminder_hook.py` / `main`
- Entrypoint: `security-guidance hook entrypoint`
- Attacker controls: diff content from normal edits and commits
- Exploit idea: Drive `security-guidance hook entrypoint` with attacker-controlled diff content from normal edits and commits and test whether `main` changes security behavior in a way that reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake.
- Invariant to test: dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes
- Expected Immunefi impact: Cross-repo, cross-session, or wrong-target mutation with real security impact
- Fast validation: script commit, amend, or push flows against crafted repos and verify stop-hook, commit-review, and push-sweep still surface the dangerous change
