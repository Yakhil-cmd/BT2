# Q1305: Security-guidance main hook warning dedup bypass via maybe bootstrap agent sdk async

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `_maybe_bootstrap_agent_sdk_async` via `async bootstrap of Agent SDK support` and control diff content from normal edits and commits so that the codebase reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake, breaking the invariant that dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/security-guidance/hooks/security_reminder_hook.py` / `_maybe_bootstrap_agent_sdk_async`
- Entrypoint: `async bootstrap of Agent SDK support`
- Attacker controls: diff content from normal edits and commits
- Exploit idea: Drive `async bootstrap of Agent SDK support` with attacker-controlled diff content from normal edits and commits and test whether `_maybe_bootstrap_agent_sdk_async` changes security behavior in a way that reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake.
- Invariant to test: dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: script commit, amend, or push flows against crafted repos and verify stop-hook, commit-review, and push-sweep still surface the dangerous change
