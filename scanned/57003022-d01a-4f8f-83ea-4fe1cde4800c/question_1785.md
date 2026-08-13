# Q1785: Security-guidance main hook warning dedup bypass via handle user prompt submit

## Question
Can an unprivileged attacker while staying inside the public, unprivileged attacker model reach `handle_user_prompt_submit` via `UserPromptSubmit baseline capture` and control diff content from normal edits and commits so that the codebase reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake, breaking the invariant that dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/security-guidance/hooks/security_reminder_hook.py` / `handle_user_prompt_submit`
- Entrypoint: `UserPromptSubmit baseline capture`
- Attacker controls: diff content from normal edits and commits
- Exploit idea: Drive `UserPromptSubmit baseline capture` with attacker-controlled diff content from normal edits and commits and test whether `handle_user_prompt_submit` changes security behavior in a way that reuse a prior warning key or counter path so a new dangerous action emits no warning or rewake.
- Invariant to test: dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: script commit, amend, or push flows against crafted repos and verify stop-hook, commit-review, and push-sweep still surface the dangerous change
