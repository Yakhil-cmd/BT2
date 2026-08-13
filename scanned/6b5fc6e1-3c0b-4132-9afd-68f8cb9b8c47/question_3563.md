# Q3563: Security-guidance session state cross session state bleed via save state

## Question
Can an unprivileged attacker while staying inside the public, unprivileged attacker model reach `save_state` via `security-guidance state save` and control normal concurrent Claude Code activity in one repo so that the codebase cause one session to inherit allow, deny, or review state from another session, breaking the invariant that locking must not let one session disable warnings or reuse review state from another and leading to Unauthorized file read or write outside the user-approved workspace or target scope?

## Target
- File/function: `plugins/security-guidance/hooks/session_state.py` / `save_state`
- Entrypoint: `security-guidance state save`
- Attacker controls: normal concurrent Claude Code activity in one repo
- Exploit idea: Drive `security-guidance state save` with attacker-controlled normal concurrent Claude Code activity in one repo and test whether `save_state` changes security behavior in a way that cause one session to inherit allow, deny, or review state from another session.
- Invariant to test: locking must not let one session disable warnings or reuse review state from another
- Expected Immunefi impact: Unauthorized file read or write outside the user-approved workspace or target scope
- Fast validation: run two sessions against crafted repos and assert warning counters, baselines, and pending state never cross-contaminate
