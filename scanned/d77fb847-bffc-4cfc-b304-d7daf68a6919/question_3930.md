# Q3930: Security-guidance session state cross session state bleed via with locked state

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `with_locked_state` via `state mutation under lock` and control normal concurrent Claude Code activity in one repo so that the codebase cause one session to inherit allow, deny, or review state from another session, breaking the invariant that locking must not let one session disable warnings or reuse review state from another and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/security-guidance/hooks/session_state.py` / `with_locked_state`
- Entrypoint: `state mutation under lock`
- Attacker controls: normal concurrent Claude Code activity in one repo
- Exploit idea: Drive `state mutation under lock` with attacker-controlled normal concurrent Claude Code activity in one repo and test whether `with_locked_state` changes security behavior in a way that cause one session to inherit allow, deny, or review state from another session.
- Invariant to test: locking must not let one session disable warnings or reuse review state from another
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: run two sessions against crafted repos and assert warning counters, baselines, and pending state never cross-contaminate
