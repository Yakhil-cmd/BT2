# Q3684: Security-guidance session state cross session state bleed via load state

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `load_state` via `security-guidance state load` and control normal concurrent Claude Code activity in one repo so that the codebase cause one session to inherit allow, deny, or review state from another session, breaking the invariant that locking must not let one session disable warnings or reuse review state from another and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/security-guidance/hooks/session_state.py` / `load_state`
- Entrypoint: `security-guidance state load`
- Attacker controls: normal concurrent Claude Code activity in one repo
- Exploit idea: Drive `security-guidance state load` with attacker-controlled normal concurrent Claude Code activity in one repo and test whether `load_state` changes security behavior in a way that cause one session to inherit allow, deny, or review state from another session.
- Invariant to test: locking must not let one session disable warnings or reuse review state from another
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: run two sessions against crafted repos and assert warning counters, baselines, and pending state never cross-contaminate
