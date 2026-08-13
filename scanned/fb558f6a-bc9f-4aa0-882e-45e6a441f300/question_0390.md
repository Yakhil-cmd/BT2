# Q390: Security-guidance session state cross session state bleed via load state

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `load_state` via `security-guidance state load` and control normal concurrent Claude Code activity in one repo so that the codebase cause one session to inherit allow, deny, or review state from another session, breaking the invariant that state must stay isolated per session and repo and leading to Unauthorized file read or write outside the user-approved workspace or target scope?

## Target
- File/function: `plugins/security-guidance/hooks/session_state.py` / `load_state`
- Entrypoint: `security-guidance state load`
- Attacker controls: normal concurrent Claude Code activity in one repo
- Exploit idea: Drive `security-guidance state load` with attacker-controlled normal concurrent Claude Code activity in one repo and test whether `load_state` changes security behavior in a way that cause one session to inherit allow, deny, or review state from another session.
- Invariant to test: state must stay isolated per session and repo
- Expected Immunefi impact: Unauthorized file read or write outside the user-approved workspace or target scope
- Fast validation: run two sessions against crafted repos and assert warning counters, baselines, and pending state never cross-contaminate
