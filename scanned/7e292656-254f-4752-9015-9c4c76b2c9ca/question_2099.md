# Q2099: Security-guidance session state cross session state bleed via save state

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `save_state` via `security-guidance state save` and control normal concurrent Claude Code activity in one repo so that the codebase cause one session to inherit allow, deny, or review state from another session, breaking the invariant that state must stay isolated per session and repo and leading to Security-control bypass that silently disables or routes around blocking, review, or permission boundaries?

## Target
- File/function: `plugins/security-guidance/hooks/session_state.py` / `save_state`
- Entrypoint: `security-guidance state save`
- Attacker controls: normal concurrent Claude Code activity in one repo
- Exploit idea: Drive `security-guidance state save` with attacker-controlled normal concurrent Claude Code activity in one repo and test whether `save_state` changes security behavior in a way that cause one session to inherit allow, deny, or review state from another session.
- Invariant to test: state must stay isolated per session and repo
- Expected Immunefi impact: Security-control bypass that silently disables or routes around blocking, review, or permission boundaries
- Fast validation: run two sessions against crafted repos and assert warning counters, baselines, and pending state never cross-contaminate
