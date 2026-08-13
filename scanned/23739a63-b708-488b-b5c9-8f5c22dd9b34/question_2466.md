# Q2466: Security-guidance session state cross session state bleed via with locked state

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `with_locked_state` via `state mutation under lock` and control normal concurrent Claude Code activity in one repo so that the codebase cause one session to inherit allow, deny, or review state from another session, breaking the invariant that state must stay isolated per session and repo and leading to Logic-level service disruption caused by bypassing a required guard or misbinding security state?

## Target
- File/function: `plugins/security-guidance/hooks/session_state.py` / `with_locked_state`
- Entrypoint: `state mutation under lock`
- Attacker controls: normal concurrent Claude Code activity in one repo
- Exploit idea: Drive `state mutation under lock` with attacker-controlled normal concurrent Claude Code activity in one repo and test whether `with_locked_state` changes security behavior in a way that cause one session to inherit allow, deny, or review state from another session.
- Invariant to test: state must stay isolated per session and repo
- Expected Immunefi impact: Logic-level service disruption caused by bypassing a required guard or misbinding security state
- Fast validation: run two sessions against crafted repos and assert warning counters, baselines, and pending state never cross-contaminate
