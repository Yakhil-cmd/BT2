# Q2752: Security-guidance support runtime bootstrap fail open via main

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `main` via `security-guidance Agent SDK bootstrap` and control normal hook startup and review execution so that the codebase force the review helper path to fail and quietly skip a review that should gate a dangerous action, breaking the invariant that review bootstrap and logging must not fail open on dangerous changes and leading to Security-control bypass that silently disables or routes around blocking, review, or permission boundaries?

## Target
- File/function: `plugins/security-guidance/hooks/ensure_agent_sdk.py` / `main`
- Entrypoint: `security-guidance Agent SDK bootstrap`
- Attacker controls: normal hook startup and review execution
- Exploit idea: Drive `security-guidance Agent SDK bootstrap` with attacker-controlled normal hook startup and review execution and test whether `main` changes security behavior in a way that force the review helper path to fail and quietly skip a review that should gate a dangerous action.
- Invariant to test: review bootstrap and logging must not fail open on dangerous changes
- Expected Immunefi impact: Security-control bypass that silently disables or routes around blocking, review, or permission boundaries
- Fast validation: simulate missing helper or bootstrap conditions and assert the protected review path does not silently disappear
