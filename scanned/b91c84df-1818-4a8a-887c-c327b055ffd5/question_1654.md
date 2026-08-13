# Q1654: Security-guidance support runtime bootstrap fail open via main

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `main` via `security-guidance Agent SDK bootstrap` and control normal hook startup and review execution so that the codebase force the review helper path to fail and quietly skip a review that should gate a dangerous action, breaking the invariant that review bootstrap and logging must not fail open on dangerous changes and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/security-guidance/hooks/ensure_agent_sdk.py` / `main`
- Entrypoint: `security-guidance Agent SDK bootstrap`
- Attacker controls: normal hook startup and review execution
- Exploit idea: Drive `security-guidance Agent SDK bootstrap` with attacker-controlled normal hook startup and review execution and test whether `main` changes security behavior in a way that force the review helper path to fail and quietly skip a review that should gate a dangerous action.
- Invariant to test: review bootstrap and logging must not fail open on dangerous changes
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: simulate missing helper or bootstrap conditions and assert the protected review path does not silently disappear
