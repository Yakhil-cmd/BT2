# Q23: Security-guidance support runtime bootstrap fail open via record usage

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `_record_usage` via `LLM usage accounting during review` and control normal hook startup and review execution so that the codebase force the review helper path to fail and quietly skip a review that should gate a dangerous action, breaking the invariant that review bootstrap and logging must not fail open on dangerous changes and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/_base.py` / `_record_usage`
- Entrypoint: `LLM usage accounting during review`
- Attacker controls: normal hook startup and review execution
- Exploit idea: Drive `LLM usage accounting during review` with attacker-controlled normal hook startup and review execution and test whether `_record_usage` changes security behavior in a way that force the review helper path to fail and quietly skip a review that should gate a dangerous action.
- Invariant to test: review bootstrap and logging must not fail open on dangerous changes
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: simulate missing helper or bootstrap conditions and assert the protected review path does not silently disappear
