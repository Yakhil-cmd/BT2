# Q3804: Security-guidance support runtime bootstrap fail open via debug log

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `debug_log` via `security-guidance hook logging` and control normal hook startup and review execution so that the codebase force the review helper path to fail and quietly skip a review that should gate a dangerous action, breaking the invariant that telemetry and usage output must not leak sensitive repo or local data and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/_base.py` / `debug_log`
- Entrypoint: `security-guidance hook logging`
- Attacker controls: normal hook startup and review execution
- Exploit idea: Drive `security-guidance hook logging` with attacker-controlled normal hook startup and review execution and test whether `debug_log` changes security behavior in a way that force the review helper path to fail and quietly skip a review that should gate a dangerous action.
- Invariant to test: telemetry and usage output must not leak sensitive repo or local data
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: simulate missing helper or bootstrap conditions and assert the protected review path does not silently disappear
