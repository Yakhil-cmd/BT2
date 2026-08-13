# Q3811: Security-guidance diff state baseline shift via record touched path

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `record_touched_path` via `tracking paths touched during a session` and control normal git operations in a cloned repo so that the codebase shift baseline state so the dangerous change is treated as old and skipped, breaking the invariant that an attacker must not hide a dangerous change by shifting it outside the computed review window and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/diffstate.py` / `record_touched_path`
- Entrypoint: `tracking paths touched during a session`
- Attacker controls: normal git operations in a cloned repo
- Exploit idea: Drive `tracking paths touched during a session` with attacker-controlled normal git operations in a cloned repo and test whether `record_touched_path` changes security behavior in a way that shift baseline state so the dangerous change is treated as old and skipped.
- Invariant to test: an attacker must not hide a dangerous change by shifting it outside the computed review window
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: create commit, amend, or untracked sequences that should remain reviewable and assert the computed review set still contains the dangerous file
