# Q3813: Security-guidance diff state baseline shift via restore unreviewed stop state

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `restore_unreviewed_stop_state` via `retry after partial stop-hook failure` and control normal git operations in a cloned repo so that the codebase shift baseline state so the dangerous change is treated as old and skipped, breaking the invariant that an attacker must not hide a dangerous change by shifting it outside the computed review window and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/diffstate.py` / `restore_unreviewed_stop_state`
- Entrypoint: `retry after partial stop-hook failure`
- Attacker controls: normal git operations in a cloned repo
- Exploit idea: Drive `retry after partial stop-hook failure` with attacker-controlled normal git operations in a cloned repo and test whether `restore_unreviewed_stop_state` changes security behavior in a way that shift baseline state so the dangerous change is treated as old and skipped.
- Invariant to test: an attacker must not hide a dangerous change by shifting it outside the computed review window
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: create commit, amend, or untracked sequences that should remain reviewable and assert the computed review set still contains the dangerous file
