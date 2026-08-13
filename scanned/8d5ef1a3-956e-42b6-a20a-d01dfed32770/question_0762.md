# Q762: Security-guidance diff state baseline shift via consume stop state

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `consume_stop_state` via `Stop-hook review-set computation` and control normal git operations in a cloned repo so that the codebase shift baseline state so the dangerous change is treated as old and skipped, breaking the invariant that the review set must stay bound to the right repo, baseline, and touched paths and leading to Unauthorized file read or write outside the user-approved workspace or target scope?

## Target
- File/function: `plugins/security-guidance/hooks/diffstate.py` / `consume_stop_state`
- Entrypoint: `Stop-hook review-set computation`
- Attacker controls: normal git operations in a cloned repo
- Exploit idea: Drive `Stop-hook review-set computation` with attacker-controlled normal git operations in a cloned repo and test whether `consume_stop_state` changes security behavior in a way that shift baseline state so the dangerous change is treated as old and skipped.
- Invariant to test: the review set must stay bound to the right repo, baseline, and touched paths
- Expected Immunefi impact: Unauthorized file read or write outside the user-approved workspace or target scope
- Fast validation: create commit, amend, or untracked sequences that should remain reviewable and assert the computed review set still contains the dangerous file
