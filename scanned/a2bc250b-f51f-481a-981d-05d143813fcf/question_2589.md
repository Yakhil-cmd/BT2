# Q2589: Security-guidance diff state baseline shift via save baseline sha

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `save_baseline_sha` via `UserPromptSubmit baseline capture` and control normal git operations in a cloned repo so that the codebase shift baseline state so the dangerous change is treated as old and skipped, breaking the invariant that the review set must stay bound to the right repo, baseline, and touched paths and leading to Security-control bypass that silently disables or routes around blocking, review, or permission boundaries?

## Target
- File/function: `plugins/security-guidance/hooks/diffstate.py` / `save_baseline_sha`
- Entrypoint: `UserPromptSubmit baseline capture`
- Attacker controls: normal git operations in a cloned repo
- Exploit idea: Drive `UserPromptSubmit baseline capture` with attacker-controlled normal git operations in a cloned repo and test whether `save_baseline_sha` changes security behavior in a way that shift baseline state so the dangerous change is treated as old and skipped.
- Invariant to test: the review set must stay bound to the right repo, baseline, and touched paths
- Expected Immunefi impact: Security-control bypass that silently disables or routes around blocking, review, or permission boundaries
- Fast validation: create commit, amend, or untracked sequences that should remain reviewable and assert the computed review set still contains the dangerous file
