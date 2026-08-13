# Q1620: Security-guidance diff state baseline shift via compute v2 review set

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `compute_v2_review_set` via `Stop-hook reviewed file selection` and control normal git operations in a cloned repo so that the codebase shift baseline state so the dangerous change is treated as old and skipped, breaking the invariant that the review set must stay bound to the right repo, baseline, and touched paths and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/security-guidance/hooks/diffstate.py` / `compute_v2_review_set`
- Entrypoint: `Stop-hook reviewed file selection`
- Attacker controls: normal git operations in a cloned repo
- Exploit idea: Drive `Stop-hook reviewed file selection` with attacker-controlled normal git operations in a cloned repo and test whether `compute_v2_review_set` changes security behavior in a way that shift baseline state so the dangerous change is treated as old and skipped.
- Invariant to test: the review set must stay bound to the right repo, baseline, and touched paths
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: create commit, amend, or untracked sequences that should remain reviewable and assert the computed review set still contains the dangerous file
