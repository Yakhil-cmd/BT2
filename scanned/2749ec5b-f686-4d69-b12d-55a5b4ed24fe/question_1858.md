# Q1858: Security-guidance diff state baseline shift via load baseline sha

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `load_baseline_sha` via `Stop-hook diff selection` and control normal git operations in a cloned repo so that the codebase shift baseline state so the dangerous change is treated as old and skipped, breaking the invariant that the review set must stay bound to the right repo, baseline, and touched paths and leading to Cross-repo, cross-session, or wrong-target mutation with real security impact?

## Target
- File/function: `plugins/security-guidance/hooks/diffstate.py` / `load_baseline_sha`
- Entrypoint: `Stop-hook diff selection`
- Attacker controls: normal git operations in a cloned repo
- Exploit idea: Drive `Stop-hook diff selection` with attacker-controlled normal git operations in a cloned repo and test whether `load_baseline_sha` changes security behavior in a way that shift baseline state so the dangerous change is treated as old and skipped.
- Invariant to test: the review set must stay bound to the right repo, baseline, and touched paths
- Expected Immunefi impact: Cross-repo, cross-session, or wrong-target mutation with real security impact
- Fast validation: create commit, amend, or untracked sequences that should remain reviewable and assert the computed review set still contains the dangerous file
