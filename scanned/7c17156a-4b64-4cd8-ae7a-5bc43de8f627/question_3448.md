# Q3448: Security-guidance diff state baseline shift via get baseline file content

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `get_baseline_file_content` via `baseline content lookup during review` and control normal git operations in a cloned repo so that the codebase shift baseline state so the dangerous change is treated as old and skipped, breaking the invariant that the review set must stay bound to the right repo, baseline, and touched paths and leading to Logic-level service disruption caused by bypassing a required guard or misbinding security state?

## Target
- File/function: `plugins/security-guidance/hooks/diffstate.py` / `get_baseline_file_content`
- Entrypoint: `baseline content lookup during review`
- Attacker controls: normal git operations in a cloned repo
- Exploit idea: Drive `baseline content lookup during review` with attacker-controlled normal git operations in a cloned repo and test whether `get_baseline_file_content` changes security behavior in a way that shift baseline state so the dangerous change is treated as old and skipped.
- Invariant to test: the review set must stay bound to the right repo, baseline, and touched paths
- Expected Immunefi impact: Logic-level service disruption caused by bypassing a required guard or misbinding security state
- Fast validation: create commit, amend, or untracked sequences that should remain reviewable and assert the computed review set still contains the dangerous file
