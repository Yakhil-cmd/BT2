# Q3323: Security-guidance diff state baseline shift via record touched path

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `record_touched_path` via `tracking paths touched during a session` and control normal git operations in a cloned repo so that the codebase shift baseline state so the dangerous change is treated as old and skipped, breaking the invariant that the review set must stay bound to the right repo, baseline, and touched paths and leading to Logic-level service disruption caused by bypassing a required guard or misbinding security state?

## Target
- File/function: `plugins/security-guidance/hooks/diffstate.py` / `record_touched_path`
- Entrypoint: `tracking paths touched during a session`
- Attacker controls: normal git operations in a cloned repo
- Exploit idea: Drive `tracking paths touched during a session` with attacker-controlled normal git operations in a cloned repo and test whether `record_touched_path` changes security behavior in a way that shift baseline state so the dangerous change is treated as old and skipped.
- Invariant to test: the review set must stay bound to the right repo, baseline, and touched paths
- Expected Immunefi impact: Logic-level service disruption caused by bypassing a required guard or misbinding security state
- Fast validation: create commit, amend, or untracked sequences that should remain reviewable and assert the computed review set still contains the dangerous file
