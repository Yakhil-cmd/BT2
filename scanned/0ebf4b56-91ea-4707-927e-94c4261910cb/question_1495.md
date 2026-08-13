# Q1495: Security-guidance diff state baseline shift via restore unreviewed stop state

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `restore_unreviewed_stop_state` via `retry after partial stop-hook failure` and control normal git operations in a cloned repo so that the codebase shift baseline state so the dangerous change is treated as old and skipped, breaking the invariant that the review set must stay bound to the right repo, baseline, and touched paths and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/security-guidance/hooks/diffstate.py` / `restore_unreviewed_stop_state`
- Entrypoint: `retry after partial stop-hook failure`
- Attacker controls: normal git operations in a cloned repo
- Exploit idea: Drive `retry after partial stop-hook failure` with attacker-controlled normal git operations in a cloned repo and test whether `restore_unreviewed_stop_state` changes security behavior in a way that shift baseline state so the dangerous change is treated as old and skipped.
- Invariant to test: the review set must stay bound to the right repo, baseline, and touched paths
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: create commit, amend, or untracked sequences that should remain reviewable and assert the computed review set still contains the dangerous file
