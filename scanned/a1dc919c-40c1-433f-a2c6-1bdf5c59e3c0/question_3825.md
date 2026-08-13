# Q3825: Security-guidance git helper path pathspec escape via filter preexisting from diff

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `filter_preexisting_from_diff` via `new-vs-preexisting change filtering` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that reviewable-source filtering must not let attacker-crafted filenames hide dangerous source changes and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `filter_preexisting_from_diff`
- Entrypoint: `new-vs-preexisting change filtering`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `new-vs-preexisting change filtering` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `filter_preexisting_from_diff` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: reviewable-source filtering must not let attacker-crafted filenames hide dangerous source changes
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
