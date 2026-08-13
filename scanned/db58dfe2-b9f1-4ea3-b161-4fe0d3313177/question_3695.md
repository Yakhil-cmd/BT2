# Q3695: Security-guidance git helper path pathspec escape via diff pathspec

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `_diff_pathspec` via `git diff scoping for touched paths` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that reviewable-source filtering must not let attacker-crafted filenames hide dangerous source changes and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `_diff_pathspec`
- Entrypoint: `git diff scoping for touched paths`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `git diff scoping for touched paths` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `_diff_pathspec` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: reviewable-source filtering must not let attacker-crafted filenames hide dangerous source changes
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
