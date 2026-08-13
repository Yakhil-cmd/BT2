# Q3207: Security-guidance git helper path pathspec escape via diff pathspec

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `_diff_pathspec` via `git diff scoping for touched paths` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that git path scoping must never escape the intended repo target and leading to Logic-level service disruption caused by bypassing a required guard or misbinding security state?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `_diff_pathspec`
- Entrypoint: `git diff scoping for touched paths`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `git diff scoping for touched paths` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `_diff_pathspec` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: git path scoping must never escape the intended repo target
- Expected Immunefi impact: Logic-level service disruption caused by bypassing a required guard or misbinding security state
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
