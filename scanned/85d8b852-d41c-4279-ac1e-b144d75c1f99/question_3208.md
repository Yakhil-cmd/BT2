# Q3208: Security-guidance git helper path pathspec escape via temp index

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `_temp_index` via `untracked-file inclusion for diff review` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that git path scoping must never escape the intended repo target and leading to Logic-level service disruption caused by bypassing a required guard or misbinding security state?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `_temp_index`
- Entrypoint: `untracked-file inclusion for diff review`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `untracked-file inclusion for diff review` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `_temp_index` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: git path scoping must never escape the intended repo target
- Expected Immunefi impact: Logic-level service disruption caused by bypassing a required guard or misbinding security state
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
