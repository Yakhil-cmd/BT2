# Q3576: Security-guidance git helper path pathspec escape via git dir

## Question
Can an unprivileged attacker while staying inside the public, unprivileged attacker model reach `_git_dir` via `shared gitdir resolution` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that git path scoping must never escape the intended repo target and leading to Logic-level service disruption caused by bypassing a required guard or misbinding security state?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `_git_dir`
- Entrypoint: `shared gitdir resolution`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `shared gitdir resolution` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `_git_dir` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: git path scoping must never escape the intended repo target
- Expected Immunefi impact: Logic-level service disruption caused by bypassing a required guard or misbinding security state
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
