# Q891: Security-guidance git helper path pathspec escape via git toplevel

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `_git_toplevel` via `repo-root detection` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that git path scoping must never escape the intended repo target and leading to Unauthorized file read or write outside the user-approved workspace or target scope?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `_git_toplevel`
- Entrypoint: `repo-root detection`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `repo-root detection` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `_git_toplevel` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: git path scoping must never escape the intended repo target
- Expected Immunefi impact: Unauthorized file read or write outside the user-approved workspace or target scope
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
