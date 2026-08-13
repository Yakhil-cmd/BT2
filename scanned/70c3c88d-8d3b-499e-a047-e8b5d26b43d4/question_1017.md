# Q1017: Security-guidance git helper path pathspec escape via extract file paths from diff

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `extract_file_paths_from_diff` via `diff path extraction` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that git path scoping must never escape the intended repo target and leading to Unauthorized file read or write outside the user-approved workspace or target scope?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `extract_file_paths_from_diff`
- Entrypoint: `diff path extraction`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `diff path extraction` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `extract_file_paths_from_diff` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: git path scoping must never escape the intended repo target
- Expected Immunefi impact: Unauthorized file read or write outside the user-approved workspace or target scope
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
