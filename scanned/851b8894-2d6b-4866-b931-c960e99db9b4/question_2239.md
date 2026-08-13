# Q2239: Security-guidance git helper path pathspec escape via filter preexisting from diff

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `filter_preexisting_from_diff` via `new-vs-preexisting change filtering` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that git path scoping must never escape the intended repo target and leading to Cross-repo, cross-session, or wrong-target mutation with real security impact?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `filter_preexisting_from_diff`
- Entrypoint: `new-vs-preexisting change filtering`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `new-vs-preexisting change filtering` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `filter_preexisting_from_diff` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: git path scoping must never escape the intended repo target
- Expected Immunefi impact: Cross-repo, cross-session, or wrong-target mutation with real security impact
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
