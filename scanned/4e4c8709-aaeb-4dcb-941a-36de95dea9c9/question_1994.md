# Q1994: Security-guidance git helper path pathspec escape via parse diff into files

## Question
Can an unprivileged attacker without any local shell access beyond what Claude Code normally receives reach `parse_diff_into_files` via `diff file splitting for review` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that git path scoping must never escape the intended repo target and leading to Cross-repo, cross-session, or wrong-target mutation with real security impact?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `parse_diff_into_files`
- Entrypoint: `diff file splitting for review`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `diff file splitting for review` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `parse_diff_into_files` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: git path scoping must never escape the intended repo target
- Expected Immunefi impact: Cross-repo, cross-session, or wrong-target mutation with real security impact
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
