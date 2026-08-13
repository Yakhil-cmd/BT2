# Q1625: Security-guidance git helper path pathspec escape via get git diff

## Question
Can an unprivileged attacker without maintainer, admin, or leaked-credential assumptions reach `get_git_diff` via `Stop-hook and commit-review diff collection` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that git path scoping must never escape the intended repo target and leading to Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `get_git_diff`
- Entrypoint: `Stop-hook and commit-review diff collection`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `Stop-hook and commit-review diff collection` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `get_git_diff` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: git path scoping must never escape the intended repo target
- Expected Immunefi impact: Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
