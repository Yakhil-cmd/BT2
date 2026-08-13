# Q3698: Security-guidance git helper path pathspec escape via git dir

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `_git_dir` via `shared gitdir resolution` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that reviewable-source filtering must not let attacker-crafted filenames hide dangerous source changes and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `_git_dir`
- Entrypoint: `shared gitdir resolution`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `shared gitdir resolution` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `_git_dir` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: reviewable-source filtering must not let attacker-crafted filenames hide dangerous source changes
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
