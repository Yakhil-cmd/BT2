# Q3701: Security-guidance git helper path pathspec escape via extract file paths from diff

## Question
Can an unprivileged attacker through a normal cloned-repo workflow reach `extract_file_paths_from_diff` via `diff path extraction` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that reviewable-source filtering must not let attacker-crafted filenames hide dangerous source changes and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `extract_file_paths_from_diff`
- Entrypoint: `diff path extraction`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `diff path extraction` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `extract_file_paths_from_diff` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: reviewable-source filtering must not let attacker-crafted filenames hide dangerous source changes
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
