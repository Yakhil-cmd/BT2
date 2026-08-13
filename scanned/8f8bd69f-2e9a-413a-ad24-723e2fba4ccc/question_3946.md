# Q3946: Security-guidance git helper path pathspec escape via parse diff into files

## Question
Can an unprivileged attacker using only repository-controlled content and standard command inputs reach `parse_diff_into_files` via `diff file splitting for review` and control repo-controlled file paths, symlinks, unicode names, and nested worktree layouts so that the codebase craft paths that fall outside the intended repo diff scope while still influencing the review call, breaking the invariant that reviewable-source filtering must not let attacker-crafted filenames hide dangerous source changes and leading to Unauthorized local command execution that bypasses Claude Code approval or deny controls?

## Target
- File/function: `plugins/security-guidance/hooks/gitutil.py` / `parse_diff_into_files`
- Entrypoint: `diff file splitting for review`
- Attacker controls: repo-controlled file paths, symlinks, unicode names, and nested worktree layouts
- Exploit idea: Drive `diff file splitting for review` with attacker-controlled repo-controlled file paths, symlinks, unicode names, and nested worktree layouts and test whether `parse_diff_into_files` changes security behavior in a way that craft paths that fall outside the intended repo diff scope while still influencing the review call.
- Invariant to test: reviewable-source filtering must not let attacker-crafted filenames hide dangerous source changes
- Expected Immunefi impact: Unauthorized local command execution that bypasses Claude Code approval or deny controls
- Fast validation: exercise pathspec and diff parsing with weird but valid git filenames and verify the intended source file remains in scope
