### Title
Filenames beginning with `..` are silently dropped from the git-diff pathspec, hiding attacker-controlled source changes from security review - ([File: plugins/security-guidance/hooks/gitutil.py])

### Finding Description
`_diff_pathspec` is meant to convert absolute touched-paths into repo-relative git pathspecs, dropping only paths that truly resolve *outside* the repo (e.g. `~/.claude/...`). Its exclusion test is a naive string check: [1](#0-0) 

```python
r = os.path.relpath(os.path.realpath(p), cwd_abs)
...
if r.startswith(".."):
    continue
rel.append(r)
```

`os.path.relpath` returns a leading `..` component only when the target is a true ancestor-escape (e.g. `../../etc/passwd`), but the check uses `str.startswith("..")` rather than verifying `..` as a discrete path *component*. Any legitimately tracked file whose basename literally begins with the two characters `..` — e.g. `..evil.py`, `...bak.js`, `..config.py` at the repo root — produces a relative path string like `..evil.py`, which also satisfies `.startswith("..")` even though the file is entirely inside the repository.

This path is reached from the normal review flow: `compute_v2_review_set` (in `diffstate.py`) builds `review_paths` from `git status`/`git diff --name-only`, which happily includes such a file once it's tracked and dirtied. The Stop hook then calls `get_git_diff(repo_root, content_base, paths=review_paths, ...)`, which calls `_diff_pathspec` to build the pathspec for the actual `git diff` invocation used for the security review: [2](#0-1) 

Because the wrongly-classified file is dropped from the `["--"] + rel` pathspec, the subsequent `git diff ... -- <pathspec>` command silently excludes it from `diff_output`. `parse_diff_into_files`/`extract_file_paths_from_diff` never see the file's diff at all, so `analyze_code_security`/the LLM-based review never inspects its content — even though `_is_reviewable_source` would otherwise classify it as a normal source file. No later stage re-checks that every entry in `review_paths` made it into the diff.

### Impact Explanation
An attacker who can write files inside the working repository (a normal, unprivileged capability via Write/Edit tool calls) can name a source file `..payload.py` (or any name whose first two characters are `..`) at the repo root, put dangerous code in it (e.g. a backdoored shell invocation, credential exfiltration, or a supply-chain-poisoning change), and have that change committed/staged as part of a turn. Because `_diff_pathspec` drops it from the pathspec, the security-guidance Stop/PostToolUse hooks compute an empty or partial diff that never includes this file, so `analyze_code_security`/agentic review finds nothing to flag — the dangerous change bypasses the security reminder entirely while remaining fully present in the actual working tree/commit, later executed or approved as if it had been reviewed. This matches "Unauthorized local command execution that bypasses Claude Code approval or deny controls," since the hook's review — which gates further reminders/warnings — is defeated by filename choice alone.

### Likelihood Explanation
This requires no special privilege beyond normal repository write access, which any turn already has (Write/Edit/Bash tool calls). Creating a filename starting with `..` is a trivial, fully attacker-controlled, deterministic action — no race condition, no symlink trickery, and no reliance on OS-specific quirks; it reproduces on every OS/git version since it's a pure string-prefix bug in `_diff_pathspec`. This makes it highly repeatable.

### Recommendation
Replace the substring check with a component-based check that only rejects genuine ancestor escapes, e.g.:
```python
parts = r.split(os.sep)
if r == os.pardir or parts[0] == os.pardir:
    continue
```
or use `os.path.commonpath([cwd_abs, os.path.realpath(p)]) == cwd_abs` / `Path(...).is_relative_to(cwd_abs)` (Python 3.9+) instead of string prefix matching, so filenames merely *starting with* `..` are treated as in-scope.

### Proof of Concept
Unit test plan for `gitutil._diff_pathspec` / `gitutil.get_git_diff`:
1. Create a temp git repo, `git init`, commit an initial file.
2. Create `..evil.py` at repo root containing a security-relevant pattern (e.g. `os.system(user_input)`), `git add` and commit it as the baseline, then modify its content (append a new dangerous line) to simulate an in-turn edit.
3. Call `paths = [os.path.join(repo, "..evil.py")]` and `pathspec = _diff_pathspec(repo, paths)`.
   - Expected (buggy) result: `pathspec == []` (the file is incorrectly excluded) even though `os.path.realpath(".. evil.py")` is strictly inside `repo`.
   - Expected (fixed) result: `pathspec == ["--", "..evil.py"]`.
4. Call `get_git_diff(repo, "HEAD", paths=paths)` and assert:
   - Buggy behavior: returns `""` (or a diff missing `..evil.py`), i.e., the dangerous edit is absent from `diff_output`.
   - Fixed behavior: `diff_output` contains the `..evil.py` diff with the injected dangerous line, confirming the file re-enters the reviewable set.

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

**File:** plugins/security-guidance/hooks/gitutil.py (L391-414)
```python
def get_git_diff(cwd, baseline_sha, full_context=False, paths=None, untracked_paths=None):
    """
    Get the git diff between the baseline SHA and the current working tree,
    including untracked (new) files.

    Uses a temporary copy of the git index (GIT_INDEX_FILE) so the user's
    real index is never modified. The temp index gets intent-to-add entries
    for untracked files, making them visible in the diff output. Cleanup
    is just deleting the temp file in a finally block.

    If `paths` is given, the diff is restricted to those paths (relative to
    cwd; absolute paths are converted, paths outside cwd are dropped).
    `untracked_paths` (repo-root-relative) is forwarded to _temp_index so it
    can add only those files instead of scanning the whole worktree.
    """
    pathspec = _diff_pathspec(cwd, paths)
    if paths and not pathspec:
        # Caller restricted to specific paths but none are inside this repo
        # (e.g. only ~/.claude/... edits). Returning "" flows to skip(6); an
        # empty pathspec would mean an UNRESTRICTED diff — the bug this whole
        # change exists to fix.
        return ""

    cmd = [*GIT_CMD, "diff", "--no-color", "--no-ext-diff", baseline_sha] + (["--unified=99999"] if full_context else []) + pathspec
```
