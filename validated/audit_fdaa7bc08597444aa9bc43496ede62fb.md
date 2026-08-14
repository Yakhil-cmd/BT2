Based on my analysis of `plugins/security-guidance/hooks/gitutil.py`, this specific escape does not hold up.

**Key defenses already in place:**

1. **Symlink containment**: `_diff_pathspec` explicitly calls `os.path.realpath()` on both the `cwd` and each candidate path before computing `os.path.relpath`, and drops any result starting with `".."` — this is a deliberate anti-symlink-escape check (the comment even calls out the macOS `/var` ↔ `/private/var` case), so a symlink inside the repo pointing outside of it is resolved and excluded rather than passed through to `git diff`. [1](#0-0) 

2. **Unicode/special-char filenames**: The callers that build the file lists (`_git_name_only`, `_git_status_porcelain`) use `-c core.quotePath=false` with `-z`-delimited output, which is specifically designed to keep non-ASCII and space-containing paths intact rather than quoted/garbled — avoiding path-parsing mismatches that could otherwise cause a path to be miscategorized. [2](#0-1) [3](#0-2) 

3. **Nested worktrees**: `_find_git_index` and `_git_toplevel`/`_git_dir` explicitly use `git rev-parse --git-dir`, `--show-toplevel`, and `--git-common-dir` to correctly resolve the real index/root even when `.git` is a file pointing into a shared worktree gitdir — this is the standard, git-endorsed way to handle linked worktrees, not a bypassable heuristic. [4](#0-3) [5](#0-4) 

4. **Fail-closed behavior**: `get_git_diff` explicitly returns `""` (treated as "nothing to review") rather than falling back to an unrestricted diff when a caller passed specific paths but none survived the containment filter, which is the exact failure mode the code comment says it exists to prevent. [6](#0-5) 

5. **Read-only operation with isolated index**: `get_git_diff`/`_temp_index` only ever run `git diff`/`git add --intent-to-add` against a *temporary copy* of the index, never mutating the user's real index or writing files outside the temp file it creates and cleans up in a `finally` block — there is no file-write vector here at all, only a read-only diff computation.
<invoke name="read_file">
<parameter name="repo_name">Camomtat/claude-code--016</parameter>
<parameter name="file_path">plugins/security-guidance/hooks/gitutil.py</parameter>
<parameter name="start_line">91</parameter>
<parameter name="end_line">142</parameter>
</invoke>

### Citations

**File:** plugins/security-guidance/hooks/gitutil.py (L48-67)
```python
def _find_git_index(cwd):
    """
    Find the real index file for a git repo. Handles worktrees where .git
    is a file pointing to the main repo's gitdir.
    Returns the absolute path to the index file, or None.
    """
    try:
        result = subprocess.run(
            [*GIT_CMD, "rev-parse", "--git-dir"],
            cwd=cwd, capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return None
        git_dir = result.stdout.strip()
        if not os.path.isabs(git_dir):
            git_dir = os.path.join(cwd, git_dir)
        index_path = os.path.join(git_dir, "index")
        return index_path if os.path.isfile(index_path) else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
```

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

**File:** plugins/security-guidance/hooks/gitutil.py (L144-176)
```python
def _git_toplevel(cwd):
    """Absolute repo root for `cwd`, or None if not in a work tree."""
    try:
        r = subprocess.run(
            [*GIT_CMD, "rev-parse", "--show-toplevel"],
            cwd=cwd, capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _git_dir(repo_root):
    """Absolute shared `.git` directory for repo_root.

    Uses `rev-parse --git-common-dir` so linked worktrees resolve to the
    SHARED gitdir, not the per-worktree `.git/worktrees/<name>/`. That way
    push-sweep's reviewed-shas record (and the bash-hook-once sentinel)
    is per-clone — a commit reviewed in one worktree counts as reviewed
    if a different worktree later pushes it. Returns None on failure so
    callers can degrade (push-sweep state is best-effort).
    """
    try:
        r = subprocess.run(
            [*GIT_CMD, "rev-parse", "--git-common-dir"],
            cwd=repo_root, capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return None
        d = r.stdout.strip()
        return d if os.path.isabs(d) else os.path.join(repo_root, d)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
```

**File:** plugins/security-guidance/hooks/gitutil.py (L303-318)
```python
def _git_name_only(cwd, base, include_untracked=False):
    """Return the set of repo-root-relative paths that differ from `base`,
    or None if git failed (unresolvable ref, not a repo, timeout). Callers
    must distinguish None (error → don't trust as a filter) from set()
    (genuinely nothing changed). `-c core.quotePath=false -z` keeps non-ASCII
    and space-containing paths intact."""
    def _run(env):
        result = subprocess.run(
            [*GIT_CMD, "-c", "core.quotePath=false", "diff", "--name-only", "-z", base],
            cwd=cwd, capture_output=True, text=True, timeout=30,
            env=env,
        )
        if result.returncode != 0:
            debug_log(f"_git_name_only({base!r}) rc={result.returncode}: {result.stderr[:200]}")
            return None
        return {p for p in result.stdout.split("\0") if p}
```

**File:** plugins/security-guidance/hooks/gitutil.py (L330-345)
```python
def _git_status_porcelain(cwd):
    """One `git status --porcelain=v1 -z` → (tracked_dirty, untracked) sets of
    repo-root-relative paths, or (None, None) on error. Replaces the
    `_temp_index + git diff HEAD --name-only` pair for the v2 dirty_now
    computation: faster in large repos, and yields the
    untracked set separately so the later get_git_diff can do a targeted
    `add -N -- <files>` instead of a whole-tree `add -N .`.

    -uall: list individual files inside untracked directories (default
    collapses to `dir/`). Required so the untracked set subtracts cleanly
    against the UPS-time `_list_untracked` snapshot, which uses ls-files and
    therefore always lists individual files."""
    try:
        r = subprocess.run(
            [*GIT_CMD, "-c", "core.quotePath=false", "status",
             "--porcelain=v1", "-uall", "-z"],
```

**File:** plugins/security-guidance/hooks/gitutil.py (L406-412)
```python
    pathspec = _diff_pathspec(cwd, paths)
    if paths and not pathspec:
        # Caller restricted to specific paths but none are inside this repo
        # (e.g. only ~/.claude/... edits). Returning "" flows to skip(6); an
        # empty pathspec would mean an UNRESTRICTED diff — the bug this whole
        # change exists to fix.
        return ""
```
