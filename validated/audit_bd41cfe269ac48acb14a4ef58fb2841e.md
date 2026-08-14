### Title
Unescaped repo-controlled filenames enable git pathspec glob/magic injection that widens `get_git_diff` scope beyond intended paths - (File: plugins/security-guidance/hooks/gitutil.py)

### Summary
`_diff_pathspec`, used by `get_git_diff` to restrict `git diff` to the security-review file set, converts attacker-controllable repo file paths into raw `git diff -- <pathspec>` arguments without neutralizing git's pathspec wildcard/magic syntax. A repo-controlled filename containing glob characters (`*`, `?`, `[...]`) or a leading `:` (pathspec magic marker) can broaden or redirect the diff match beyond the single intended file, causing files outside the intended `review_paths`/`untracked_paths` scope to be included in the diff text that is subsequently sent to the remote LLM review sink.

### Finding Description
`get_git_diff(cwd, baseline_sha, ..., paths=review_paths, untracked_paths=untracked)` builds its `git diff` invocation via `_diff_pathspec`: [1](#0-0) 

This function only resolves symlinks with `os.path.realpath` and rejects paths whose relative form escapes `cwd` via a leading `..` — it defends against directory traversal, but it does **not** escape or neutralize git pathspec special syntax before splicing the resulting strings after `--` in the `git diff` command: [2](#0-1) 

Git treats arguments after `--` as pathspecs, not literal filenames, by default: leading `*`, `?`, `[...]` act as shell-style globs (which git's wildmatch can match across path components), and a leading `:` triggers pathspec "magic" (e.g. `:(top)`, `:(icase)`, `:(exclude)`, `:!pattern`, `:/pattern`). Nowhere in `GIT_CMD` or in `get_git_diff`/`_diff_pathspec` is `--literal-pathspecs`, `GIT_LITERAL_PATHSPECS=1`, or `--` per-path quoting/`:(literal)` prefixing applied to counteract this: [3](#0-2) 

The path list fed into `get_git_diff` originates from `compute_v2_review_set`, which derives `review_paths` and the untracked subset directly from `git status`/`git diff --name-only` output on real repo-worktree filenames — fully attacker-controlled if the attacker can add/rename a file in the repo (a normal, unprivileged clone workflow: adding a file named e.g. `*`, `?`, or one beginning with `:`): [4](#0-3) 

These `review_paths` flow into `get_git_diff` in the Stop-hook path: [5](#0-4) 

Because `_diff_pathspec` passes the crafted filename through unmodified, `git diff -- <crafted-name>` no longer scopes the diff to exactly that file: a bare `*`/`?`/`[...]` name causes wildcard matching of arbitrary sibling paths in the tree, and a `:`-prefixed name is parsed as pathspec magic (`:(top)`, `:(icase)`, `:(exclude)`, etc.), changing match semantics rather than matching the literal file. Since `full_context=False` diffs (and later `full_context=True` variants) are fed to `parse_diff_into_files` and ultimately shipped to the Anthropic API for LLM review, any unintended files pulled into scope by this pathspec-widening are disclosed to that external sink — including files that were never part of `review_paths`/`untracked_paths`, defeating the intended repo/path scoping invariant asserted in the module's own comments (`_diff_pathspec` docstring, `get_git_diff` docstring).

### Impact Explanation
This breaks the "git path scoping must never escape the intended repo target" invariant: content from files outside the intended, security-reviewed change set can be pulled into the diff and transmitted to the remote LLM review endpoint, an unintended sink. This matches the stated Immunefi impact category of "Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink." The severity is bounded by the fact that only files within the same git worktree (not outside it — the realpath/`..`-prefix check does correctly block traversal outside `cwd`) can be pulled in, but that is still a scope violation relative to the intended per-turn/per-commit review set, and can expose files the reviewing/review-triggering user did not intend to expose (e.g. other dirty/untracked files with secrets sitting in the same worktree).

### Likelihood Explanation
Exploitation only requires the ability to add a file with a specially-crafted name to the repository being reviewed — no elevated privileges, no admin/maintainer access, and no social engineering are needed, matching the "unprivileged attacker via normal cloned-repo workflow" threat model. The Stop hook and commit-review diff-collection flow runs automatically on ordinary edit/commit turns, so simply creating or modifying such a file during a session is sufficient to trigger `get_git_diff` with the malicious path in `review_paths`/`untracked_paths`. This is reliably repeatable since the vulnerable code path (`_diff_pathspec` → `get_git_diff`) is deterministic and always invoked on Stop with a non-empty review set.

### Recommendation
Neutralize git pathspec magic in `_diff_pathspec` before returning relative paths: either invoke git with `--literal-pathspecs` (or set `GIT_LITERAL_PATHSPECS=1` in the subprocess environment) for all `git diff`/`git diff --name-only` calls in `gitutil.py`, or explicitly prefix every computed relative path with the `:(literal)` pathspec magic (e.g. `f":(literal){r}"`) so that filenames are matched exactly rather than interpreted as globs or magic keywords. Apply the same fix consistently to `_git_name_only` and any other function that splices repo-derived filenames into a `git` pathspec position.

### Proof of Concept
Unit test plan for `plugins/security-guidance/hooks/gitutil.py`:
1. Create a temp git repo; commit an initial file `secret.txt` with sentinel content `SECRET_MARKER`, plus a baseline commit SHA.
2. Create a second file whose name is a glob/magic pathspec character, e.g. `*` (or `?`, or a file literally named `:(top)x` depending on OS filename restrictions), and modify `secret.txt` so it becomes "dirty" but is NOT included in `review_paths`.
3. Call `get_git_diff(repo_root, baseline_sha, paths=[<path to the glob-named file only>], untracked_paths=[])`.
4. Assert (expected/failing invariant): the returned diff text should contain changes ONLY for the glob-named file, but due to the unescaped pathspec, `secret.txt`'s changes (or `SECRET_MARKER`) also appear in the diff output — demonstrating pathspec-driven scope escape.
5. Repeat with `--literal-pathspecs` (or `:(literal)` prefixing) applied as the fix, and assert the diff now contains only the single intended file's changes, confirming the fix closes the escape.

### Citations

**File:** plugins/security-guidance/hooks/gitutil.py (L25-29)
```python
GIT_CMD = [
    "git",
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=/dev/null",
]
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

**File:** plugins/security-guidance/hooks/gitutil.py (L391-419)
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
    try:
        with _temp_index(cwd, untracked_paths) as env:
            # env is None when no index could be found (bare repo / not a
            # repo) — diff still runs, just without untracked-file support.
            result = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=30, env=env)
```

**File:** plugins/security-guidance/hooks/diffstate.py (L375-428)
```python
    repo_root is the git toplevel — `git diff --name-only` outputs paths
    relative to it (not to cwd), so the caller's get_git_diff must run
    from there too or pathspecs won't match.

    Also returns the untracked subset of review_set so get_git_diff can do
    a targeted `add -N -- <files>` instead of a whole-tree scan.
    """
    repo = _git_toplevel(cwd) or cwd
    if not isinstance(untracked_at_baseline, dict):
        untracked_at_baseline = {}

    tracked_dirty, untracked = _git_status_porcelain(repo)
    if tracked_dirty is None:
        return [], "HEAD", repo, [], {"dirty_now_count": -1, "changed_since_count": -1, "review_set_count": 0}

    def _unchanged_since_baseline(p):
        base_mtime = untracked_at_baseline.get(p)
        if base_mtime is None:
            return False
        try:
            return os.stat(os.path.join(repo, p)).st_mtime_ns == base_mtime
        except OSError:
            return False

    preexisting_unchanged = {p for p in untracked if _unchanged_since_baseline(p)}
    new_untracked = untracked - preexisting_unchanged
    dirty_now = tracked_dirty | new_untracked

    diff_base = "HEAD"
    current_head = _git_rev_parse_head(repo)
    if (head_at_capture and current_head and head_at_capture != current_head
            and _is_ancestor(repo, head_at_capture, current_head)):
        dirty_now |= _git_name_only(repo, f"{head_at_capture}..HEAD") or set()
        diff_base = head_at_capture

    # changed_since: tracked files vs the stash baseline (no temp index — the
    # stash never contained untracked files anyway), then union with
    # currently-untracked. The previous `include_untracked=True` arm cost a
    # full `git add -N .` (slow in large repos) per call to surface
    # untracked files in the diff output — but `git diff <stash>` already
    # lists them as "only in worktree" without that, and we have the explicit
    # set from status regardless.
    if baseline_sha:
        changed_since = _git_name_only(repo, baseline_sha)
        if changed_since is not None:
            changed_since |= new_untracked
    else:
        changed_since = None
    # changed_since is None on missing baseline OR on git error (e.g. the
    # dangling stash SHA was pruned). Either way, don't intersect with ∅ —
    # that would silently zero the review set. Fall back to dirty_now.
    review_set = (dirty_now & changed_since) if changed_since is not None else dirty_now

    review_paths = [os.path.join(repo, p) for p in sorted(review_set)]
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1792-1813)
```python
    review_paths, diff_base, repo_root, untracked, v2_metrics = compute_v2_review_set(
        cwd, baseline_sha, head_at_capture, untracked_at_baseline
    )
    if not review_paths:
        debug_log("Stop hook: empty review set")
        _skip(9, touched_paths_count=len(touched_paths))
    debug_log(f"Stop hook: review_set={len(review_paths)} base={diff_base[:12]} dirty_now={v2_metrics['dirty_now_count']} changed_since={v2_metrics['changed_since_count']}")
    # Run from repo_root so the toplevel-relative review_paths resolve.
    # Diff CONTENT against the turn-start stash (baseline_sha) so the LLM
    # sees only this-turn edits — diffing against HEAD includes the user's
    # pre-turn uncommitted WIP, which inflates review_ms and can re-flag
    # the same pre-existing pattern every turn. The file LIST still comes
    # from git state (compute_v2_review_set), so Bash/subagent edits are
    # caught either way. Fall back to diff_base (HEAD/head_at_capture)
    # when the stash is missing or pruned.
    content_base = baseline_sha or diff_base
    diff_output = get_git_diff(repo_root, content_base, full_context=False,
                               paths=review_paths, untracked_paths=untracked)
    if diff_output is None and content_base != diff_base:
        debug_log(f"Stop hook: diff against {content_base[:12]} failed — falling back to {diff_base}")
        diff_output = get_git_diff(repo_root, diff_base, full_context=False,
                                   paths=review_paths, untracked_paths=untracked)
```
