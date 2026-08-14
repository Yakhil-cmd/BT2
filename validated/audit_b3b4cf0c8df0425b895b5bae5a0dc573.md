### Title
Attacker-controlled untracked filenames with git pathspec-magic prefixes can break `get_git_diff`'s single batched invocation and suppress security review of unrelated malicious files - (File: plugins/security-guidance/hooks/gitutil.py)

### Summary
`_diff_pathspec` (used by `get_git_diff`, which wraps every diff review with `_temp_index`) converts touched/untracked repo paths into raw pathspec arguments without neutralizing git's pathspec "magic" syntax (leading `:`, `:(exclude)`, `:!`, `:^`, etc.). Because all reviewed paths for a Stop-hook/commit-review pass are supplied as a single `git diff -- <path1> <path2> ...` invocation, one attacker-crafted filename with pathspec-magic meaning can make the whole `git diff` call fail or match a different scope than intended, which can suppress review output for every file in that batch — including genuinely dangerous, unrelated source changes.

### Finding Description
`_temp_index` in `plugins/security-guidance/hooks/gitutil.py` (lines 91-141) is the mechanism that stages untracked files with `git add --intent-to-add -- <surviving paths>` into a throwaway index so they appear in subsequent `git diff` calls [1](#0-0) . The paths it adds come straight from repo-controlled filenames discovered by `_git_status_porcelain`/`_list_untracked` (both correctly `-z`/NUL-delimited so unicode/space filenames parse cleanly) [2](#0-1) .

The actual diff scoping is done by `_diff_pathspec`, which realpath-resolves and relativizes each touched path and appends `["--"] + rel` to the `git diff` argv [3](#0-2) . This function only guards against paths escaping the repo root (`..`) and macOS symlink aliasing — it does **not** neutralize git's pathspec magic syntax. Git treats any pathspec element beginning with `:` specially (`:(exclude)`, `:(icase)`, shorthand `:!`/`:^`, etc.); an unrecognized magic keyword causes `git diff` to exit non-zero for the *entire* invocation, not just the offending path.

`get_git_diff` builds one combined `git diff ... -- rel1 rel2 ...` command covering every path in the review set and runs it inside `_temp_index` [4](#0-3) . On non-zero exit it only logs and returns `None` [5](#0-4) . Because the review set can legitimately contain many files touched in a turn (`compute_v2_review_set` unions tracked-dirty and new-untracked paths into one batch) [6](#0-5) , an attacker who can get a single colon-prefixed (or otherwise pathspec-magic) filename into the untracked/dirty set alongside a genuinely dangerous file forces the shared `git diff` call to fail, which drops the diff for **all** files in that batch, not just the crafted one — hiding the dangerous change from the LLM security reviewer that would otherwise `exit(2)` and block/flag it.

### Impact Explanation
If the batched diff silently returns `None`/empty due to one poisoned filename, the Stop-hook / commit-review LLM security scan never sees the attacker's actual dangerous edits (e.g., a backdoored script or injected shell command) in that turn, so no `exit(2)` guidance is raised and Claude's approval/deny gating for that content is effectively bypassed. This matches "Unauthorized local command execution that bypasses Claude Code approval or deny controls" since the review layer — one of the guardrails gating what dangerous code gets surfaced/blocked — is disabled by an unrelated, easily-crafted filename.

### Likelihood Explanation
Feasible for any attacker who can introduce a file into the working tree with a pathspec-magic-prefixed name (e.g. `:evil.py`, `:(exclude)x`), such as via repository content, a prior commit, or content Claude itself is induced to write during a session. No special privilege beyond ordinary repo write access is required, and it's repeatable every time such a filename coexists with other dirty/untracked files in the same review batch.

### Recommendation
Sanitize/neutralize pathspec magic before passing repo-relative filenames to `git diff` in `_diff_pathspec` — either prefix each path with `./` (which git treats as disabling top-level magic interpretation) or pass `--literal-pathspecs` / `-c core.literalPathspecs=... ` equivalent (`GIT_LITERAL_PATHSPECS=1` env var) to `GIT_CMD` for these calls so every element is treated literally regardless of leading characters. Additionally, make `get_git_diff` fail per-file rather than fail the whole batch (e.g., diff files individually or retry without the offending path) so one bad filename cannot suppress review of unrelated files.

### Proof of Concept
Unit/integration test plan for `gitutil.py`:
1. Create a temp git repo with one commit (baseline).
2. Create two untracked files: `":evil.py"` (or `":(exclude)x.py"`) with benign content, and `"backdoor.py"` containing an obviously dangerous pattern (e.g. `os.system(user_input)`).
3. Call `get_git_diff(repo, baseline_sha, untracked_paths=[":evil.py", "backdoor.py"])` (or drive it via `compute_v2_review_set` + the Stop-hook path).
4. Assert: current behavior — `git diff` subprocess returns non-zero (pathspec magic error) and `get_git_diff` returns `None`, so `backdoor.py`'s dangerous content never reaches `parse_diff_into_files`/`extract_file_paths_from_diff` and the LLM reviewer.
5. Expected (fixed) behavior — the diff succeeds and includes `backdoor.py`'s content regardless of the co-present `:evil.py` filename, verified by asserting `"os.system"` appears in the returned diff text.

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

**File:** plugins/security-guidance/hooks/gitutil.py (L117-135)
```python
        if untracked_paths is None:
            add_args = ["."]
        elif untracked_paths:
            # `git add -N -- a b nonexistent` is atomic — one missing path
            # makes it exit 128 and add NOTHING, so a file removed between
            # `git status` and here would silently drop ALL untracked files
            # from the diff. --ignore-missing only works with --dry-run, so
            # filter to surviving paths (lexists so dangling symlinks count).
            surviving = [p for p in untracked_paths
                         if os.path.lexists(os.path.join(cwd, p))]
            add_args = ["--"] + surviving if surviving else None
        else:
            add_args = None
        if add_args:
            subprocess.run(
                [*GIT_CMD, "add", "--intent-to-add"] + add_args,
                cwd=cwd, capture_output=True, text=True, timeout=10,
                env=env,
            )
```

**File:** plugins/security-guidance/hooks/gitutil.py (L406-424)
```python
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
        if result.returncode != 0:
            debug_log(f"git diff failed: {result.stderr[:200].decode('utf-8', errors='replace')}")
            return None
        # Decode with errors='replace' so binary diffs don't crash
        return result.stdout.decode("utf-8", errors="replace")
```

**File:** plugins/security-guidance/hooks/diffstate.py (L319-351)
```python
def _list_untracked(cwd):
    """Repo-root-relative untracked (and not-ignored) path → mtime_ns, or {}
    on error. Used at UPS to snapshot the pre-turn untracked set so the Stop
    hook can exclude unchanged pre-existing untracked files from review.
    mtime is captured so an in-place edit during the turn is still reviewed.

    Uses ls-files (not status) for the UPS path: the index diff isn't needed,
    and ls-files --others only walks the worktree against .gitignore."""
    try:
        repo = _git_toplevel(cwd) or cwd
        r = subprocess.run(
            [*GIT_CMD, "-c", "core.quotePath=false", "ls-files",
             "--others", "--exclude-standard", "-z"],
            cwd=repo, capture_output=True, text=True, timeout=15,
        )
        if r.returncode != 0:
            debug_log(f"_list_untracked rc={r.returncode}: {r.stderr[:200]}")
            return {}
        out = {}
        for p in r.stdout.split("\0"):
            if not p:
                continue
            try:
                out[p] = os.stat(os.path.join(repo, p)).st_mtime_ns
            except OSError:
                out[p] = 0
            if len(out) >= UNTRACKED_BASELINE_CAP:
                debug_log(f"_list_untracked: capped at {UNTRACKED_BASELINE_CAP}")
                break
        return out
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        debug_log(f"_list_untracked error: {e}")
        return {}
```

**File:** plugins/security-guidance/hooks/diffstate.py (L386-428)
```python
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
