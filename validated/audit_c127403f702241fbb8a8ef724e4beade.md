### Title
Git pathspec-magic injection in `_diff_pathspec` allows repo-controlled filenames to bypass or corrupt the security-review diff scope - ([File: plugins/security-guidance/hooks/gitutil.py])

### Summary
`_diff_pathspec` converts touched/review-set file paths into raw arguments spliced after `--` for `git diff`, without disabling git's pathspec "magic" syntax or quoting a leading `:`. A repo-controlled file whose (repo-relative) name begins with `:` (e.g. `:(exclude)payload.py`, `:!secret.py`, `:(glob)*`) is interpreted by git as pathspec magic rather than a literal filename, letting the file silently drop out of (or otherwise distort) the diff that feeds the Stop-hook / commit / push security reviewers.

### Finding Description
`_diff_pathspec` (`plugins/security-guidance/hooks/gitutil.py:70-88`) turns each touched path into a `git diff`-relative string and returns `["--"] + rel`: [1](#0-0) 

These strings are appended verbatim as pathspec arguments in `get_git_diff`: [2](#0-1) 

`GIT_CMD` never sets `--literal-pathspecs` or `core.literalPathspecs`, and no caller wraps each element in `:(literal)`: [3](#0-2) 

Git's pathspec grammar treats an argument that begins with `:` as a magic signature (`:(exclude)…`, `:(glob)…`, `:!…`, etc.) rather than a literal path. The review-set paths that reach `_diff_pathspec` are themselves derived from real repository content — `_git_status_porcelain`/`_git_name_only` enumerate actual on-disk filenames via `git status`/`git diff --name-only` (`core.quotePath=false` preserves non-ASCII/space but does not escape `:`): [4](#0-3) [5](#0-4) 

and are then fed straight through `compute_v2_review_set` → `get_git_diff` → `_diff_pathspec` in the Stop hook: [6](#0-5) 

An attacker who can name a file in the working tree (e.g. via an edit Claude Code makes on their behalf, or a file already present/committed in an untrusted repository the agent is asked to work in) can craft a filename such as `:(exclude)payload.py`. When that name is the only or a controlling pathspec token, `git diff -- ':(exclude)payload.py' other.py` semantically means "diff other.py but exclude anything matching payload.py" — the malicious file's own diff never appears in `git diff`'s output, even though it is genuinely dirty/touched. Alternatively, an unrecognized/malformed magic word (`:(bogus)name`) makes `git diff` exit non-zero, so `get_git_diff` returns `None`: [7](#0-6) 

In `handle_stop_hook`, a `None`/empty diff is treated as "no changes since baseline" and the whole security review is skipped: [8](#0-7) 

Either way, `_diff_pathspec`'s job — restricting/normalizing the diff to exactly the intended touched files — is subverted by pathspec magic embedded in the filename itself, so the git-diff-based review scope no longer matches the intended file set (silently dropping the malicious file, or aborting the whole review).

### Impact Explanation
This is a logic-level bypass of the security-guidance plugin's core enforcement mechanism: the LLM-based diff review (`analyze_code_security`) that is supposed to inspect every touched/dirty file before Claude's turn completes. A file named with leading pathspec magic can have its actual content changes hidden from that reviewer, or can cause the entire Stop-hook review for the turn to be skipped (`_skip(6)`), letting genuinely malicious code changes go unreviewed. This matches "Logic-level service disruption caused by bypassing a required guard."

### Likelihood Explanation
Reachable by any actor able to name a file in the working tree that Claude Code/the plugin will treat as "touched" — no special privileges beyond ordinary repository content control are required (e.g. operating in an attacker-supplied/untrusted repo, or a subagent/tool writing a file with an attacker-influenced name). The magic-prefix characters (`:`, `!`, `(`, `)`) are all valid in POSIX/most filesystem filenames, so crafting such a name is trivial and fully repeatable.

### Recommendation
In `_diff_pathspec`, force every emitted pathspec element to be treated literally — either prefix each relative path with `:(literal)` (git ≥2.13) or add `-c core.literalPathspecs=true` (equivalently pass `--literal-pathspecs` before the pathspec args) to the `git diff`/`git status`/`git diff --name-only` invocations that consume these paths. This makes leading `:` characters in filenames inert instead of being parsed as pathspec magic.

### Proof of Concept
Unit test plan for `_diff_pathspec` / `get_git_diff`:
1. Create a temp git repo; `git init`.
2. Create and commit a baseline file `a.py`.
3. Create a new file literally named `:(exclude)payload.py` containing an obviously vulnerable pattern (e.g. `os.system(user_input)`), and stage/commit or leave dirty.
4. Call `get_git_diff(repo, baseline_sha, paths=[abs_path_to_a.py, abs_path_to_payload_file])`.
5. Assert: the returned diff text does NOT contain the payload file's content/header (`diff --git a/:(exclude)payload.py ...`) even though the file is genuinely new/dirty — demonstrating the file silently escaped the intended review scope.
6. Repeat with a malformed magic name `:(bogus)x.py` as one of the touched paths and assert `get_git_diff` returns `None` (subprocess non-zero exit), then assert that `handle_stop_hook`'s downstream logic (`if not diff_output or not diff_output.strip(): _skip(6)`) causes the entire review to be skipped for the turn, even though other legitimately-touched files (e.g. `a.py`) had reviewable changes.

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

**File:** plugins/security-guidance/hooks/gitutil.py (L303-327)
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

    try:
        if not include_untracked:
            return _run(None)
        with _temp_index(cwd) as env:
            return _run(env)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        debug_log(f"_git_name_only({base!r}) error: {e}")
        return None
```

**File:** plugins/security-guidance/hooks/gitutil.py (L330-373)
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
            cwd=cwd, capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            debug_log(f"_git_status_porcelain rc={r.returncode}: {r.stderr[:200]}")
            return None, None
        tracked, untracked = set(), set()
        entries = r.stdout.split("\0")
        i = 0
        while i < len(entries):
            e = entries[i]
            if not e:
                i += 1
                continue
            xy, path = e[:2], e[3:]
            if xy == "??":
                untracked.add(path)
            else:
                tracked.add(path)
                # Rename/copy entries are XY old\0new\0 — second NUL field is
                # the origin path; consume it so it isn't misparsed as a new
                # 2-char-status entry.
                if "R" in xy or "C" in xy:
                    i += 1
            i += 1
        return tracked, untracked
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        debug_log(f"_git_status_porcelain error: {e}")
        return None, None
```

**File:** plugins/security-guidance/hooks/gitutil.py (L406-419)
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
```

**File:** plugins/security-guidance/hooks/gitutil.py (L420-424)
```python
        if result.returncode != 0:
            debug_log(f"git diff failed: {result.stderr[:200].decode('utf-8', errors='replace')}")
            return None
        # Decode with errors='replace' so binary diffs don't crash
        return result.stdout.decode("utf-8", errors="replace")
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1792-1821)
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
    # filter_preexisting_from_diff needs a resolvable pre-turn ref; fall
    # back to HEAD when UPS never captured a baseline (print mode).
    if not baseline_sha:
        baseline_sha = "HEAD"

    if not diff_output or not diff_output.strip():
        debug_log("Stop hook: no changes since baseline")
        _skip(6)
```
