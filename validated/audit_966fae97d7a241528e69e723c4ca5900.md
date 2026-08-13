### Title
Amended/rewritten commits bypass `compute_v2_review_set`'s `dirty_now ∩ changed_since` filter, hiding dangerous changes from Stop-hook review - (File: `plugins/security-guidance/hooks/diffstate.py`)

### Summary
`capture_git_baseline` correctly snapshots a SHA of the working tree at `UserPromptSubmit` for later diffing, but `compute_v2_review_set` (also in `diffstate.py`) derives the review set as `dirty_now ∩ changed_since`, where `dirty_now` only includes files reported by `git status` (uncommitted) or files reachable by a *linear* fast-forward from `head_at_capture`. A commit that rewrites history relative to `head_at_capture` (e.g. `git commit --amend`, `rebase`, or `reset && recommit`) — all normal git operations available to Claude/attacker during a turn — makes the file appear neither "dirty" nor part of a linear-advance diff, even though `changed_since` (diffed directly against the stash baseline) still shows it changed. The intersection then silently drops the file from `review_set`, so the Stop hook's LLM review never sees it, and the baseline is subsequently advanced past it, permanently removing it from the review window.

### Finding Description
`compute_v2_review_set` in `plugins/security-guidance/hooks/diffstate.py` builds the reviewed file set as: [1](#0-0) 

- `tracked_dirty`/`untracked` come from `git status --porcelain` via `_git_status_porcelain`, which only reflects uncommitted changes relative to the *current* HEAD.
- The only mechanism that adds committed-but-not-uncommitted files to `dirty_now` is the linear-advance branch: [2](#0-1) 
This only fires when `_is_ancestor(repo, head_at_capture, current_head)` is true — i.e., `head_at_capture` is a strict ancestor of the new HEAD (a genuine fast-forward commit chain).
- `changed_since` is computed independently as a raw `git diff --name-only <baseline_sha>` against the working tree, so it still reflects the true content diff regardless of how the commit history was rewritten: [3](#0-2) 
- Final `review_set = dirty_now & changed_since` (line 426): if `dirty_now` doesn't contain the file (because it's been committed via an operation that isn't a clean fast-forward from `head_at_capture`), the file is excluded from `review_set` no matter what `changed_since` says.

Exploit flow: during a Claude turn, the dangerous change is written and then folded into history via `git commit --amend` (or `git reset --soft <parent> && git commit`, or a rebase) instead of a plain `git commit`. This produces a new HEAD whose parent equals `head_at_capture`'s parent rather than making `head_at_capture` an ancestor, so `_is_ancestor` returns `False`. `git status` shows a clean tree (the change is committed), so `tracked_dirty` is empty for that path. `review_set` therefore excludes the dangerous file even though `changed_since` (diff against the UPS-captured baseline stash SHA) would have flagged it. The Stop hook then finds no reviewable diff files and exits without warning: [4](#0-3) 
Worse, on a clean/no-finding Stop, or on the next `UserPromptSubmit`, `capture_git_baseline` re-snapshots the current (already-amended) worktree state as the new baseline: [5](#0-4) [6](#0-5) 
This permanently shifts the dangerous change to "before the baseline," so it is never picked up as new content in any subsequent turn either — it is durably hidden outside the review window.

None of the existing guards catch this: `_is_ancestor` is a strict linear-history check with no fallback for non-fast-forward commits; `filter_preexisting_from_diff` operates on already-filtered `diff_files` so it never sees the dropped file; and there is no allowlist/approval step gating `git commit --amend`/`rebase` as riskier than `git commit`.

### Impact Explanation
This breaks the stated invariant that "an attacker must not hide a dangerous change by shifting it outside the computed review window." Any dangerous code (e.g., a backdoor, hardcoded secret, command-injection sink) introduced by Claude/an attacker-influenced turn and folded into an amended or rebased commit escapes the Stop-hook's LLM vulnerability scan entirely and is never surfaced to the user, and the state permanently treats it as pre-existing. This is a local command-execution/approval-bypass class impact: the security-guidance plugin's only enforcement point (the Stop-hook LLM review that exits with code 2 to force remediation) is silently defeated for a normal, unprivileged git workflow, allowing dangerous changes to persist unreviewed and unremediated.

### Likelihood Explanation
High feasibility and full repeatability: the only precondition is a git-tracked clone (the plugin's normal operating environment) and use of common git operations (`commit --amend`, `rebase`, `reset --soft && commit`) during a single turn, all of which are ordinary developer/attacker-reachable Bash actions with no special privilege. No parsing bypass, no malformed input, no timing race is required — it is a deterministic logic gap in the intersection of `dirty_now` and `changed_since`.

### Recommendation
Do not gate committed-file detection on strict linear ancestry alone. Either:
1. Drop the `dirty_now` intersection requirement for committed changes and instead always include the set of paths from `changed_since` when they differ from the true baseline content (i.e., trust `_git_name_only(repo, baseline_sha)` directly for tracked files, only using `dirty_now` to additionally pull in currently-uncommitted work), or
2. When `_is_ancestor` returns `False` (non-linear history change since baseline), fall back to a full `git diff --name-only baseline_sha HEAD` (not just working tree vs baseline) unioned into `dirty_now`, so amended/rebased commits are still counted as "dirty since baseline" instead of being excluded.

### Proof of Concept
Integration test plan (pytest-style) in the existing test suite for `diffstate.py`/`compute_v2_review_set`:
1. Init a git repo with an initial commit `initial.py`.
2. Simulate UPS: call `capture_git_baseline(cwd)` → `baseline_sha`; record `head_at_capture = _git_rev_parse_head(cwd)`.
3. Write `evil.py` with a dangerous pattern, `git add`, `git commit -m "add evil"`.
4. Run `git commit --amend -m "add evil (amended)"` (simulating history rewrite without touching content further, or add one more line then amend).
5. Call `compute_v2_review_set(cwd, baseline_sha, head_at_capture, {})`.
6. Assert (expected, currently failing): `review_paths` contains `evil.py`'s absolute path.
   - Actual observed behavior: `_is_ancestor(repo, head_at_capture, current_head)` is `False` (amend rewrote HEAD to a sibling commit), `tracked_dirty` is empty (`git status` clean), so `review_set` is empty and `evil.py` is silently dropped — reproducing the bypass.

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L163-201)
```python
def capture_git_baseline(cwd):
    """
    Capture a git ref representing the current working tree state.
    Uses `git stash create` which creates a commit object for the current state
    (HEAD + uncommitted changes) without modifying the stash list or working tree.
    Falls back to HEAD if the working tree is clean.
    Returns the SHA string, or None if not in a git repo or if the repo has no commits.

    NOTE: `git stash create` does NOT capture untracked files. UPS pairs this
    SHA with a `_list_untracked()` snapshot stored as `untracked_at_baseline`,
    and `compute_v2_review_set` subtracts that set so pre-existing untracked
    files are not reviewed as Claude-authored.
    """
    try:
        # Check if HEAD exists (i.e., repo has at least one commit)
        head_check = subprocess.run(
            [*GIT_CMD, "rev-parse", "HEAD"],
            cwd=cwd, capture_output=True, text=True, timeout=5
        )
        if head_check.returncode != 0:
            # No commits yet — skip review rather than creating commits in the user's repo
            debug_log("No commits in repo, skipping baseline capture")
            return None

        result = subprocess.run(
            [*GIT_CMD, "stash", "create"],
            cwd=cwd, capture_output=True, text=True, timeout=15
        )
        sha = result.stdout.strip()
        if sha:
            return sha

        # Working tree is clean — stash create returns empty. Use HEAD.
        result = subprocess.run(
            [*GIT_CMD, "rev-parse", "HEAD"],
            cwd=cwd, capture_output=True, text=True, timeout=5
        )
        sha = result.stdout.strip()
        return sha if sha else None
```

**File:** plugins/security-guidance/hooks/diffstate.py (L399-426)
```python
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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1824-1827)
```python
    diff_files = parse_diff_into_files(diff_output)
    if not diff_files:
        debug_log("Stop hook: no source code files in diff")
        _skip(7)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1892-1919)
```python
        # Update baseline so next stop hook iteration only sees new changes
        new_sha = capture_git_baseline(cwd)
        new_untracked_baseline = _list_untracked(cwd) if new_sha else None

        def _record_fire(state):
            state["stop_hook_fire_count"] = fire_index
            state["stop_hook_fire_count_ts"] = _time.time()
            # Re-read under lock — the commit-review PostToolUse hook may have
            # appended findings since consume_stop_state snapshotted.
            # Dedupe on (filePath, category) — vulnerableCode includes diff
            # context lines that drift between fires, so byte-identical
            # matching let the same finding accumulate as "new" each fire.
            existing = [f for f in state.get("previous_findings", []) if isinstance(f, dict)]
            seen = {(f.get("filePath", ""), f.get("category", "")) for f in existing}
            for f in finding_snapshots:
                key = (f["filePath"], f["category"])
                if key not in seen:
                    seen.add(key)
                    existing.append(f)
            state["previous_findings"] = existing
            state["previous_findings_ts"] = _time.time()
            if new_sha:
                state["baseline_sha"] = new_sha
                state["untracked_at_baseline"] = new_untracked_baseline
        with_locked_state(session_id, _record_fire)

        if new_sha:
            debug_log(f"Updated git baseline after stop hook: {new_sha[:12]}")
```
