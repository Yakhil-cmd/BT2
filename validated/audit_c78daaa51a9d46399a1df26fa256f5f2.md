### Title
Amend/rebase after a mid-turn commit can drop the committed dangerous file from the Stop-hook review set - (File: `plugins/security-guidance/hooks/diffstate.py`, function `compute_v2_review_set`, with `capture_git_baseline` supplying the baseline SHA)

### Summary
`compute_v2_review_set` in `plugins/security-guidance/hooks/diffstate.py` builds the reviewed file list as `dirty_now & changed_since`, where `dirty_now` only includes committed changes if `head_at_capture` is still a git ancestor of the current `HEAD` [1](#0-0) . If the branch history between the captured baseline and Stop time is rewritten (e.g. `git commit --amend`, `git rebase`, or any operation that leaves `head_at_capture` no longer an ancestor of the new `HEAD`), the committed-but-since-rewritten file is excluded from `dirty_now` even though it genuinely changed relative to the stash baseline (`changed_since`). Because `review_set` is an intersection, that file silently drops out of the Stop hook's review set and skips the LLM security scan.

### Finding Description
The Stop hook computes what to review purely from git state via `compute_v2_review_set`, using two independently derived sets: `dirty_now` (worktree-dirty files plus committed files when `head_at_capture..HEAD` is a strict fast-forward) and `changed_since` (`git diff --name-only <baseline_sha>` against the stash-baseline commit object, i.e., content differences) [2](#0-1) . The final `review_set = dirty_now & changed_since` when `changed_since` is available [3](#0-2) .

The `head_at_capture` ancestor check uses `_is_ancestor`, which only returns true if `head_at_capture` is reachable from the current `HEAD` (i.e. HEAD moved strictly forward via ordinary commits) [4](#0-3) . Any history-rewriting operation performed during the same turn — `git commit --amend`, interactive rebase, `reset --hard` followed by re-commit, etc. — that changes the commit graph so `head_at_capture` is no longer an ancestor of the new `HEAD` disables this branch of `dirty_now`. Since the dangerous change is now fully committed (not present in the working tree), it also does not appear in `tracked_dirty` from `git status --porcelain`. The result: the dangerous file is present in `changed_since` (since `git diff <stash_sha>` compares tree content regardless of history) but absent from `dirty_now`, so it is excluded from `review_set` entirely and the Stop hook exits early via `_skip(9)` / a reduced file list without ever generating a diff for that file [5](#0-4) .

Notably, `touched_paths` (recorded via PostToolUse on every Edit/Write/Bash tool call) is snapshotted by `consume_stop_state` but is used only for restore-on-transient-skip and telemetry — it is never merged into `review_paths` inside `handle_stop_hook`, so it provides no independent safety net against this gap [6](#0-5) .

This is reachable through entirely ordinary agent/attacker-influenced git operations in the session (commit, then amend/rebase before Stop fires) — no privileged access or out-of-band tampering with the state file is required, only sequencing of normal git commands that Claude Code (or a prompt-injected instruction) can issue via the Bash tool.

### Impact Explanation
A dangerous code change committed and then amended/rebased during a turn can bypass the Stop hook's LLM security review entirely, since it never enters the diff sent to the analysis (`analyze_code_security` never sees the file) [7](#0-6) . This breaks the stated invariant that the plugin's review set stays bound to the actual set of changes made during the turn, undermining the entire security-guidance safety mechanism (silent detection bypass for backdoors, hardcoded secrets, command injection, etc., that the plugin exists to catch).

### Likelihood Explanation
This requires no special privilege beyond normal agent git usage within a session: commit a change, then perform a normal amend or rebase before the Stop hook fires (or across multiple Stop iterations where a prior baseline capture recorded an older `head_at_capture`). This is a very plausible sequence in real agentic coding sessions (Claude routinely amends commits to fix messages, squashes WIP commits, or rebases branches), making the bypass window easy to trigger unintentionally or via prompt injection instructing the agent to "clean up commit history."

### Recommendation
Do not gate the committed-changes term of `dirty_now` on strict ancestor-forwarding of `head_at_capture`. Instead, always union in `_git_name_only(repo, baseline_sha)` content-diff results directly into `dirty_now` (not just via the ancestor branch), or drop the ancestor-only branch and rely solely on content-diff (`changed_since`) as the authoritative review-set source instead of intersecting it away. At minimum, detect when `head_at_capture` is no longer an ancestor of `HEAD` and treat that as "history rewritten this turn" — falling back to a full diff against `baseline_sha` (which is already content-accurate) rather than silently narrowing the file list via the broken ancestor-based `dirty_now` term.

### Proof of Concept
Unit/integration test in the style of the existing `compute_v2_review_set` test suite:
1. Init a git repo, commit an initial file, capture `baseline_sha = capture_git_baseline(cwd)` and `head_at_capture = _git_rev_parse_head(cwd)`.
2. Write `backdoor.py` with dangerous content, `git add` + `git commit -m "add backdoor"` (HEAD now linear descendant of `head_at_capture`) — assert `compute_v2_review_set(cwd, baseline_sha, head_at_capture)` includes `backdoor.py` (sanity baseline).
3. Now amend the commit (`git commit --amend -m "add backdoor v2"`) or run `git rebase -i` to reorder/squash, producing a new HEAD SHA where `_is_ancestor(repo, head_at_capture, new_head)` is `False` (verify directly).
4. Re-run `compute_v2_review_set(cwd, baseline_sha, head_at_capture, {})` and assert that `backdoor.py` is **missing** from `review_paths` even though `git diff --no-color baseline_sha -- backdoor.py` (content diff) shows it changed — this demonstrates the review-set/diff mismatch.
5. Expected (fixed) behavior: `review_paths` must still contain `backdoor.py` in this scenario.

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L386-426)
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
```

**File:** plugins/security-guidance/hooks/gitutil.py (L377-387)
```python
def _is_ancestor(cwd, maybe_ancestor, descendant):
    """True if `maybe_ancestor` is reachable from `descendant` (i.e. HEAD
    moved forward via commit/merge, not sideways via checkout)."""
    try:
        result = subprocess.run(
            [*GIT_CMD, "merge-base", "--is-ancestor", maybe_ancestor, descendant],
            cwd=cwd, capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1728-1798)
```python
    snap = consume_stop_state(session_id)
    fire_count = snap["fire_count"]
    touched_paths = snap["touched_paths"]
    baseline_sha = snap["baseline_sha"]
    snap_baseline = baseline_sha  # pre-reassignment value for restore-on-transient-skip
    head_at_capture = snap["head_at_capture"]
    untracked_at_baseline = snap.get("untracked_at_baseline") or {}
    previous_findings = snap["previous_findings"]

    # Sweep pattern-warning outcomes (pure local work; stop_hook_active is
    # already guaranteed False here so no double-count guard needed).
    sweep = {}
    warn_fixed, warn_unresolved, warn_unresolved_mask = sweep_pending_warnings(session_id)
    if warn_fixed or warn_unresolved:
        sweep = {
            "warn_fixed": warn_fixed,
            "warn_unresolved": warn_unresolved,
            "warn_unresolved_mask": warn_unresolved_mask,
        }

    v2_metrics = {}

    def _skip(reason, restore=False, **extra):
        if restore:
            restore_unreviewed_stop_state(session_id, touched_paths, snap_baseline)
        # CC truncates metrics to 10 keys by
        # insertion order. v2_metrics (3) must precede sweep (3) so the v2
        # diagnostics survive when extra adds touched_paths_count + ip_* keys.
        emit_metrics({
            "skipped": True, "skip_reason": reason, "fire_index": fire_count + 1,
            "diff_strategy_v2": True,
            **v2_metrics, **extra, **sweep,
        })
        sys.exit(0)

    # Limit stop hook firings per asyncRewake loop to prevent infinite loops.
    # fire_count auto-expires after STOP_LOOP_STATE_TTL_SEC so a stale count
    # from a prior turn doesn't block this one.
    if MAX_STOP_HOOK_FIRINGS > 0 and fire_count >= MAX_STOP_HOOK_FIRINGS:
        debug_log(f"Stop hook: already fired {fire_count} times (max {MAX_STOP_HOOK_FIRINGS}), skipping")
        _skip(2)

    if not ENABLE_CODE_SECURITY_REVIEW or not HAS_API_CREDENTIALS:
        debug_log("Stop hook: LLM review disabled or no API credentials")
        _skip(3)

    # Stop-hook-only kill switch — placed after consume_stop_state so
    # touched_paths is still cleared each turn (a disabled Stop hook that
    # never consumed state would accumulate stale paths) and after the sweep
    # so pattern-warning efficacy metrics still emit. The commit/push reviews
    # have their own gates (ENABLE_COMMIT_REVIEW / ENABLE_CODE_SECURITY_REVIEW).
    if not ENABLE_STOP_REVIEW:
        debug_log("Stop hook: ENABLE_STOP_REVIEW=0")
        # 50+ for opt-out skips that aren't push-sweep (which owns 40-49).
        _skip(50)

    if not ensure_anthropic_reachable():
        debug_log("Stop hook: api.anthropic.com unreachable")
        _skip(10, restore=True)

    if not cwd:
        debug_log("Stop hook: no cwd")
        _skip(4)

    review_paths, diff_base, repo_root, untracked, v2_metrics = compute_v2_review_set(
        cwd, baseline_sha, head_at_capture, untracked_at_baseline
    )
    if not review_paths:
        debug_log("Stop hook: empty review set")
        _skip(9, touched_paths_count=len(touched_paths))
    debug_log(f"Stop hook: review_set={len(review_paths)} base={diff_base[:12]} dirty_now={v2_metrics['dirty_now_count']} changed_since={v2_metrics['changed_since_count']}")
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1857-1859)
```python
    concrete_guidance, vulns = analyze_code_security(
        diff_files, is_diff=True, previous_findings=previous_findings
    )
```
