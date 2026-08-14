### Title
Race between async Stop-hook failure recovery and next-turn baseline capture silently drops reviewed edits - (File: `plugins/security-guidance/hooks/diffstate.py`)

### Summary
`restore_unreviewed_stop_state` is designed to re-arm `touched_paths` (and, conditionally, `baseline_sha`) when the Stop hook exits early for a transient reason (e.g. Anthropic unreachable, HTTP error). Because the Stop hook runs asynchronously ("asyncRewake") after Claude's turn ends, `handle_user_prompt_submit` for the *next* turn can race the recovery path and overwrite `baseline_sha` with a fresh SHA captured *after* the unreviewed edit already exists on disk, before `restore_unreviewed_stop_state` runs. The restore function only re-applies the saved baseline when `state.get("baseline_sha")` is still falsy, so it silently accepts the racing, more-advanced baseline — permanently hiding the previously-touched dangerous file from `compute_v2_review_set`'s diff-based intersection.

### Finding Description
`consume_stop_state` (`plugins/security-guidance/hooks/diffstate.py:74-113`) atomically snapshots and clears `touched_paths` on disk but leaves `baseline_sha` untouched. `handle_stop_hook` (`plugins/security-guidance/hooks/security_reminder_hook.py:1700-1972`) then performs slow work — `ensure_anthropic_reachable()`, LLM calls — before deciding whether to call `restore_unreviewed_stop_state(session_id, touched_paths, snap_baseline)` on transient failure (`_skip(10, restore=True)` at line 1786, and again at line 1951 on `llm._last_call_claude_http_error`).

During that window, `touched_paths` is empty on disk (already cleared by `consume_stop_state`) while the dangerous edit is still present in the working tree. If the user submits the next prompt before the failing Stop hook finishes, `handle_user_prompt_submit` (`plugins/security-guidance/hooks/security_reminder_hook.py:446-515`) runs concurrently: it captures a brand-new baseline SHA via `capture_git_baseline(cwd)` (a normal `git stash create`/`git rev-parse HEAD` — ordinary git operations an attacker can trigger just by making commits/edits and prompting again), then takes the state lock and checks `state.get("touched_paths") and state.get("baseline_sha")` (line 493) to decide whether to preserve the old baseline. Because `touched_paths` is empty at that instant, the preservation guard does not trigger, and UPS overwrites `state["baseline_sha"]` with the new SHA — which already includes the still-unreviewed dangerous change.

When the delayed `restore_unreviewed_stop_state` finally executes (`plugins/security-guidance/hooks/diffstate.py:116-137`), it re-adds the file path to `touched_paths` (dedupe/prepend), but its baseline restoration is gated by:
```
if baseline_sha and not state.get("baseline_sha"):
    state["baseline_sha"] = baseline_sha
```
Since `state["baseline_sha"]` is now non-empty (the racing, newer SHA), this condition is false and the old (correct, pre-edit) baseline is never restored. The stale-but-correct `snap_baseline` is discarded.

On the next Stop fire, `compute_v2_review_set` (`plugins/security-guidance/hooks/diffstate.py:353-438`) intersects `dirty_now` with `changed_since` computed against the new baseline (`_git_name_only(repo, baseline_sha)`). Because the new baseline was captured *after* the dangerous file's content was already present, `git diff <new_baseline>` shows no difference for that file, so it drops out of `changed_since` and therefore out of `review_set`, even though it is still listed in the restored `touched_paths`. The file is treated as pre-existing/old and is never reviewed, despite genuinely being an unreviewed, Claude-authored (or attacker-influenced in a cloned-repo automation flow) edit.

This breaks the stated invariant that "the review set must stay bound to the right repo, baseline, and touched paths": the touched-path tracking and the baseline advance become decoupled by the race, and the diff-based review set silently loses coverage of a file that was never actually reviewed.

### Impact Explanation
A dangerous file modification (e.g., introducing a command-injection or path-traversal primitive, or writing outside the intended workspace) made during a turn whose Stop hook transiently fails (a common condition — the reachability check or LLM HTTP call can legitimately fail intermittently) can be permanently excluded from the security review pipeline if the user's next prompt lands in the narrow race window. This results in unauthorized/unreviewed file writes passing through the guidance/enforcement layer that is supposed to gate them, matching "Unauthorized file read or write outside the user-approved workspace or target scope" since the review meant to catch and block such content is bypassed.

### Likelihood Explanation
The race requires: (1) a Stop hook failure that is transient and not vanishingly rare (`ensure_anthropic_reachable` network check, or an LLM HTTP error — both realistic in normal operation, e.g. flaky network or rate limiting), and (2) the user (or an automated harness driving Claude Code, e.g. in CI/agentic loops) submitting the next prompt while the async Stop hook is still in flight, which is explicitly called out in the codebase's own comments as a real, previously-observed race ("Telemetry showed a meaningful share of would-be reviews lost when the next turn's UPS wiped touched_paths before Stop read it" — the existing `consume_stop_state` fix addresses the `touched_paths`-wipe half of this race but not the `baseline_sha`-advance half). No special privileges are needed; only ordinary git operations (edit, commit, prompt again) in a cloned repo, making this reachable by any user of a fast-moving, automated, or reduced-latency session.

### Recommendation
Make baseline restoration unconditional/monotonic-safe in `restore_unreviewed_stop_state`: instead of only setting `baseline_sha` when currently unset, always restore the *older* (pre-turn) baseline when a restore is triggered by a transient Stop failure, or better, track a version/generation token alongside `baseline_sha` so a racing UPS write can be detected and the restore can force the baseline back to `snap_baseline` regardless of what UPS wrote in between. Alternatively, have `handle_user_prompt_submit` treat "empty touched_paths" as ambiguous during the async Stop window (e.g., check a `stop_in_flight` flag under the same lock) rather than assuming empty implies "safe to advance baseline."

### Proof of Concept
Integration/invariant test (pytest-style, using the existing state-locking helpers):
1. Simulate turn 1: call `record_touched_path(session_id, "danger.py")`, `save_baseline_sha(session_id, B0)`.
2. Call `consume_stop_state(session_id)` to snapshot (`touched_paths=["danger.py"]`, `baseline_sha=B0`) and clear `touched_paths` on disk, as Stop hook does before its slow network call.
3. Before calling `restore_unreviewed_stop_state`, simulate the racing next-turn UPS: modify the working tree so `danger.py`'s new content is present, run `capture_git_baseline(cwd)` to get `B1` (which already includes `danger.py`'s changes), and write it via the same `_save` logic in `handle_user_prompt_submit` (checking `state.get("touched_paths")` — expect it to be falsy and thus overwrite `state["baseline_sha"] = B1`).
4. Now call `restore_unreviewed_stop_state(session_id, ["danger.py"], B0)` (simulating the delayed Stop hook's transient-failure recovery).
5. Assert: `load_baseline_sha(session_id)` should ideally be `B0` (or otherwise arranged so `danger.py` remains reviewable) — current code will show it is `B1`.
6. Call `compute_v2_review_set(cwd, load_baseline_sha(session_id), head_at_capture, {})` and assert `danger.py` is present in the review set. Current implementation will fail this assertion — `danger.py` is dropped from `review_set` because `git diff B1` shows no change for it, demonstrating the baseline-shift-past-unreviewed-edit bug. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L74-137)
```python
def consume_stop_state(session_id):
    """Atomically snapshot all state the Stop hook needs and clear touched_paths.

    The Stop hook is asyncRewake — it runs in the background after Claude's
    turn ends. The user can submit a new prompt before this hook finishes its
    initial state read. Telemetry showed a meaningful share of would-be reviews lost when
    the next turn's UPS wiped touched_paths before Stop read it.

    Single locked read-then-clear closes that window: PostToolUse appends
    after this clear go into the next snapshot; UPS overwrites of baseline_sha
    after this snapshot are invisible to this Stop fire.
    """
    import time as _time
    now = _time.time()

    def _snap(state):
        fire_ts = state.get("stop_hook_fire_count_ts", 0)
        expired = (now - fire_ts) > STOP_LOOP_STATE_TTL_SEC
        findings_ts = state.get("previous_findings_ts", fire_ts)
        findings_expired = (now - findings_ts) > PREVIOUS_FINDINGS_TTL_SEC
        snap = {
            "touched_paths": list(state.get("touched_paths", [])),
            "baseline_sha": state.get("baseline_sha"),
            "head_at_capture": state.get("head_at_capture"),
            "untracked_at_baseline": (
                dict(state["untracked_at_baseline"])
                if isinstance(state.get("untracked_at_baseline"), dict) else {}
            ),
            "fire_count": 0 if expired else state.get("stop_hook_fire_count", 0),
            "fire_count_expired": expired and state.get("stop_hook_fire_count", 0) > 0,
            "previous_findings": [] if findings_expired else list(state.get("previous_findings", [])),
        }
        state["touched_paths"] = []
        return snap

    return with_locked_state(session_id, _snap) or {
        "touched_paths": [], "baseline_sha": None, "head_at_capture": None,
        "untracked_at_baseline": {},
        "fire_count": 0, "fire_count_expired": False, "previous_findings": [],
    }


def restore_unreviewed_stop_state(session_id, paths, baseline_sha):
    """Put consumed touched_paths back so the next Stop reviews them.

    consume_stop_state cleared touched_paths on disk; if Stop then exits
    early for a transient reason (CCR API unreachable, Haiku HTTP error)
    the next UPS would see an empty list, fall through the preservation
    guard, and re-baseline past the unreviewed edits. Restoring keeps the
    guard armed. Prepend+dedupe so any concurrent next-turn PostToolUse
    appends survive.
    """
    if not paths:
        return

    def _restore(state):
        existing = state.get("touched_paths", [])
        merged = list(dict.fromkeys(list(paths) + list(existing)))
        if len(merged) > 200:
            merged = merged[:200]
        state["touched_paths"] = merged
        if baseline_sha and not state.get("baseline_sha"):
            state["baseline_sha"] = baseline_sha
    with_locked_state(session_id, _restore)
```

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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L479-503)
```python
    # If the previous turn's Stop hook never ran (user interrupt, follow-up
    # during work, tool-reject, model crash, maxTurns, PostToolUse block…),
    # touched_paths is still populated because consume_stop_state is the only
    # consumer and it runs under the state lock. Overwriting baseline_sha now
    # would re-baseline *past* those unreviewed edits, making them permanently
    # invisible to the next Stop. Preserve the old baseline so the next Stop
    # diffs the aborted turn's edits plus the new turn's edits together.
    preserved = {"value": False}

    def _save(state):
        # Only preserve if there's actually an old baseline to preserve.
        # First UPS of a session can have touched_paths if PostToolUse
        # somehow ran first (print mode, odd harnesses) — in that case
        # we still need to capture a baseline.
        if state.get("touched_paths") and state.get("baseline_sha"):
            preserved["value"] = True
            return
        if sha:
            state["baseline_sha"] = sha
            state["head_at_capture"] = head
        # untracked_at_baseline is independent of whether the stash produced
        # a SHA — write it unconditionally so compute_v2_review_set's
        # preexisting-untracked exclusion works in untracked-only trees.
        state["untracked_at_baseline"] = untracked_now
    with_locked_state(session_id, _save)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1728-1794)
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
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1949-1951)
```python
    if llm._last_call_claude_http_error is not None:
        debug_log(f"Stop hook: API call failed with status {llm._last_call_claude_http_error}")
        restore_unreviewed_stop_state(session_id, touched_paths, snap_baseline)
```
