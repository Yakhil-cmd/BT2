### Title
Stale-guard in `restore_unreviewed_stop_state` lets a racing UserPromptSubmit baseline capture silently drop already-touched dangerous diffs from review - (File: `plugins/security-guidance/hooks/diffstate.py`)

### Summary
`restore_unreviewed_stop_state` is meant to re-arm the "unreviewed edits" guard after a Stop hook exits early (e.g. transient LLM/API failure), but it only restores `baseline_sha` when `state.get("baseline_sha")` is currently falsy [1](#0-0) . Because `consume_stop_state` clears `touched_paths` before the LLM call runs and the subsequent `restore_unreviewed_stop_state` call happens only after that call fails [2](#0-1) , a concurrent `UserPromptSubmit` (next turn) can race in between, see an empty `touched_paths`, and legitimately advance `baseline_sha`/`head_at_capture` past the very commit/edit that was never reviewed [3](#0-2) . When the retry then calls `restore_unreviewed_stop_state`, it re-adds the touched path but keeps the now-advanced baseline (since one is already present), so the next `compute_v2_review_set` diff against that baseline no longer shows the dangerous file as changed and it is excluded from review.

### Finding Description
The Stop-hook review pipeline works as: `consume_stop_state` atomically snapshots and clears `touched_paths`, `baseline_sha`, and `head_at_capture` for the LLM review [2](#0-1) . If the review call then fails for a transient reason (documented explicitly as "CCR API unreachable, Haiku HTTP error"), `restore_unreviewed_stop_state(session_id, paths, baseline_sha)` is called to put `touched_paths` back and restore the baseline so the guard in `handle_user_prompt_submit` stays armed [4](#0-3) .

The critical flaw is the conditional restore: `if baseline_sha and not state.get("baseline_sha")`. This assumes `baseline_sha` on disk can only be empty (never overwritten) during the gap between `consume_stop_state` and the failed call's `restore_unreviewed_stop_state`. But `handle_user_prompt_submit` (UPS) is a separate, concurrently-firing hook that writes `state["baseline_sha"]` and `state["head_at_capture"]` whenever `touched_paths` is empty at UPS time [3](#0-2) . Since Stop hooks run as `asyncRewake` (background, after the turn ends) — as documented at the top of `consume_stop_state` — a new user turn's UPS can fire, observe the just-cleared `touched_paths` as empty, and capture a brand-new `baseline_sha`/`head_at_capture` that already sits at or beyond the state containing the unreviewed dangerous edit (e.g., if the edit was committed in the interim).

When the retrying Stop hook subsequently calls `restore_unreviewed_stop_state`, `state.get("baseline_sha")` is now truthy (the fresher one UPS wrote), so the old, correct pre-failure baseline is discarded and never restored — only `touched_paths` is merged back. The next `compute_v2_review_set(cwd, baseline_sha, head_at_capture, ...)` diffs the working tree against this advanced baseline: `changed_since = _git_name_only(repo, baseline_sha)` [5](#0-4) , and `review_set = dirty_now & changed_since` [6](#0-5) . If the dangerous file's current content matches the advanced baseline (already committed/captured there), it is absent from `changed_since`, and — if it is also not currently dirty relative to `HEAD`/`head_at_capture` — absent from `dirty_now` too, so it drops out of `review_set` even though it is present in the restored `touched_paths` list. The file is silently skipped from LLM review, breaking the stated invariant that the review set stays bound to the correct baseline and touched paths.

### Impact Explanation
A dangerous code change (e.g., hardcoded secret, command injection, exfiltration payload) authored by Claude during a turn whose Stop hook transiently fails is permanently excluded from the security review pipeline once the racing baseline advance occurs, because `restore_unreviewed_stop_state`'s guard treats "any existing baseline" as sufficient, not "the correct pre-failure baseline." This matches the target Immunefi impact category: sensitive code/diff content is never surfaced for review and can reach an unintended sink (committed, pushed, or otherwise persisted) without the intended human/LLM safety check ever firing.

### Likelihood Explanation
This requires: (1) a transient Stop-hook failure (network blip to the review LLM, which the docstring itself calls out as an expected occurrence), and (2) a subsequent UserPromptSubmit racing in before the retry's `restore_unreviewed_stop_state` call completes — plausible in interactive sessions where a new prompt/turn begins while the prior asyncRewake Stop hook is still finishing or retrying. No special privilege is needed; this is purely a timing/ordering issue in normal session operation combined with ordinary git commit/amend/untracked-file activity in the repo.

### Recommendation
Make `restore_unreviewed_stop_state` unconditionally restore the pre-failure `baseline_sha` (and `head_at_capture`) rather than only filling it in when absent, or have it compare timestamps/generation counters to detect and defer to a genuinely newer legitimate baseline rather than assuming presence implies freshness. At minimum, restore should also carry forward the pre-failure `head_at_capture` so `compute_v2_review_set` can still union in commits made since the aborted turn, and the UPS preservation guard should be based on whether the Stop retry is still pending, not solely on `touched_paths` being non-empty.

### Proof of Concept
Integration test plan (pytest-style, using existing `with_locked_state`/`diffstate` test fixtures):
1. Initialize a git repo with an initial commit.
2. Call `save_baseline_sha(session_id, sha1)` and `record_touched_path(session_id, "vuln.py")` to simulate a turn that wrote a dangerous file.
3. Call `consume_stop_state(session_id)` to simulate Stop firing (clears `touched_paths`, returns snapshot with `baseline_sha=sha1`).
4. Simulate the failing LLM call (skip / raise).
5. Before calling `restore_unreviewed_stop_state`, simulate the race: commit `vuln.py`'s dangerous content, then call `handle_user_prompt_submit`-equivalent logic (or directly call `capture_git_baseline` + write `state["baseline_sha"] = sha2`) since `touched_paths` is currently empty on disk.
6. Call `restore_unreviewed_stop_state(session_id, ["vuln.py"], sha1)`.
7. Assert `load_baseline_sha(session_id) == sha2` (not `sha1`) — proving the stale-baseline was not restored.
8. Call `compute_v2_review_set(cwd, sha2, head_at_capture, {})` and assert `"vuln.py"` is **absent** from the returned review set even though it is present in `state["touched_paths"]` — demonstrating the dangerous file is silently dropped from review, violating the expected invariant that the review set stays bound to touched paths.

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L74-113)
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
```

**File:** plugins/security-guidance/hooks/diffstate.py (L116-137)
```python
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

**File:** plugins/security-guidance/hooks/diffstate.py (L417-422)
```python
    if baseline_sha:
        changed_since = _git_name_only(repo, baseline_sha)
        if changed_since is not None:
            changed_since |= new_untracked
    else:
        changed_since = None
```

**File:** plugins/security-guidance/hooks/diffstate.py (L426-426)
```python
    review_set = (dirty_now & changed_since) if changed_since is not None else dirty_now
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L486-503)
```python
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
