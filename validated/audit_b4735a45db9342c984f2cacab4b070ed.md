### Title
Security-review Stop hook can be silently and permanently defeated when the LLM review "no-ops" - ([File: plugins/security-guidance/hooks/security_reminder_hook.py])

### Summary
The `security-guidance` plugin's `Stop` hook mirrors the Sense-redeem bug class: it eagerly *consumes* (clears) the tracked state that represents "files needing a security review" before handing control to an external, unreliable component (the Claude API call that performs the actual review), and only restores that consumed state on two specific, enumerated failure paths. Any other way the external review fails to produce a real verdict causes the consumed `touched_paths` record to be lost forever, functionally bypassing the security-guidance control for that turn's edits — the same "pull the resource first, then call an untrusted/unreliable party with no guaranteed completion, and no way to recover the resource afterward" pattern as the Sense `Redeemer`.

### Finding Description
`consume_stop_state` snapshots and atomically clears `touched_paths` (the list of files edited this turn that are pending security review) as the very first step of the `Stop` hook, specifically because the hook is asynchronous and races with the next turn's `UserPromptSubmit`: [1](#0-0) 

This clear happens unconditionally, before the (slow, network-dependent, LLM-driven) review has actually run: [2](#0-1) 

The code recognizes this "consume-before-completion" hazard and added `restore_unreviewed_stop_state` to put `touched_paths` back — but only wires it into two specific skip reasons:
- reason `10`, when the pre-flight connectivity probe fails: [3](#0-2) 
- the post-call branch, only when `llm._last_call_claude_http_error` is explicitly set (i.e., only for HTTP-layer errors from `_call_claude`): [4](#0-3) 

Every other exit from `handle_stop_hook` — fire-count exceeded (`_skip(2)`), review disabled/no credentials (`_skip(3)`), missing `cwd` (`_skip(4)`), stop-review opt-out (`_skip(50)`), and, most importantly, the normal "review ran but returned no vulnerabilities" branch when `_last_call_claude_http_error` is `None` — treats the already-cleared `touched_paths` as consumed with no restoration: [5](#0-4) [6](#0-5) 

This is exactly the Sense flaw shape: `amount`/`touched_paths` is computed and irrevocably consumed (`token.balanceOf` transferred / `touched_paths` cleared) *before* the untrusted external call (`ISense(d).redeem` / the Claude API review) is known to have actually completed its job, and the mitigation (recovering the consumed value) is only wired for a narrow subset of failure modes the author anticipated (connectivity probe, explicit HTTP error), not the general case of "the external call ran but didn't actually deliver a real verdict."

### Impact Explanation
If `analyze_code_security`/`_call_claude` returns cleanly with an empty/degenerate result for any reason other than a recorded HTTP error — e.g., a malformed or truncated model response, a caught-but-unclassified exception inside `analyze_code_security` (its full exception handling could not be fully verified within the tool budget available), or the model simply producing no findings for content it was actually never shown — the hook logs "no security issues found" and exits 0 without restoring `touched_paths`. Since `touched_paths` was already cleared before the review ran, those edited files are never queued for review again by any other mechanism. This permanently and silently defeats the `security-guidance` Stop-hook control for that turn's changes, i.e. attacker-influenced or vulnerable code introduced in that turn can pass through with the review believed to have "passed," analogous to the Sense principal being irrecoverably lost once the malicious/no-op redeemer returns.

### Likelihood Explanation
Medium. It does not require a malicious external contract as in the Sense case, but it does require the shared trust assumption that the external LLM call ("untrusted" in the sense of being uncontrollable/non-deterministic, like Sense's `redeem`) either succeeds completely or reports itself via `_last_call_claude_http_error`. Any gap in that error classification (network blackholes not caught by the pre-flight probe, provider content-filtering/timeout responses that don't map to a tracked HTTP status, or any unhandled exception path inside `analyze_code_security`/`_call_claude` not visible in the code reviewed) reproduces the bug automatically, with no attacker action needed beyond making an edit during a turn where the review silently fails.

### Recommendation
Invert the control: only clear/consume `touched_paths` after `analyze_code_security` has returned a *positively confirmed* successful outcome (vulns found and reported, or vulns explicitly absent from a verified-successful API response), not merely "no exception raised down to this line." Treat every non-success outcome (any exception, any falsy/ambiguous LLM result, any missing explicit "call succeeded" signal) the same as the currently-handled HTTP-error case and route it through `restore_unreviewed_stop_state`, so the default behavior on ambiguity is fail-closed (state preserved, reviewed later) rather than fail-open (state silently dropped).

### Proof of Concept
1. During a turn, edit a file containing a genuinely new vulnerability; `touched_paths` accumulates that file via `PostToolUse`.
2. Trigger `Stop`. `consume_stop_state` clears `touched_paths` immediately: [2](#0-1) 
3. `analyze_code_security` is called; suppose it returns `(None, [])` for a reason other than a tracked HTTP error (e.g., an internal exception is swallowed somewhere in the LLM call path, or the model's response fails a downstream parse and the code falls through to "no findings").
4. Because `llm._last_call_claude_http_error` is `None`, the hook takes the "no security issues found" branch and exits 0 without calling `restore_unreviewed_stop_state`: [6](#0-5) 
5. `touched_paths` is now empty on disk. The vulnerable edit from step 1 is never re-queued for review by any hook, and the developer/agent proceeds believing the code was checked.

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L74-107)
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
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1724-1735)
```python
    # Snapshot all state under one lock BEFORE any slow work (sweep file I/O,
    # git, network). asyncRewake Stop runs in the background; the next turn's
    # UPS/PostToolUse can fire while we're still here. The snapshot is immune
    # to those writes — they affect the NEXT Stop fire's snapshot.
    snap = consume_stop_state(session_id)
    fire_count = snap["fire_count"]
    touched_paths = snap["touched_paths"]
    baseline_sha = snap["baseline_sha"]
    snap_baseline = baseline_sha  # pre-reassignment value for restore-on-transient-skip
    head_at_capture = snap["head_at_capture"]
    untracked_at_baseline = snap.get("untracked_at_baseline") or {}
    previous_findings = snap["previous_findings"]
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1766-1790)
```python
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
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1949-1972)
```python
    if llm._last_call_claude_http_error is not None:
        debug_log(f"Stop hook: API call failed with status {llm._last_call_claude_http_error}")
        restore_unreviewed_stop_state(session_id, touched_paths, snap_baseline)
    else:
        debug_log("Stop hook: no security issues found")
    # CC truncates metrics to 10 keys by
    # insertion order. The previous **sweep,**v2_metrics tail meant the 3
    # v2_metrics keys were always sliced off this most-common path, so the
    # diff-strategy diagnostics never reached telemetry. Drop sweep here (it's
    # PostToolUse-warning state, orthogonal to diff-strategy comparison).
    # 6 base + optional api_error + 3 v2_metrics = ≤10.
    emit_metrics({
        "vulns_found": 0,
        "diff_strategy_v2": True,
        "files_reviewed": len(diff_files),
        "touched_paths_count": len(touched_paths),
        "review_ms": review_ms,
        "fire_index": fire_index,
        **({"api_error": llm._last_call_claude_http_error} if llm._last_call_claude_http_error is not None else {}),
        **({"diff_truncated": llm._last_review_truncated_bytes}
           if llm._last_review_truncated_bytes else {}),
        **v2_metrics,
    })
    sys.exit(0)
```
