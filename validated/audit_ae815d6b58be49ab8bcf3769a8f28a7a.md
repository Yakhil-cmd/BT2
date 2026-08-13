Based on my research, I found a concrete, code-level bypass in `handle_stop_hook`'s loop-prevention counter, though I was unable to retrieve the exact numeric value of `MAX_STOP_HOOK_FIRINGS` before running out of iterations.

### Title
Stop-hook fire-count guard silently disables all future security review (including the real final turn) once the retry budget is exhausted - (File: `plugins/security-guidance/hooks/security_reminder_hook.py`)

### Summary
`handle_stop_hook` caps how many times the asyncRewake loop can re-fire per session using a shared `stop_hook_fire_count` counter with a 120-second TTL. The cap check does not distinguish "recursive rewake fire" from "the final, real Stop event for the turn" — once `fire_count >= MAX_STOP_HOOK_FIRINGS` within the TTL window, every subsequent Stop hook invocation is skipped unreviewed, including the one covering the truly last/dangerous diff of the turn.

### Finding Description
`consume_stop_state` snapshots and clears `touched_paths` on every Stop fire [1](#0-0) . `handle_stop_hook` reads `fire_count` from that snapshot and, before doing any diff/LLM work, checks it against `MAX_STOP_HOOK_FIRINGS` and calls `_skip(2)` (an unconditional `sys.exit(0)` with no `restore=True`) if the budget is exhausted [2](#0-1) . The comment says the counter "auto-expires after `STOP_LOOP_STATE_TTL_SEC`" (120s) so a stale count from a prior turn doesn't block the current one [3](#0-2) , but within that 120-second window there is no way to distinguish a legitimate rewake retry from the genuinely final Stop event of the turn — both are gated by the same counter check with the same silent `_skip(2)` exit.

An attacker who controls repository/task content (e.g., a malicious coding task, PR description, or repo structure) that causes the agent to go through a burst of distinct fix/rewake cycles (each cycle: Stop fires → vulnerability found → exit 2 → agent "fixes" it → Stop fires again) can exhaust `MAX_STOP_HOOK_FIRINGS` inside the 120s TTL window purely through normal edit/fix activity. If the actually dangerous edit is introduced as the last action in that burst, the final Stop-hook invocation that would have reviewed it instead hits the exhausted counter and exits silently with `skip_reason=2` — no LLM review, no guidance banner, no exit-2 rewake, and (crucially) `_skip(2)` does not call `restore_unreviewed_stop_state`, so `touched_paths` is not restored either. If the session ends shortly after (no further user turn triggers UPS/Stop), that dangerous diff never gets reviewed at all, because `baseline_sha` is only advanced when a genuine finding is recorded via `_record_fire` — but the *unreviewed skip* path leaves the review permanently deferred to "whenever TTL expires and Stop next fires," which may never happen before the conversation naturally concludes.

### Impact Explanation
This breaks the stated invariant that "dangerous edits and commands must stay reviewable and blockable even across retries" — a burst of legitimate-looking fix/rewake activity (attacker-influenceable via crafted repo/task content that forces multiple distinct vulnerabilities to surface and get fixed in sequence) can exhaust the loop-guard counter and cause the Stop hook to silently no-op on the turn's real, final dangerous change, with zero user-visible warning. This matches the "Security-control bypass that silently disables or routes around blocking, review, or permission boundaries" impact class, since the bypass is a direct consequence of the hook's own hard-coded counter logic rather than an LLM judgment call.

### Likelihood Explanation
Requires no privilege escalation — only repository/task content that induces several distinct fix cycles within a 120-second window (a plausible outcome of a complex or intentionally noisy task), followed by a genuinely dangerous final edit. Feasibility depends on the exact value of `MAX_STOP_HOOK_FIRINGS` (not confirmed via available tools) and on the agent naturally cycling through that many distinct rewake fires quickly; this is a real but moderate-likelihood race/window condition rather than a trivially reproducible one-shot bypass.

### Recommendation
Distinguish the "final Stop for this turn" from "recursive rewake Stop" — e.g., by not gating the very last Stop invocation of a turn on the fire-count cap, or by emitting a user-visible warning (not just a metrics `skip_reason`) whenever `_skip(2)` fires, so the user knows a diff was left unreviewed. Also consider persisting the skipped review as still-pending (rather than silently discarding it) so the next successful hook fire (Stop, commit-review, or push-sweep) is guaranteed to catch it regardless of TTL timing.

### Proof of Concept
Integration test plan for `handle_stop_hook` in `plugins/security-guidance/hooks/security_reminder_hook.py`:
1. Seed session state so `stop_hook_fire_count == MAX_STOP_HOOK_FIRINGS` and `stop_hook_fire_count_ts` is recent (within `STOP_LOOP_STATE_TTL_SEC`).
2. Create a git working tree with a genuinely dangerous diff (e.g., a new `eval(request.args[...])` sink) that is not present in `previous_findings`.
3. Invoke `handle_stop_hook` with `stop_hook_active=False` (simulating the final, real Stop for the turn, not an active rewake).
4. Assert the process exits 0 with `skip_reason=2` and that `analyze_code_security` / `sys.stderr.write` guidance were never invoked — confirming the dangerous diff was never surfaced to the user despite this being the last opportunity to review it in the session.

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L21-29)
```python
# =====================================================================
# TTL constants
# =====================================================================

# stop_hook_fire_count expires after this many seconds.
# The asyncRewake loop (vuln→exit(2)→fix→Stop again) is ~30-60s/cycle, so 120s
# comfortably contains MAX_STOP_HOOK_FIRINGS while letting the next user turn
# proceed unblocked. Replaces the UPS-reset that raced against background Stop.
STOP_LOOP_STATE_TTL_SEC = 120
```

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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1763-1772)
```python
    # Limit stop hook firings per asyncRewake loop to prevent infinite loops.
    # fire_count auto-expires after STOP_LOOP_STATE_TTL_SEC so a stale count
    # from a prior turn doesn't block this one.
    if MAX_STOP_HOOK_FIRINGS > 0 and fire_count >= MAX_STOP_HOOK_FIRINGS:
        debug_log(f"Stop hook: already fired {fire_count} times (max {MAX_STOP_HOOK_FIRINGS}), skipping")
        _skip(2)

    if not ENABLE_CODE_SECURITY_REVIEW or not HAS_API_CREDENTIALS:
        debug_log("Stop hook: LLM review disabled or no API credentials")
        _skip(3)
```
