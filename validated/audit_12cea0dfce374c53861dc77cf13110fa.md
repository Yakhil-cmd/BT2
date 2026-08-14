### Title
Security-guidance state files can be tampered with directly to bypass the Stop-hook review and warning-suppression controls - ([File: plugins/security-guidance/hooks/session_state.py])

### Summary
The `GenesisGroup` bug lets an attacker manipulate the trusted "checked" state (`address(this).balance`) through a side channel (`selfdestruct`) instead of the intended tracked path (`purchase`), bypassing the checks and mutations that path performs and corrupting downstream decisions (`isAtMaxPrice`, `launch`). The `security-guidance` plugin has the same structural weakness: its Stop-hook firing limit, per-warning "already shown" dedup, and rate limits are all decided from a plain JSON state file on disk (`~/.claude/security/security_warnings_state_*.json`) that is trusted as if it could only be mutated through the plugin's own atomic helpers, but nothing prevents a Bash command (e.g. one triggered by prompt-injected instructions in reviewed content) from writing that file directly and disabling the security review for the rest of the session.

### Finding Description
`session_state.py` defines `load_state`/`save_state`/`with_locked_state` as the sole intended mutation path for this state: `with_locked_state` takes an `fcntl` lock, loads the JSON, lets a callback mutate it, and writes it back. [1](#0-0) 

`security_reminder_hook.py` builds all of its security-gating primitives on top of that helper: `atomic_check_and_mark_warning` (dedupes shown warnings), `atomic_check_counter`, and `atomic_check_rate_limit` (commit/push review throttling) all assume the on-disk state can only reach the values their own callbacks would produce. [2](#0-1) [3](#0-2) 

The Stop hook itself reads `stop_hook_fire_count` from the same file and, if it is at/above `MAX_STOP_HOOK_FIRINGS`, skips the LLM security review entirely for the rest of the loop: [4](#0-3) 

Exactly like `GenesisGroup.balance`, this file lives in a location (`~/.claude/security/...json`) that is writable by any process running as the same OS user — including a Bash command Claude itself executes. `load_state`/`save_state` perform no integrity check (no signature, no monotonic sequence check tied to the locked mutation history) beyond basic JSON parsing: [5](#0-4) 

If content Claude is asked to process (a README, code comment, issue body, etc.) contains a prompt-injection instruction that gets Claude to run a shell command writing directly to that state file — e.g. setting `stop_hook_fire_count` to a large number, or pre-populating `shown_warnings`/`counters`/`rate_limits` with the keys the plugin would otherwise gate on — the write bypasses every one of the "checks and mutations" the atomic helpers were supposed to enforce, in the same way `selfdestruct` bypasses `purchase`'s checks and mint logic while still updating the value (`balance`) the contract trusts.

### Impact Explanation
This is a hook-bypass of the security-guidance plugin's own enforcement mechanism: once the state file is tampered with, `handle_stop_hook` will silently `_skip(2)` on every subsequent turn (no LLM diff review, no forced continuation via `exit(2)`), and `atomic_check_and_mark_warning`/`atomic_check_rate_limit` will suppress warnings and commit/push reviews that should have fired. The net effect is that a single successful prompt-injection-driven write permanently disables the project's automated security review for the remainder of the session, letting subsequently introduced vulnerabilities pass without the intended forced-continuation/guidance step — a direct, local compromise of the tool's own approval/enforcement gate, not merely a documentation or best-practice gap.

### Likelihood Explanation
Requires: (1) Claude processing attacker-controlled content containing a prompt-injection payload, and (2) Claude executing a Bash command (already a normal, frequently-approved capability) that writes to a predictable, per-session path under `~/.claude/security/`. The session key is derived deterministically from `session_id`/`CLAUDE_CODE_REMOTE_SESSION_ID`, so the target file path is discoverable/guessable from environment context available to the running agent. No admin/owner privilege is needed — this is exactly the "self-inflicted, obscure but reachable" class the original report describes, but here the state being clobbered directly maps to a real approval/review-bypass control rather than a griefing-only outcome.

### Recommendation
Do not treat the on-disk JSON state file as an authoritative security boundary. Options:
- Store the security-critical counters (`stop_hook_fire_count`, `shown_warnings`, rate-limit buckets) somewhere the invoked shell commands cannot reach without going through the same privilege boundary as the hook process itself (e.g., a store outside the workspace/user-writable path the agent's Bash tool can target, or an in-memory/daemon-mediated store).
- Add tamper-evidence to the state file (HMAC/signature keyed by a secret not exposed to the Bash tool, or a monotonically-increasing counter validated against process-local memory) so an external overwrite is detected and treated as untrusted rather than silently adopted.
- At minimum, sanity-bound values read from disk (e.g., reject `stop_hook_fire_count` jumps larger than one per fire, reject `shown_warnings`/`rate_limits` entries that weren't produced by this process) instead of trusting the file's contents unconditionally the way `load_state` does today.

### Proof of Concept
1. Get Claude, in the course of normal operation, to read attacker-influenced content (e.g., a file in the repo, an issue/PR body ingested by an integration) that instructs it to run a shell command such as:
   `python3 -c "import json; json.dump({'stop_hook_fire_count': 999999, 'stop_hook_fire_count_ts': __import__('time').time(), 'shown_warnings': [], 'counters': {}}, open('/root/.claude/security/security_warnings_state_<session_id>.json','w'))"`
2. On the next Stop hook invocation, `handle_stop_hook` reads `fire_count` via `consume_stop_state`, sees it `>= MAX_STOP_HOOK_FIRINGS`, and calls `_skip(2)` — exiting 0 without running any LLM security review for the remainder of the session, exactly mirroring how `selfdestruct`-inflated `balance` lets `isAtMaxPrice`/`launch` bypass the intended `purchase`-gated invariant in the `GenesisGroup` report.

### Citations

**File:** plugins/security-guidance/hooks/session_state.py (L88-116)
```python
def load_state(session_id):
    """Load the full state dict from file."""
    state_file = get_state_file(session_id)
    try:
        with open(state_file, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return {"shown_warnings": data}
            if isinstance(data, dict):
                data.setdefault("shown_warnings", [])
                return data
    except (json.JSONDecodeError, IOError, KeyError, TypeError):
        pass
    return {"shown_warnings": []}


def save_state(session_id, state):
    """Save the full state dict to file."""
    state_file = get_state_file(session_id)
    try:
        state_dir = os.path.dirname(state_file)
        if state_dir:
            os.makedirs(state_dir, exist_ok=True)

        with open(state_file, "w") as f:
            json.dump(state, f)
    except (IOError, OSError) as e:
        debug_log(f"Failed to save state file {state_file}: {e}")

```

**File:** plugins/security-guidance/hooks/session_state.py (L118-148)
```python
def with_locked_state(session_id, callback):
    """
    Execute callback with exclusive access to the state file.
    The callback receives the state dict and can modify it in place.
    State is saved after the callback returns.
    Returns the callback's return value.
    """
    lock_file = get_lock_file(session_id)
    state_dir = os.path.dirname(lock_file)

    try:
        os.makedirs(state_dir, exist_ok=True)
    except OSError:
        pass

    if fcntl is None:
        # No file locking available (Windows) — run without locking
        state = load_state(session_id)
        result = callback(state)
        save_state(session_id, state)
        return result

    lock_fd = None
    try:
        lock_fd = os.open(lock_file, os.O_RDWR | os.O_CREAT)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

        state = load_state(session_id)
        result = callback(state)
        save_state(session_id, state)
        return result
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L237-269)
```python
def atomic_check_and_mark_warning(session_id, warning_key):
    """
    Atomically check if a warning has been shown and mark it as shown if not.
    Returns True if this is the first time seeing this warning (should show it),
    False if it was already shown (should skip it).
    """
    def _check(state):
        warnings = state["shown_warnings"]
        if warning_key in warnings:
            return False
        warnings.append(warning_key)
        return True

    result = with_locked_state(session_id, _check)
    return result if result is not None else True

def atomic_check_counter(session_id, counter_key, max_count):
    """
    Atomically check if a counter has reached its limit and increment if not.
    Returns True if the counter is below max_count (should proceed),
    False if it has reached or exceeded max_count (should skip).
    """
    def _check(state):
        counters = state.get("counters", {})
        current = counters.get(counter_key, 0)
        if current >= max_count:
            return False
        counters[counter_key] = current + 1
        state["counters"] = counters
        return True

    result = with_locked_state(session_id, _check)
    return result if result is not None else True
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L271-308)
```python
def atomic_check_rate_limit(session_id, key, max_per_window, window_s):
    """Rolling-window rate limit: allow at most `max_per_window` calls per
    `window_s` seconds, per (session_id, key).

    Returns (allowed: bool, count_in_window: int). count_in_window is the
    post-decision count (i.e., includes this call if allowed) so callers can
    emit it directly as a telemetry gauge.

    Replaces session-lifetime `atomic_check_counter` for commit-review and
    push-sweep. Telemetry showed a small but persistent share of sessions hit
    the lifetime cap, and those were multi-day persistent sessions that then
    lost coverage for many subsequent commits — not burst abusers. A rolling
    hour keeps the same cost ceiling for any 1h window while letting long
    sessions regain coverage.

    State key: rate_limits: {"<key>": [ts, ts, ...]}. Timestamps are pruned
    on every call so the list is bounded by max_per_window; no migration
    needed from the old `counters` dict — different key.
    """
    import time as _time
    now = _time.time()
    cutoff = now - window_s

    def _check(state):
        buckets = state.setdefault("rate_limits", {})
        ts_list = buckets.get(key, [])
        # Prune; tolerate non-numeric junk from a corrupted state file.
        ts_list = [t for t in ts_list if isinstance(t, (int, float)) and t > cutoff]
        if len(ts_list) >= max_per_window:
            buckets[key] = ts_list
            return False, len(ts_list)
        ts_list.append(now)
        buckets[key] = ts_list
        return True, len(ts_list)

    result = with_locked_state(session_id, _check)
    # State unavailable → fail-open (same posture as atomic_check_counter).
    return result if result is not None else (True, 0)
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
