### Title
Missing locking in `with_locked_state` fcntl-unavailable branch enables lost-update race on `security_warnings_state_*.json` (rate-limit/counter bypass on Windows) - ([File: plugins/security-guidance/hooks/session_state.py])

### Summary
`with_locked_state` in `plugins/security-guidance/hooks/session_state.py` only takes an `fcntl.flock` exclusive lock when `fcntl` is importable; on the `fcntl is None` branch (Windows, or any platform where `fcntl` import fails) it runs `load_state -> callback -> save_state` with zero synchronization. Two hook invocations for the same `session_id` racing this path can lose updates to state (e.g. `touched_paths`, rate-limit counters), causing state built on `atomic_check_rate_limit`/`atomic_check_counter` semantics to silently under-count or drop entries.

### Finding Description
`with_locked_state` (plugins/security-guidance/hooks/session_state.py:118-138) branches on `fcntl is None`:
```
if fcntl is None:
    state = load_state(session_id)
    result = callback(state)
    save_state(session_id, state)
    return result
```
There is no file lock, no mutex, and no compare-and-swap on save — this is a plain read-modify-write with a window between `load_state` and `save_state`. If two hook invocations for the same effective state key (`_state_key`, which resolves to `CLAUDE_CODE_REMOTE_SESSION_ID` or `session_id`) execute concurrently — e.g. an attacker-controlled repository content triggers overlapping `PostToolUse[Bash]` and `Stop` hook callbacks issuing multiple simultaneous Bash tool calls — both processes can call `load_state` before either calls `save_state`. Whichever process saves last overwrites the other's mutation, producing a classic lost-update race. Because the `atomic_check_*` helpers (in `security_reminder_hook.py`, built on top of `with_locked_state`) rely on this function to guarantee atomic read-modify-write for rate limits/counters/`touched_paths` bookkeeping, this guarantee is void on the no-`fcntl` path. The locked (POSIX/`flock`) branch correctly serializes access via `lock_fd`/`fcntl.flock(LOCK_EX)`, but the unlocked branch provides none of that protection.

### Impact Explanation
On any platform where `fcntl` is unavailable (this codebase explicitly targets Windows via `except ImportError: fcntl = None`), concurrent hook invocations for the same session can lose track of rate-limit counts or previously-flagged/touched paths. If those counters gate a "deny" decision (rate limiting, repeated-warning suppression, or dedup of already-reviewed paths), a lost update can cause the security-guidance plugin to under-enforce — e.g. a counter that should have tripped a threshold gets reset by a losing writer, or a `touched_paths` entry recorded by one invocation is silently dropped by the other. This is a logic/enforcement-integrity bug in the plugin's own bookkeeping, not a remote command-execution or credential-disclosure primitive, and it is scoped to the local state file rather than to git automation, review/export, or networked tool calls.

### Likelihood Explanation
Requires (a) the fcntl-unavailable code path (Windows deployment, or any environment where the `fcntl` import fails) and (b) two hook invocations racing for the same session/remote-session key within the same TOCTOU window. Genuinely overlapping hook executions for a single session_id require the host application to actually dispatch concurrent hook calls (e.g. overlapping PostToolUse and Stop hooks) — this is plausible under CCR's remote-session model where `CLAUDE_CODE_REMOTE_SESSION_ID` unifies multiple CC processes, but it is dependent on the host's hook scheduling behavior and does not by itself demonstrate that "attacker-supplied repo commands" alone can force such overlap without the host already permitting concurrent hook dispatch.

### Recommendation
Provide a real cross-platform lock in `with_locked_state` instead of a no-op branch on Windows: use `msvcrt.locking()` (Windows equivalent of `flock`) or a portable file-lock library (e.g. `portalocker`/`filelock`) so the `load_state -> callback -> save_state` sequence is serialized on all platforms. Alternatively, use an OS-level named mutex/semaphore keyed by the same lock-file path, and ensure the same exception/cleanup semantics as the POSIX branch.

### Proof of Concept
Unit test in `plugins/security-guidance/hooks/` test suite:
1. Monkeypatch `session_state.fcntl = None` to force the unlocked branch.
2. Point `SECURITY_WARNINGS_STATE_DIR` to a temp directory and use a fixed `session_id`.
3. Spawn two threads, each calling `with_locked_state(session_id, callback)` where thread A's callback appends `"/path/a"` to `state["touched_paths"]` and thread B's callback appends `"/path/b"`, both callbacks sleeping briefly between the `load_state`-triggered read and the mutation to widen the race window (or use a `time.sleep` injected via a wrapped `load_state`/`save_state`) to deterministically force the interleaving `A.load -> B.load -> A.save -> B.save`.
4. After both threads join, call `session_state.load_state(session_id)` and assert both `"/path/a"` and `"/path/b"` are present in `touched_paths`.
5. Expected result on current code: the assertion fails (only one path survives), demonstrating the lost update; after applying a real lock (e.g. `msvcrt.locking`), both entries survive. [1](#0-0)

### Citations

**File:** plugins/security-guidance/hooks/session_state.py (L118-161)
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

    except (OSError, IOError) as e:
        debug_log(f"Lock/state operation failed: {e}")
        return None

    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            except (OSError, IOError):
                pass

```
