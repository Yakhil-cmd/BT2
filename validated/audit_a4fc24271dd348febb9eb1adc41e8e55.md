### Title
Security-guidance state files stored under `~/.claude/security/` inherit default (non-owner-only) permissions on multi-user hosts, exposing review findings and vulnerable-code snippets to other local users - (File: `plugins/security-guidance/hooks/session_state.py`)

### Summary
The external report's root cause is a mismatch between an *assumed* confidentiality boundary and the *actual* storage mechanism: Solidity `private` restricts contract-level access but not underlying storage visibility. The same class of assumption failure exists in the `security-guidance` plugin's session-state persistence: the code and comments treat `~/.claude/security/` as an owner-only, per-session-private location, but the actual directory/file creation calls in `session_state.py` do not enforce that restriction, unlike the sibling module `_base.py` which explicitly hardens the same directory.

### Finding Description
`plugins/security-guidance/hooks/_base.py` creates the shared state directory with an explicit owner-only mode and documents why: [1](#0-0) [2](#0-1) 

showing the developers' explicit assumption that `~/.claude/security` must be `0700` "so other local users can't read review/debug output."

However, `plugins/security-guidance/hooks/session_state.py`, which manages the actual per-session JSON state file (`security_warnings_state_<session>.json`) and its lock file, creates the same directory without any mode restriction, and writes the JSON file with a plain `open(..., "w")` (no explicit `os.open`/`os.chmod` with a restrictive mode): [3](#0-2) [4](#0-3) 

`os.makedirs(state_dir, exist_ok=True)` (no `mode=` argument) creates the directory subject only to the process umask — typically `0o755` on common Linux defaults — and `open(state_file, "w")` creates the file at typically `0o644`. `get_lock_file`'s lock file is opened the same way via `os.open(lock_file, os.O_RDWR | os.O_CREAT)` with no mode argument. If `with_locked_state`/`save_state` executes before `_base.debug_log` has ever hardened the directory (e.g., the very first hook invocation on a host doesn't happen to call `debug_log` first, or a different process/user creates the directory first), the directory is left world-readable/executable and the JSON state file inside it is left world-readable.

That JSON state is not innocuous: it accumulates `pending_warnings`, `shown_warnings`, counters, and — critically — `previous_findings`, which the push-sweep handler populates with `filePath`, `category`, and `vulnerableCode` snippets extracted directly from the LLM security reviewer's output: [5](#0-4) 

`vulnerableCode` here is literally the exact vulnerable line(s) quoted by the review prompt (per `llm.py`'s instructions to "quote the exact line(s)"), i.e., a persisted, on-disk record of security-relevant source snippets and file paths from the user's private session/project.

### Impact Explanation
On any multi-user host (shared devbox, CI runner, container image with a permissive default umask) other local, unprivileged users who can read `~/<other_user>/.claude/security/security_warnings_state_*.json` (or the shared state dir if `SECURITY_WARNINGS_STATE_DIR` points to a shared location) can read another user's/session's flagged vulnerable code snippets, file paths, and finding categories — exactly the kind of "private by assumption, public by mechanism" confidentiality break the external report calls out. The developer comment in `_base.py` explicitly acknowledges this is the threat model being defended against, but `session_state.py` does not consistently apply the same defense to the file that actually carries the sensitive payload.

### Likelihood Explanation
Exploitability depends on directory-creation ordering and host umask configuration: if `_base.py`'s `debug_log` (which passes `mode=0o700` and only applies it "on creation") always runs first in every invocation path, the directory is already hardened before `session_state.py` touches it and the issue is latent. But `with_locked_state`/`save_state` in `session_state.py` do not depend on `debug_log` having run first, so any invocation order where state is written before the directory is hardened (e.g., a fresh install, or a differently-permissioned pre-existing directory from an older version) leaves the disclosure window open. This is a real but conditional/timing-dependent exposure rather than a guaranteed one on every install.

### Recommendation
Harden directory and file creation consistently in `session_state.py`:
- Replace `os.makedirs(state_dir, exist_ok=True)` in both `save_state` and `with_locked_state` with the same `mode=0o700` pattern used in `_base.py`, and explicitly `os.chmod` if the directory pre-exists with looser permissions.
- Create the state JSON file via `os.open(state_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)` instead of the bare `open(..., "w")`, mirroring the `0o600` file mode already used for the debug log.
- Apply the same explicit mode to `get_lock_file`'s `os.open` call.

### Proof of Concept
1. On a fresh multi-user host with a permissive umask (e.g., `umask 022`), ensure `~/.claude/security/` does not yet exist and that no `debug_log` call has occurred.
2. Trigger a security-guidance hook path that calls `with_locked_state`/`save_state` directly (e.g., `atomic_check_and_mark_warning`) without any prior `debug_log` invocation.
3. Observe the resulting directory (`ls -ld ~/.claude/security`) is `0755` and the state file (`ls -l ~/.claude/security/security_warnings_state_*.json`) is `0644`.
4. As a second unprivileged local user on the same host, read the first user's `security_warnings_state_*.json` and confirm `previous_findings[].vulnerableCode`/`filePath` entries are visible.

### Citations

**File:** plugins/security-guidance/hooks/_base.py (L13-19)
```python
# Debug log file. Lives under the plugin state dir (default ~/.claude/security/)
# rather than /tmp because /tmp is world-writable on multi-user hosts (TOCTOU /
# symlink-attack surface, cross-user log leakage). Overridable per-process via
# SECURITY_GUIDANCE_DEBUG_LOG, or per-state-dir via SECURITY_WARNINGS_STATE_DIR.
_DEFAULT_STATE_DIR = os.path.expanduser(
    os.environ.get("SECURITY_WARNINGS_STATE_DIR") or "~/.claude/security"
)
```

**File:** plugins/security-guidance/hooks/_base.py (L32-38)
```python
        # Ensure parent dir exists — first hook invocation on a fresh install
        # creates ~/.claude/security/ if it isn't already there. 0700 so other
        # local users can't read review/debug output (only applies on creation).
        try:
            os.makedirs(os.path.dirname(DEBUG_LOG_FILE), mode=0o700, exist_ok=True)
        except OSError:
            pass
```

**File:** plugins/security-guidance/hooks/session_state.py (L104-115)
```python
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

**File:** plugins/security-guidance/hooks/session_state.py (L118-131)
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
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1665-1681)
```python
    snapshots = [
        {"filePath": v.get("filePath", ""),
         "category": v.get("category", "Unknown"),
         "vulnerableCode": v.get("vulnerableCode", "")}
        for v in reported
    ]
    def _record(state):
        existing = [f for f in state.get("previous_findings", [])
                    if isinstance(f, dict)]
        seen = {(f.get("filePath", ""), f.get("category", "")) for f in existing}
        for f in snapshots:
            k = (f["filePath"], f["category"])
            if k not in seen:
                seen.add(k); existing.append(f)
        state["previous_findings"] = existing
        state["previous_findings_ts"] = _time.time()
    with_locked_state(session_id, _record)
```
