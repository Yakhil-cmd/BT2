## Finding

### Title
Security-guidance plugin session state file is created world-readable, exposing security findings and code snippets to other local users - (File: `plugins/security-guidance/hooks/session_state.py`)

### Summary
The `security-guidance` plugin persists per-session security-review state — including previously-flagged vulnerability findings, exact vulnerable code snippets, and touched file paths — to disk under `~/.claude/security/`. The `save_state` function writes this file with Python's default `open(path, "w")`, which relies on the process umask rather than an explicit restrictive mode, and the containing directory is created via `os.makedirs(state_dir, exist_ok=True)` with no explicit mode either. On typical multi-user hosts (shared devboxes, CI runners, containers with permissive umasks) this results in the state file being readable (and the directory listable) by any other local user, exposing proprietary source snippets and security-sensitive review data.

### Finding Description
`get_state_file` computes a per-session JSON path under `~/.claude/security/` [1](#0-0) . `save_state` writes the state dict to that file with a plain `open(state_file, "w")` call, taking no steps to constrain the resulting file mode: [2](#0-1) 

Because no explicit mode/`os.chmod`/`os.open` with an `O_CREAT` mode argument is used, the file is created at the OS default (`0o666` masked by umask, typically `0o644` — world-readable) rather than owner-only `0o600`. The same gap exists in the directory creation call, `os.makedirs(state_dir, exist_ok=True)`, used both in `save_state` and `with_locked_state` [3](#0-2) [4](#0-3) , which does not pass a restrictive `mode=0o700`.

This is the same bug class as the `symbol-cli` report: a `fs.writeFileSync`/`open(..., "w")`-style call that persists sensitive data to a predictable path under the user's home directory without explicitly narrowing permissions, leaving it readable by any co-resident local user or process. Notably, the plugin's own LLM security-review prompt explicitly defines this exact pattern as a vulnerability class ("Insecure File Permissions on Credential Writes" — file writes creating secrets/persisted-agent-memory under a path other local users can reach, at a mode more permissive than `0o600`/`0o700`) [5](#0-4) , and the sibling module `_base.py` correctly applies `0o700`/`0o600` for its own debug log [6](#0-5) , showing the project is aware of the risk but did not apply it consistently to `session_state.py`.

### Impact Explanation
The state file stores `previous_findings`, which include `filePath`, `category`, and `vulnerableCode` — i.e., exact source-code excerpts identified as security-sensitive during the session's review — plus `shown_warnings` and touched-paths bookkeeping (consumed in `llm.py`'s `_finding_keys`/`_dedup_against_state` and the prompt-building logic) [7](#0-6) . On a shared machine, any other local account can read these files and learn precise details about vulnerabilities (including the vulnerable code itself) present in a victim's private repository before they are fixed — an information-disclosure vector that could help an attacker exploit the same repository, or leak proprietary source code.

### Likelihood Explanation
Exploitation requires only that an attacker have an unprivileged local account on the same host as the victim (shared devbox, CI runner, container host, or any multi-tenant compute) — no special privileges are needed to read a world-readable file. This mirrors the "Difficulty: High" characterization in the original report only in the sense that it depends on shared-host access, but locating the file is trivial (deterministic path `~/.claude/security/security_warnings_state_<session_id>.json`).

### Recommendation
**Short term:** In `save_state`, create the file with an explicit owner-only mode, e.g. via `os.open(state_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)` and `os.fdopen(...)` (matching the pattern already used in `_base.py`'s `debug_log`), and pass `mode=0o700` to the `os.makedirs` calls in both `save_state` and `with_locked_state`.

**Long term:** Add a check when loading state (or on plugin startup) that warns if `~/.claude/security/` or its contents have permissions broader than `0o700`/`0o600`, and tighten them automatically, consistent with the long-term recommendation in the original `symbol-cli` report.

### Proof of Concept
1. On a shared Linux host with a permissive umask (e.g. `umask 022`, the common default), run Claude Code with the `security-guidance` plugin enabled and trigger a Write/Edit that the plugin's Stop-hook review flags as a vulnerability (e.g. write a file containing a hardcoded secret).
2. As the same user, inspect the resulting file: `ls -l ~/.claude/security/security_warnings_state_*.json` — observe mode `-rw-r--r--` (0o644), world-readable.
3. As a second unprivileged local user, run `cat ~/<victim>/.claude/security/security_warnings_state_*.json` (assuming standard home-directory execute/read permissions) to read the victim's `previous_findings`, including the exact vulnerable code snippet flagged during the session.

### Citations

**File:** plugins/security-guidance/hooks/session_state.py (L37-40)
```python
def get_state_file(session_id):
    """Get session-specific state file path."""
    state_dir = os.environ.get("SECURITY_WARNINGS_STATE_DIR", os.path.expanduser("~/.claude/security"))
    return os.path.join(state_dir, f"security_warnings_state_{_state_key(session_id)}.json")
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

**File:** plugins/security-guidance/hooks/session_state.py (L126-131)
```python
    state_dir = os.path.dirname(lock_file)

    try:
        os.makedirs(state_dir, exist_ok=True)
    except OSError:
        pass
```

**File:** plugins/security-guidance/hooks/llm.py (L680-707)
```python
def _finding_keys(findings: List[Dict[str, Any]]) -> set:
    return {(f.get("filePath", ""), f.get("category", ""))
            for f in findings if isinstance(f, dict)}


def _dedup_against_state(session_id: str, vulns: List[Dict[str, Any]],
                         prompted: set) -> Tuple[List[Dict[str, Any]], int]:
    """Drop vulns that a CONCURRENT asyncRewake hook wrote to
    previous_findings while this hook's LLM was running.

    `prompted` is the (filePath, category) set the LLM was already told about
    via the prev_section prompt block. The LLM is instructed to only re-flag
    those if the attempted fix is incomplete, so a re-flag of a `prompted`
    entry is an intentional "fix didn't work" verdict and MUST pass through.
    We therefore re-read state now and only filter the race delta —
    (seen_now − prompted) — i.e. findings the LLM was never told about
    because they were written mid-review by the other hook.
    Returns (surviving_vulns, n_dropped).
    """
    if not vulns:
        return vulns, 0
    fresh = with_locked_state(
        session_id, lambda s: list(s.get("previous_findings", []))
    ) or []
    race_delta = _finding_keys(fresh) - prompted
    kept = [v for v in vulns
            if (v.get("filePath", ""), v.get("category", "")) not in race_delta]
    return kept, len(vulns) - len(kept)
```

**File:** plugins/security-guidance/hooks/llm.py (L868-868)
```python
**Insecure File Permissions on Credential Writes**: A file write creating a token, secret, lockfile-with-auth, or persisted-agent-memory under a path other local users can reach, where the resulting mode is more permissive than owner-only (0o600 file / 0o700 dir). Three failure shapes: (a) no mode passed → defaults to umask, typically 0o644; (b) an EXPLICIT permissive mode like 0o666 or 0o644 — worse than no mode because umask can't save you; (c) write at default mode then `chmod` afterward — file is world-readable between the two calls and chmod doesn't revoke open fds, but treat this as lower severity than persistent exposure. On multi-user hosts (devboxes, CI runners, Docker with permissive umask, shared compute) the gap between intended-mode and actual-mode is a credential-disclosure → ... (truncated)
```

**File:** plugins/security-guidance/hooks/_base.py (L33-49)
```python
        # creates ~/.claude/security/ if it isn't already there. 0700 so other
        # local users can't read review/debug output (only applies on creation).
        try:
            os.makedirs(os.path.dirname(DEBUG_LOG_FILE), mode=0o700, exist_ok=True)
        except OSError:
            pass
        try:
            if os.path.getsize(DEBUG_LOG_FILE) > DEBUG_LOG_MAX_BYTES:
                # os.replace is atomic on POSIX; under a racing fleet the loser
                # gets FileNotFoundError, which is fine — the append below
                # recreates the file.
                os.replace(DEBUG_LOG_FILE, DEBUG_LOG_FILE + ".1")
        except OSError:
            pass
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        # 0600 on creation; existing files keep their mode.
        fd = os.open(DEBUG_LOG_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
```
