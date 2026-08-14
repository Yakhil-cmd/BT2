### Title
Session/remote-session-scoped dedup state lacks workspace binding, allowing cross-project vulnerability-finding suppression - ([File: plugins/security-guidance/hooks/session_state.py])

### Summary
The security-guidance plugin's Stop/PostToolUse hooks (commit-review, push-sweep) suppress re-flagging a vulnerability once it has been "shown" to the user, using a `(filePath, category)` key stored in a per-session state file. The state file identity is derived only from `session_id` (or the longer-lived `CLAUDE_CODE_REMOTE_SESSION_ID`), with no binding to the workspace/project root the finding actually came from. This is the same root-cause class as the Harpie `changeRecipientAddress()` bug: a trust decision recorded under one "domain" (there: a chain; here: a project directory) is missing a domain separator, so it can be silently replayed against a different domain that happens to reuse the same key material.

### Finding Description
`_state_key()` builds the identifier used for the state/lock file path purely from the session id: [1](#0-0) 

The accompanying comment explicitly documents that `CLAUDE_CODE_REMOTE_SESSION_ID` is intentionally preferred because it "is stable across restarts" of the underlying CC process, while `session_id` itself resets per turn: [2](#0-1) 

`get_state_file`/`load_state`/`save_state`/`with_locked_state` all key exclusively off this session identifier — never off `cwd`, `CLAUDE_PROJECT_DIR`, or a repo root: [3](#0-2) [4](#0-3) 

This state is what backs the `previous_findings` dedup mechanism. `_finding_keys` reduces a finding to `(filePath, category)` with no project-root component, and `_dedup_against_state` filters live findings against whatever is currently stored under that session key: [5](#0-4) 

The LLM review prompt is explicitly instructed to treat any `(filePath, category)` pair that matches a `previous_findings` entry as "already handled" and skip re-flagging it unless the code changed: [6](#0-5) 

Because the state key is bound only to `session_id`/`CLAUDE_CODE_REMOTE_SESSION_ID` and not to the working directory, if the same remote session identifier is active across more than one project/workspace (e.g., a long-lived remote session where the user or an automation changes `cwd` to a different repo clone, or parallel CC processes tied to the same `CLAUDE_CODE_REMOTE_SESSION_ID` in different worktrees), a finding recorded as "shown/handled" for `filePath=src/db.py`, `category=SQL Injection` in Project A will cause the *same* `(filePath, category)` pair in unrelated Project B to be treated as already-reviewed and suppressed — even though it was never actually reviewed there. This is functionally identical to the Harpie bug: the signed/stored decision ("this finding was surfaced/handled") is missing the domain separator (project root) that should have scoped it, so it gets silently "replayed" into a different, unrelated context.

### Impact Explanation
This is a fail-open bypass of the security-guidance auto-review guardrail rather than a crypto asset-theft bug, but the mechanism is directly analogous to the reported class: a decision meant to be scoped to one execution context leaks its trust into another because the scoping identifier was never included. Concretely, a genuinely new/unfixed vulnerability introduced by Claude in one project can go unreported to the user because a coincidentally-matching `(filePath, category)` pair was already dismissed in a different project under the shared session identifier — undermining the plugin's core guarantee that newly introduced vulnerabilities are always surfaced.

### Likelihood Explanation
Requires that the same `CLAUDE_CODE_REMOTE_SESSION_ID` (documented as intentionally long-lived/stable across process restarts) is exercised against more than one working directory/repo, and that the vulnerable file's relative path plus vulnerability category coincide between the two projects (common for generic paths like `app.py`, `server.js`, `main.py`, or common categories like SQL Injection/Hardcoded Secrets). This is plausible in remote/background-session or multi-repo/worktree workflows but is not a trivially-triggered single-command exploit, so likelihood is moderate rather than high.

### Recommendation
Bind the state-file key to the project/workspace root in addition to the session identifier — e.g., hash `(session_key, repo_root_or_cwd)` together when computing `_state_key`, mirroring how the reviewed-shas log is deliberately kept repo-local via `.git`-scoped storage. This mirrors the Harpie fix of adding `chain.id` into the signed payload: add the missing "domain" (workspace) into the key used for the previous-findings/shown-warnings state before trusting it.

### Proof of Concept
1. Start a Claude Code session in Project A with a persistent `CLAUDE_CODE_REMOTE_SESSION_ID` set (as happens in CCR-style remote sessions).
2. Trigger a commit-review finding for `src/app.py` category `SQL Injection`; it gets recorded into `previous_findings` in the state file keyed by `_state_key(session_id)` → effectively the remote session id.
3. Without ending the remote session, switch `cwd` to unrelated Project B (different repo) that also has a file at relative path `src/app.py` containing a *different*, newly introduced SQL Injection vulnerability.
4. The Stop/commit-review hook in Project B loads the same state file (same remote session key), sees `(src/app.py, SQL Injection)` in `previous_findings`, and per the prompt instructions in `llm.py` (`prev_section`) treats it as already surfaced/handled — suppressing the new, unrelated finding in Project B. [7](#0-6) [5](#0-4)

### Citations

**File:** plugins/security-guidance/hooks/session_state.py (L25-46)
```python
def _state_key(session_id):
    # In CCR each user turn is a new CC process with a fresh session_id; the
    # remote session ID is stable across those restarts. Prefer it so the
    # pending-warnings sweep and any unprocessed touched_paths survive.
    key = os.environ.get("CLAUDE_CODE_REMOTE_SESSION_ID") or session_id
    # The key becomes a filename component under the state dir. CC session ids
    # are UUIDs (sanitization is a no-op for them), but nothing in the hook
    # protocol guarantees that, so strip path separators and anything else
    # that could escape the state dir, and bound the length.
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(key))[:128]


def get_state_file(session_id):
    """Get session-specific state file path."""
    state_dir = os.environ.get("SECURITY_WARNINGS_STATE_DIR", os.path.expanduser("~/.claude/security"))
    return os.path.join(state_dir, f"security_warnings_state_{_state_key(session_id)}.json")


def get_lock_file(session_id):
    """Get session-specific lock file path."""
    state_dir = os.environ.get("SECURITY_WARNINGS_STATE_DIR", os.path.expanduser("~/.claude/security"))
    return os.path.join(state_dir, f"security_warnings_state_{_state_key(session_id)}.lock")
```

**File:** plugins/security-guidance/hooks/session_state.py (L118-138)
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

**File:** plugins/security-guidance/hooks/llm.py (L767-782)
```python
    structured_prev = [f for f in (previous_findings or []) if isinstance(f, dict)]
    if structured_prev:
        prev_lines = "\n".join(
            f"  - {f.get('filePath', '?')} [{f.get('category', '?')}]: {f.get('vulnerableCode', '?')}"
            for f in structured_prev
        )
        prev_section = (
            "PREVIOUS FINDINGS (already surfaced to the developer earlier this turn — DO NOT re-flag):\n"
            "The exact findings below were already shown to the developer, who has either fixed them or "
            "acknowledged them as not applicable. DO NOT report any finding whose (filePath, category) pair "
            "matches an entry below — it was already handled. The vulnerableCode may differ slightly from "
            "what you see now (diff context lines shift between fires) — match on file + category, not exact "
            "code bytes. ONLY re-flag a (filePath, category) from this list if the code at that location was "
            "CHANGED since the prior review and the change is an incomplete fix or introduces a new issue.\n"
            f"{prev_lines}\n"
        )
```
