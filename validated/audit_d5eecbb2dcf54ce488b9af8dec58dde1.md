### Title
Security-guidance hook state keyed by `CLAUDE_CODE_REMOTE_SESSION_ID` mixes/corrupts touched-file and baseline data across concurrent sessions - (File: `plugins/security-guidance/hooks/session_state.py`)

### Summary
The `security-guidance` plugin's Stop-hook security review (the automated "read every changed file, diff it against a baseline, flag vulnerabilities" trust boundary) stores its per-turn review data — `baseline_sha`, `touched_paths`, `previous_findings` — in a state file keyed not by the actual Claude Code `session_id`, but preferentially by the `CLAUDE_CODE_REMOTE_SESSION_ID` environment variable. Any two Claude Code processes that share that environment variable (e.g. a Remote-Control-dispatched background agent inheriting its parent's env, or two CCR-restarted processes overlapping in time) write into the exact same state file, mixing data belonging to different turns/sessions the same way the Oracle bug mixed `SDPriceData` from block 14400 and block 21600 into the same `prices` array.

### Finding Description
`_state_key` in `session_state.py` computes the on-disk state filename like this: [1](#0-0) 

```
def _state_key(session_id):
    key = os.environ.get("CLAUDE_CODE_REMOTE_SESSION_ID") or session_id
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(key))[:128]
```

The comment justifies this by saying "In CCR each user turn is a new CC process with a fresh session_id; the remote session ID is stable across those restarts" — i.e., the intent is that the *same logical session*, restarted across turns, keeps using the same state file so `touched_paths` survives process restarts.

The problem is that this key collapses the identity of "one review epoch" onto an environment variable that is not guaranteed to be exclusive to a single concurrent reviewer. `UserPromptSubmit` writes a fresh `baseline_sha`/`head_at_capture`/`untracked_at_baseline` into this shared state on every turn: [2](#0-1) 

`PostToolUse` appends every edited file into the same shared `touched_paths` list: [3](#0-2) 

And `Stop` atomically snapshots-and-clears that shared list to compute what to review: [4](#0-3) 

If two processes end up with the same `CLAUDE_CODE_REMOTE_SESSION_ID` (an env var that is inherited by any subprocess Claude Code spawns unless explicitly stripped — e.g. a background/subagent task dispatched from a Remote-Control session, or two overlapping CCR-restarted turns) but operate on **different working directories/baselines**, their `touched_paths`, `baseline_sha`, and `previous_findings` get interleaved in the single shared file exactly like the Oracle's `prices` array being appended to by both the 14400-block reporters and the 21600-block reporters. The consequence mirrors the referenced bug precisely: whichever session's `Stop` hook fires first calls `consume_stop_state`, which clears `touched_paths` for *both* sessions at once (line 106: `state["touched_paths"] = []`), permanently losing the other session's yet-unreviewed edits — the analog of "as soon as the 14400 block is finalized, the data for block 21600 is lost as well."

### Impact Explanation
This is a corruption of the trust boundary that the security-guidance plugin is supposed to enforce: reviewing every AI-authored diff for vulnerabilities before the turn ends. If one session's `Stop` hook consumes and wipes another session's `touched_paths`, that other session's file edits are never diffed and never reviewed — vulnerable or malicious code changes (secrets, injection, path traversal, etc.) silently bypass the automated review with no error surfaced to the user. Because `baseline_sha`/`head_at_capture` can also be overwritten by the "wrong" session's `UserPromptSubmit`, a later `Stop` can diff against a baseline from an unrelated working tree/session, producing a garbage or empty review set — again causing real changes to go unreviewed. This is an unprivileged-user-reachable hook-bypass analog: no special repo permissions are needed, only running two sessions/agents that happen to share the remote-session env var.

### Likelihood Explanation
Likelihood is moderate: it requires two Claude Code processes that legitimately or accidentally share `CLAUDE_CODE_REMOTE_SESSION_ID` while diverging in `session_id`/cwd — a configuration explicitly anticipated by the code comment ("each user turn is a new CC process with a fresh session_id; the remote session ID is stable across those restarts"), but the code does not distinguish "same logical session restarted" from "different concurrent session sharing the env var." Any environment where the variable is inherited by concurrently-running child processes (background agents, forked sessions, or two terminals exporting the same value) triggers the collision without any attacker action beyond normal usage.

### Recommendation
Derive the state key from a value that uniquely identifies one review epoch and cannot be shared across two concurrently-active reviewers — e.g., always use `session_id` for keying and use the remote session ID only as a linking value, or namespace the remote-session key by cwd/repo root and a monotonic epoch counter, deleting/rotating any prior epoch's `touched_paths`/`baseline_sha` before starting a new one (mirroring the Oracle fix's `currentEpochBlock` check-and-delete pattern) instead of accumulating into a single shared list keyed only by an inheritable environment variable.

### Proof of Concept
1. Start Claude Code Remote Control session A in repo `/repo-a`, which sets `CLAUDE_CODE_REMOTE_SESSION_ID=R1` in its environment.
2. Dispatch a background/sub-agent task B that inherits env var `CLAUDE_CODE_REMOTE_SESSION_ID=R1` but runs in a different working directory `/repo-b` with a different `session_id`.
3. Both A and B's `UserPromptSubmit`/`PostToolUse`/`Stop` hooks resolve to the identical state file `security_warnings_state_R1.json` via `_state_key`.
4. B edits a file containing an injected vulnerability; its path is appended to the shared `touched_paths`.
5. A's `Stop` hook fires first, calling `consume_stop_state`, which snapshots and clears the shared `touched_paths` (including B's file) before B's own `Stop` hook runs.
6. B's `Stop` hook now sees an empty `touched_paths`, so the vulnerable file B wrote is never diffed or sent to the LLM reviewer — the security review is silently bypassed.

### Citations

**File:** plugins/security-guidance/hooks/session_state.py (L25-34)
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
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L446-503)
```python
def handle_user_prompt_submit(input_data):
    """
    Handle UserPromptSubmit — capture git baseline SHA.
    Called on every user prompt. Updates the baseline so the stop hook
    only reviews changes made since the last prompt.

    Does NOT reset touched_paths/fire_count/previous_findings — those are
    consumed by Stop (consume_stop_state) and time-expired respectively.
    UPS racing the asyncRewake Stop hook caused a meaningful share of reviews
    to be lost when the wipe landed before Stop's state read.

    """
    cwd = input_data.get("cwd", "")
    if not cwd:
        debug_log("UPS: no cwd, skipping baseline capture")
        sys.exit(0)

    session_id = input_data.get("session_id", "default")
    # stash-create and ls-files both walk the worktree (~2-5s each in a very
    # large repo). Run them concurrently so UPS latency stays ≈ max(both).
    import concurrent.futures as _cf
    with _cf.ThreadPoolExecutor(max_workers=2) as _ex:
        _f_sha = _ex.submit(capture_git_baseline, cwd)
        _f_ut = _ex.submit(_list_untracked, cwd)
        sha = _f_sha.result()
        # Always capture the untracked snapshot. `git stash create` returns
        # empty when there are no TRACKED changes, but pre-existing untracked
        # files still need to be excluded from the next Stop's review_set —
        # otherwise an untracked-only working tree gets every untracked file
        # reviewed on every turn until something tracked is dirtied.
        untracked_now = _f_ut.result() or {}
    head = _git_rev_parse_head(cwd)

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

**File:** plugins/security-guidance/hooks/diffstate.py (L57-71)
```python
def record_touched_path(session_id, file_path):
    """Append a file path to the touched_paths list (deduped, capped at 200).

    Stop is the consumer and clears under the same lock it reads with; UPS
    no longer wipes. The cap is a defensive bound for sessions where Stop
    never fires (disabled mid-session, abort) — git diff naturally filters
    stale paths so over-retention is harmless, just wasteful.
    """
    def _record(state):
        paths = state.setdefault("touched_paths", [])
        if file_path not in paths:
            paths.append(file_path)
            if len(paths) > 200:
                del paths[:len(paths) - 200]
    with_locked_state(session_id, _record)
```

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
