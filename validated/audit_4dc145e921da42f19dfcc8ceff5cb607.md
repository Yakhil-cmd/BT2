### Title
Silent, permanent bypass of the security-guidance Stop hook when `get_git_diff` fails transiently after `touched_paths` has already been consumed - (File: `plugins/security-guidance/hooks/security_reminder_hook.py`)

### Summary
The `M-36` report describes a class of bug where a state checkpoint (`lastRebalancingPeriod`) is advanced *before* the corresponding accrual actually happens, and the accrual check only fires on a strict inequality — so once the checkpoint is bumped without accrual, that period's rewards are permanently lost. The `security-guidance` plugin's Stop hook has the same root-cause pattern: it atomically clears the `touched_paths` tracking marker *before* confirming that the corresponding security review actually ran, and a transient failure path fails to distinguish "genuinely nothing to review" from "the review could not be performed," permanently dropping the unreviewed edits from tracking.

### Finding Description
`handle_stop_hook` begins by calling `consume_stop_state`, which under a single lock reads and then **clears** `touched_paths` in the same operation [1](#0-0) . This clear happens unconditionally, before any diff is actually computed or reviewed — it is the exact analog of `lastRebalancingPeriod` being bumped before `addToTotalRewards` has verified accrual.

Later, the hook computes the diff via `get_git_diff`, whose contract explicitly distinguishes a genuinely empty diff (`""`) from a command failure (`None`, e.g. non-zero exit code, timeout, or `OSError`) [2](#0-1) . This None/"" distinction is documented elsewhere in the same codebase as safety-critical: `_git_diff_range`'s docstring states "on failure (timeout, non-zero exit, missing git) it must NOT mark them reviewed — otherwise unreviewed commits get permanently silenced" [3](#0-2) .

However, in `handle_stop_hook` this distinction is discarded:
```
if not diff_output or not diff_output.strip():
    debug_log("Stop hook: no changes since baseline")
    _skip(6)
``` [4](#0-3) 

Both `None` (git command failed) and `""` (truly no changes) fall through to `_skip(6)`, which is called **without** `restore=True`. `restore=True` is the only mechanism that puts the already-cleared `touched_paths`/`baseline_sha` back into state via `restore_unreviewed_stop_state` [5](#0-4) ; it is used solely for the `ensure_anthropic_reachable()` failure path (`_skip(10, restore=True)`) [6](#0-5) .

Because `touched_paths` was already zeroed by `consume_stop_state` and is not restored on a `get_git_diff` failure, the next turn's `UserPromptSubmit` handler sees an empty `touched_paths` and therefore does **not** preserve the old baseline — the preservation guard is explicitly keyed on `touched_paths` being non-empty [7](#0-6) . The baseline silently advances past the unreviewed edits, permanently removing them from any future diff/review.

### Impact Explanation
The Stop hook is the last-line enforcement mechanism that forces Claude to fix flagged vulnerabilities (SQLi, command injection, hardcoded secrets, etc.) before ending a turn, via `sys.exit(2)` [8](#0-7) . A single transient `git diff` failure (subprocess timeout, temp-index race, disk contention, non-zero exit) occurring after `consume_stop_state` has already cleared `touched_paths` causes that turn's file edits to be **permanently and silently excluded** from security review — not merely delayed to the next Stop firing. Any vulnerable or malicious code written in that turn (including code introduced via prompt injection or a compromised tool) will never be flagged or blocked, defeating the purpose of the security-guidance enforcement hook without any visible error to the user.

### Likelihood Explanation
This requires the `git diff` subprocess invoked by `get_git_diff` to fail (30s timeout, `OSError`, or non-zero exit) at the specific point after `consume_stop_state` has run. This is plausible in large repositories, resource-constrained CI/background sessions, or under filesystem contention from concurrent git operations (the temp-index mechanism copies and mutates the index file). It does not require attacker control of the hook itself, only an environment or timing condition that triggers a transient git failure — moderate likelihood in real-world large-repo/CI usage rather than a purely theoretical edge case.

### Recommendation
In `handle_stop_hook`, distinguish `diff_output is None` (git failure) from `diff_output == ""` (genuine no-op), mirroring the handling already documented for `_git_diff_range`. On `None`, call `_skip(6, restore=True)` (or a dedicated skip reason) so `restore_unreviewed_stop_state` re-arms `touched_paths`/`baseline_sha` for the next Stop invocation, consistent with the existing `ensure_anthropic_reachable()` failure handling.

### Proof of Concept
Conceptual reproduction:
1. Claude edits a file containing an injected vulnerability (e.g., via a malicious tool result or prompt injection) during a turn; `record_touched_path` records it.
2. The Stop hook fires; `consume_stop_state` atomically snapshots and clears `touched_paths` [9](#0-8) .
3. `get_git_diff` fails transiently (e.g., simulate by injecting a `subprocess.TimeoutExpired` or forcing a non-zero exit in the underlying `git diff` call) and returns `None` [10](#0-9) .
4. `handle_stop_hook` treats this as "no changes since baseline" and calls `_skip(6)` without restoring state [4](#0-3) .
5. The next `UserPromptSubmit` sees empty `touched_paths`, does not preserve the old baseline, and re-baselines past the vulnerable edit [11](#0-10) .
6. The vulnerable code is never reviewed or flagged by any subsequent Stop/commit-review/push-sweep hook fire, permanently bypassing the security-guidance control.

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

**File:** plugins/security-guidance/hooks/gitutil.py (L193-210)
```python
def _git_diff_range(repo_root, base, head="HEAD"):
    """`git diff -p base head` as text on success, None on error.

    Distinguishing failure from success-with-empty-diff matters: the push-sweep
    caller marks the tail reviewed when the diff is empty (nothing to review),
    but on failure (timeout, non-zero exit, missing git) it must NOT mark
    them reviewed — otherwise unreviewed commits get permanently silenced.
    """
    try:
        r = subprocess.run(
            [*GIT_CMD, "diff", "-p", "--no-color", "--no-ext-diff", base, head],
            cwd=repo_root, capture_output=True, timeout=30,
        )
        if r.returncode != 0:
            return None
        return r.stdout.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
```

**File:** plugins/security-guidance/hooks/gitutil.py (L414-427)
```python
    cmd = [*GIT_CMD, "diff", "--no-color", "--no-ext-diff", baseline_sha] + (["--unified=99999"] if full_context else []) + pathspec
    try:
        with _temp_index(cwd, untracked_paths) as env:
            # env is None when no index could be found (bare repo / not a
            # repo) — diff still runs, just without untracked-file support.
            result = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=30, env=env)
        if result.returncode != 0:
            debug_log(f"git diff failed: {result.stderr[:200].decode('utf-8', errors='replace')}")
            return None
        # Decode with errors='replace' so binary diffs don't crash
        return result.stdout.decode("utf-8", errors="replace")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        debug_log(f"git diff error: {e}")
        return None
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L479-502)
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
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1784-1786)
```python
    if not ensure_anthropic_reachable():
        debug_log("Stop hook: api.anthropic.com unreachable")
        _skip(10, restore=True)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1819-1821)
```python
    if not diff_output or not diff_output.strip():
        debug_log("Stop hook: no changes since baseline")
        _skip(6)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1944-1947)
```python

        # Exit code 2 with stderr forces Claude to continue and fix
        sys.stderr.write(PROVENANCE_BANNER + "\n\n" + concrete_guidance + CONTINUATION_SUFFIX + "\n")
        sys.exit(2)
```
