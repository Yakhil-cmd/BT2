### Title
Review-set AND-intersection drops amended/rebased commits, causing Stop-hook to silently skip reviewing dangerous changes - (File: `plugins/security-guidance/hooks/diffstate.py`)

### Summary
`compute_v2_review_set` intersects `dirty_now` (working-tree-dirty files, optionally extended by a `head_at_capture..HEAD` linear-ancestor diff) with `changed_since` (a diff of the pre-turn stash baseline against the on-disk state) to build the Stop-hook's file list. When a normal, unprivileged git operation like `git commit --amend` or a rebase rewrites history so `head_at_capture` is no longer an ancestor of the new `HEAD`, `dirty_now` loses the file entirely if the working tree is otherwise clean, while `changed_since` still contains it — the AND-intersection then yields an empty review set for that file, and the Stop hook exits via `_skip(9, ...)` without ever sending the diff to the LLM reviewer.

### Finding Description
`consume_stop_state` snapshots `baseline_sha` and `head_at_capture` captured at the previous `UserPromptSubmit` [1](#0-0) , and `handle_stop_hook` feeds them straight into `compute_v2_review_set` [2](#0-1) .

Inside `compute_v2_review_set`:
- `dirty_now` starts from `_git_status_porcelain` (current working-tree dirty/untracked files only) and is only extended with `head_at_capture..HEAD` when `_is_ancestor(repo, head_at_capture, current_head)` holds [3](#0-2) .
- `changed_since` is computed via `_git_name_only(repo, baseline_sha)` [4](#0-3) , which runs `git diff --name-only <baseline_sha>` with no second ref — this compares the baseline against the *current on-disk worktree/index*, independent of commit history rewriting [5](#0-4) .
- The final `review_set = dirty_now & changed_since` [6](#0-5) .

If, during the turn, the dangerous edit is committed and then the history is rewritten with a normal `git commit --amend` (or `git rebase`, `git reset --hard` + recommit, `git commit --amend --no-edit`), `_is_ancestor(head_at_capture, HEAD)` returns `False` because `head_at_capture` is no longer reachable from the rewritten `HEAD`. With a clean working tree after the amend, `_git_status_porcelain` returns no tracked-dirty entries for that file, so `dirty_now` becomes empty for it. `changed_since` still contains the file because `_git_name_only(repo, baseline_sha)` diffs against the live worktree content, which does differ from the pre-turn stash. The AND-intersection then excludes the file from `review_set`. `handle_stop_hook` treats an empty `review_paths` as `_skip(9, ...)` and exits `0` — the dangerous change is never diffed, never sent to the LLM analyzer, and no `exit code 2` review/continuation is forced [2](#0-1) .

No approval/allowlist/workspace guard exists to catch this: the Stop hook is the sole review surface for this turn's uncommitted+committed edits per the module's own doc comment [7](#0-6) , and there is no fallback re-check when `_is_ancestor` fails.

### Impact Explanation
This breaks the stated invariant that "the review set must stay bound to the right repo, baseline, and touched paths": a file that objectively differs from the session's git baseline is dropped from review purely because of a linear-ancestry check that ordinary `git commit --amend`/rebase invalidates. Since the Stop hook's LLM review is the mechanism gating whether Claude is forced to continue and address findings (`exit code 2`), silently skipping the review set lets a dangerous change (e.g., injected shell command, backdoor, secret) pass through a full turn undetected — a local security-review bypass of the exact kind the plugin exists to prevent.

### Likelihood Explanation
The trigger requires only standard git usage: commit a change, then amend or rebase it (or otherwise rewrite `HEAD` non-linearly) while leaving the working tree clean afterward. This is routine behavior an agentic coding session can perform without any elevated privilege, secrets, or social engineering, and is fully reproducible deterministically given `head_at_capture` and a subsequent history rewrite.

### Recommendation
Do not gate the `head_at_capture..HEAD` diff on `_is_ancestor`; when `head_at_capture` is not an ancestor of `HEAD` (or is missing), fall back to diffing `changed_since`-derived paths directly rather than intersecting with a potentially incomplete `dirty_now`, or simply drop the intersection and always take the union of `dirty_now` and `changed_since` for the review set so that a non-empty `changed_since` never gets silently zeroed out by a stale/invalidated `dirty_now`.

### Proof of Concept
Integration test around `compute_v2_review_set` (or `handle_stop_hook`):
1. Init a repo, commit an initial file, capture `baseline_sha = capture_git_baseline(cwd)` and `head_at_capture = _git_rev_parse_head(cwd)`.
2. Write a dangerous change to `danger.py` (e.g., `os.system(user_input)`), `git add`, `git commit -m "add danger"`.
3. Run `git commit --amend -m "add danger (amended)"` with a clean working tree afterward (no dirty files).
4. Call `compute_v2_review_set(cwd, baseline_sha, head_at_capture, {})`.
5. Assert `danger.py` is present in the returned `review_paths` — expected to FAIL under current logic (`review_set` empty because `dirty_now` lacks `danger.py` while `changed_since` contains it), confirming the file is dropped from the Stop-hook's LLM review pipeline despite differing from baseline.

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

**File:** plugins/security-guidance/hooks/diffstate.py (L401-408)
```python
    dirty_now = tracked_dirty | new_untracked

    diff_base = "HEAD"
    current_head = _git_rev_parse_head(repo)
    if (head_at_capture and current_head and head_at_capture != current_head
            and _is_ancestor(repo, head_at_capture, current_head)):
        dirty_now |= _git_name_only(repo, f"{head_at_capture}..HEAD") or set()
        diff_base = head_at_capture
```

**File:** plugins/security-guidance/hooks/diffstate.py (L417-420)
```python
    if baseline_sha:
        changed_since = _git_name_only(repo, baseline_sha)
        if changed_since is not None:
            changed_since |= new_untracked
```

**File:** plugins/security-guidance/hooks/diffstate.py (L426-426)
```python
    review_set = (dirty_now & changed_since) if changed_since is not None else dirty_now
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L17-22)
```python
2. **Stop hook (final review)**: When Claude finishes, uses `git diff` against a
   baseline SHA (captured at UserPromptSubmit) to get only the code changed during the
   session. Runs two Haiku analyses on the diff:
   a) Concrete vulnerability scan with severity ratings
   b) Areas-of-concern analysis identifying categories to investigate
   Exits with code 2 to force Claude to continue and address findings.
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1792-1798)
```python
    review_paths, diff_base, repo_root, untracked, v2_metrics = compute_v2_review_set(
        cwd, baseline_sha, head_at_capture, untracked_at_baseline
    )
    if not review_paths:
        debug_log("Stop hook: empty review set")
        _skip(9, touched_paths_count=len(touched_paths))
    debug_log(f"Stop hook: review_set={len(review_paths)} base={diff_base[:12]} dirty_now={v2_metrics['dirty_now_count']} changed_since={v2_metrics['changed_since_count']}")
```

**File:** plugins/security-guidance/hooks/gitutil.py (L303-318)
```python
def _git_name_only(cwd, base, include_untracked=False):
    """Return the set of repo-root-relative paths that differ from `base`,
    or None if git failed (unresolvable ref, not a repo, timeout). Callers
    must distinguish None (error → don't trust as a filter) from set()
    (genuinely nothing changed). `-c core.quotePath=false -z` keeps non-ASCII
    and space-containing paths intact."""
    def _run(env):
        result = subprocess.run(
            [*GIT_CMD, "-c", "core.quotePath=false", "diff", "--name-only", "-z", base],
            cwd=cwd, capture_output=True, text=True, timeout=30,
            env=env,
        )
        if result.returncode != 0:
            debug_log(f"_git_name_only({base!r}) rc={result.returncode}: {result.stderr[:200]}")
            return None
        return {p for p in result.stdout.split("\0") if p}
```
