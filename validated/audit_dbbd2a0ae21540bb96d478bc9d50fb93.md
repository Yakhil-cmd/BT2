### Title
Stop-hook review-set computation misses dangerous commits when HEAD diverges from the captured baseline, allowing the change to be silently skipped - ([File: plugins/security-guidance/hooks/diffstate.py])

### Summary
`compute_v2_review_set` computes the Stop-hook's review set as `dirty_now ∩ changed_since`, where `dirty_now` is only unioned with `head_at_capture..HEAD` when `_is_ancestor(head_at_capture, current_head)` holds true [1](#0-0) . If the working tree becomes clean after a commit and the new `HEAD` is not a linear descendant of `head_at_capture` (e.g. after `git reset --hard` to an unrelated ref, a checkout to a divergent branch, or a history-rewriting `rebase`/`amend` that changes the parent chain), `dirty_now` stays empty and the intersection with `changed_since` is empty regardless of what `changed_since` (diff against the stash baseline) contains. This makes the Stop hook exit via the empty-review-set skip path even though the dangerous file genuinely differs from the session baseline.

### Finding Description
`consume_stop_state` snapshots `baseline_sha`/`head_at_capture` under a lock and clears `touched_paths` for the Stop hook [2](#0-1) . `handle_stop_hook` then calls `compute_v2_review_set(cwd, baseline_sha, head_at_capture, untracked_at_baseline)` to determine which files to send for LLM review [3](#0-2) .

Inside `compute_v2_review_set`:
- `dirty_now = tracked_dirty | new_untracked` reflects only the current worktree/index dirty state [4](#0-3) .
- The only mechanism that lets committed changes into `dirty_now` is the linear-ancestor branch: `dirty_now |= git diff --name-only head_at_capture..HEAD` — but this is gated on `_is_ancestor(head_at_capture, current_head)` returning true [1](#0-0) .
- `review_set = dirty_now & changed_since` (or `dirty_now` alone if `changed_since` is `None`) [5](#0-4) .

Because the final review set is an intersection anchored on `dirty_now`, an empty `dirty_now` always yields an empty `review_set`, irrespective of `changed_since` (which is computed independently from `baseline_sha` and would correctly show the dangerous file as changed). If Claude (driven by attacker-controlled repository content/instructions) performs ordinary git operations that (a) leave the working tree clean after committing the dangerous change, and (b) make the resulting `HEAD` not a git-ancestor-descendant of `head_at_capture` (e.g. `git reset --hard <other-ref>` then commit, checking out an unrelated branch and committing there, or a rebase/amend that changes the commit's parent lineage), then `dirty_now` is empty and the whole review set collapses to empty. `handle_stop_hook` then hits the `if not review_paths: _skip(9, ...)` path with no restoration of state [6](#0-5) , meaning the dangerous commit is never diffed or sent to the LLM reviewer, and no findings/`exit(2)` are produced to force remediation.

This breaks the stated invariant in the code's own comments — that the `dirty_now` union is meant to be "immune to checkout/pull ballooning" [7](#0-6)  — because the ancestor-gated union has no fallback when ancestry doesn't hold, silently dropping a real content difference from the review scope rather than degrading safely.

### Impact Explanation
The Stop hook is the last-resort LLM safety net for reviewing "everything Claude did this turn" via `git diff` against the session baseline [8](#0-7) . If a dangerous change (e.g. a hardcoded credential, command-injection sink, or a disabled security control) can be committed such that it evades this review entirely due to the ancestry-gated `dirty_now` computation, the change proceeds without any LLM-driven remediation prompt (`exit(2)`) or approval gate — enabling unauthorized local command execution / persistence that should have been caught and blocked by Claude Code's security-guidance controls.

### Likelihood Explanation
This requires no privileged access — only normal git commands executable from within a Claude Code session (`git reset --hard`, `git checkout <branch>`, `git rebase`, or committing on a different local ref than the one active at `UserPromptSubmit` time). Such sequences are entirely plausible outcomes of attacker-controlled repository content (e.g. malicious instructions embedded in a README, issue, or automation script) steering Claude toward operations that diverge HEAD from the captured baseline while leaving the tree clean. The condition is reproducible deterministically once the specific git sequence is known, since `_is_ancestor` is a straightforward `git merge-base --is-ancestor` type check with no fallback path.

### Recommendation
Do not gate the entire `dirty_now` computation on a strict linear-ancestor check. When `head_at_capture` is not an ancestor of `HEAD` (or when `_is_ancestor` fails/returns unknown), fall back to unioning `dirty_now` with the full symmetric diff between `head_at_capture` and `HEAD` (or with `changed_since` from `baseline_sha` directly) rather than leaving `dirty_now` empty. At minimum, treat `changed_since` as authoritative when `dirty_now` is empty but `changed_since` is non-empty and clearly derived from a valid baseline, so a real content difference is never silently dropped by the intersection.

### Proof of Concept
Integration test plan (pytest, using a temp git repo and monkeypatched `cwd`):
1. Init a repo, make an initial commit (`head_at_capture`/`baseline_sha` = C0).
2. Simulate UPS: call `capture_git_baseline` to get `baseline_sha` and record `head_at_capture = C0`.
3. Simulate Claude's turn: `git checkout -b other` (or `git reset --hard <unrelated-orphan-commit>`), then write a dangerous file (e.g. `os.system(user_input)`), `git add -A && git commit -m evil` — leaving the working tree clean, with new `HEAD = C1` where `_is_ancestor(C0, C1)` is `False`.
4. Call `compute_v2_review_set(cwd, baseline_sha=C0, head_at_capture=C0, untracked_at_baseline={})`.
5. Assert (expected-but-failing): `review_paths` contains the dangerous file's path.
   Actual (bug): `review_paths == []`, confirming the dangerous commit is excluded from the review window despite `git diff C0 C1` clearly showing the change.
6. Additionally drive through `handle_stop_hook` end-to-end with mocked LLM call and assert `_skip(9)` (empty review set) is hit and `sys.exit(2)`/LLM review never triggered for the dangerous file.

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

**File:** plugins/security-guidance/hooks/diffstate.py (L356-360)
```python
    review_set = (files dirty vs current HEAD, plus files committed this turn
    when HEAD advanced linearly) ∩ (files whose content differs from the
    pre-turn stash baseline). The first term is immune to checkout/pull
    ballooning; the second filters out the user's untouched pre-turn WIP.
    Falls back to dirty_now alone when no baseline is available.
```

**File:** plugins/security-guidance/hooks/diffstate.py (L399-401)
```python
    preexisting_unchanged = {p for p in untracked if _unchanged_since_baseline(p)}
    new_untracked = untracked - preexisting_unchanged
    dirty_now = tracked_dirty | new_untracked
```

**File:** plugins/security-guidance/hooks/diffstate.py (L403-408)
```python
    diff_base = "HEAD"
    current_head = _git_rev_parse_head(repo)
    if (head_at_capture and current_head and head_at_capture != current_head
            and _is_ancestor(repo, head_at_capture, current_head)):
        dirty_now |= _git_name_only(repo, f"{head_at_capture}..HEAD") or set()
        diff_base = head_at_capture
```

**File:** plugins/security-guidance/hooks/diffstate.py (L417-426)
```python
    if baseline_sha:
        changed_since = _git_name_only(repo, baseline_sha)
        if changed_since is not None:
            changed_since |= new_untracked
    else:
        changed_since = None
    # changed_since is None on missing baseline OR on git error (e.g. the
    # dangling stash SHA was pruned). Either way, don't intersect with ∅ —
    # that would silently zero the review set. Fall back to dirty_now.
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
