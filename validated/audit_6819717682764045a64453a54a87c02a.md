### Title
`compute_v2_review_set` drops dangerous files from Stop-hook review when normal git history operations break the `head_at_capture`→`HEAD` ancestry link - ([File: plugins/security-guidance/hooks/diffstate.py])

### Summary
`compute_v2_review_set` intersects `dirty_now` (files dirty relative to the *current* HEAD/index, plus a commit-range diff that is only added when `head_at_capture` is an ancestor of the current HEAD) with `changed_since` (diff against the turn-start stash `baseline_sha`). When ordinary git operations during a turn (e.g. `git commit` + `git reset --hard`, `git commit --amend` after a rebase, or checkout to another ref) make the dangerous file appear "clean" against the current HEAD/index and simultaneously break the ancestor relationship between `head_at_capture` and the new HEAD, the file is excluded from `dirty_now` even though it still differs from `baseline_sha`. Because `review_set = dirty_now & changed_since`, the file is silently dropped from review despite genuinely being a this-turn change.

### Finding Description
`compute_v2_review_set` at [1](#0-0)  builds the review set as:

- `tracked_dirty`/`untracked` from `_git_status_porcelain(repo)`, which reflects the diff between the worktree and the *current* index/HEAD only — it says nothing about the turn-start baseline.
- A conditional extra term, `dirty_now |= _git_name_only(repo, f"{head_at_capture}..HEAD")`, added **only if** `head_at_capture != current_head` **and** `_is_ancestor(repo, head_at_capture, current_head)` holds [2](#0-1) .
- `changed_since`, computed independently from `baseline_sha` (a `git stash create` snapshot taken at UserPromptSubmit time) via `_git_name_only(repo, baseline_sha)` [3](#0-2) .
- `review_set = dirty_now & changed_since` [4](#0-3) .

The comment at the top of the function documents the intended invariant explicitly: `review_set = (files dirty vs current HEAD, plus files committed this turn when HEAD advanced linearly) ∩ (files whose content differs from the pre-turn stash baseline)` [5](#0-4) . This design assumes HEAD only ever "advances linearly" from `head_at_capture`. Normal, unprivileged git operations that Claude (or an attacker driving Claude via repo content/PR text/tool output) can invoke in a cloned repo break that assumption:

1. Turn starts; `capture_git_baseline` stashes worktree state as `baseline_sha`, and `head_at_capture` = current HEAD (call it C0) — recorded in `handle_user_prompt_submit` [6](#0-5) .
2. Claude edits a dangerous file `X` and commits it (`C1`, parent `C0`) — normal git usage.
3. Claude (or injected instructions) then performs another ordinary git action that moves HEAD off the `C0 → C1` line without leaving `C0` as an ancestor of the new HEAD (for example resetting to an unrelated ref that already contains identical content for `X`, or a rebase/squash sequence that discards `C1` and produces a commit whose relationship to `C0` is not a simple ancestor chain in the direction the check expects, or moving to a completely different branch/tag that happens to have matching content for `X`).
4. At Stop time: `_is_ancestor(repo, head_at_capture, current_head)` returns `False`, so the `head_at_capture..HEAD` diff term is never unioned into `dirty_now`. `_git_status_porcelain` shows `X` as clean against the new HEAD (nothing staged/dirty). Thus `dirty_now` no longer contains `X`.
5. `changed_since` (diff of `baseline_sha` vs. worktree) still would show `X` as changed, since its content differs from the pre-turn snapshot — but the intersection with `dirty_now` zeroes it out anyway, per line 426.
6. `X` is silently excluded from `review_paths`, bypassing the LLM security review entirely in `handle_stop_hook` [7](#0-6) .

No existing check catches this: there is no validation that `head_at_capture` is reachable from or related to the resulting HEAD in the non-ancestor case beyond simply omitting the commit-range term; there is no fallback to union `changed_since` alone when the commit-range term can't be computed. This directly violates the stated invariant that "the review set must stay bound to the right repo, baseline, and touched paths."

### Impact Explanation
This is a logic-level bypass of a security guard: a genuinely dangerous code change made during the session can be excluded from the Stop-hook's LLM vulnerability review, meaning the mandatory "must fix before continuing" gate (`sys.exit(2)` path in `handle_stop_hook`) never fires for that file. This matches "Logic-level service disruption caused by bypassing a required guard or misbinding security state" — the review-set computation misbinds itself to a HEAD state that no longer reflects the actual touched/dangerous file, allowing the change to be treated as pre-existing/old and skipped.

### Likelihood Explanation
The precondition is only "normal git operations in a cloned repo" performed during a turn — no privilege beyond standard developer/agent git usage (commit, reset, rebase, amend, checkout) is required, matching the unprivileged attacker model. It is fully repeatable: any sequence that (a) commits the dangerous file so it becomes clean relative to some HEAD, and (b) subsequently moves HEAD such that `head_at_capture` is not an ancestor of the resulting HEAD while `X`'s tracked-dirty status is also clean, reproduces the bypass deterministically.

### Recommendation
Do not gate the `head_at_capture..HEAD` term on strict ancestry, or provide a fallback: when `_is_ancestor` is false (or `head_at_capture` is unreachable), union `dirty_now` directly with `changed_since` rather than only intersecting the status-based `dirty_now` with `changed_since`. Concretely, review_set should be `((dirty_now_status ∪ commit_diff_if_ancestor) ∩ changed_since) ∪ (changed_since when ancestry cannot be established)`, or simpler: treat `changed_since` (diff against the immutable pre-turn stash) as authoritative for "was this file touched this turn," and only use the status/HEAD-range term to *widen* (not narrow) the set, never to gate it out via intersection when history has moved non-linearly.

### Proof of Concept
Integration test plan (pytest style, operating on a temp git repo):
1. Init a repo with an initial commit `C0` containing a benign file `X` with safe content.
2. Call `capture_git_baseline(cwd)` to get `baseline_sha`, and record `head_at_capture = C0`.
3. Edit `X` with dangerous content (e.g., `os.system(user_input)`), `git add`, `git commit` → `C1`.
4. Perform a normal git operation that discards the ancestor relationship, e.g.:
   - `git reset --hard C0` then `git commit --allow-empty -m "unrelated"` on a divergent branch, then `git checkout -B main <new-commit-with-X-already-containing-dangerous-content-but-committed-directly>` — i.e., construct a new commit `C2` (not a descendant of `C0` in the ancestor-check's expected direction, or use `git rebase`/squash to replace `C1`) such that `X` in the worktree matches `C2`'s tree (clean) and `_is_ancestor(repo, C0, C2)` is `False`.
5. Call `compute_v2_review_set(cwd, baseline_sha, head_at_capture="C0", untracked_at_baseline={})`.
6. Assert: `X`'s absolute path is **not** in `review_paths` (demonstrating the bug) while manually confirming via `git diff --name-only baseline_sha` that `X` genuinely differs from the pre-turn baseline — i.e., the invariant "review set must contain files that changed since baseline" is violated.
7. Expected (fixed) behavior: `review_paths` should still contain `X` because its content differs from `baseline_sha`, regardless of the HEAD movement pattern.

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L356-360)
```python
    review_set = (files dirty vs current HEAD, plus files committed this turn
    when HEAD advanced linearly) ∩ (files whose content differs from the
    pre-turn stash baseline). The first term is immune to checkout/pull
    ballooning; the second filters out the user's untouched pre-turn WIP.
    Falls back to dirty_now alone when no baseline is available.
```

**File:** plugins/security-guidance/hooks/diffstate.py (L386-426)
```python
    tracked_dirty, untracked = _git_status_porcelain(repo)
    if tracked_dirty is None:
        return [], "HEAD", repo, [], {"dirty_now_count": -1, "changed_since_count": -1, "review_set_count": 0}

    def _unchanged_since_baseline(p):
        base_mtime = untracked_at_baseline.get(p)
        if base_mtime is None:
            return False
        try:
            return os.stat(os.path.join(repo, p)).st_mtime_ns == base_mtime
        except OSError:
            return False

    preexisting_unchanged = {p for p in untracked if _unchanged_since_baseline(p)}
    new_untracked = untracked - preexisting_unchanged
    dirty_now = tracked_dirty | new_untracked

    diff_base = "HEAD"
    current_head = _git_rev_parse_head(repo)
    if (head_at_capture and current_head and head_at_capture != current_head
            and _is_ancestor(repo, head_at_capture, current_head)):
        dirty_now |= _git_name_only(repo, f"{head_at_capture}..HEAD") or set()
        diff_base = head_at_capture

    # changed_since: tracked files vs the stash baseline (no temp index — the
    # stash never contained untracked files anyway), then union with
    # currently-untracked. The previous `include_untracked=True` arm cost a
    # full `git add -N .` (slow in large repos) per call to surface
    # untracked files in the diff output — but `git diff <stash>` already
    # lists them as "only in worktree" without that, and we have the explicit
    # set from status regardless.
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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L477-503)
```python
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
