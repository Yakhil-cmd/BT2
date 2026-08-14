### Title
Non-ancestor HEAD moves (`reset --hard`, branch reassignment, orphan history) bypass `compute_v2_review_set`, hiding committed dangerous changes from Stop-hook review - (File: plugins/security-guidance/hooks/diffstate.py)

### Summary
`compute_v2_review_set` only unions in commits made since `head_at_capture` when `_is_ancestor(head_at_capture, current_head)` is true, i.e. only for a strictly linear HEAD advance. Any normal git operation that moves `HEAD` to a commit that does **not** have `head_at_capture` as an ancestor (e.g. `git reset --hard` to a sibling/other-branch commit, force-checkout, or committing on a detached/orphan history and then pointing the branch at it) leaves the working tree clean and produces an empty `dirty_now` set for the already-committed dangerous file, so the intersection `dirty_now ∩ changed_since` in `compute_v2_review_set` becomes empty even though `changed_since` (diff against `baseline_sha`) would still show the file as modified.

### Finding Description
`capture_git_baseline` (`plugins/security-guidance/hooks/diffstate.py:163-204`) is invoked from `handle_user_prompt_submit` on every `UserPromptSubmit` [1](#0-0) , recording `baseline_sha` (a `git stash create` SHA / HEAD) and `head_at_capture` (current HEAD) into session state.

At Stop time, `compute_v2_review_set` (`plugins/security-guidance/hooks/diffstate.py:353-438`) builds the review set as:

```
review_set = dirty_now ∩ changed_since
```

where `dirty_now` = current git-status dirty files, **plus**, only if `_is_ancestor(head_at_capture, current_head)` holds, the files touched between `head_at_capture` and `HEAD`: [2](#0-1) 

`_is_ancestor` (`plugins/security-guidance/hooks/gitutil.py:377-388`) only returns true when the old HEAD is reachable from the new HEAD, i.e. a strictly linear/fast-forward-style advance: [3](#0-2) 

If, during the same session, Claude (potentially driven by attacker-controlled repository content or PR/issue text acting as a prompt injection instructing "helpful" git cleanup) commits a dangerous change and then performs any *normal* git operation that moves `HEAD` non-linearly relative to `head_at_capture` — e.g. `git reset --hard <other-commit>`, checking out and force-updating a branch to a commit built from a different/detached ancestry, or rewriting history via rebase onto an unrelated base — the working tree becomes clean and `_is_ancestor(head_at_capture, HEAD)` is false. The linear-advance branch is skipped, so `dirty_now` no longer includes the dangerous file at all (it is neither "dirty" against the new HEAD nor pulled in via the ancestor branch). Since `review_set` is an **intersection**, `changed_since` (which still shows the file as different from `baseline_sha`) cannot rescue it — the file drops out entirely. `compute_v2_review_set` then returns an empty `review_paths`, and `handle_stop_hook` hits the "empty review set" skip path: [4](#0-3) 

The dangerous, already-committed change is never diffed, never sent to the LLM reviewer, and is silently folded into the repository's normal history — the Stop hook exits 0 as if nothing happened.

### Impact Explanation
This breaks the stated invariant that an attacker must not be able to hide a dangerous change by shifting it outside the computed review window. Because the security-guidance Stop hook is the sole gate that forces Claude to address vulnerabilities found in code it writes during a turn (`sys.exit(2)` with guidance), causing the review set to go empty means a dangerous command/code change committed by Claude during the session bypasses all Claude Code security-guidance review and is not surfaced for approval or correction — matching "Unauthorized local command execution that bypasses Claude Code approval or deny controls" since the change proceeds into the repo/working tree unreviewed.

### Likelihood Explanation
This requires no elevated privilege: it only requires normal git commands executable by the Bash tool within a cloned repository during an ordinary Claude Code session (`git reset --hard`, branch checkout/force-update, rebase). An attacker who can influence Claude's actions via repository content (e.g. a malicious README/PR instructing "clean up your branch with `git reset --hard origin/main` after committing" or similar plausible-sounding git hygiene instructions) can reliably trigger this non-linear HEAD condition. The bug is deterministic given the described git sequence, not timing-dependent, making it reproducible.

### Recommendation
Do not gate the `head_at_capture..HEAD` diff behind a strict ancestor check that silently drops non-linear history from the review set. Instead:
- When `_is_ancestor` is false, fall back to reviewing based on `changed_since` alone (don't intersect with a `dirty_now` that structurally cannot include committed-then-rewound content), or
- Explicitly detect non-linear/force-moved HEAD (e.g. via reflog) and treat it as requiring full review of `changed_since` rather than skipping, and
- Add a fast invariant test asserting that after commit + `git reset --hard <divergent-commit>` (or similar non-ancestor HEAD move), `compute_v2_review_set` still returns the dangerous file in `review_paths`.

### Proof of Concept
Integration test outline for `compute_v2_review_set` (`plugins/security-guidance/hooks/diffstate.py`):
1. Init a repo, commit `H0` (clean tree). Capture `baseline_sha = H0`, `head_at_capture = H0` (mirrors UPS baseline capture).
2. Create branch `tmp` from `H0~0`'s parent (or an unrelated root), add `dangerous.py` with a dangerous pattern, commit as `C1` (parent not `H0`).
3. On `main`, run `git reset --hard C1` (or `git checkout -B main C1`) so `HEAD == C1`, working tree clean, and `_is_ancestor(H0, C1)` is `False`.
4. Call `compute_v2_review_set(repo, baseline_sha=H0, head_at_capture=H0, untracked_at_baseline={})`.
5. Assert `dangerous.py` (absolute path) IS present in the returned `review_paths` — i.e., the dangerous file must not be excluded from review purely because HEAD advanced non-linearly.
6. Expected current (vulnerable) behavior: `review_paths` is empty / does not contain `dangerous.py`, demonstrating the review-window bypass.

### Citations

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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1792-1797)
```python
    review_paths, diff_base, repo_root, untracked, v2_metrics = compute_v2_review_set(
        cwd, baseline_sha, head_at_capture, untracked_at_baseline
    )
    if not review_paths:
        debug_log("Stop hook: empty review set")
        _skip(9, touched_paths_count=len(touched_paths))
```

**File:** plugins/security-guidance/hooks/diffstate.py (L403-409)
```python
    diff_base = "HEAD"
    current_head = _git_rev_parse_head(repo)
    if (head_at_capture and current_head and head_at_capture != current_head
            and _is_ancestor(repo, head_at_capture, current_head)):
        dirty_now |= _git_name_only(repo, f"{head_at_capture}..HEAD") or set()
        diff_base = head_at_capture

```

**File:** plugins/security-guidance/hooks/gitutil.py (L377-387)
```python
def _is_ancestor(cwd, maybe_ancestor, descendant):
    """True if `maybe_ancestor` is reachable from `descendant` (i.e. HEAD
    moved forward via commit/merge, not sideways via checkout)."""
    try:
        result = subprocess.run(
            [*GIT_CMD, "merge-base", "--is-ancestor", maybe_ancestor, descendant],
            cwd=cwd, capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
```
