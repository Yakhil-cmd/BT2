### Title
Stop-hook review-set computation drops content injected via `git commit --amend` / non-linear HEAD rewrites, letting dangerous changes bypass security review - ([File: plugins/security-guidance/hooks/diffstate.py])

### Summary
`compute_v2_review_set` (invoked from `handle_stop_hook` right after `consume_stop_state`) intersects "files dirty vs current HEAD (plus files reachable via a *linear* HEAD advance)" with "files changed vs the pre-turn stash baseline" to build the Stop-hook's review set. Because history-rewriting git operations such as `git commit --amend` move HEAD sideways rather than forward, and leave the working tree clean, the "dirty vs HEAD" term becomes empty for the rewritten file even though it genuinely differs from the pre-turn baseline, so the intersection silently drops it and the Stop-hook review is skipped entirely.

### Finding Description
`consume_stop_state` (`plugins/security-guidance/hooks/diffstate.py:74-113`) hands `baseline_sha` and `head_at_capture` (both captured once per turn at `UserPromptSubmit`, see `handle_user_prompt_submit`, `plugins/security-guidance/hooks/security_reminder_hook.py:446-503`) to `compute_v2_review_set` (`plugins/security-guidance/hooks/diffstate.py:353-438`), which is the sole determinant of what the Stop hook reviews (`handle_stop_hook`, `plugins/security-guidance/hooks/security_reminder_hook.py:1792-1798`).

The review set is computed as:
```
dirty_now = tracked_dirty(vs current HEAD) ∪ new_untracked
if head_at_capture is a *linear ancestor* of current HEAD:
    dirty_now |= diff(head_at_capture..HEAD)
changed_since = diff(baseline_sha..worktree)
review_set = dirty_now ∩ changed_since
``` [1](#0-0) 

`_is_ancestor` explicitly only recognizes forward, linear HEAD motion ("moved forward via commit/merge, not sideways via checkout") [2](#0-1) . A normal, unprivileged git operation like `git commit --amend` (or `git rebase -i` reword/edit, `git reset --soft && git commit`) rewrites an existing commit that was **not created during this turn** into a sibling commit. After the amend the working tree is clean against the new HEAD, so `tracked_dirty` is empty for that file, and `head_at_capture` (the turn-start HEAD, a sibling of the new HEAD, not an ancestor) fails `_is_ancestor`, so the linear-advance term also contributes nothing. Meanwhile `changed_since` (diffed against the pre-turn stash snapshot) correctly still shows the file as changed, but the empty `dirty_now` zeroes the intersection. `review_paths` ends up empty and the Stop hook exits via `_skip(9)` ("empty review set") with no LLM review and no warning at all [3](#0-2) .

This is distinct from the dedicated amend-delta logic in the commit-review PostToolUse hook (`_resolve_amend_pre_sha`, `is_amend` handling in `handle_commit_review_posttooluse`) [4](#0-3) , which is a separate execution path gated on `Bash(git commit:*)` regex matching, `ENABLE_COMMIT_REVIEW`, and hourly rate limits. Any amend/rewrite not caught there (rate-limited, disabled, or performed via a mechanism the commit-review regex doesn't match, e.g. `git rebase -i`) leaves the Stop hook as the last line of defense — and the Stop hook's own review-set computation is defeated by exactly this class of normal git operation.

### Impact Explanation
An agent turn that (a) amends/rewrites a pre-existing commit to inject a dangerous change, or (b) otherwise produces a non-linear HEAD move while leaving the working tree clean, causes the Stop-hook's review set to be silently empty. The dangerous content is never diffed, never sent to the security LLM, and the turn completes with `skip_reason=9` and no user-visible warning — violating the stated invariant that the review set must stay bound to the actually-touched paths for the session's baseline. This is a security-control bypass (missed detection of injected vulnerable code) rather than an out-of-scope cosmetic issue, matching "wrong-target mutation with real security impact" in that the enforcement mechanism silently reviews the wrong (empty) target instead of the actually-changed file.

### Likelihood Explanation
Fully reachable with unprivileged, ordinary git usage inside a normal Bash tool call — no maintainer/admin rights, no credential leakage, and no exploitation of the state file locking or session-id derivation is required. `git commit --amend` on a commit not created in the current turn is a common, everyday operation, making this trivially reproducible and repeatable every time the pattern occurs.

### Recommendation
In `compute_v2_review_set`, do not gate the "committed this turn" term on strict linear ancestry alone. When HEAD changes non-linearly relative to `head_at_capture` (amend/rebase/reset), diff the new HEAD directly against `baseline_sha` (which already reflects the pre-turn worktree state) for the full file list, rather than intersecting with a HEAD-relative `tracked_dirty` set that gets wiped clean by the rewrite. Concretely, when `head_at_capture != current_head` and it's not a strict ancestor, fall back to unioning `dirty_now` with `changed_since` (or treating `changed_since` alone as authoritative for the file list) instead of intersecting, so sideways HEAD rewrites can't zero out the review set.

### Proof of Concept
Unit/integration test plan (extends existing `compute_v2_review_set` test suite):
1. Init a repo, create commit `C0` with `dangerous_pre.py` (benign content).
2. Capture UPS state: `head_at_capture = C0`, `baseline_sha = stash-create-or-HEAD` (== `C0`, clean tree).
3. Simulate the turn: modify `dangerous_pre.py` to inject a dangerous pattern (e.g., `eval(user_input)`), `git add`, `git commit --amend --no-edit` → new HEAD `C0'` (sibling of `C0`, same parent).
4. Call `compute_v2_review_set(cwd, baseline_sha=C0, head_at_capture=C0, ...)`.
5. Assert: `_is_ancestor(C0, C0')` is `False` (sideways move); `tracked_dirty` is empty (clean tree post-amend); expected/desired `review_set` should contain `dangerous_pre.py`, but actual `review_set` is `[]` — proving the file is dropped and `handle_stop_hook` would hit `_skip(9)` with no review, despite the dangerous content being present in `HEAD`.

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L401-426)
```python
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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1064-1112)
```python
    # `git commit --amend`: review only the delta added by the amend
    # (pre-amend..post-amend) instead of the full amended commit. Without this,
    # the amend re-reviews the entire commit including code already reviewed
    # on the original commit, costing 30-60s of LLM time and re-flagging
    # findings the user may have just amended IN ORDER TO fix. Pre-amend
    # SHA comes from the reflog and is validated to be an amend (see
    # _resolve_amend_pre_sha) — otherwise we fall back to full-commit review.
    #
    # Three guards skip the delta path and fall back to full `git show`
    # review. All three close variants of "chained `git commit && git commit
    # --amend` in one Bash call", which would otherwise enter the delta path,
    # see an empty `git diff sha_wip sha_amend`, emit skip_reason=35, and
    # silently drop the first commit's content from review (no prior
    # PostToolUse fired for it — same Bash call):
    #
    # 1. `not _reflog_shas`: reflog fallback path was taken (both commits'
    #    bash output suppressed via -q / pipe / redirect). The multi-SHA scan
    #    already populates `shas` with every fresh commit (amend + any
    #    pre-amend WIP) and the loop below `git show`s each, so coverage is
    #    correct without delta — and the delta path doesn't compose with a
    #    multi-SHA `shas` list (it would diff every entry against the same
    #    pre-amend SHA). Losing the 30-60s saving on the reflog-fallback
    #    fraction is an acceptable trade.
    #
    # 2. `len(all_shas) <= 1`: both commits visible (no -q). Two `[branch
    #    sha]` lines in bash_output → all_shas len 2. Only defined on the
    #    bash-output path; short-circuit ordering keeps it unevaluated when
    #    `_reflog_shas` is non-empty.
    #
    # 3. `commit_invocations <= 1`: asymmetric — first commit -q, amend
    #    visible. Fast-path fires on the amend's `[branch sha]` line (so
    #    `_reflog_shas` stays empty), all_shas = [sha_amend] (len 1) — guards
    #    1 and 2 both pass. The command string itself is the only remaining
    #    signal that two commits happened. False-positives (e.g.
    #    `git commit --amend -m "fix git commit bug"`) are safe — they fall
    #    back to full review.
    is_amend = bool(_GIT_AMEND_RE.search(command))
    commit_invocations = len(_GIT_COMMIT_RE.findall(command))
    pre_amend_sha = None
    if (is_amend and not _reflog_shas and len(all_shas) <= 1
            and commit_invocations <= 1):
        pre_amend_sha = _resolve_amend_pre_sha(repo_root, expected_post_sha=shas[0])
    if is_amend and pre_amend_sha:
        _base = {**_base, "amend_delta_review": True}
        debug_log(
            f"Commit review: --amend detected; reviewing delta "
            f"{pre_amend_sha[:12]}..{shas[-1][:12]}"
        )

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
