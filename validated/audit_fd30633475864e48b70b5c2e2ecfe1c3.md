### Title
Non-linear HEAD rewrites (`git commit --amend` / rebase) silently drop the dangerous file from the v2 review set, letting Claude-authored changes bypass the security diff review - (File: `plugins/security-guidance/hooks/diffstate.py`)

### Summary
`compute_v2_review_set` only widens the review window past `head_at_capture` when the current `HEAD` is a linear fast-forward descendant of the baseline (`_is_ancestor` check). Any git operation that rewrites history without preserving that ancestry — most commonly `git commit --amend`, an interactive rebase, or a reset+recommit — causes a file that Claude modified and then committed to disappear from both `dirty_now` (it's no longer dirty; it's now committed and matches the working tree) and therefore from the intersected `review_set`, even though `changed_since` (diff against the true `capture_git_baseline` SHA) still shows it as changed.

### Finding Description
`capture_git_baseline` (`plugins/security-guidance/hooks/diffstate.py:163-204`) captures a `git stash create` SHA (`baseline_sha`) plus, via the caller, `head_at_capture` (the `HEAD` SHA at `UserPromptSubmit`). Later, `compute_v2_review_set` (`diffstate.py:353-438`) reconstructs which files should be reviewed: [1](#0-0) 

```python
diff_base = "HEAD"
current_head = _git_rev_parse_head(repo)
if (head_at_capture and current_head and head_at_capture != current_head
        and _is_ancestor(repo, head_at_capture, current_head)):
    dirty_now |= _git_name_only(repo, f"{head_at_capture}..HEAD") or set()
    diff_base = head_at_capture
```

`_is_ancestor` (`plugins/security-guidance/hooks/gitutil.py:377-387`) runs `git merge-base --is-ancestor head_at_capture current_head`, which is true only for a linear, forward-moving `HEAD` (plain commits/merges). It is **false** whenever the turn's commit history is rewritten instead of extended — e.g. `git commit --amend`, `git rebase`, `git reset --soft && git commit`, or `git filter-branch`/`cherry-pick` producing a new SHA for the same tree state.

When that check fails, `diff_base` stays `"HEAD"` and `dirty_now` is derived solely from `_git_status_porcelain` (`gitutil.py:330-374`), i.e. the working-tree-vs-index diff. Once the dangerous edit has been folded into a commit via `--amend`, the working tree is clean relative to the new `HEAD`, so the file is absent from `tracked_dirty`. It is then computed as: [2](#0-1) 

```python
if baseline_sha:
    changed_since = _git_name_only(repo, baseline_sha)
    ...
review_set = (dirty_now & changed_since) if changed_since is not None else dirty_now
```

`changed_since` (diff against the real pre-turn `baseline_sha` stash) still correctly lists the dangerous file, because its content differs from the true baseline. But the intersection with `dirty_now` — which no longer contains the file because it's "clean" post-amend — silently zeroes it out of `review_set`. The Stop hook then reviews an empty or incomplete set, and the dangerous change is treated as pre-existing/old and skipped, breaking the stated invariant that "the review set must stay bound to the right repo, baseline, and touched paths."

This is reachable purely through normal git usage during a Claude turn (the model itself commonly runs `git add -A && git commit --amend --no-edit` to fix up a commit message or squash a WIP commit, or a user/agent script does an interactive rebase) — no elevated privileges, leaked credentials, or malicious repo content are needed.

### Impact Explanation
A dangerous code change (e.g., an injected backdoor, credential exfiltration, or unsafe `subprocess`/`eval` call) that Claude writes and then amends into an existing commit is excluded from the diff sent to the LLM security reviewer and from `get_git_diff`'s output. The change is treated as already-reviewed/pre-existing and is never flagged, resulting in disclosure/persistence of unreviewed sensitive/dangerous code into the repository — matching the "diff/code disclosure or unintended sink due to skipped review" impact class described in the bounty scope.

### Likelihood Explanation
The precondition — a `git commit --amend`, rebase, or equivalent non-linear rewrite happening between `capture_git_baseline`'s `head_at_capture` snapshot and the Stop hook's `compute_v2_review_set` call — is an everyday git operation, not an exotic attack technique. It requires no special repo state, only that the amend/rebase occurs within the same session after the baseline was captured. This is highly feasible and easily repeatable in any cloned repo.

### Recommendation
Don't gate the extended review window on strict linear ancestry. Instead, always union `changed_since` (diff against `baseline_sha`, which is unaffected by history rewrites since it's a snapshot object) into consideration regardless of `_is_ancestor`, or compute `dirty_now` from `_git_name_only(baseline_sha, "HEAD")` plus current working-tree dirty state rather than requiring `head_at_capture..HEAD` ancestry. Concretely, replace the ancestry-gated branch with an unconditional `dirty_now |= _git_name_only(repo, baseline_sha) or set()` (already effectively `changed_since`), and stop intersecting away committed-via-rewrite files, or track `head_at_capture`'s tree state instead of its ancestry.

### Proof of Concept
Integration test in `plugins/security-guidance/hooks/` test suite:
1. Init a repo with one commit (`README`).
2. Simulate `UserPromptSubmit`: call `capture_git_baseline(cwd)` → `baseline_sha`; record `head_at_capture = _git_rev_parse_head(cwd)`.
3. Simulate Claude writing a dangerous file `evil.py` with `os.system(user_input)`, `git add -A && git commit -m "wip"`.
4. Simulate a follow-up `git commit --amend --no-edit` (a completely normal fixup a coding agent or user performs).
5. Call `compute_v2_review_set(cwd, baseline_sha, head_at_capture, {})`.
6. Assert: `review_paths` (or `review_set`) contains `evil.py`.

Expected today: the assertion **fails** — `evil.py` is absent from `review_set` because `_is_ancestor(head_at_capture, current_head)` is `False` post-amend, `dirty_now` excludes the now-committed-and-clean file, and the intersection with `changed_since` drops it — demonstrating the review-set/baseline invariant break.

### Citations

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
