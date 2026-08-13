### Title
`compute_v2_review_set` drops amended-commit changes from review because `dirty_now` excludes non-ancestor HEAD moves - (File: `plugins/security-guidance/hooks/diffstate.py`)

### Summary
`capture_git_baseline` and the paired `compute_v2_review_set` logic determine which files get reviewed by the Stop-hook LLM security scan during a Claude Code turn. When a dangerous change is made and then folded into the repository via `git commit --amend` (or any other non-fast-forward HEAD rewrite) instead of a plain new commit, the file is silently excluded from the review set even though it differs from the UPS-time baseline.

### Finding Description
`capture_git_baseline` (`plugins/security-guidance/hooks/diffstate.py:163-204`) snapshots the working tree at `UserPromptSubmit` via `git stash create`, and `head_at_capture` is recorded as the HEAD SHA at that moment (`security_reminder_hook.py:477-503`).

At Stop time, `compute_v2_review_set` (`plugins/security-guidance/hooks/diffstate.py:353-438`) builds the review set as:

```
dirty_now = tracked_dirty | new_untracked
if head_at_capture is ancestor of current HEAD:
    dirty_now |= diff(head_at_capture..HEAD)
changed_since = diff(baseline_sha) ∪ new_untracked
review_set = dirty_now & changed_since
``` [1](#0-0) 

`dirty_now` is only populated from two sources: (1) files still dirty against current HEAD (`_git_status_porcelain`), and (2) files changed between `head_at_capture` and current HEAD, but *only* when `_is_ancestor(head_at_capture, current_head)` is true, i.e. HEAD moved forward linearly.

`git commit --amend` replaces the tip commit with a new commit object sharing the same parent — the old `head_at_capture` commit is discarded and is **not** an ancestor of the new HEAD (they are siblings). `_is_ancestor(cwd, head_at_capture, current_head)` (`plugins/security-guidance/hooks/gitutil.py:377-387`) therefore returns `False`, so the `head_at_capture..HEAD` diff is never unioned into `dirty_now`. Because the amend also commits the change, the file is no longer "dirty" against current HEAD either, so `tracked_dirty` doesn't contain it. The result: `dirty_now` is empty for that file even though `changed_since` (diff against the stash-based `baseline_sha`, computed independently of ancestry) correctly still contains it. Since `review_set = dirty_now & changed_since`, the dangerous file is excluded from the review set entirely — the Stop hook's LLM review never sees it.

This breaks the stated invariant that "the review set must stay bound to the right repo, baseline, and touched paths": ordinary git operations available to any user of the session (amend, rebase, or any history-rewriting commit action performed mid-turn) can move `dirty_now` out of sync with `changed_since`, silently dropping a genuinely new/dangerous change from review.

### Impact Explanation
A dangerous code change (e.g., command injection, credential exfiltration, backdoor) introduced by Claude and then folded into the repo with `git commit --amend` during the same turn is skipped by the Stop-hook LLM vulnerability scan (`handle_stop_hook`, `plugins/security-guidance/hooks/security_reminder_hook.py:1700+`), which is the mechanism that forces continued remediation via `sys.exit(2)`. Because the change is never surfaced, no approval/deny friction or forced-continue guidance is generated for it, allowing an unreviewed dangerous change to persist in the repository — a bypass of the plugin's local command/content-review control.

### Likelihood Explanation
This requires no elevated privileges, leaked credentials, or malicious infrastructure — only ordinary git usage (`git commit --amend`) inside the same working tree during a Claude Code turn, which is a completely normal developer/agent operation. It is deterministic and repeatable: any turn where a change is amended into an existing commit rather than added as a new one triggers the gap.

### Recommendation
Do not gate the committed-range inclusion on strict ancestry. Instead, always compute `changed_since ∩ (files that differ between baseline_sha's tree and current HEAD tree, plus current dirty/untracked state)` without requiring `head_at_capture` to be an ancestor — or simplify by making `review_set` primarily driven by `changed_since` (diff against `baseline_sha`) filtered only by exclusion sets (pre-existing untracked), rather than intersecting with an ancestry-dependent `dirty_now`. At minimum, detect non-ancestor HEAD moves (amend/rebase) and fall back to including `diff(baseline_sha..HEAD)` file names in `dirty_now` regardless of ancestry.

### Proof of Concept
Integration test plan (pytest, extending existing diffstate/hook test suite):
1. Init a temp git repo, commit an initial file, capture `baseline_sha = capture_git_baseline(cwd)` and `head_at_capture = _git_rev_parse_head(cwd)` (simulating UPS).
2. Edit a "dangerous" file (e.g., add `os.system(user_input)`), then run `git add -A && git commit --amend --no-edit` (simulating Claude committing the change via amend instead of a new commit).
3. Call `compute_v2_review_set(cwd, baseline_sha, head_at_capture, {})`.
4. Assert: the dangerous file path IS present in the returned `review_paths`.
5. Expected current (buggy) behavior: the dangerous file is absent from `review_paths` because `_is_ancestor(head_at_capture, new_HEAD)` is `False`, `dirty_now` is empty, and `review_set = dirty_now & changed_since = ∅`.
6. Control case: repeat with a plain `git commit --no-edit` (not amend) on top of `head_at_capture` and confirm the file IS correctly included, showing the divergence is specific to history-rewriting operations.

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
