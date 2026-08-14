### Title
Non-linear HEAD advancement (amend/rebase/reset) causes `compute_v2_review_set` to silently drop already-changed-and-committed dangerous files from review - (File: plugins/security-guidance/hooks/diffstate.py)

### Summary
`compute_v2_review_set` computes the Stop-hook review set as the *intersection* of `dirty_now` (files dirty vs. current HEAD, or vs. `head_at_capture` only when HEAD advanced by strict linear ancestry) and `changed_since` (files that differ from the pre-turn `baseline_sha` stash). When git history is advanced non-linearly during a turn — e.g. `git commit --amend` on a non-tip commit, `git rebase`, or `git reset` followed by a new commit — the resulting HEAD is not a descendant of `head_at_capture`, so `_is_ancestor` fails and `diff_base` stays `"HEAD"`. A file that was modified and then committed this way is no longer "dirty" relative to current HEAD, so it drops out of `dirty_now` even though `changed_since` (diff against the original stash baseline) still correctly flags it as changed. Because `review_set = dirty_now & changed_since`, the file is excluded from review entirely.

### Finding Description
In `compute_v2_review_set` (`plugins/security-guidance/hooks/diffstate.py:353-438`), `dirty_now` is built from `_git_status_porcelain` (current worktree dirtiness vs. HEAD) plus, only if `_is_ancestor(repo, head_at_capture, current_head)` holds, the linear commit range `head_at_capture..HEAD`: [1](#0-0) 

`changed_since` is independently computed as the diff against `baseline_sha` (the pre-turn stash): [2](#0-1) 

The final `review_set` is the intersection `dirty_now & changed_since`, not a union: [3](#0-2) 

This means a file must satisfy *both* conditions to be reviewed. If a dangerous edit is committed and HEAD is then moved in a way that is not a strict fast-forward from `head_at_capture` (e.g. `git commit --amend` on an earlier commit due to an interactive rebase, `git rebase`, `git reset --hard <sha>` followed by a fresh commit, or a squash-merge workflow — all "normal git operations" a repo's build script, CLAUDE.md instructions, or Makefile could direct Claude to run), then:
- The file is not "dirty" vs. current HEAD (it's committed).
- `_is_ancestor(head_at_capture, current_head)` is false, so the linear-commit union in `dirty_now` never fires.
- `changed_since` still correctly contains the file (it differs from the original stash baseline), but the intersection with the now-file-less `dirty_now` drops it.

The result: `review_set` silently excludes a file that genuinely differs from the session baseline, and the Stop hook treats the dangerous change as "old"/already-reviewed content and skips it, even though it was authored this turn. The code's own docstring acknowledges the linear-advancement assumption ("diff_base is 'HEAD' unless HEAD advanced linearly this turn") without covering the non-linear case, and separately calls out an analogous limitation for interrupted Bash-only turns, indicating the review-set computation's binding to git state is not robust to all "normal" git operation sequences.

### Impact Explanation
A file containing an unsafe/dangerous change (e.g. a backdoor, credential exfiltration, or unsafe `subprocess`/`eval` usage) that is committed via a non-linear git operation during the turn is excluded from the LLM security review performed by the Stop hook. Because the finding never surfaces, the change proceeds unflagged into the repository, which can lead to unauthorized file writes/behavior operating outside the scope the user believed was reviewed — matching the "Unauthorized file read or write outside the user-approved workspace or target scope" impact class, since the security-guidance gate is bypassed for a change that should have been caught.

### Likelihood Explanation
This requires only ordinary git operations that are common in real workflows or easily triggered by prompt-injected instructions embedded in repository content (e.g. a `CLAUDE.md`/Makefile instructing Claude to "clean up history" via amend/rebase before finishing a turn). No elevated privileges, leaked credentials, or social engineering of a human is needed — it only depends on git commands Claude itself would run as part of "normal git operations in a cloned repo," making it realistically reachable within the stated attacker model.

### Recommendation
Change `review_set` computation to a union rather than a strict intersection when `changed_since` is available and reliable, or make the linear-advancement fallback cover non-fast-forward HEAD movement (e.g., always union `changed_since ∩ (files touched per commit range head_at_capture..HEAD via `git diff head_at_capture HEAD --name-only` regardless of ancestry, falling back to full reflog scan when `_is_ancestor` fails) so that any file differing from `baseline_sha` that also appears in the commit set introduced this turn is retained. At minimum, treat `_is_ancestor` failure as a signal to widen `dirty_now` with the full set of commits reachable from current HEAD but not from `baseline_sha`'s parent (`git rev-list head_at_capture...HEAD` / symmetric diff) rather than silently falling back to the “nothing extra” default.

### Proof of Concept
Integration test plan (extending the existing test suite for `compute_v2_review_set`):
1. Initialize a git repo, create `danger.py` with benign content, commit (`C0`), capture baseline via `capture_git_baseline` → `baseline_sha`, and record `head_at_capture = C0`.
2. Simulate a Claude turn: modify `danger.py` with a dangerous payload (e.g., `os.system(user_input)`), commit as `C1` (child of `C0`).
3. Simulate an "amend/rebase cleanup" step that Claude is prompted to run: `git commit --amend -m "cleanup"` targeting an *earlier* commit via `git rebase -i --autosquash` (or simply `git reset --hard C0 && git commit -am "dangerous (reset)"`) so that the new HEAD `C1'` is **not** a descendant of `head_at_capture` per `_is_ancestor` (e.g., reset to a grandparent and recommit from there, or use `git rebase --onto` to produce a sibling commit).
4. Call `compute_v2_review_set(cwd, baseline_sha, head_at_capture, {})`.
5. Assert `danger.py` (absolute path) is present in the returned `review_paths`.
6. Expected current (buggy) behavior: `danger.py` is absent from `review_paths` because `dirty_now` no longer contains it (clean vs. new HEAD) and `_is_ancestor` fails, while `changed_since` does contain it — demonstrating the intersection drops a genuinely-changed dangerous file.

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
