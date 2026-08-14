### Title
Baseline re-capture at `UserPromptSubmit` folds unreviewed dirty changes into the new `git stash create` baseline, silently excluding dangerous edits from the next review set - (File: `plugins/security-guidance/hooks/diffstate.py`)

### Summary
`capture_git_baseline` uses `git stash create`, which snapshots HEAD **plus all current uncommitted tracked changes**, and `save_baseline_sha` stores that SHA as the new comparison point for `compute_v2_review_set`. If a dangerous edit reaches disk without being recorded in `touched_paths` (e.g. made via Bash instead of a hooked Edit/Write tool call, or the turn is interrupted before `Stop` consumes state) and a new `UserPromptSubmit` fires before that edit is reviewed, the fresh baseline commit already contains the dangerous content. The next `compute_v2_review_set` intersects `dirty_now` with `changed_since` (diffed against the *new* baseline), and since the file's content now matches the baseline tree, it drops out of `changed_since`, removing it from `review_set` even though it was never actually reviewed.

### Finding Description
`capture_git_baseline` (lines 163–204) runs `git stash create`, which "creates a commit object for the current state (HEAD + uncommitted changes)". `save_baseline_sha` (lines 43–47) persists that SHA to session state, becoming the `baseline_sha` argument to `compute_v2_review_set`. The review set is computed as `dirty_now & changed_since`, where `changed_since = _git_name_only(repo, baseline_sha)` (lines 417–426) — a diff of the working tree against `baseline_sha`.

If the dangerous change was uncommitted at the moment a new baseline is captured, its content is already embedded in the new `baseline_sha` tree. On the following turn, the file is still "dirty" relative to real `HEAD` (so it remains in `dirty_now`), but it is *not* different from `baseline_sha` (so it drops out of `changed_since`). The intersection then excludes the file from `review_set`, meaning it is skipped from review — the exact "treated as old and skipped" outcome described in the prompt.

The code itself acknowledges this gap in the docstring of `compute_v2_review_set` (lines 368–370): [1](#0-0) 

This happens specifically when `touched_paths` does not contain the dangerous file at the time of re-baseline capture — e.g. edits made via Bash commands that bypass the tool-call hook that calls `record_touched_path` (lines 57–71), or a turn that ends/aborts before `Stop`'s `consume_stop_state` (lines 74–113) processes it. `restore_unreviewed_stop_state` (lines 116–137) is a partial mitigation — it re-arms `touched_paths` and preserves `baseline_sha` only if `Stop` explicitly calls it after a transient failure — but it does not protect against edits that were never tracked in `touched_paths` to begin with, nor against `UserPromptSubmit` racing ahead of `Stop` in ways not covered by that specific restore path.

### Impact Explanation
A dangerous, attacker-influenced code change (e.g., introduced through content that causes Claude to shell out via Bash rather than through the Edit/Write tool) can be made permanently invisible to `compute_v2_review_set` once a subsequent baseline capture occurs, because the "old baseline" now already contains it. This breaks the stated invariant that "the review set must stay bound to the right repo, baseline, and touched paths," and results in the security-guidance review hook never flagging the dangerous diff — allowing an unreviewed, potentially malicious command/code change to remain in the working tree and be later executed or committed without ever passing through the security-guidance check, i.e., a scoped bypass of the review gate that normally stands between untrusted content and local command execution.

### Likelihood Explanation
This requires no special privilege beyond normal repository interaction: an attacker who can get Claude to make an uncommitted, untracked-by-`touched_paths` change (typically via a Bash-tool-driven edit rather than the hooked Edit/Write path) and have a new `UserPromptSubmit` fire before `Stop` reviews it can trigger the re-baseline. This is explicitly called out by the maintainers as a "Known limitation," indicating it is a real, reproducible gap rather than a hypothetical one, though it is also an accepted/understood trade-off relative to the older v1 behavior (which never reviewed Bash-only turns at all).

### Recommendation
Do not fold genuinely-dirty-but-unreviewed content into a fresh baseline: before calling `capture_git_baseline`/`save_baseline_sha` on a new `UserPromptSubmit`, check whether there is unconsumed working-tree state (e.g., non-empty `touched_paths`, or a diff between the current worktree and the previous `baseline_sha`) and if so, keep the prior `baseline_sha` (mirroring the existing guard in `restore_unreviewed_stop_state`) instead of advancing it. Alternatively, compute `changed_since` against the oldest unreviewed baseline still tracked for the session rather than always re-baselining at every `UserPromptSubmit`.

### Proof of Concept
Integration test plan:
1. Initialize a git repo with one commit.
2. Simulate turn 1: call `capture_git_baseline`/`save_baseline_sha` to set `baseline_sha_1` (repo clean).
3. Simulate a Bash-tool edit that modifies a tracked file with a "dangerous" pattern, **without** calling `record_touched_path` for it (mimicking an untracked/interrupted edit path).
4. Simulate turn 2's `UserPromptSubmit`: call `capture_git_baseline` again (working tree still dirty with the dangerous edit) and `save_baseline_sha` to set `baseline_sha_2` — this commit now contains the dangerous content.
5. Call `compute_v2_review_set(cwd, baseline_sha_2, head_at_capture, {})`.
6. Assert: the dangerous file is present in `dirty_now`/`tracked_dirty` (still uncommitted) but **absent** from the returned `review_paths`, demonstrating the file that was never actually reviewed is excluded from the review set purely because the second baseline capture happened to include it.

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L368-370)
```python
    Known limitation: a Bash-only turn that's interrupted before Stop fires
    leaves touched_paths empty, so the next UPS re-baselines past those edits.
    v1 never reviews Bash-only turns at all, so v2 is no worse there.
```
