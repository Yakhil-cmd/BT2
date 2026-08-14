### Title
TOCTOU in v2 review-set diff computation lets a concurrently-created untracked file be silently omitted from the reviewed diff - ([File: plugins/security-guidance/hooks/gitutil.py])

### Summary
`compute_v2_review_set()` in `plugins/security-guidance/hooks/diffstate.py` snapshots the untracked file set via `_git_status_porcelain()` and passes that fixed list as `untracked_paths` into `get_git_diff()` → `_temp_index()`. `_temp_index()` only runs `git add --intent-to-add` against that pre-captured list, so any untracked file created *after* the snapshot but *before* the temp-index `add` (or before `git diff` runs) is neither tracked, nor intent-to-added, and is therefore completely invisible to the subsequent `git diff` — it is written to disk but never appears in the diff handed to the Stop-hook reviewer.

### Finding Description
Call path: `compute_v2_review_set` (`plugins/security-guidance/hooks/diffstate.py:353-438`) calls `_git_status_porcelain(repo)` (`gitutil.py:330-374`) to get `tracked_dirty`/`untracked`, derives `untracked_in_review`, and returns it to the caller, which later invokes `get_git_diff(cwd, baseline_sha, untracked_paths=untracked_in_review)` (`gitutil.py:391-427`). `get_git_diff` opens `_temp_index(cwd, untracked_paths)` (`gitutil.py:91-141`), which copies the real index (`shutil.copy2(real_index, tmp_index)`, line 115) and then runs `git add --intent-to-add -- <surviving untracked_paths>` (lines 125-135) — restricted to exactly the paths captured at the earlier `_git_status_porcelain` call.

A file created by a concurrent agent/process in the window between the `_git_status_porcelain` snapshot and the `add --intent-to-add` call (or even after the `add` call but before `git diff` runs) is:
- not tracked in the real or temp index,
- not in `untracked_paths` (it didn't exist when the snapshot was taken), and
- therefore not added via `--intent-to-add`.

`git diff <baseline_sha>` against the temp index will not surface content that isn't tracked and wasn't intent-to-added — it simply doesn't appear as a new file in the diff, even though it exists on disk. This differs from the file-*removal* race that the code already defends against (the `surviving` filter comment at lines 120-127 explicitly acknowledges and mitigates the shrinking-set case), but there is no equivalent mitigation for a *growing* set (new files appearing) in the targeted (`untracked_paths` given) branch. The default whole-tree branch (`untracked_paths is None` → `add -N .`, line 118) is comparatively safer because it re-scans the worktree at call time, but the fast v2 path deliberately narrows to the stale snapshot for performance (per the module's own docstring, lines 99-103), reopening the window.

Note: modifying the *content* of an already-tracked/already-known file during this window is not exploitable this way, because `git diff <sha>` re-reads the actual working-tree bytes at diff-execution time; a stat/mtime mismatch against the copied index simply forces re-hashing, so content changes to already-known paths are still reflected correctly. The exploitable gap is specific to newly-created untracked paths not present in the snapshot list.

### Impact Explanation
This is a STATE_BINDING violation: the diff produced by `get_git_diff` (and therefore whatever content the Stop-hook / commit-review LLM prompt reviews) does not reflect the actual current working-tree content. In the stated multi-agent/shared-worktree threat model, a concurrent process can drop a new file into the repo during the narrow window between the Stop hook's status snapshot and its diff computation, and that file's content will be silently excluded from security review while still landing on disk (and potentially getting committed/pushed later without ever having been reviewed). This is a security-hook (review/export logic) bypass, not privilege escalation or code execution by itself, but it defeats the intended "everything Claude writes gets reviewed" guarantee that the whole plugin exists to enforce.

### Likelihood Explanation
Requires the precondition explicitly given in the prompt: an attacker/second process with write access to the same working tree that can create files during this specific window (multi-agent or shared-worktree usage that the module's own comments (`gitutil.py:99-103`, `diffstate.py` docstrings) already contemplate as a supported/considered scenario). The window spans from the `_git_status_porcelain` call inside `compute_v2_review_set` through the later `get_git_diff`/`_temp_index` add call — potentially crossing function/process boundaries with I/O and locking in between (`with_locked_state`, `consume_stop_state`), so it is not sub-millisecond; a background process racing file creation against the hook's Stop-hook firing is plausible but timing-dependent and not deterministically reproducible on every run.

### Recommendation
In the `untracked_paths`-driven path, re-verify the untracked set immediately before (or as part of) the `git add --intent-to-add` call rather than trusting a snapshot taken earlier in the call chain — e.g., have `_temp_index` re-run a fast `git status --porcelain -uall` (or `ls-files --others --exclude-standard`) scoped to the repo right before adding, and union any newly-discovered untracked paths with the caller-supplied list, instead of relying solely on the pre-computed list, while preserving the existing "surviving path" filtering.

### Proof of Concept
Integration test in `plugins/security-guidance/hooks/` test suite:
1. Initialize a git repo with one commit.
2. Call `_git_status_porcelain(repo)` to get an untracked set (empty).
3. Before invoking `get_git_diff`, simulate the race: create a new untracked file `malicious.py` with attacker-controlled content directly on disk (representing the concurrent writer), without adding it to the `untracked_paths` list passed to `get_git_diff`.
4. Call `get_git_diff(cwd, baseline_sha, untracked_paths=[])` (the stale snapshot).
5. Assert: `malicious.py` exists on disk (`os.path.isfile`) but does NOT appear in the returned diff string (`"malicious.py" not in diff`) — demonstrating the STATE_BINDING violation (diff omits real on-disk content).
6. As a regression/fix check, after applying the recommended re-scan, assert the diff DOES include `malicious.py` (or that `get_git_diff` fails safe / signals a mismatch) once the fix is applied.