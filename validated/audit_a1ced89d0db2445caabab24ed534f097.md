### Title
Stop-hook `review_set = dirty_now & changed_since` intersection lets attacker-controlled git history rewrites (orphan branch squash / rebase) hide a committed dangerous change from review - (File: `plugins/security-guidance/hooks/diffstate.py`)

### Summary
`compute_v2_review_set` (fed by the `baseline_sha`/`head_at_capture` pair that `consume_stop_state` snapshots for the Stop hook) computes the reviewable file set as the **intersection** of "files dirty vs current HEAD (plus commits since `head_at_capture` only when it is a linear ancestor)" and "files whose content differs from the pre-turn stash baseline." Because the first term depends on a fragile `merge-base --is-ancestor` check, an attacker who drives ordinary git commands (commit, then rewrite history onto a branch not descended from `head_at_capture`, e.g. via an orphan-branch squash or rebase) can make the working tree clean and non-ancestor-linked while still containing the dangerous change. The AND of the two sets then collapses to empty for that file, and it is silently dropped from the LLM security review.

### Finding Description
`consume_stop_state` (`plugins/security-guidance/hooks/diffstate.py:74-113`) snapshots `baseline_sha` and `head_at_capture` (captured at UserPromptSubmit by `capture_git_baseline`/`_git_rev_parse_head`) and hands them to `compute_v2_review_set` (`diffstate.py:353-438`):

<cite repo="Ellentat/claude-code--012" path="plugins/security-guidance/hooks/diffstate.py" start="403="408" end="426" />

```
diff_base = "HEAD"
current_head = _git_rev_parse_head(repo)
if (head_at_capture and current_head and head_at_capture != current_head
        and _is_ancestor(repo, head_at_capture, current_head)):
    dirty_now |= _git_name_only(repo, f"{head_at_capture}..HEAD") or set()
    diff_base = head_at_capture
...
review_set = (dirty_now & changed_since) if changed_since is not None else dirty_now
``` [1](#0-0) 

`dirty_now` only includes committed changes when `head_at_capture` is still an ancestor of the new `HEAD` (`_is_ancestor`, in `gitutil.py`). `changed_since` is a pure tree-content diff between `baseline_sha` and `HEAD` and is unaffected by history shape. The final `review_set` is the **intersection**, not the union, of these two signals.

An attacker (via prompt injection or a compromised repo instructing Claude to run "normal" git commands) can:
1. Let Claude edit and `git commit` the dangerous file (`H1`, parent `head_at_capture`).
2. Run `git checkout --orphan tmp && git add -A && git commit -m squash` to create a root commit `T1` with the exact same working tree (including the dangerous file) but no ancestry relation to `head_at_capture`.
3. `git branch -M tmp main` (or push `tmp` as the tracked branch) so `HEAD` now points at `T1`.

After this, the working tree is clean (`git status` shows nothing dirty), so `dirty_now` is empty for the dangerous file, and `_is_ancestor(head_at_capture, T1)` is `False`, so the committed-diff term is never added. `changed_since` (`_git_name_only(repo, baseline_sha)`) still correctly reports the file as changed relative to the stash baseline, but the intersection with an empty `dirty_now` yields an empty `review_set`. The file is dropped from `get_git_diff`/the LLM review entirely, even though the invariant "review must cover anything that changed since the session's baseline" is violated. No approval prompt, allowlist, or workspace guard intervenes because this happens purely inside the plugin's own git-diff derivation — none of these commands are flagged as anomalous, and the Stop-hook fires normally.

### Impact Explanation
This lets an attacker (or an injected instruction Claude follows) commit a dangerous/malicious code change and then use benign-looking git housekeeping (squash onto an orphan branch, interactive rebase reordering, `filter-branch`, etc.) to make the Stop-hook's `compute_v2_review_set` return an empty set for that file. The security-guidance plugin's LLM vulnerability scan and areas-of-concern review never see the dangerous diff, so Claude's own security gate is bypassed for that change, matching "Unauthorized local command execution that bypasses Claude Code approval or deny controls" — the plugin is Claude Code's local defense-in-depth mechanism against exactly this class of change, and it can be silently defeated using ordinary git operations available to any session.

### Likelihood Explanation
The preconditions are trivial: an unprivileged agent/attacker only needs the ability to run ordinary git commands in the working repo during a Claude Code session (commit, checkout --orphan, branch rename/reset, rebase) — capabilities Claude Code sessions routinely have via Bash tool use. No special permissions, secrets, or race conditions are required, and the sequence is deterministic and repeatable on every turn where the plugin's v2 diff strategy is active (default configuration, `ENABLE_STOP_REVIEW`/`ENABLE_CODE_SECURITY_REVIEW` on).

### Recommendation
Change `review_set` from an intersection to a union-with-fallback: always trust `changed_since` (the content diff against `baseline_sha`) as authoritative for what to review, and use `dirty_now` only to *add* untracked/in-progress files, not to gate out files `changed_since` already flagged. At minimum, when `head_at_capture` is not an ancestor of the new `HEAD` (a history rewrite occurred), fall back to reviewing the full `changed_since` set unioned with `dirty_now` rather than intersecting, since a non-linear HEAD move is itself a signal that the naive ancestor-diff heuristic can't be trusted to have captured everything.

### Proof of Concept
Integration test (extends existing Stop-hook / `compute_v2_review_set` test suite):
1. Init a repo, commit an initial file, call `handle_user_prompt_submit`-equivalent (`capture_git_baseline` + `_git_rev_parse_head`) to record `baseline_sha`/`head_at_capture` = `H0`.
2. Simulate Claude editing `dangerous.py` with a clearly dangerous pattern (e.g. `eval(`), commit it → `H1` (parent `H0`).
3. Run `git checkout --orphan tmp`, `git add -A && git commit -m squash` → `T1` (root commit, tree identical to `H1`'s tree).
4. `git branch -M tmp main` so `HEAD` == `T1`.
5. Call `compute_v2_review_set(cwd, baseline_sha=H0_stash_sha, head_at_capture=H0, untracked_at_baseline={})`.
6. Assert: `dangerous.py` IS present in the returned `review_paths` (expected, per invariant) — current implementation fails this assertion because `review_set` is empty (dirty_now ∩ changed_since = ∅ ∩ {dangerous.py} = ∅), demonstrating the review-window bypass.

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L403-426)
```python
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
