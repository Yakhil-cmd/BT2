### Title
Committed changes become unreviewable when HEAD advances non-linearly, letting a dangerous commit skip the Stop-hook LLM review - (File: `plugins/security-guidance/hooks/diffstate.py`)

### Summary
`compute_v2_review_set` computes `review_set = dirty_now ∩ changed_since`, where `dirty_now` is derived from `git status --porcelain` (working-tree/index dirtiness) plus, only in the special case that `head_at_capture` is a strict git-ancestor of the current HEAD, the file list from `head_at_capture..HEAD` [1](#0-0) . Any normal git sequence that leaves the working tree clean relative to a HEAD that is *not* a descendant of `head_at_capture` (checkout to another branch/orphan commit, hard reset to an unrelated ref, non-linear rebase, etc.) makes `dirty_now` empty, which forces the intersection `dirty_now ∩ changed_since` to be empty regardless of how much content actually differs from the pre-turn baseline SHA [2](#0-1) .

### Finding Description
The Stop hook (`handle_stop_hook`) calls `compute_v2_review_set(cwd, baseline_sha, head_at_capture, untracked_at_baseline)` to determine which files to diff and send to the LLM reviewer [3](#0-2) . If the returned `review_paths` is empty, the hook skips review entirely (`skip_reason=9`) with no LLM call and no baseline advance guard beyond that [4](#0-3) .

Inside `compute_v2_review_set`:
- `tracked_dirty`/`untracked` come from `git status --porcelain` against current HEAD — i.e., only uncommitted changes [5](#0-4) .
- The only path by which *committed* changes are folded into `dirty_now` is the linear-advance special case: `head_at_capture` must be a strict ancestor of current HEAD via `_is_ancestor` [6](#0-5)  — normal commit/amend-on-same-parent-chain/rebase-forward sequences satisfy this and are still caught.
- `changed_since` is a diff between the pre-turn `baseline_sha` (a `git stash create` snapshot) and the current worktree, which *does* reflect any committed dangerous change [7](#0-6) .
- However, `review_set = dirty_now & changed_since` — a pure intersection. If `dirty_now` is empty (clean working tree AND `head_at_capture` is not an ancestor of current HEAD), the intersection is empty no matter how large `changed_since` is [8](#0-7) .

Concretely: Claude (potentially directed by prompt-injected instructions embedded in repository content, e.g. a README/CONTRIBUTING.md telling the agent to "clean up" by checking out an orphan branch or resetting to a tag after making a change) can, using only ordinary git commands, do:
1. UPS captures `baseline_sha=B0`, `head_at_capture=H0`.
2. Edit `dangerous_file.py`; commit it → `HEAD=H1` (parent `H0`, still an ancestor — this alone is still caught).
3. Run any command that produces a HEAD not descended from `H0` while leaving the tree matching that HEAD (clean): e.g. `git checkout --orphan tmp && git add -A && git commit -m x`, or `git checkout <preexisting-branch-with-same-file>`, or `git reset --hard <unrelated-ref>`. Now `current_head` is not reachable from `head_at_capture`, so `_is_ancestor` is `False`, `diff_base` stays `"HEAD"`, and `dirty_now` (status-porcelain against this new clean HEAD) is empty.
4. `review_set = ∅` even though `changed_since` (diff vs `B0`) would show `dangerous_file.py` as changed. Stop hook hits `skip_reason=9` — no LLM review runs, `previous_findings`/`baseline_sha` are not even advanced meaningfully, and the dangerous content persists in the repo (e.g., merged into the target branch later) without ever being scanned. The Stop-hook LLM gate is designed to be the last enforcement point before the turn ends, so bypassing it here means malicious code changes made during the session escape the plugin's only content-based check.

No existing validation catches this: there is no independent check that `changed_since` alone (bounded to the correct repo/paths) should trigger review when `dirty_now` is empty; the `_is_ancestor` gate is the only bridge from committed changes to `dirty_now`, and it is a "linear-advance only" heuristic as the code comments acknowledge [9](#0-8) .

### Impact Explanation
This breaks the stated invariant that the review set must stay bound to the baseline and touched paths for the current turn: a file that genuinely differs from the pre-turn snapshot can be silently excluded from review, meaning Claude-authored (or injected) dangerous code changes are committed to the repository without triggering the mandatory Stop-hook LLM security scan and without the "exit code 2 forces Claude to continue and fix" enforcement [10](#0-9) . This is the exact mechanism the plugin exists to prevent, so the unreviewed dangerous content becoming part of the user's project constitutes unauthorized code entering the user-approved workspace/scope without the review gate the user relies on.

### Likelihood Explanation
Requires no special privilege beyond normal use of git commands available to any Claude session (checkout, reset --hard, checkout --orphan). It is fully reachable through ordinary automation flows (a background/async Stop hook that never revisits git history state), and could be triggered either by a compromised/careless prompt sequence or by repository content that instructs Claude to perform such git operations as part of a "workflow" (prompt injection via README/CI docs). It is deterministic and reproducible given the described command sequence.

### Recommendation
Do not gate committed-but-clean changes solely on `dirty_now`. Instead, always compute `changed_since` (diff against `baseline_sha`) independently as a floor for the review set, and treat `review_set` as `changed_since` restricted to paths inside the repo (dropping `dirty_now` as a hard AND-gate). At minimum, when `_is_ancestor` returns `False` (non-linear HEAD movement), fall back to using `changed_since` alone (not intersected with the now-unreliable `dirty_now`) so committed diffs against the pre-turn baseline are still reviewed.

### Proof of Concept
Integration test outline (pytest, using a real tmp git repo):
1. `git init`; create `safe.py`; commit → `H0`.
2. `baseline_sha = capture_git_baseline(repo)`; `head_at_capture = _git_rev_parse_head(repo)`.
3. Write `dangerous_file.py` with e.g. `os.system(user_input)`; `git add -A && git commit -m "add feature"` → `H1`.
4. `git checkout --orphan tmp_branch && git add -A && git commit -m "same tree, new lineage"` → `H2` (tree still contains `dangerous_file.py`, working tree clean, `H2` not a descendant of `head_at_capture`).
5. Call `review_paths, diff_base, repo_root, untracked, metrics = compute_v2_review_set(repo, baseline_sha, head_at_capture, {})`.
6. **Expected (pre-fix, demonstrating the bug):** `review_paths == []` and `metrics["review_set_count"] == 0`, even though `git diff --name-only baseline_sha` (run manually) shows `dangerous_file.py` as changed.
7. **Assertion for a fixed implementation:** `dangerous_file.py` (absolute path) must be present in `review_paths`.

### Citations

**File:** plugins/security-guidance/hooks/diffstate.py (L372-377)
```python
    Returns (absolute paths sorted, diff_base, repo_root, metrics).
    diff_base is "HEAD" unless HEAD advanced linearly this turn (commits),
    in which case it's head_at_capture so committed files produce a diff.
    repo_root is the git toplevel — `git diff --name-only` outputs paths
    relative to it (not to cwd), so the caller's get_git_diff must run
    from there too or pathspecs won't match.
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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1945-1946)
```python
        # Exit code 2 with stderr forces Claude to continue and fix
        sys.stderr.write(PROVENANCE_BANNER + "\n\n" + concrete_guidance + CONTINUATION_SUFFIX + "\n")
```

**File:** plugins/security-guidance/hooks/gitutil.py (L330-373)
```python
def _git_status_porcelain(cwd):
    """One `git status --porcelain=v1 -z` → (tracked_dirty, untracked) sets of
    repo-root-relative paths, or (None, None) on error. Replaces the
    `_temp_index + git diff HEAD --name-only` pair for the v2 dirty_now
    computation: faster in large repos, and yields the
    untracked set separately so the later get_git_diff can do a targeted
    `add -N -- <files>` instead of a whole-tree `add -N .`.

    -uall: list individual files inside untracked directories (default
    collapses to `dir/`). Required so the untracked set subtracts cleanly
    against the UPS-time `_list_untracked` snapshot, which uses ls-files and
    therefore always lists individual files."""
    try:
        r = subprocess.run(
            [*GIT_CMD, "-c", "core.quotePath=false", "status",
             "--porcelain=v1", "-uall", "-z"],
            cwd=cwd, capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            debug_log(f"_git_status_porcelain rc={r.returncode}: {r.stderr[:200]}")
            return None, None
        tracked, untracked = set(), set()
        entries = r.stdout.split("\0")
        i = 0
        while i < len(entries):
            e = entries[i]
            if not e:
                i += 1
                continue
            xy, path = e[:2], e[3:]
            if xy == "??":
                untracked.add(path)
            else:
                tracked.add(path)
                # Rename/copy entries are XY old\0new\0 — second NUL field is
                # the origin path; consume it so it isn't misparsed as a new
                # 2-char-status entry.
                if "R" in xy or "C" in xy:
                    i += 1
            i += 1
        return tracked, untracked
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        debug_log(f"_git_status_porcelain error: {e}")
        return None, None
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
