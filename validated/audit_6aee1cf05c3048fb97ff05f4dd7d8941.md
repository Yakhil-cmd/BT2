### Title
Push-sweep marks entire commit range "reviewed" even when files were dropped from security scanning — permanent bypass of automated security review - ([File: plugins/security-guidance/hooks/security_reminder_hook.py])

### Summary
`handle_push_sweep_posttooluse` marks all commits in a pushed range as fully reviewed via `_append_reviewed_shas`, even though the set of files actually scanned by the LLM reviewer can be a truncated subset when the diff exceeds `MAX_PUSH_SWEEP_FILES`. This mirrors the reported bug class: a tracking pointer/state ("reviewed" status, analogous to `validatorWithdrawalIndex`) advances based on range/loop completion rather than on the actual protective action (full content review) having occurred for every item in scope.

### Finding Description
The push-sweep hook reviews the diff for a pushed commit range and, on completion, calls `_append_reviewed_shas(repo_root, tail, vulns_found=len(vulns or []))` to persist that every sha in `tail` was reviewed [1](#0-0) . This reviewed-set is subsequently used by `_compute_push_sweep_base` to advance the diff base past "the contiguous reviewed prefix," skipping those commits' content entirely on future pushes [2](#0-1) .

However, when the number of changed files exceeds `MAX_PUSH_SWEEP_FILES` (default 30), the code explicitly drops the lowest-priority files before invoking the LLM reviewer: [3](#0-2) 
The comment at this call site acknowledges the tradeoff ("reviewing the riskiest MAX_PUSH_SWEEP_FILES is strictly better than reviewing none... We still mark tail reviewed afterward") but this means the dropped files' content is never actually scanned by `analyze_code_security` / `_agentic_review_with_race`, yet the full commit range (`tail`) is still recorded as "reviewed" at line 1623. Because `_compute_push_sweep_base` treats reviewed shas as fully covered and skips them on all subsequent push-sweeps, any vulnerable code sitting in a file that was deprioritized/dropped from one oversized push is never revisited by push-sweep again — the "reviewed" state advanced based on loop/range completion, not on the actual review action having covered that file.

This directly parallels the reported Solidity bug: `validatorWithdrawalIndex` (state marking "this validator's turn is done") advanced based on loop iteration completing rather than actual unbonding occurring, letting some validators' principal permanently dodge unbonding. Here, "this commit's turn is done (reviewed)" advances based on the diff loop completing rather than every file in it actually being scanned, letting some files permanently dodge security review.

### Impact Explanation
This is a direct weakening of the security-guidance plugin's automated review coverage. In a large push (>30 changed files) — e.g., an initial import, a big merge, or a compound `git commit && git push` after many edits — the code deliberately keeps only the riskiest-looking files by heuristic (`_prioritize_diff_files`), but marks the whole range reviewed regardless of the drop. Any genuinely vulnerable file that the heuristic misjudged as lower-risk is skipped by the LLM and then permanently exempted from future push-sweep re-scanning of that commit range, because the base will always advance past it. The stated mitigation ("per-commit review remains the primary surface for those files") only holds if the per-commit-review hook actually ran and covered those same files earlier in the session — if it did not (e.g., hook disabled temporarily, rate-limited via `MAX_COMMIT_REVIEWS_PER_HOUR`, or the commits were made outside a reviewed session), the file has no other review path. This is a genuine, code-supported automation-bleed/security-bypass analog: it undermines the tool's own security-review guarantee for the affected local project without requiring a malicious peer or external actor.

### Likelihood Explanation
Occurs whenever a push contains more than `MAX_PUSH_SWEEP_FILES` (30, configurable via `SG_PUSH_SWEEP_MAX_FILES`) changed files — a realistic and not-uncommon scenario (large refactors, vendoring, initial commits, squash-merges). No attacker action or malicious peer is required; it is a logic bug reachable via ordinary use of an unprivileged user's own repository and its git operations.

### Recommendation
Only persist `_append_reviewed_shas` for the files actually reviewed, or split the "reviewed" bookkeeping per-file (not just per-sha) so dropped files remain eligible for review on a subsequent push. At minimum, when `_dropped` is non-empty, either (a) do not advance the reviewed-shas state for that range, mirroring how `skip_reason=45` (diff fetch failure) already intentionally withholds marking `tail` reviewed to avoid silently advancing the prefix past unreviewed content [4](#0-3) , or (b) track reviewed coverage at file granularity so `_compute_push_sweep_base`/future sweeps re-include the specific dropped files rather than treating the whole commit range as fully covered.

### Proof of Concept
1. In a repo with push-sweep enabled, accumulate more than 30 changed files across several commits (e.g., a large feature branch merge), including one file containing an obvious vulnerability (e.g., hardcoded secret or command injection) that a file-prioritization heuristic would rank as low risk (e.g., a config or test-like path).
2. `git push`. The hook triggers `handle_push_sweep_posttooluse`; `diff_files` exceeds `MAX_PUSH_SWEEP_FILES`, so `_prioritize_diff_files` drops the vulnerable file from `diff_files` [5](#0-4) .
3. The LLM review runs only on the retained files; the vulnerable file is never sent for analysis, yet `_append_reviewed_shas(repo_root, tail, ...)` marks every commit sha in the push (including the one introducing the vulnerable file) as reviewed [6](#0-5) .
4. On any future push, `_compute_push_sweep_base` sees this sha in `reviewed` and advances the diff base past it, so the vulnerable file's introducing commit is excluded from all future push-sweep diffs [7](#0-6)  — the vulnerability is never flagged by this surface.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L717-737)
```python
def _compute_push_sweep_base(prev_upstream, push_range, reviewed):
    """Advance the diff base past the contiguous reviewed prefix.

    Spec: review `git diff B..HEAD` where `B` is the newest commit such that
    `prev_upstream..B` is entirely in `reviewed`. Returns (B, unreviewed_tail).
    `B == None` means the whole range is reviewed (caller should skip).
    `push_range` must be oldest→newest.

    Examples (✓=reviewed, ✗=not):
      [✓1, ✗2, ✓3]  → B=1, tail=[2,3]   (cannot trim suffix; Read is at HEAD)
      [✓1, ✓2, ✓3]  → B=None            (all reviewed → skip)
      [✗1, ✓2, ✗3]  → B=prev_upstream, tail=[1,2,3]
      []            → B=None
    """
    i = 0
    while i < len(push_range) and push_range[i] in reviewed:
        i += 1
    if i == len(push_range):
        return None, []
    base = push_range[i - 1] if i > 0 else prev_upstream
    return base, push_range[i:]
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1550-1561)
```python
    if diff_text is None:
        # Diff failed (non-zero exit / 30s timeout / git missing). Do NOT
        # mark `tail` reviewed — we did not actually review it. Marking
        # them would silently advance the prefix past unreviewed commits
        # forever (the whole point of push-sweep is to catch outside-CC
        # commits, and a 50-commit range over large files can hit the
        # 30s timeout). skip_reason=45 lets a retry / smaller subsequent
        # push still cover them, mirroring how skip_reason=31 handles
        # too-many-files without recording the tail.
        emit_metrics({**_base, "pushed": len(push_range),
                      "unreviewed": len(tail), "skip_reason": 45})
        sys.exit(0)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1579-1586)
```python
    if len(diff_files) > 10 * MAX_PUSH_SWEEP_FILES:
        emit_metrics({**_base, "pushed": len(push_range),
                      "unreviewed": len(tail), "skip_reason": 31,
                      "diff_files_count": len(diff_files)})
        sys.exit(0)
    diff_files, _dropped = _prioritize_diff_files(diff_files, MAX_PUSH_SWEEP_FILES)
    if _dropped:
        _base = {**_base, "diff_files_dropped": _dropped}
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1620-1623)
```python
    review_ms = int((_time.time() - review_start) * 1000)

    # The tail is now covered by this net-diff review.
    _append_reviewed_shas(repo_root, tail, vulns_found=len(vulns or []))
```
