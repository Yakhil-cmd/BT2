### Title
Push-sweep batches multiple git commits into one net-diff security review and marks the entire commit range "reviewed" even when files were dropped from the batch, silently bypassing security-guidance coverage for the dropped files - (File: plugins/security-guidance/hooks/security_reminder_hook.py)

### Summary
The external report describes a batching flaw: `_executeNonAtomicOrders` aggregates per-order fees and only settles them at the end of the loop, so failure/behavior at the tail of the batch can defeat the purpose of processing items independently, causing coverage that should be partial to become effectively all-or-nothing. The `handle_push_sweep_posttooluse` function in this repo's `security-guidance` plugin exhibits an analogous batching trust-boundary issue: it aggregates an entire range of pushed commits into a single diff, caps/truncates the file set actually sent to the LLM reviewer, but then marks the *whole* commit range as "reviewed" regardless of what was dropped from the batch — an unprivileged repo contributor can exploit this to get vulnerable code permanently excluded from future automated security review.

### Finding Description
`handle_push_sweep_posttooluse` computes a git commit range (`push_range`) covering everything pushed since the last known upstream, and diffs it as one batched unit (`_git_diff_range`) rather than reviewing each commit independently [1](#0-0) .

When the number of changed files in that combined diff exceeds `MAX_PUSH_SWEEP_FILES`, `_prioritize_diff_files` truncates the file list, and the function explicitly documents that the dropped files are assumed to be "low-risk" — yet it still marks the *entire* commit `tail` as reviewed in the persistent `.git/sg-reviewed-shas` state right after the (partial) review completes, independent of what was actually analyzed: [2](#0-1) 

The comment at the call site is explicit about the tradeoff being intentional: "We still mark `tail` reviewed afterward — the dropped files are by construction the low-risk ones (config, .gen, tests, migrations)... Per-commit review remains the primary surface for those files" [3](#0-2) .

This mirrors the Seaport bug's root cause: a loop/batch aggregates state (fee amount / reviewed-SHA set) and commits that aggregate as a single all-or-nothing unit at the end, even though the individual items in the batch were not uniformly processed. Here, once a SHA is recorded as "reviewed," `_compute_push_sweep_base` treats the entire `prev_upstream..B` prefix as covered and will never re-diff it on a later push [4](#0-3) . If the dropped file's risk classification (`_prioritize_diff_files`'s heuristic) is wrong, or an attacker deliberately pads a push with many benign/no-op files to force the real vulnerable file below the `MAX_PUSH_SWEEP_FILES` cut line, that file is marked reviewed and permanently exempted from the push-sweep surface, without the code ever having been sent to the LLM.

Similarly, the same commit-review path (`handle_commit_review_posttooluse`) marks resolved SHAs as reviewed via `_append_reviewed_shas` right after the review call regardless of whether the diff review itself was truncated [5](#0-4) , reinforcing the same "batch aggregate → mark-all-done" pattern that the Seaport report flags as unsafe when a batch's outcome doesn't match the individual items' actual processing state.

### Impact Explanation
This is a hook-bypass / security-check bypass in the `security-guidance` plugin's automated code-review defenses, one of the explicitly allowed trust boundaries for this analysis. An unprivileged contributor (or a compromised/careless model-driven agent) who pushes a large commit range containing many low-priority files alongside a genuinely vulnerable file can rely on the `MAX_PUSH_SWEEP_FILES` truncation to keep the vulnerable file out of the LLM's diff, while the tool still records the entire range — including the vulnerable commit — as "reviewed." Because the per-commit `commit-review` hook is presented as the "primary surface" backstop and push-sweep as a secondary net, if push-sweep is the surface actually exercised (e.g., commits made without triggering `git commit` through Claude Code, or via `-q`/redirected output that the commit hook's SHA detection misses and falls to push-sweep), the vulnerable code can permanently escape automated review, degrading the plugin's core security guarantee.

### Likelihood Explanation
Reaching this path only requires a normal, unprivileged git workflow: pushing a range of commits large enough (or with enough touched files) to exceed `MAX_PUSH_SWEEP_FILES` (default 30) but under the 10x hard-skip ceiling. This is a realistic scenario for legitimate large pushes (dependency bumps, generated file updates, vendored code, migrations) and does not require any special permission, git configuration, or malicious infrastructure — only knowledge of the file-count cap, which is visible in the plugin's own source and documented cap-behavior comments.

### Recommendation
Do not mark commits/SHAs as "reviewed" for files that were dropped by the prioritization cap. Instead, track review coverage at the (sha, file) granularity, or only advance the reviewed-prefix boundary up to the last commit whose *entire* file set was actually included in the reviewed diff, leaving any commit that contributed a dropped file as unreviewed so it is retried on the next sweep or backstopped by the Stop hook. Alternatively, when files are dropped due to the cap, split the batch into multiple review passes (or emit a persistent unresolved flag) rather than treating dropped/truncated content as equivalent to reviewed content — mirroring the report's recommendation to "not batch up" outcomes that don't uniformly apply to every item in the batch.

### Proof of Concept
1. On a repo with `security-guidance` push-sweep enabled and `SG_PUSH_SWEEP_MAX_FILES` at its default (30), locally create a branch with ~40 changed files across several commits, where one commit near the end of the diff-priority ordering contains an obviously exploitable vulnerability (e.g., a command-injection sink) and the other ~35 files are innocuous (docs, config, generated files).
2. Push the branch. `handle_push_sweep_posttooluse` computes `push_range` for all new commits, builds the combined diff, and calls `_prioritize_diff_files(diff_files, MAX_PUSH_SWEEP_FILES)` — see truncation call at [6](#0-5) . Because the count is under the `10 * MAX_PUSH_SWEEP_FILES` hard-skip threshold, the sweep proceeds but the vulnerable file is dropped from `diff_files` by the cap.
3. `analyze_code_security`/`agentic_review` never see the vulnerable file's diff, so no finding is produced for it.
4. `_append_reviewed_shas(repo_root, tail, vulns_found=len(vulns or []))` is called at [7](#0-6) , marking every commit in `tail` — including the one containing the vulnerability — as reviewed.
5. Any subsequent push whose range starts after this prefix will have `_compute_push_sweep_base` skip re-diffing this prefix entirely (see logic at [4](#0-3) ), so the vulnerable commit is never surfaced by push-sweep again, and if the file is never touched again, per-commit review's "backstop" never fires either.

I was not able to execute this end-to-end (would require live git repos, `ANTHROPIC_API_KEY` credentials, and the `claude_agent_sdk`), so the exploit is derived from static analysis of the documented cap/mark-reviewed logic rather than an observed live bypass.

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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1248-1265)
```python
    # push-sweep state: record this commit as reviewed (full 40-hex sha) so a
    # later `git push` can advance its diff base past it. Recorded here — after
    # the review ran but before any exit path — so it's marked regardless of
    # whether findings were emitted. `shas` holds abbreviated refs from
    # `[branch sha]`; resolve to full so set-membership in the push-sweep is
    # exact. Best-effort; failures here never block the review result.
    try:
        full_shas = []
        for s in shas:
            r = subprocess.run(
                [*GIT_CMD, "rev-parse", "--verify", "-q", s],
                cwd=repo_root, capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                full_shas.append(r.stdout.strip())
        _append_reviewed_shas(repo_root, full_shas, vulns_found=len(vulns or []))
    except Exception:
        pass
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1521-1549)
```python
    prev_upstream = _detect_prev_upstream(repo_root, bash_output)
    if not prev_upstream:
        debug_log("Push sweep: could not determine prev_upstream")
        emit_metrics({"skipped": True, "skip_reason": 41, **_base})
        sys.exit(0)

    push_range = _git_rev_list_range(repo_root, prev_upstream, "HEAD")
    if not push_range:
        emit_metrics({"skipped": True, "skip_reason": 42, **_base, "pushed": 0})
        sys.exit(0)
    if len(push_range) > MAX_PUSH_SWEEP_RANGE:
        # Huge first-push of a long-lived branch — Stop hook is the backstop.
        emit_metrics({"skipped": True, "skip_reason": 43, **_base,
                      "pushed": len(push_range)})
        sys.exit(0)

    reviewed = _load_reviewed_shas(repo_root)
    base, tail = _compute_push_sweep_base(prev_upstream, push_range, reviewed)
    prefix_advanced = len(push_range) - len(tail)
    if base is None:
        debug_log("Push sweep: every pushed commit already reviewed")
        emit_metrics({**_base, "pushed": len(push_range), "unreviewed": 0,
                      "prefix_advanced": prefix_advanced})
        sys.exit(0)

    debug_log(f"Push sweep: range={len(push_range)} prefix_advanced="
              f"{prefix_advanced} base={base[:12]} tail={len(tail)}")

    diff_text = _git_diff_range(repo_root, base, "HEAD")
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1569-1623)
```python
    # Same prioritize-don't-bail logic as commit-review (see comment there).
    # push-sweep ranges are net diffs over many commits so they hit the cap
    # more often; reviewing the riskiest MAX_PUSH_SWEEP_FILES is strictly
    # better than reviewing none. We still mark `tail` reviewed afterward —
    # the dropped files are by construction the low-risk ones (config, .gen,
    # tests, migrations), and NOT advancing the base would make the next
    # push re-hit the same overflow with an even larger range. Per-commit
    # review remains the primary surface for those files. The 10×
    # pathological guard stays so a 500-file vendored-dir push doesn't burn
    # a counter slot.
    if len(diff_files) > 10 * MAX_PUSH_SWEEP_FILES:
        emit_metrics({**_base, "pushed": len(push_range),
                      "unreviewed": len(tail), "skip_reason": 31,
                      "diff_files_count": len(diff_files)})
        sys.exit(0)
    diff_files, _dropped = _prioritize_diff_files(diff_files, MAX_PUSH_SWEEP_FILES)
    if _dropped:
        _base = {**_base, "diff_files_dropped": _dropped}

    _allowed, _rate_n = atomic_check_rate_limit(
        session_id, "PushSweep",
        MAX_COMMIT_REVIEWS_PER_HOUR, COMMIT_REVIEW_RATE_WINDOW_S)
    _base = {**_base, "rate_count": _rate_n}
    if not _allowed:
        emit_metrics({"skipped": True, "skip_reason": 23, **_base})
        sys.exit(0)

    import time as _time
    now = _time.time()
    previous_findings = with_locked_state(
        session_id,
        lambda s: list(s.get("previous_findings", []))
        if (now - s.get("previous_findings_ts", 0)) <= PREVIOUS_FINDINGS_TTL_SEC
        else []
    ) or []

    review_start = _time.time()
    rel_touched = [fp for fp, _ in diff_files]
    if _agentic_commit_review_enabled():
        concrete_guidance, vulns, agentic_metrics = _agentic_review_with_race(
            repo_root, diff_files, rel_touched, previous_findings
        )
        if agentic_metrics.get("agentic_fallback"):
            concrete_guidance, vulns = analyze_code_security(
                diff_files, is_diff=True, previous_findings=previous_findings
            )
    else:
        concrete_guidance, vulns = analyze_code_security(
            diff_files, is_diff=True, previous_findings=previous_findings
        )
        agentic_metrics = {}
    review_ms = int((_time.time() - review_start) * 1000)

    # The tail is now covered by this net-diff review.
    _append_reviewed_shas(repo_root, tail, vulns_found=len(vulns or []))
```
