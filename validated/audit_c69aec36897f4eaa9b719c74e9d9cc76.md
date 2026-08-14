Based on my research, there's a legitimate structural analog in the `security-guidance` plugin's commit/push review hooks. The bug-class from the audit report — "fee/authorization computed on the full requested quantity while the actual operation is silently capped to a smaller amount, with no signal of the mismatch" — maps to how `security_reminder_hook.py` computes security coverage vs. what it actually records as "reviewed."

### Title
Commit/push-sweep hooks mark full diff as security-reviewed while the LLM only scanned a capped subset of files - (File: `plugins/security-guidance/hooks/security_reminder_hook.py`)

### Summary
`handle_commit_review_posttooluse` and `handle_push_sweep_posttooluse` cap the file list passed to the security scanner (`analyze_code_security` / `_agentic_review_with_race`) via `_prioritize_diff_files(diff_files, MAX_DIFF_FILES)`, silently dropping lower-priority files when a commit/push touches more than the cap. After the (partial) scan runs, the hooks unconditionally record the **entire** commit range as reviewed via `_append_reviewed_shas`, which permanently suppresses future re-scanning of that SHA range by the `Stop`/next commit-review/push-sweep hooks.

### Finding Description
In the commit-review path, `diff_files` is truncated to `MAX_DIFF_FILES` entries by priority score, with the drop count only recorded as telemetry (`diff_files_dropped`): [1](#0-0) 

The scan (`analyze_code_security` or the agentic reviewer) then only ever sees the capped `diff_files`: [2](#0-1) 

Immediately afterward, the full commit SHA range is marked reviewed regardless of how many files were actually dropped from analysis, and this "reviewed" marker is exactly what future invocations use to decide a range never needs to be scanned again: [3](#0-2) 

The same pattern repeats in the push-sweep handler: the full `tail` (pushed-but-unreviewed SHA range) is passed to `_append_reviewed_shas` after only a `MAX_PUSH_SWEEP_FILES`-capped subset of files was actually analyzed: [4](#0-3) [5](#0-4) 

`_append_reviewed_shas` records these SHAs as reviewed on disk in `.git/sg-reviewed-shas`, and later lookups use that record to decide whether a range needs review at all: [6](#0-5) 

This is the same root-cause shape as the audit finding: one subsystem computes/records a result "as if" the full requested scope (all `records` / all diff files in the commit) was processed, while a downstream subsystem (`load_prices` capping at 20 / `_prioritize_diff_files` capping at `MAX_DIFF_FILES`) silently truncated the actual work performed. The caller (fee payer / the security-review coverage guarantee) is given credit/charge for the full scope, but only a subset was truly acted upon — and there is no signal exposed to the security boundary that would prevent it from trusting the stale/incomplete "reviewed" state.

### Impact Explanation
Files dropped by `_prioritize_diff_files` (e.g., low-priority-suffix files, or any file beyond the cap in large scaffolds/refactors/big pushes) are never analyzed by the LLM security reviewer, yet their containing commit SHAs are permanently marked "reviewed." Because `previous_findings`/`sg-reviewed-shas` state is exactly what the `Stop` hook and later commit-review/push-sweep invocations consult to skip re-scanning already-covered ranges, a vulnerability introduced in a dropped file in an oversized commit/push will never be surfaced by this security-guidance tooling again — not on that commit, not on a later push, and not by the `Stop` hook, since the range is treated as fully vetted. This defeats the entire purpose of the plugin's automated code-security review for exactly the class of changes (large multi-file scaffolds/refactors) the code comments explicitly call out as "where cross-file source→sink vulns hide."

### Likelihood Explanation
This triggers automatically and silently on any commit or push that exceeds `MAX_DIFF_FILES` / `MAX_PUSH_SWEEP_FILES` (a plain per-invocation cap, not a rare edge case — large scaffolds, generated-code commits, and squash/rebase pushes routinely exceed typical file caps). No attacker action or malicious peer is required; an ordinary unprivileged user's normal large commit or push is enough to produce a silent coverage gap, matching the "unprivileged-user analog" requirement.

### Recommendation
Only record as reviewed the SHAs/files that were actually passed into `analyze_code_security`/`_agentic_review_with_race`. Concretely: track which files were dropped by `_prioritize_diff_files`, and either (a) do not advance the "reviewed" state for any commit whose diff had files dropped, or (b) persist the drop information so the next Stop/commit-review/push-sweep pass explicitly re-includes the previously-dropped files for review rather than treating the range as fully vetted. At minimum, `diff_files_dropped > 0` should downgrade the state from "fully reviewed" to a partial-review marker so downstream skip logic can't treat it as complete coverage.

### Proof of Concept
1. Create a commit touching more than `MAX_DIFF_FILES` source files, where the extra files beyond the cap contain an injected vulnerability (e.g., a `subprocess.run(shell=True)` call with unsanitized input) in a file that sorts to a low-priority score in `_prioritize_diff_files` (e.g. under `/migrations/` or matching `.gen.ts`).
2. Run the commit-review hook (`handle_commit_review_posttooluse`): confirm via `debug_log`/`diff_files_dropped` telemetry that the vulnerable file was dropped from the LLM scan. [7](#0-6) 
3. Observe that `_append_reviewed_shas` still records the full commit SHA(s) as reviewed. [3](#0-2) 
4. Amend/push again touching only unrelated files, or check `.git/sg-reviewed-shas` state directly — the earlier commit's SHA is present as reviewed, and re-running commit-review/push-sweep/Stop on that range no-ops, permanently hiding the vulnerable file from any future automated review pass.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1192-1201)
```python
    if len(diff_files) > 10 * MAX_DIFF_FILES:
        debug_log(f"Commit review: pathological diff ({len(diff_files)} files), skipping")
        emit_metrics({"skipped": True, "skip_reason": 31, **_base,
                      "diff_files_count": len(diff_files)})
        sys.exit(0)
    diff_files, _dropped = _prioritize_diff_files(diff_files, MAX_DIFF_FILES)
    if _dropped:
        debug_log(f"Commit review: prioritized to {len(diff_files)} files "
                  f"(dropped {_dropped} lower-risk)")
        _base = {**_base, "diff_files_dropped": _dropped}
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1230-1246)
```python
    agentic_metrics: Dict[str, Any] = {}
    if _agentic_commit_review_enabled():
        rel_touched = [fp for fp, _ in diff_files]
        concrete_guidance, vulns, _am = _agentic_review_with_race(
            repo_root, diff_files, rel_touched, previous_findings
        )
        agentic_metrics.update(_am)
        # Fall back to single-shot only on agentic FAILURE (SDK/investigate
        # crash). If agentic completed and returned 0 findings, trust that.
        if agentic_metrics.get("agentic_fallback"):
            concrete_guidance, vulns = analyze_code_security(
                diff_files, is_diff=True, previous_findings=previous_findings
            )
    else:
        concrete_guidance, vulns = analyze_code_security(
            diff_files, is_diff=True, previous_findings=previous_findings
        )
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1248-1260)
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
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1569-1586)
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
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1620-1623)
```python
    review_ms = int((_time.time() - review_start) * 1000)

    # The tail is now covered by this net-diff review.
    _append_reviewed_shas(repo_root, tail, vulns_found=len(vulns or []))
```

**File:** plugins/security-guidance/hooks/diffstate.py (L267-280)
```python
def _append_reviewed_shas(repo_root, shas, vulns_found=0):
    """Record that `shas` were reviewed. Best-effort; never raises.

    Uses fcntl.flock for the read-gc-write; appends are O_APPEND-atomic but
    GC needs the lock so concurrent CC sessions in the same clone don't race
    each other's truncation.
    """
    p = _reviewed_shas_path(repo_root)
    if not p or not shas:
        return
    import time as _time
    ts = int(_time.time())
    pv = _PV or 0
    lines = [f"{s}\t{ts}\t{pv}\t{int(vulns_found)}\n" for s in shas]
```
