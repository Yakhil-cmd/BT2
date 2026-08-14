### Title
Coarse `(filePath, category)` dedup key in commit-review lets a later critical vulnerability be silently suppressed by an earlier low-severity finding - ([File: plugins/security-guidance/hooks/security_reminder_hook.py])

### Summary
`handle_commit_review_posttooluse` dedups newly-found vulnerabilities against `previous_findings` using only `(filePath, category)` as the key, ignoring `vulnerableCode` and `severity`. An attacker who can make the LLM classify two different vulnerabilities in the same file under the same `category` string can get a first, low-severity commit's finding recorded, causing a later, genuinely different and more severe finding at the same path+category to be dropped from `new_vulns`, suppressing the `exit(2)` stderr guidance entirely.

### Finding Description
`_record_findings` (and the equivalent block in `handle_push_sweep_posttooluse`) persists findings into shared session state keyed only by `(filePath, category)`: [1](#0-0) 
The comment explicitly documents the intentional design tradeoff: `vulnerableCode` bytes drift between fires (diff context lines shift), so matching on it under-dedupes, and the code aligns with Stop's `_record_fire` by keying only on `(filePath, category)`. [2](#0-1) 

`_dedup_against_state` is called with `prompted=_finding_keys(previous_findings)`, and `new_vulns` is computed from that same coarse key: [3](#0-2) 

If `new_vulns` ends up empty, the handler exits 0 silently with only a metrics emission — no stderr guidance, no `exit(2)`: [4](#0-3) 

Exploit flow: commit 1 introduces a low-severity issue in `file.py` that the LLM classifies as category `X`; `_record_findings` stores `("file.py", "X")` in `previous_findings`. Commit 2 introduces a genuinely different, critical vulnerability in the same file that the LLM also classifies as category `X` (attacker only needs to shape the code pattern so the LLM's categorization label matches — categories are coarse strings like "SQL Injection", "Command Injection", etc., not tied to specific code snippets). Because the dedup key ignores `vulnerableCode` and `severity`, the critical finding is treated as already-reported and dropped, causing silent `sys.exit(0)` instead of the intended `sys.exit(2)` rewake with security guidance.

### Impact Explanation
This suppresses the security warning surfaced to the user/model for a critical vulnerability, allowing dangerous code to be committed without the expected block/continue-loop enforcement that `exit(2)` + stderr guidance is designed to trigger. This matches a "security control bypass / trust-boundary bypass" impact class: the hook's core enforcement mechanism (rewake-on-vulnerability) is defeated by attacker-influenced commit sequencing within a single file+category, even though the underlying vulnerabilities are unrelated in severity and content.

### Likelihood Explanation
Preconditions are realistic and fully within an ordinary contributor's control: the attacker only needs to make two commits touching the same file path, where the LLM's classification of both maps to the same `category` label (categories are coarse, e.g., broad OWASP-style names) — no privileged access, no LLM prompt injection of the raw vulnerability text is strictly required, only crafting code that reliably classifies similarly. This is a repeatable, low-effort local sequencing attack reachable purely through normal commit workflow, which is explicitly the mechanism `handle_commit_review_posttooluse` monitors.

### Recommendation
Tighten the dedup key so that the coarse `(filePath, category)` match is only treated as "already reported" when severity does not escalate, or add a severity/hash-of-vulnerableCode component to the key so a higher-severity finding at the same path+category is never dropped. E.g., in `_dedup_against_state`, only suppress a new finding when an existing entry at the same key has severity >= the new finding's severity, and always let strictly more severe re-detections at the same key surface (mirroring the intent already stated in `handle_push_sweep_posttooluse`'s comment that "fix incomplete" re-flags at the same key should not be silently dropped).

### Proof of Concept
Integration test plan for `_dedup_against_state` / `_record_findings`:
1. Seed session state via `_record_findings`-equivalent with one finding: `{"filePath": "app.py", "category": "SQL Injection", "vulnerableCode": "cursor.execute(f'SELECT ... {low}')", }` with implied low severity.
2. Call `handle_commit_review_posttooluse` (or directly `_dedup_against_state`) with a `vulns` list containing a new finding for the same `filePath`/`category` but different `vulnerableCode` and `severity: "critical"`.
3. Assert `new_vulns` is non-empty and contains the critical finding (currently fails — `new_vulns` is empty because the key `("app.py", "SQL Injection")` is already in `prompted`).
4. Assert that in the current implementation, `sys.exit(0)` is invoked instead of `sys.exit(2)` and no stderr guidance is written, confirming the suppression.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1319-1332)
```python
    # Late dedup: drop only what a concurrent Stop hook wrote while our LLM
    # ran. Anything in `previous_findings` (the pre-LLM snapshot) that the
    # LLM chose to re-flag is an intentional "fix incomplete" verdict.
    new_vulns, n_deduped = _dedup_against_state(
        session_id, vulns, prompted=_finding_keys(previous_findings)
    )

    if not new_vulns:
        debug_log("Commit review: all findings already known, skipping")
        emit_metrics({
            "vulns_found": 0, **_base, **_agentic_m, "deduped": n_deduped,
            "files_reviewed": len(diff_files), "review_ms": review_ms,
        })
        sys.exit(0)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1334-1345)
```python
    # Record new findings into shared state. Key on (filePath, category) —
    # vulnerableCode bytes drift between fires (diff context lines shift) so
    # matching on it under-dedupes; this aligns with Stop's _record_fire.
    finding_snapshots = [
        {
            "filePath": v.get("filePath", ""),
            "category": v.get("category", "Unknown"),
            "vulnerableCode": v.get("vulnerableCode", ""),
        }
        for v in new_vulns
    ]

```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1346-1356)
```python
    def _record_findings(state):
        existing = [f for f in state.get("previous_findings", []) if isinstance(f, dict)]
        seen = {(f.get("filePath", ""), f.get("category", "")) for f in existing}
        for f in finding_snapshots:
            key = (f["filePath"], f["category"])
            if key not in seen:
                seen.add(key)
                existing.append(f)
        state["previous_findings"] = existing
        state["previous_findings_ts"] = _time.time()
    with_locked_state(session_id, _record_findings)
```
