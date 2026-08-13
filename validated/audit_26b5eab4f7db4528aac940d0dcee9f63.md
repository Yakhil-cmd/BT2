### Title
Security-review finding dedup keyed on (filePath, category) only — later distinct dangerous edits in same file/category are silently suppressed - ([File: plugins/security-guidance/hooks/security_reminder_hook.py])

### Summary
The `security-guidance` Stop/commit-review/push-sweep pipeline stores LLM-found vulnerabilities in shared session state (`previous_findings`) and deduplicates future findings against that list using only `(filePath, category)` as the key, deliberately ignoring `vulnerableCode`. An attacker who controls diff content across a session (via normal edits/commits/amends/pushes that Claude is asked to make in a repo) can cause an initial low-severity finding to be recorded for a given `(file, category)` pair, after which any subsequent, materially different and more dangerous finding in the same file with the same `category` label is treated as already-known and never re-surfaced, never triggers `exit(2)`, and never re-wakes the model.

### Finding Description
In `handle_commit_review_posttooluse` (`plugins/security-guidance/hooks/security_reminder_hook.py`), after `analyze_code_security`/`agentic_review` produce `vulns`, the code deduplicates via `_dedup_against_state(session_id, vulns, prompted=_finding_keys(previous_findings))` [1](#0-0) . Newly-surfaced findings that pass this dedup are recorded back into shared `previous_findings` state keyed explicitly on `(filePath, category)`, with an inline comment acknowledging that `vulnerableCode` is intentionally excluded from the key because it "drifts between fires": [2](#0-1) 

This same `previous_findings` state is shared across the Stop hook, the commit-review PostToolUse hook, and the push-sweep PostToolUse hook (`consume_stop_state`, `_read_previous`, and the push-sweep reader all read/write the identical `previous_findings` key with a 1-hour TTL) [3](#0-2) . Because the key omits any content/line/severity discriminator, once one finding for `(fileX, "Injection")` (for example) has been recorded, any later, unrelated, and more severe vulnerability that the LLM classifies under the same `category` string in the same file is treated by `_dedup_against_state` as a repeat and dropped from `new_vulns`, hitting the "all findings already known, skipping" path with no `exit(2)` and no rewake: [4](#0-3) 

An attacker who supplies repository content or drives ordinary edit/commit/amend/push flows (the stated attacker model — "diff content from normal edits and commits") can trivially engineer this: commit a trivial/benign-looking finding of a given category in a target file first (or have Claude introduce one incidentally), then commit the truly dangerous payload (e.g., a hardcoded exfiltration token, a new injection sink) in the same file under a category the reviewer is likely to reuse. Since the dedup and the `_reviewed_shas` per-SHA gate (`_load_reviewed_shas`/`_append_reviewed_shas`) both persist across retries, amends, and pushes (`.git/sg-reviewed-shas`, `previous_findings` with 1h TTL) [5](#0-4) , the suppression holds across the exact retry/amend/push flows the invariant is supposed to protect.

No existing check re-validates suppressed findings against the actual `vulnerableCode` or line location before dropping them — the only downstream re-check (`sweep_pending_warnings`) applies solely to pattern-based (regex) PostToolUse warnings, not to the LLM-based commit/push/stop review findings, so nothing catches the category-collision case.

### Impact Explanation
A genuinely dangerous, newly-introduced change (e.g., a secret leak, command injection, or a change that exfiltrates code/diff/token content to an external sink) can be committed, amended, and pushed while the security-guidance plugin's Stop hook, commit-review hook, and push-sweep — the three surfaces meant to keep dangerous edits "reviewable and blockable even across retries, amends, and pushes" — stay silent because the finding collides on `(filePath, category)` with an earlier, unrelated finding. This directly enables the stated impact class: sensitive code/prompt/token/diff/local-file content introduced by the dangerous edit reaches an unintended sink (e.g., committed and pushed to a remote) without the reviewer ever emitting a warning or forcing Claude to address it.

### Likelihood Explanation
This requires no privilege beyond being able to influence what Claude edits/commits in a session — the documented attacker model here (repository content, normal edit/commit flows). It requires two findings of the same LLM-assigned `category` string touching the same file path within the same session/TTL window (up to 1 hour, shared across Stop/commit/push surfaces), which is a low bar since LLM category labels are coarse (e.g., "Injection", "Hardcoded Credentials", "Insecure Deserialization"). The mechanism is deterministic code (not probabilistic LLM behavior) once the first finding is recorded, making it reliably reproducible.

### Recommendation
Change the dedup/record key in `_record_findings` (and the corresponding key used by `_dedup_against_state`/`_finding_keys` in `llm.py`) to include a stable content discriminator beyond `(filePath, category)` — e.g., a normalized hash of `vulnerableCode` plus line-range, or the specific rule/CWE id — so that two structurally different vulnerabilities in the same file and coarse category are not conflated. At minimum, cap dedup validity so a "fixed" finding (file content no longer matches) is purged from `previous_findings` before being used to suppress new findings, mirroring the pattern-layer `sweep_pending_warnings` re-check that LLM-based findings currently lack.

### Proof of Concept
Integration test plan (pytest-style, targeting `security_reminder_hook.handle_commit_review_posttooluse`):
1. Monkeypatch `analyze_code_security` (or `agentic_review`) to first return one vuln: `{"filePath": "app.py", "category": "Injection", "vulnerableCode": "os.system(user_input)"}`.
2. Drive a fake `git commit` PostToolUse event through `handle_commit_review_posttooluse`; assert `exit(2)` fires and `previous_findings` state now contains `{"filePath": "app.py", "category": "Injection", ...}`.
3. Monkeypatch `analyze_code_security` to return a second, unrelated and more severe vuln: `{"filePath": "app.py", "category": "Injection", "vulnerableCode": "eval(requests.get(url).text)"}` (a distinct RCE-class sink, same category label).
4. Drive a second fake commit event within the `PREVIOUS_FINDINGS_TTL_SEC` window; assert that `_dedup_against_state` drops this finding (`new_vulns` empty), `sys.exit(0)` is called instead of `exit(2)`, and no `rewakeSummary`/stderr guidance is emitted — confirming the dangerous second change is never surfaced, violating the "must stay reviewable and blockable" invariant.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1319-1324)
```python
    # Late dedup: drop only what a concurrent Stop hook wrote while our LLM
    # ran. Anything in `previous_findings` (the pre-LLM snapshot) that the
    # LLM chose to re-flag is an intentional "fix incomplete" verdict.
    new_vulns, n_deduped = _dedup_against_state(
        session_id, vulns, prompted=_finding_keys(previous_findings)
    )
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1326-1332)
```python
    if not new_vulns:
        debug_log("Commit review: all findings already known, skipping")
        emit_metrics({
            "vulns_found": 0, **_base, **_agentic_m, "deduped": n_deduped,
            "files_reviewed": len(diff_files), "review_ms": review_ms,
        })
        sys.exit(0)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1334-1356)
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

**File:** plugins/security-guidance/hooks/diffstate.py (L31-36)
```python
# previous_findings expires independently. Dedup is content-based ((filePath,
# vulnerableCode) — see _record_fire), so a longer TTL suppresses exact-repeat
# re-flags across turns without masking regressions that change the code. v2's
# git-derived review set can re-surface the same uncommitted file across turns;
# 120s could let warnings pile up over a long session.
PREVIOUS_FINDINGS_TTL_SEC = int(os.environ.get("PREVIOUS_FINDINGS_TTL_SEC", "3600"))
```

**File:** plugins/security-guidance/hooks/diffstate.py (L242-264)
```python
_REVIEWED_SHAS_BASENAME = "sg-reviewed-shas"
_REVIEWED_SHAS_CAP = 500

def _reviewed_shas_path(repo_root):
    gd = _git_dir(repo_root)
    return os.path.join(gd, _REVIEWED_SHAS_BASENAME) if gd else None


def _load_reviewed_shas(repo_root):
    """Set of full 40-hex shas previously reviewed in this clone."""
    p = _reviewed_shas_path(repo_root)
    if not p or not os.path.exists(p):
        return set()
    out = set()
    try:
        with open(p, "r") as f:
            for line in f:
                sha = line.split("\t", 1)[0].strip()
                if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha):
                    out.add(sha)
    except OSError:
        pass
    return out
```
