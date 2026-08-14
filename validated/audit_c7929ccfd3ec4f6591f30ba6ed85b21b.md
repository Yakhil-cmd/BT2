### Title
Coarse `(filePath, category)` dedup key lets an attacker reuse a prior warning key to permanently suppress and mark-reviewed a genuinely new dangerous change - (File: `plugins/security-guidance/hooks/security_reminder_hook.py`)

### Summary
`handle_push_sweep_posttooluse` (and the sibling `handle_commit_review_posttooluse` / `handle_stop_hook`) dedupe LLM findings against `previous_findings` using only the tuple `(filePath, category)`, not the vulnerable code or line content. An attacker who controls diff content across commits/pushes can trigger one low-value finding of a given category in a file, then introduce a genuinely dangerous, unrelated vulnerability of the *same category* in the *same file* on a later commit/push — the second finding is silently dropped from `new_vulns` and never surfaced to the user, while the push-sweep still unconditionally marks the covering commit range as reviewed in `.git/sg-reviewed-shas`.

### Finding Description
`handle_push_sweep_posttooluse` calls `_dedup_against_state(session_id, vulns or [], prompted=_finding_keys(previous_findings))` at [1](#0-0) . The recording logic for findings — both in commit-review (`state["previous_findings"]`) and Stop (`_record_fire`) — explicitly keys on `(filePath, category)` rather than `vulnerableCode`, by design, because diff context lines shift between fires: [2](#0-1) [3](#0-2) 

The push-sweep's own recording of "reported" findings uses the identical coarse key: [4](#0-3) 

Because the key omits line number, code snippet, and severity, any two *distinct* vulnerabilities of the same `category` in the same file collide. An attacker who fully controls the diff (ordinary edits/commits, no elevated privilege needed) can:
1. Introduce a trivial/benign finding of category `C` in file `F` in an early commit/push — this gets shown once and recorded into `previous_findings` as `(F, C)`.
2. In a later commit/push, replace it with (or add) a genuinely dangerous vulnerability that the LLM classifies under the same category `C` in the same file `F`.
3. `_dedup_against_state` sees `(F, C)` already in `prompted`/`previous_findings` and drops the new (dangerous) finding from `new_vulns`, so no warning/rewake is emitted for it — `sys.exit(0)` is taken at [5](#0-4) .
4. Independent of whether `new_vulns` is empty, the push-sweep unconditionally advances the reviewed-commit log via `_append_reviewed_shas(repo_root, tail, ...)` at [6](#0-5) , which is called *before* the dedup step. This permanently marks the SHAs carrying the dangerous change as reviewed in `.git/sg-reviewed-shas` (capped/deduped set, see `_append_reviewed_shas` in `diffstate.py`), so future pushes/`_compute_push_sweep_base` treat that prefix as already covered and never re-diff it — even on amends/rebases that keep those shas in history, or on subsequent pushes whose base advances past them.

No existing guard (allowlist, workspace guard, session binding, repo scoping) checks for this collision; the dedup logic is intentionally coarse for a legitimate reason (line drift across fires) but has no secondary check (e.g., hashing the vulnerable-code snippet or requiring severity match) to prevent semantically different findings from colliding.

### Impact Explanation
This is a Security-control bypass: an attacker-controlled diff can cause a genuinely dangerous change to permanently evade the push-sweep, commit-review, and Stop-hook review surfaces by pre-seeding a same-category/same-file "known" finding. Because `_append_reviewed_shas` marks the covering range reviewed regardless of dedup outcome, the suppression is durable — it is not merely "not shown this time" but "never diffed again" for that push-sweep pathway, breaking the stated invariant that dangerous edits/commands must remain reviewable and blockable across retries, amends, and pushes.

### Likelihood Explanation
Feasible with only the access already granted to a normal Claude Code session: the ability to author file edits and run `git commit`/`git push`. It requires knowledge of how the LLM's `category` taxonomy buckets findings for a given file (observable by watching prior warnings/telemetry, or via straightforward experimentation — planting varied vulnerability types and observing which categories the reviewer assigns). No privilege escalation, no bypass of git or CC's own auth is needed — purely a property of the review pipeline's dedup key granularity.

### Recommendation
Strengthen the dedup key so it cannot collide across semantically distinct findings in the same file/category:
- Include a stable content fingerprint (e.g., a normalized hash of `vulnerableCode` stripped of pure whitespace/line-number drift, or the finding's `filePath` + `category` + a hash of the surrounding function/symbol) rather than the raw `(filePath, category)` pair.
- Do not call `_append_reviewed_shas` to mark a range as fully reviewed when `_dedup_against_state` suppressed any findings for that range; instead persist only the actually-reviewed-and-shown prefix, or store an explicit "partially reviewed, N findings suppressed by dedup" marker that forces re-diffing of that range on the next sweep.
- Consider re-validating suppressed findings against the previous `vulnerableCode` snapshot with a similarity threshold (not exact byte match) before treating them as already-known, so genuinely new dangerous code in the same category/file is still surfaced.

### Proof of Concept
Integration test plan (extends existing hook test harness for `handle_push_sweep_posttooluse` / `handle_commit_review_posttooluse`):
1. Set up a repo with `SG_PUSH_SWEEP=1` and mock the LLM (`analyze_code_security`) to return deterministic findings.
2. Commit 1: introduce `foo.py` with a low-severity issue; mock LLM returns `[{"filePath": "foo.py", "category": "Injection", "vulnerableCode": "os.system(cmd)"}]`. Run `handle_commit_review_posttooluse` (or push-sweep) — assert it exits 2 and `previous_findings` now contains `("foo.py", "Injection")`.
3. Commit 2: replace the line with a clearly different, more dangerous injection (`subprocess.run(shell=True, input=user_data)`), mock LLM returns `[{"filePath": "foo.py", "category": "Injection", "vulnerableCode": "subprocess.run(..., shell=True)"}]`.
4. Run `git push`, invoke `handle_push_sweep_posttooluse` with a synthetic `tool_response.stderr` containing a valid push range line.
5. Assert: `sys.exit(0)` is called (no warning/rewake emitted) even though the vulnerable code differs entirely, and assert `.git/sg-reviewed-shas` now contains the new commit SHA (via `_load_reviewed_shas(repo_root)`), proving the dangerous change is both unreported and marked permanently reviewed.
6. Negative control: change `category` to a distinct value in step 3 and confirm the finding *is* reported — demonstrating the bypass is specifically due to `(filePath, category)` key collision, not a general dedup failure.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1334-1336)
```python
    # Record new findings into shared state. Key on (filePath, category) —
    # vulnerableCode bytes drift between fires (diff context lines shift) so
    # matching on it under-dedupes; this aligns with Stop's _record_fire.
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1622-1623)
```python
    # The tail is now covered by this net-diff review.
    _append_reviewed_shas(repo_root, tail, vulns_found=len(vulns or []))
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1625-1627)
```python
    new_vulns, n_deduped = _dedup_against_state(
        session_id, vulns or [], prompted=_finding_keys(previous_findings)
    )
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1641-1643)
```python
    if not new_vulns:
        debug_log("Push sweep: no new findings")
        sys.exit(0)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1671-1680)
```python
    def _record(state):
        existing = [f for f in state.get("previous_findings", [])
                    if isinstance(f, dict)]
        seen = {(f.get("filePath", ""), f.get("category", "")) for f in existing}
        for f in snapshots:
            k = (f["filePath"], f["category"])
            if k not in seen:
                seen.add(k); existing.append(f)
        state["previous_findings"] = existing
        state["previous_findings_ts"] = _time.time()
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1901-1904)
```python
            # Dedupe on (filePath, category) — vulnerableCode includes diff
            # context lines that drift between fires, so byte-identical
            # matching let the same finding accumulate as "new" each fire.
            existing = [f for f in state.get("previous_findings", []) if isinstance(f, dict)]
```
