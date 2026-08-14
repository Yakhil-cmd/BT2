### Title
Coarse (filePath, category) warning-dedup key in push-sweep/commit-review/Stop review lets a new, more dangerous finding in an already-flagged file+category be silently suppressed - (File: `plugins/security-guidance/hooks/security_reminder_hook.py`)

### Summary
`handle_push_sweep_posttooluse` (and `handle_commit_review_posttooluse`/`handle_stop_hook`) route vulnerability findings through `_dedup_against_state(session_id, vulns, prompted=_finding_keys(previous_findings))` before deciding whether to warn/rewake. The `previous_findings` entries that seed this dedup set are recorded keyed on `(filePath, category)` rather than the specific vulnerable content, as the code explicitly documents. That means once one instance of a given vulnerability category has been reported for a file, any subsequently introduced — and potentially far more dangerous — instance of the *same category in the same file* is treated as already-prompted and dropped from `new_vulns`, so no warning/rewake fires for it on push-sweep, commit-review, or Stop.

### Finding Description
`handle_push_sweep_posttooluse` builds the diff for the pushed range, calls `analyze_code_security`/`_agentic_review_with_race` to get `vulns`, then filters them:
```
new_vulns, n_deduped = _dedup_against_state(
    session_id, vulns or [], prompted=_finding_keys(previous_findings)
)
...
if not new_vulns:
    debug_log("Push sweep: no new findings")
    sys.exit(0)
``` [1](#0-0) 

The `previous_findings` state that seeds `prompted` is written elsewhere (Stop hook shown, but the same shared state is read by push-sweep and commit-review) with an explicitly coarse key:
```
# Dedupe on (filePath, category) — vulnerableCode includes diff
# context lines that drift between fires, so byte-identical
# matching let the same finding accumulate as "new" each fire.
existing = [f for f in state.get("previous_findings", []) if isinstance(f, dict)]
seen = {(f.get("filePath", ""), f.get("category", "")) for f in existing}
``` [2](#0-1) 

Because `previous_findings` is deliberately deduped on `(filePath, category)` (not the actual vulnerable code), and `_finding_keys(previous_findings)` is fed straight into `_dedup_against_state` for push-sweep, commit-review, and the Stop hook alike, an attacker who can get any content committed into the repo (e.g. through normal edits/commits, or content that originates from repo/issue/PR text that Claude later incorporates) can:
1. Cause a first, low-severity instance of a vulnerability category (e.g. `Hardcoded Secret`, `SQL Injection`, etc.) to be reported for file `F` early in the session — this gets merged into `previous_findings` keyed `(F, category)`.
2. Later, in a subsequent commit/push, introduce a genuinely dangerous instance of the *same category* in the *same file* (different code, different severity, potentially a real secret or injectable command).
3. When `handle_push_sweep_posttooluse` (or commit-review/Stop) re-reviews the range, the new finding for `(F, category)` is already present in `prompted`, so `_dedup_against_state` drops it from `new_vulns`, `emit_metrics` reports zero/low `vulns_found`, and `sys.exit(0)` is taken with **no stderr write, no exit code 2, and no `asyncRewake`** — the model is never forced to address the new, dangerous change.

This breaks the stated invariant ("warning dedup and counters must not suppress a new in-scope issue") because the suppression is keyed on a coarse `(file, category)` tuple rather than on the actual vulnerable content, so a genuinely new and more dangerous finding sharing that tuple is silently dropped.

I was not able to directly view the full bodies of `_dedup_against_state` and `_finding_keys` in this pass (they were not returned by search/grep), so I cannot cite their exact line numbers or fully rule out that they perform a finer-grained comparison (e.g. also hashing `vulnerableCode`) before applying the `(filePath, category)` `prompted` set. The explicit in-code comment on the write path, however, states the dedup semantics are `(filePath, category)`-based specifically to avoid "the same finding accumulating as new," which strongly suggests the read-side matching intentionally uses the same coarse key.

### Impact Explanation
If confirmed, this allows an attacker who can influence ordinary repository edits/commits (no special privileges) to get a dangerous change — e.g., a maliciously modified secret, a new command-injection sink, or an altered dangerous shell invocation — pushed without triggering the security-guidance `asyncRewake` warning, because an earlier, unrelated (and possibly intentionally seeded) finding of the same category in the same file already exists in `previous_findings`. Since the security-guidance hook is one of the layers meant to catch dangerous commands/code before they're accepted into the workflow, silently suppressing it lets dangerous local actions proceed unflagged — matching "Unauthorized local command execution that bypasses Claude Code approval or deny controls."

### Likelihood Explanation
Feasibility depends on: (1) the attacker being able to get two findings of the same category attributed to the same file across the session (achievable simply by editing/committing normal code that trips the pattern/LLM reviewer twice), and (2) `_finding_keys`/`_dedup_against_state` genuinely using the coarse `(filePath, category)` key as implied by the write-path comment. This is a realistic, repeatable scenario in normal development flow (e.g., a file with a known/accepted low-risk finding, followed by a real regression in the same category), not a contrived edge case — but it requires confirming the exact matching logic in `_dedup_against_state`/`_finding_keys`, which I could not fully verify in this session.

### Recommendation
Change the dedup key used by `_dedup_against_state`/`_finding_keys` (and the `previous_findings` `seen` set) to include a content-derived discriminator (e.g., a normalized hash of the vulnerable code block, or the pattern/rule ID plus a line-range fingerprint) rather than the bare `(filePath, category)` tuple, so that a new instance of the same category in the same file is only suppressed when it is substantively the same finding, not merely categorically similar.

### Proof of Concept
Integration test plan against `security_reminder_hook.py`:
1. Set up a temp git repo; simulate a session where a first commit introduces a low-severity finding of category `C` in file `F` and let `handle_commit_review_posttooluse`/`handle_stop_hook` run so `previous_findings` in session state contains `{"filePath": F, "category": C, "vulnerableCode": "<low-risk snippet>"}`.
2. Push that commit — `handle_push_sweep_posttooluse` reviews and marks `F`'s finding reviewed as expected.
3. Introduce a second commit that replaces the code in `F` with a genuinely dangerous instance of the same category `C` (e.g., a real hardcoded credential or an injectable shell command), and push it.
4. Assert that `handle_push_sweep_posttooluse` calls `_dedup_against_state` with `prompted` containing `(F, C)`, and check whether the new dangerous finding is incorrectly filtered out of `new_vulns` (test should currently FAIL if the vulnerability is a true regression, confirming the bypass) — expected/fixed behavior: `new_vulns` should still contain the new finding, `sys.exit(2)` should fire with the finding printed to stderr, and `rewake_summary` should be non-empty.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1625-1643)
```python
    new_vulns, n_deduped = _dedup_against_state(
        session_id, vulns or [], prompted=_finding_keys(previous_findings)
    )

    # Metrics — keep within the 10-key cap; agentic sub-metrics are dropped
    # here in favour of the push-sweep funnel keys (telemetry can join on session_id
    # to the per-commit fires for agentic detail). rewake_summary must ride
    # this line (CC reads only the first {-prefixed stdout line); it's a
    # no-op when new_vulns is empty since we exit 0 below.
    emit_metrics({
        **_base, "pushed": len(push_range), "unreviewed": len(tail),
        "prefix_advanced": prefix_advanced, "vulns_found": len(new_vulns),
        "files_reviewed": len(diff_files), "review_ms": review_ms,
        **({"deduped": n_deduped} if n_deduped else {}),
    }, rewake_summary=_format_vulns_summary(new_vulns, prefix="Push security review found"))

    if not new_vulns:
        debug_log("Push sweep: no new findings")
        sys.exit(0)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1899-1911)
```python
            # Re-read under lock — the commit-review PostToolUse hook may have
            # appended findings since consume_stop_state snapshotted.
            # Dedupe on (filePath, category) — vulnerableCode includes diff
            # context lines that drift between fires, so byte-identical
            # matching let the same finding accumulate as "new" each fire.
            existing = [f for f in state.get("previous_findings", []) if isinstance(f, dict)]
            seen = {(f.get("filePath", ""), f.get("category", "")) for f in existing}
            for f in finding_snapshots:
                key = (f["filePath"], f["category"])
                if key not in seen:
                    seen.add(key)
                    existing.append(f)
            state["previous_findings"] = existing
```
