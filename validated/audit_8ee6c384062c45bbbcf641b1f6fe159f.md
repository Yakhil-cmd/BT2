### Title
Coarse `(filePath, category)` dedup key lets a malicious commit "poison" the security-review state to silently suppress a concurrently-introduced, genuinely different vulnerability from ever being reported - (File: plugins/security-guidance/hooks/security_reminder_hook.py)

### Summary
The `security-guidance` plugin's commit-review and Stop hooks track already-reported findings in a shared, session-scoped JSON state file (`previous_findings`) so that concurrently-running review passes ("asyncRewake" hooks) don't duplicate work or double-warn the user. The dedup key used for this tracking is the coarse pair `(filePath, category)` rather than the actual vulnerable code/line, and a hard, unconditional drop (`_dedup_against_state`) is applied to any finding whose key appears in this shared state — exactly analogous to the Venus `pendingScoreUpdates` counter that an attacker could decrement out from under legitimate future updates. A user who can trigger two overlapping review passes over the same file can pre-seed the `(filePath, category)` key with an unrelated/trivial finding so that a real, more severe vulnerability of the same category introduced in a concurrent commit is deduped away and never surfaced to the user.

### Finding Description
`_dedup_against_state` re-reads `previous_findings` from the locked state file and drops any candidate vuln whose `(filePath, category)` key is present, restricted only to the "race delta" (entries not already known to the LLM that ran the current review): [1](#0-0) 

This is invoked from both the commit-review PostToolUse handler and the Stop hook handler, each of which persists the current turn's findings into the same shared `previous_findings` list keyed by `(filePath, category)`: [2](#0-1) [3](#0-2) 

The `_record_fire` comment explicitly documents the design tradeoff: dedup is done on `(filePath, category)` and not on the exact vulnerable code snippet, because "vulnerableCode includes diff context lines that drift between fires" — i.e., the designers deliberately chose a coarse key that does not distinguish between two different vulnerability instances of the same category in the same file: [4](#0-3) 

Both the commit-review and Stop-hook reviews run as background ("asyncRewake") LLM passes that can take many seconds (or, for the agentic path, up to the `SG_AGENTIC_RACE_DELAY_S` window plus tool-call budget), and the code explicitly acknowledges they can run concurrently over the same session state: [5](#0-4) 

Because the hard drop in `_dedup_against_state` fires whenever the `(filePath, category)` key is present in the *fresh* state — regardless of whether it was written by a truly identical finding or an unrelated one — a user can deliberately race two commits/edits touching the same file so that one review pass records a decoy finding of category `X` for `file.py` while a second, concurrent pass is mid-flight analyzing a genuinely different (and more dangerous) instance of category `X` in the same `file.py`. When the second pass finishes, its real finding is silently dropped as a "duplicate" via the race-delta filter, and no warning is ever surfaced to the user or committer.

### Impact Explanation
This lets a user (or malicious code being committed) bypass the automated security-review guardrail that this plugin is specifically designed to enforce, allowing a real, previously-unflagged vulnerability to be committed without any warning ever being shown — the direct security-relevant analog of the Venus bug's "freeze my unfavorable state so it never gets corrected" pattern, here applied to a code/vulnerability-disclosure trust boundary instead of a token-reward boundary. The blast radius is limited to the local review session/state file the plugin maintains and does not grant any new capability by itself, but it does neutralize an explicit safety control (silent, no error, no `NoScoreUpdatesRequired()`-style visible failure) and can facilitate real vulnerable/malicious code slipping through code review undetected.

### Likelihood Explanation
Exploitation requires deliberately engineering a race between two concurrent review passes over the same file — e.g., firing two `git commit`s (or a commit plus a Stop-hook fire) in quick succession while the agentic reviewer's tool-call loop for the first is still running, and ensuring both passes match the same `(filePath, category)` pair. This is plausible for an attacker with normal repo-commit privileges and knowledge of the plugin's behavior (confirmed by the code's own comments acknowledging this concurrency), but it does require some timing precision, so likelihood is moderate rather than trivial.

### Recommendation
Change the dedup/suppression key from `(filePath, category)` to something that uniquely identifies the specific vulnerability instance (e.g., a normalized hash of the vulnerable code span, or `(filePath, category, line-range/content-hash)`), so that a decoy finding in one category cannot suppress an unrelated, concurrently-discovered finding of the same category in the same file. If a coarse key must be kept for performance, only use it to *deduplicate literal re-reports of the exact same finding*, and never let it hard-drop a finding produced by a different, concurrently-running review pass without at least logging/telemetry so the suppression is auditable.

### Proof of Concept
1. In a repo with the `security-guidance` plugin's commit-review hook enabled, start a commit that touches `foo.py` and includes a trivial/benign pattern that the LLM reviewer would classify under category `"SQL Injection"` (triggers `agentic_review`/`analyze_code_security`, which is slow — tens of seconds to minutes).
2. Before that review completes, make a second, fast commit (or edit) to `foo.py` that introduces a genuinely exploitable, unrelated SQL-injection sink also classified as category `"SQL Injection"`.
3. If the second commit's review pass finishes and calls `_dedup_against_state` while the first pass has already written `(foo.py, "SQL Injection")` into `previous_findings` (state written under `with_locked_state`), the second, real finding is dropped as a race-delta duplicate and no guidance/warning is ever emitted to the user, per the logic in `_dedup_against_state` (`plugins/security-guidance/hooks/llm.py:685-707`) and `_record_fire` (`plugins/security-guidance/hooks/security_reminder_hook.py:1896-1916`).

### Citations

**File:** plugins/security-guidance/hooks/llm.py (L685-707)
```python
def _dedup_against_state(session_id: str, vulns: List[Dict[str, Any]],
                         prompted: set) -> Tuple[List[Dict[str, Any]], int]:
    """Drop vulns that a CONCURRENT asyncRewake hook wrote to
    previous_findings while this hook's LLM was running.

    `prompted` is the (filePath, category) set the LLM was already told about
    via the prev_section prompt block. The LLM is instructed to only re-flag
    those if the attempted fix is incomplete, so a re-flag of a `prompted`
    entry is an intentional "fix didn't work" verdict and MUST pass through.
    We therefore re-read state now and only filter the race delta —
    (seen_now − prompted) — i.e. findings the LLM was never told about
    because they were written mid-review by the other hook.
    Returns (surviving_vulns, n_dropped).
    """
    if not vulns:
        return vulns, 0
    fresh = with_locked_state(
        session_id, lambda s: list(s.get("previous_findings", []))
    ) or []
    race_delta = _finding_keys(fresh) - prompted
    kept = [v for v in vulns
            if (v.get("filePath", ""), v.get("category", "")) not in race_delta]
    return kept, len(vulns) - len(kept)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L832-853)
```python
def _agentic_review_with_race(
    repo_root: str,
    diff_files: List[Tuple[str, str]],
    rel_touched: List[str],
    previous_findings: List[Dict[str, Any]],
) -> Tuple[Optional[str], List[Dict[str, Any]], Dict[str, Any]]:
    """Race the agentic reviewer against a delayed single-shot fallback.

    Agentic starts at t=0. After SG_AGENTIC_RACE_DELAY_S (default 180s), the
    single-shot diff reviewer also starts. Whichever finishes first wins. If
    agentic finishes before the delay elapses, the fallback never runs.

    Metrics added:
      race_winner    : 1 = agentic won, 2 = fallback won (CC accepts only
                       bool/finite-number metric values — strings would discard the dict)
      race_delay_s   : the configured delay
      race_started   : 1 if the fallback was actually launched, else 0

    Only the commit-review handler calls this — external harnesses invoke
    agentic_review() directly and are unaffected. SG_AGENTIC_NO_RACE=1
    disables the race for any other caller that wants pure agentic.
    """
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1319-1337)
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

    # Record new findings into shared state. Key on (filePath, category) —
    # vulnerableCode bytes drift between fires (diff context lines shift) so
    # matching on it under-dedupes; this aligns with Stop's _record_fire.
    finding_snapshots = [
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1896-1916)
```python
        def _record_fire(state):
            state["stop_hook_fire_count"] = fire_index
            state["stop_hook_fire_count_ts"] = _time.time()
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
            state["previous_findings_ts"] = _time.time()
            if new_sha:
                state["baseline_sha"] = new_sha
                state["untracked_at_baseline"] = new_untracked_baseline
        with_locked_state(session_id, _record_fire)
```
