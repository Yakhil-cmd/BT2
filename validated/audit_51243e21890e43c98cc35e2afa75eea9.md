### Title
Coarse `(filePath, category)` dedup key in `handle_stop_hook` silently suppresses new dangerous findings that share a prior category in the same file - (File: `plugins/security-guidance/hooks/security_reminder_hook.py`)

### Summary
`handle_stop_hook` records and deduplicates LLM-flagged vulnerabilities by the tuple `(filePath, category)` instead of by the actual vulnerable content. Once a finding for a given file and category (e.g. "Command Injection") has been surfaced once, any subsequent turn that reintroduces a *different* dangerous snippet in the same file under the same LLM-assigned category is silently dropped from `vulns` before the exit(2)/rewake path runs, so no warning or `stop_hook` block fires for the new dangerous code.

### Finding Description
In `handle_stop_hook`, after `analyze_code_security` returns `vulns` for the diff since the last baseline, the hook calls `_dedup_against_state(session_id, vulns, prompted=_finding_keys(previous_findings))` and, on any surviving `vulns`, records them via `_record_fire`: [1](#0-0) 

The comment explicitly documents the design choice: findings are keyed on `(filePath, category)`, not on `vulnerableCode`, because diff-context bytes drift between fires: [2](#0-1) 

Because the key omits the actual vulnerable code, once one finding of category `X` in file `F` has been recorded into `previous_findings` (which persists for up to `PREVIOUS_FINDINGS_TTL_SEC` = 3600s, per `diffstate.py`): [3](#0-2) 

any subsequent Stop-hook fire (across retries, amends, or additional edits in the same session/window) that reintroduces a *new and different* dangerous snippet of the same LLM-assigned category in the same file will be treated as an already-seen finding and dropped by `_dedup_against_state` before `concrete_guidance`/`exit(2)` is emitted. The commit-review path uses the identical keying for the same stated reason: [4](#0-3) 

`_dedup_against_state`/`_finding_keys` are defined in `llm.py`; their usage confirms the same `(filePath, category)` granularity is applied consistently across the Stop hook and commit-review hook, so the gap is not file-local to one entrypoint. LLM-assigned categories are coarse (e.g., "Command Injection", "SQL Injection", "Path Traversal"), so two genuinely distinct dangerous commands/edits in the same file are very likely to collide under the same category label, especially since diff content is fully attacker/agent-controlled (an untrusted repo can steer Claude, via injected instructions, comments, or issue/PR text, into repeatedly modifying the same file with new dangerous payloads of a similar class).

### Impact Explanation
Once the first finding for a `(file, category)` pair has fired and been recorded, an attacker who can influence subsequent edits to that same file (via prompt injection embedded in repository content, issue/PR text, or automation loops that keep editing the same file) can introduce new, different dangerous code of the same category and have it pass through `handle_stop_hook` (and the equivalent commit-review path) with `vulns_found: 0`/no `exit(2)`, and no rewake warning — up to the `PREVIOUS_FINDINGS_TTL_SEC` window (1 hour). This lets a dangerous command/edit execute or land in a commit without ever being surfaced to the user for approval, matching "Unauthorized local command execution that bypasses Claude Code approval or deny controls."

### Likelihood Explanation
No special privileges are required beyond normal edit/commit flows already reachable by an agent working in a repository with attacker-influenced content. The only precondition is that two distinct dangerous edits to the same file get bucketed under the same LLM category — plausible given the limited category vocabulary used by `analyze_code_security`. The bug is deterministic once the category collision occurs (the code explicitly keys on `(filePath, category)` with no content check), making it reliably reproducible within a session or within the 3600s TTL window.

### Recommendation
Change the dedup/record key to include a stronger signature of the actual vulnerable content (e.g., a normalized hash of `vulnerableCode` plus line-range, rather than raw byte match which was the original problem) so that dedup only suppresses re-flagging of the *same* underlying issue, not any new issue that merely shares a file and category. Alternatively, key on `(filePath, category, normalized_snippet_hash)` and keep a much shorter TTL for category-level re-surfacing when the file has changed again since the last recorded finding.

### Proof of Concept
Integration test plan:
1. Start a session, set `baseline_sha` via UPS-equivalent state.
2. Turn 1: agent edits `foo.py` introducing vulnerable code A that `analyze_code_security` classifies as category `"Command Injection"`. Call `handle_stop_hook`; assert `exit(2)` is raised and `previous_findings` now contains `{"filePath": "foo.py", "category": "Command Injection", ...A...}` (via `_record_fire`).
3. Turn 2 (simulate a "fix" that is not actually a fix, or a follow-up edit): agent edits `foo.py` again, replacing the code with a *different* dangerous snippet B (e.g., a different unsanitized `subprocess.call` on user input) still classified as `"Command Injection"`.
4. Call `handle_stop_hook` again within the `PREVIOUS_FINDINGS_TTL_SEC` window; mock/stub `analyze_code_security` to return vuln B with `filePath="foo.py"`, `category="Command Injection"`, and `vulnerableCode` containing the new payload.
5. Assert that `_dedup_against_state` drops vuln B (because `(foo.py, "Command Injection")` is already in `prompted`), that `handle_stop_hook` exits with `0` (not `2`), and that no stderr guidance/rewake is emitted — demonstrating the new dangerous code B was never surfaced.

### Citations

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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1870-1911)
```python
    # Late dedup: drop only what a concurrent commit-review wrote while our
    # LLM ran. Anything already in `previous_findings` (the consume_stop_state
    # snapshot) that the LLM re-flagged is an intentional "fix incomplete"
    # verdict and passes through.
    if vulns:
        vulns, n_deduped = _dedup_against_state(
            session_id, vulns, prompted=_finding_keys(previous_findings)
        )
        if n_deduped and not vulns:
            debug_log("Stop hook: all findings already delivered by commit-review")
            _skip(35, deduped=n_deduped, review_ms=review_ms)
        concrete_guidance = _format_vulns_guidance(vulns)

    if concrete_guidance:
        finding_snapshots = [
            {
                "filePath": v.get("filePath", ""),
                "category": v.get("category", "Unknown"),
                "vulnerableCode": v.get("vulnerableCode", ""),
            }
            for v in vulns
        ]
        # Update baseline so next stop hook iteration only sees new changes
        new_sha = capture_git_baseline(cwd)
        new_untracked_baseline = _list_untracked(cwd) if new_sha else None

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
