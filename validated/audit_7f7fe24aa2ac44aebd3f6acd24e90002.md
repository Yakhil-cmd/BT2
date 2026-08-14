### Title
Front-byte diff truncation in `cap_diff_for_prompt` lets attacker-padded diffs push vulnerable hunks past the review boundary - (File: `plugins/security-guidance/hooks/review_api.py`)

### Summary
`cap_diff_for_prompt` (and its duplicate `_cap_files_for_prompt` in `llm.py`) truncates each file's diff content by taking a fixed prefix of bytes (`content[:DIFF_PER_FILE_BYTES]`) and, once the total byte budget is exhausted, replaces entire remaining files' content with an `[omitted by security-guidance...]` marker. Because this truncation is purely positional (front-preserving, order-preserving) and not risk-aware, an attacker who controls the diff content (e.g. the coding agent itself, or content injected into files it edits) can pad the beginning of a diff/file list with low-risk filler so the actual dangerous hunk lands past the per-file or total cap and is silently dropped before the review LLM ever sees it.

### Finding Description
`cap_diff_for_prompt` in `plugins/security-guidance/hooks/review_api.py` truncates per-file content strictly by taking the leading bytes: `content = content[:DIFF_PER_FILE_BYTES] + "\n... [truncated...]"` [1](#0-0)  and, once the running `total` exceeds `DIFF_TOTAL_BYTES`, appends subsequent files with content fully replaced by `"[omitted by security-guidance: total diff byte cap reached]"` while still keeping the file path visible [2](#0-1) . The identical logic exists in `llm.py`'s `_cap_files_for_prompt`, used by the Stop-hook single-shot review path [3](#0-2) .

This function is invoked directly in the agentic investigate-prompt builder, `build_investigate_prompt`, which calls `cap_diff_for_prompt(diff_files)` before constructing the diff text sent to the review model [4](#0-3) , and the same pattern is used by `analyze_code_security`/`agentic_review` via `_cap_files_for_prompt` in the Stop-hook and commit-review flows [5](#0-4) [6](#0-5) .

The only prioritization that exists (`_prioritize_diff_files` in `gitutil.py`) reorders *entire files* by risk score, but only engages when the file count exceeds `MAX_DIFF_FILES` [7](#0-6) ; it does nothing to protect against a single file whose own diff content exceeds `DIFF_PER_FILE_BYTES` (default 80,000 bytes) or a small set of files whose combined content exceeds `DIFF_TOTAL_BYTES` (default 400,000 bytes). Within one file's diff (or within the concatenation of files up to the byte caps), there is no hunk-level risk ranking — the cap is applied by raw prefix.

Exploit flow: an attacker-controlled turn (i.e., the coding agent under adversarial influence, or a large generated/boilerplate change) can place a large block of innocuous content (comments, boilerplate, generated code, padding lines) before the actually dangerous `+` lines in the same file, or add several large low-risk files ahead of the truly dangerous file in diff order. Because `git diff` output preserves file/hunk order and the truncation is a straight byte-offset cut, the dangerous hunk is pushed past `DIFF_PER_FILE_BYTES` (dropped with a generic truncation marker) or past `DIFF_TOTAL_BYTES` (dropped entirely, replaced with an "omitted" placeholder). The review model — whether the single-shot Stop-hook reviewer (`analyze_code_security`) or the agentic investigate stage (`build_investigate_prompt`/`agentic_review`) — never receives the dangerous lines and therefore cannot flag them, so the security-control decision (exit code 2 blocking / continue) is made on an incomplete view of the change.

No existing check compensates for this: `_prioritize_diff_files` operates at file granularity and only when file count is large; `cap_diff_for_prompt`/`_cap_files_for_prompt` have no line/hunk-level risk awareness at all.

### Impact Explanation
This breaks the reviewed invariant that truncation must not consistently drop the high-risk lines the user expects reviewed. Since the Stop-hook and commit-review flows gate on the LLM's findings (`sys.exit(2)` only fires when `concrete_guidance`/vulns are non-empty) [8](#0-7) , a dangerous change whose vulnerable lines are truncated away is silently approved. This is a Security-control bypass that routes around the plugin's blocking/review boundary without any error or alert distinguishable from a normal clean review, matching the "silently disables or routes around blocking, review, or permission boundaries" impact category.

### Likelihood Explanation
The precondition is simply generating (or having the diff contain) enough low-risk filler content ahead of the dangerous change within the existing per-file/total byte budgets (80KB/400KB by default, both operator-configurable but defaulting to these values) — trivially achievable with routine large refactors, generated code, vendored boilerplate, or deliberately padded comments, all of which are ordinary repository-controlled content. No credentials, admin rights, or social engineering are required, and the behavior is fully deterministic/reproducible given the same diff ordering and sizes.

### Recommendation
Make truncation risk-aware instead of strictly front-preserving: within `cap_diff_for_prompt`/`_cap_files_for_prompt`, prioritize retaining diff hunks that contain `+`/`-` change lines (especially ones matching security-risk path/content heuristics already used by `_prioritize_diff_files`) over unchanged context or low-risk boilerplate, and consider capping per-hunk rather than raw byte-prefix per file. At minimum, log/emit a metric (or refuse silent pass) whenever truncation drops any `+` line from a file, so blocking decisions are not made against an incomplete diff, and surface to the caller which specific hunks were dropped rather than a single generic marker.

### Proof of Concept
Unit test plan (extends existing `review_api.py` test surface):
1. Construct `files = [("app/danger.py", "# filler\n" * N + "+os.system(user_input)\n")]` where the filler makes the file exceed `DIFF_PER_FILE_BYTES` before the dangerous `+` line.
2. Call `cap_diff_for_prompt(files)` and assert that the returned content for `app/danger.py` does NOT contain `os.system(user_input)` — demonstrating the dangerous line was truncated away.
3. Construct a total-byte-cap variant: `files = [("pad1.py", "x" * DIFF_TOTAL_BYTES), ("danger.py", "+os.system(user_input)\n")]`; call `cap_diff_for_prompt(files)`; assert `danger.py`'s returned content equals the omission marker `"[omitted by security-guidance: total diff byte cap reached]"` and does not contain the dangerous line.
4. Feed the capped output into `build_investigate_prompt`/`analyze_code_security` and assert the resulting prompt string omits the dangerous line, confirming the review model never receives it — i.e., the "dangerous file or path" is present (filename shown) but the actual risky content is not "correctly anchored" for review, violating the stated invariant.

### Citations

**File:** plugins/security-guidance/hooks/review_api.py (L42-48)
```python
    for fp, content in files:
        if len(content) > DIFF_PER_FILE_BYTES:
            dropped += len(content) - DIFF_PER_FILE_BYTES
            content = (
                content[:DIFF_PER_FILE_BYTES]
                + "\n... [truncated by security-guidance: file exceeds per-file byte cap]"
            )
```

**File:** plugins/security-guidance/hooks/review_api.py (L49-55)
```python
        room = DIFF_TOTAL_BYTES - total
        if room <= 0:
            dropped += len(content)
            out.append(
                (fp, "[omitted by security-guidance: total diff byte cap reached]")
            )
            continue
```

**File:** plugins/security-guidance/hooks/review_api.py (L156-176)
```python
def build_investigate_prompt(
    touched_paths: list[str],
    diff_files: list[tuple[str, str]],
    *,
    context_note: str = "",
) -> str:
    capped, _ = cap_diff_for_prompt(diff_files)
    diff_text = "\n\n".join(
        f"=== DIFF: {fp} ===\n{content}" for fp, content in capped
    )
    return (
        "Review this change for security vulnerabilities.\n\n"
        "Changed files (you may Read these and any other file in the repo):\n"
        + "\n".join(f"  - {p}" for p in touched_paths[:50])
        + context_note
        + "\n\nUnified diff (only + lines are new):\n\n"
        + diff_text
        + extensibility.guidance_block()
        + "\n\nInvestigate per the method in your instructions, then return "
        "the findings list."
    )
```

**File:** plugins/security-guidance/hooks/llm.py (L158-183)
```python
def _cap_files_for_prompt(files):
    """Cap per-file and total content bytes before they're packed into the
    review prompt. Returns the capped (path, content) list. Sets module-level
    _last_review_truncated_bytes to the number of bytes dropped (0 if none) so
    the Stop hook can emit a `diff_truncated` metric. Truncation markers are
    written INSIDE the content so the reviewer knows the file is incomplete.
    """
    global _last_review_truncated_bytes
    _last_review_truncated_bytes = 0
    out = []
    total = 0
    for fp, content in files:
        if len(content) > DIFF_PER_FILE_BYTES:
            _last_review_truncated_bytes += len(content) - DIFF_PER_FILE_BYTES
            content = content[:DIFF_PER_FILE_BYTES] + "\n... [truncated by security-guidance: file exceeds per-file byte cap]"
        room = DIFF_TOTAL_BYTES - total
        if room <= 0:
            _last_review_truncated_bytes += len(content)
            out.append((fp, "[omitted by security-guidance: total diff byte cap reached]"))
            continue
        if len(content) > room:
            _last_review_truncated_bytes += len(content) - room
            content = content[:room] + "\n... [truncated by security-guidance: total diff byte cap reached]"
        total += len(content)
        out.append((fp, content))
    return out
```

**File:** plugins/security-guidance/hooks/llm.py (L738-746)
```python
    files = _cap_files_for_prompt(files)

    # Build the files section
    files_section = []
    for fp, content in files:
        ext = os.path.splitext(fp)[1].lower()
        label = "DIFF" if is_diff else "FILE"
        files_section.append(f"=== {label}: {fp} ===\n```{ext.lstrip('.')}\n{content}\n```")
    files_text = "\n\n".join(files_section)
```

**File:** plugins/security-guidance/hooks/llm.py (L1139-1141)
```python
    diff_text = "\n\n".join(
        f"=== DIFF: {fp} ===\n{content}" for fp, content in _cap_files_for_prompt(diff_files)
    )
```

**File:** plugins/security-guidance/hooks/gitutil.py (L512-525)
```python
def _prioritize_diff_files(diff_files, cap):
    """When `diff_files` exceeds `cap`, return the top-`cap` by security
    relevance plus the count dropped. Otherwise return (diff_files, 0).

    Score = (risk_tokens_in_path, not_low_priority, added_lines). The
    added-lines proxy is `content.count('\\n+')` which counts diff additions
    cheaply without re-parsing hunks. This is a heuristic, not a guarantee —
    the goal is to review the likely-dangerous subset of an over-cap diff
    instead of reviewing nothing. Diffs that exceed the cap are typically
    large multi-file scaffolds, and the cross-file source→sink vulnerabilities
    in them concentrate in a handful of api/client/route files.
    """
    if len(diff_files) <= cap:
        return diff_files, 0
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1943-1947)
```python
        }, rewake_summary=_format_vulns_summary(vulns))

        # Exit code 2 with stderr forces Claude to continue and fix
        sys.stderr.write(PROVENANCE_BANNER + "\n\n" + concrete_guidance + CONTINUATION_SUFFIX + "\n")
        sys.exit(2)
```
