### Title
Byte-prefix diff truncation in `cap_diff_for_prompt` can silently drop attacker-placed malicious lines from the security review prompt - (File: plugins/security-guidance/hooks/review_api.py)

### Summary
`cap_diff_for_prompt` truncates each file's diff to a fixed byte prefix (`DIFF_PER_FILE_BYTES`) and allocates the remaining total-byte budget (`DIFF_TOTAL_BYTES`) to files strictly in the order they are handed in, without any risk-based prioritization. An attacker who controls the diff content being reviewed (e.g. a large PR, a machine-generated commit, or an agent-produced change influenced by injected repo content) can pad the beginning of a file's diff — or add several large decoy files earlier in the list — to push the actually dangerous lines past the cutoff, causing them to be replaced with a `"[truncated ...]"`/`"[omitted ...]"` marker before the reviewer model ever sees them.

### Finding Description
`cap_diff_for_prompt` (plugins/security-guidance/hooks/review_api.py:31-64) iterates `files` in the given order and:
1. Per-file cap: `content[:DIFF_PER_FILE_BYTES]` keeps only the *first* 80,000 bytes of a file's diff, discarding everything after that offset. [1](#0-0) 
2. Total cap: `room = DIFF_TOTAL_BYTES - total` is computed sequentially; once the running total exceeds 400,000 bytes, any subsequent file in the list is entirely replaced with `"[omitted by security-guidance: total diff byte cap reached]"`. [2](#0-1) 

Both caps operate purely on byte position/order, not on the semantic risk of the content. This is invoked from `build_investigate_prompt`, which feeds the capped diff directly into the Stage-1 investigate prompt sent to the review model — the model literally cannot see bytes that were dropped. [3](#0-2) 

Exploit flow: an attacker who can influence the content of the diff being reviewed (e.g., a large auto-generated file, vendored/minified blob, verbose banner/comment, or many benign-looking files ordered before the malicious one) can:
- Front-load a single file's diff with >80,000 bytes of innocuous filler so the actual malicious `+` lines fall after the per-file truncation point and are dropped, or
- Supply enough preceding files/content to exhaust the 400,000-byte total budget before the file containing the dangerous change is reached, causing it to be entirely `"[omitted]"`.

No mitigation exists for either case: there is no line-level risk scoring, no guarantee that the tail of a diff (where appended malicious lines often live) is preserved, and no reordering to prioritize files/hunks that match dangerous sink patterns before applying the cap.

### Impact Explanation
This breaks the stated invariant that truncation must not consistently drop the high-risk lines the user expects reviewed. Since the two-stage agentic reviewer (`AGENTIC_INVESTIGATE_SYSTEM` / `AGENTIC_REFUTE_SYSTEM`) is the security backstop surfaced to the user via `format_findings`, a dropped dangerous line means the security-guidance plugin reports a clean/incomplete result even though a real vulnerability (e.g., a backdoor, credential exfiltration, or unsafe sink) is present in the actual commit. Consequences fall under wrong-target/incomplete-scope security review: the user proceeds believing the change was reviewed, silently missing exploitable code that ships to their repository/session.

### Likelihood Explanation
The precondition is simply that the diff content reviewed be large or attacker-shaped — realistic for vendored files, generated code, base64/data blobs, or multi-file commits, none of which require any privilege beyond normal repository content. The behavior is deterministic (prefix truncation, sequential allocation) and fully reproducible with a crafted diff.

### Recommendation
Replace prefix-only truncation with content-aware capping: preserve diff hunks/lines matching high-risk sink keywords (exec/eval/subprocess, network calls, credential/env access, file writes) regardless of position, and/or keep both head and tail of an over-long file diff rather than only the head. For the total-byte cap, prioritize allocation by risk heuristics (e.g., files matching sensitive path patterns or containing sink keywords) instead of raw list order, and always guarantee at least a summary/marker with the full list of dropped file paths so the reviewer/user knows which files were not fully inspected.

### Proof of Concept
Unit test plan for `cap_diff_for_prompt`:
1. Construct `files = [("evil.py", "A"*90000 + "\nsubprocess.run(attacker_cmd, shell=True)\n")]`. Call `cap_diff_for_prompt(files)` and assert the returned content does **not** contain `"subprocess.run(attacker_cmd"` — demonstrating the dangerous line is dropped by the per-file cap.
2. Construct `files = [(f"decoy{i}.py", "x"*50000) for i in range(9)] + [("evil.py", "subprocess.run(attacker_cmd, shell=True)")]` (total > 400,000 bytes before reaching `evil.py`). Call `cap_diff_for_prompt(files)` and assert `evil.py`'s entry equals the `"[omitted by security-guidance: total diff byte cap reached]"` marker — demonstrating the dangerous file is entirely excluded from the prompt.
3. Feed the capped output into `build_investigate_prompt` and assert the resulting prompt string does not contain the string `attacker_cmd`, confirming the reviewer model never receives the dangerous content — violating the "must not consistently drop high-risk lines" invariant.

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

**File:** plugins/security-guidance/hooks/review_api.py (L49-64)
```python
        room = DIFF_TOTAL_BYTES - total
        if room <= 0:
            dropped += len(content)
            out.append(
                (fp, "[omitted by security-guidance: total diff byte cap reached]")
            )
            continue
        if len(content) > room:
            dropped += len(content) - room
            content = (
                content[:room]
                + "\n... [truncated by security-guidance: total diff byte cap reached]"
            )
        total += len(content)
        out.append((fp, content))
    return out, dropped
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
