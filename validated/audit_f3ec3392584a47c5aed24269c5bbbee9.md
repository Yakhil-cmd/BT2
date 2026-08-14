### Title
Diff byte-cap truncation in `build_investigate_prompt` can silently omit attacker-padded dangerous files from the LLM security review - (File: `plugins/security-guidance/hooks/review_api.py`)

### Summary
`build_investigate_prompt` builds the Stage-1 "investigate" prompt for the agentic security reviewer by concatenating capped diff content produced by `cap_diff_for_prompt`. That capping function enforces a per-file byte cap (`DIFF_PER_FILE_BYTES`, default 80,000) and a *global* byte cap (`DIFF_TOTAL_BYTES`, default 400,000) across all files in the diff, and once the global budget is exhausted it silently replaces the remainder of a file's content with `"[omitted by security-guidance: total diff byte cap reached]"`. Because file order and sizes inside a diff are fully attacker-controlled (an unprivileged contributor authoring the diff/PR content), an attacker can pad earlier files (alphabetically or otherwise ordered ahead of the real payload) to exhaust the 400 KB budget before the actually dangerous file is serialized, causing the reviewer to never see the vulnerable code at all.

### Finding Description
`build_investigate_prompt` (`plugins/security-guidance/hooks/review_api.py:156-176`) takes `diff_files: list[tuple[str, str]]` — attacker-controlled paths and diff content — and calls `cap_diff_for_prompt(diff_files)` (`review_api.py:31-64`) before joining the result into the prompt text with no further validation:

```
capped, _ = cap_diff_for_prompt(diff_files)
diff_text = "\n\n".join(f"=== DIFF: {fp} ===\n{content}" for fp, content in capped)
```

`cap_diff_for_prompt` iterates `files` in the order given, accumulating a running `total` byte count. Once `total` reaches `DIFF_TOTAL_BYTES`, every subsequent file's diff content is replaced wholesale with a placeholder string (`review_api.py:49-55`), and a file whose content only partially fits is truncated mid-content (`review_api.py:56-62`). There is no signal to the caller identifying *which* files were dropped by name/severity, and `build_investigate_prompt` does not re-sort files by risk before capping — it trusts whatever order `diff_files` arrives in.

Because the function operates purely on the `(path, content)` list supplied by the caller, and diff/file order and size are attacker-controlled content of a normal commit/PR (no maintainer/admin/credential assumption needed), an attacker can craft a change set where several large-but-benign files (e.g., vendored assets, generated fixtures, padded comments) are ordered ahead of the file containing the actual dangerous change, pushing the dangerous file's content past the 400 KB global cap. The dangerous file's diff is then replaced with the omission placeholder before ever reaching `AGENTIC_INVESTIGATE_SYSTEM`/the LLM, meaning the review model is deprived of the exact "+ lines" it is instructed to scan — the tool believes it reviewed the change, but the change was structurally erased from its input. This directly violates the intended invariant that prompt assembly must not let untrusted repo content suppress review of dangerous changes.

### Impact Explanation
This is a logic-level bypass of a security control: the automated diff reviewer (Stage-1 investigate → self-refute pipeline) is the mechanism intended to catch dangerous commits before they land or before a Stop-hook warning fires. An attacker who controls diff content can deterministically make the pipeline "review" a payload while the actual vulnerable hunk is never presented to the model, defeating the guard without needing any prompt-injection wording — it is a pure byte-budget starvation attack on `cap_diff_for_prompt`/`build_investigate_prompt`. This matches "Logic-level service disruption caused by bypassing a required guard" since the reviewer silently returns clean/incomplete results for a change that does contain a dangerous pattern.

### Likelihood Explanation
Fully reachable by an unprivileged actor who can only submit ordinary diff/commit content (a PR, a set of edited files, or content reaching the agentic Stop-hook review). No maintainer/admin rights, leaked credentials, or social engineering are required — padding files or choosing filenames that sort ahead of the target is trivial and repeatable. The only unknown is whether every call site of `agentic_review`/`build_investigate_prompt` first applies risk-based re-ordering (e.g., `_prioritize_diff_files` in `gitutil.py`, which the Stop-hook path in `security_reminder_hook.py` uses only when file *count* exceeds `MAX_DIFF_FILES`); that prioritization is by file count, not cumulative byte size, so even a small number of large files can still exhaust the total-byte cap while staying under the file-count threshold, and `review_api.py`'s own docstring states the module is intended to be imported directly by "external agentic harnesses" with no such pre-sorting guarantee.

### Recommendation
- In `cap_diff_for_prompt`, sort or prioritize files by security-risk signal (path heuristics, presence of `+`/`-` hunks in code file extensions vs. data/asset files) before applying the total-byte budget, so budget-starvation cannot displace a risk-relevant file.
- When a file is fully or partially omitted due to the byte cap, surface that fact structurally (e.g., a `dropped_files: list[str]` return value) so the caller/hook can flag "review incomplete" rather than silently treating the run as a clean pass.
- Consider capping per-file bytes more conservatively relative to the total budget count of files (proportional allocation) instead of first-come-first-served, to prevent early files from starving later ones regardless of order.

### Proof of Concept
Unit test against `plugins/security-guidance/hooks/review_api.py`:
```python
from review_api import build_investigate_prompt, DIFF_TOTAL_BYTES

def test_dangerous_file_survives_total_byte_cap():
    padding = "x" * (DIFF_TOTAL_BYTES - 100)   # attacker-controlled benign filler
    dangerous_marker = "DANGEROUS_SINK_MARKER_eval(user_input)"
    diff_files = [
        ("aaa_padding_file.txt", padding),           # sorts/arrives before target
        ("zzz_actual_vuln.py", f"+{dangerous_marker}"),
    ]
    prompt = build_investigate_prompt(["aaa_padding_file.txt", "zzz_actual_vuln.py"], diff_files)
    assert dangerous_marker in prompt, (
        "dangerous diff content was dropped by the total-byte cap; "
        "the review model never saw the vulnerable line"
    )
```
Expected today: assertion fails — `zzz_actual_vuln.py`'s content is replaced by the `"[omitted by security-guidance: total diff byte cap reached]"` placeholder, demonstrating that attacker-controlled padding suppresses review of the dangerous file. [1](#0-0) [2](#0-1)

### Citations

**File:** plugins/security-guidance/hooks/review_api.py (L31-64)
```python
def cap_diff_for_prompt(
    files: list[tuple[str, str]],
) -> tuple[list[tuple[str, str]], int]:
    """Cap per-file and total diff bytes; return (capped_files, bytes_dropped).

    Truncation markers are written inside the content so the reviewer
    knows the file is incomplete.
    """
    out: list[tuple[str, str]] = []
    dropped = 0
    total = 0
    for fp, content in files:
        if len(content) > DIFF_PER_FILE_BYTES:
            dropped += len(content) - DIFF_PER_FILE_BYTES
            content = (
                content[:DIFF_PER_FILE_BYTES]
                + "\n... [truncated by security-guidance: file exceeds per-file byte cap]"
            )
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
