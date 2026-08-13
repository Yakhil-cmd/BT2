### Title
Fixed 8000-byte diff truncation in `build_refute_prompt` can drop the diff evidence for a flagged vulnerability, causing the self-refute stage to wrongly classify it as pre-existing and drop it - ([File: plugins/security-guidance/hooks/review_api.py])

### Summary
`build_refute_prompt` truncates the full diff to a hardcoded `diff_text[:8000]` slice with no regard for which files/lines correspond to the candidate findings being adjudicated. Because the refute system prompt instructs the model to REFUTE any candidate whose `vulnerableCode` "does NOT appear on any + line in the DIFF block above," an attacker who controls the diff content (padding earlier files, choosing filenames that sort first, or simply submitting a change large enough to exceed 8KB across multiple touched files) can push the diff hunk containing the actual vulnerable `+` line past the 8000-character cutoff, so it is no longer visible in the refute prompt.

### Finding Description
`build_refute_prompt` (plugins/security-guidance/hooks/review_api.py, lines 210-283) builds the stage-2 self-refute prompt by embedding the full candidate list and then appending `diff_text[:8000]` — a raw byte-offset slice with no per-candidate awareness and no attempt to keep the relevant hunks in view: [1](#0-0) 

The same construct (`diff_text[:8000]`) is duplicated verbatim in the production hot path in `llm.py`'s `agentic_review`, confirming this is not merely importable-library code but the actual code that runs on every Stop-hook review: [2](#0-1) 

The refute instructions explicitly tell the model to refute a candidate as PRE-EXISTING when its cited code is absent from the DIFF block: [3](#0-2) 

`diff_text` itself is built by concatenating per-file diff blocks in the order files appear in `diff_files` (which follows git-diff ordering, i.e., largely alphabetical by path) after the earlier per-file/total caps (`DIFF_PER_FILE_BYTES`=80000, `DIFF_TOTAL_BYTES`=400000) have already been applied: [4](#0-3) 

Since those caps allow diffs far larger than 8000 bytes, any multi-file or moderately-sized single-file diff will have its tail truncated out of the refute prompt. An attacker who controls the diff (e.g., by naming files so they sort earlier, or by padding an early file with churn) can arrange for the true vulnerable `+` line to fall past byte 8000, so it is invisible to stage-2. The refute model, following its own instructions verbatim, would then have a textual basis to REFUTE the finding as "PRE-EXISTING" even though it was genuinely introduced by the diff, because the model is told to make this determination from the pasted DIFF block. While the refute agent does have Read/Grep tool access to the repo and could independently verify by reading the file, nothing in the prompt or schema forces that fallback — the refute instructions direct it to cite "DIFF block above" evidence directly, so a model that trusts the pasted block as authoritative can silently drop a real finding.

### Impact Explanation
This is a security-control bypass: it can cause the two-stage agentic reviewer to silently discard a correctly identified HIGH/CRITICAL vulnerability at the adjudication stage, without any error or user-visible signal — the Stop hook would report "no security issues found" for a diff that actually introduced one. This matches the target Immunefi impact category "Security-control bypass that silently disables or routes around blocking, review, or permission boundaries," since the review/blocking mechanism itself is what gets routed around.

### Likelihood Explanation
The precondition is simply an attacker-controlled diff exceeding ~8KB with the vulnerable hunk positioned after that offset in file-concatenation order — a very common, easily reachable condition given the actual per-file/total caps are 80KB/400KB, and file ordering is influenced by filenames the attacker (as a repo contributor whose change is being reviewed) chooses. No privilege escalation, and no special tooling is needed beyond crafting the diff/PR content; this is fully within "attacker controls diff content" as described in the target. The reduction in effectiveness is probabilistic (depends on whether the refute-stage LLM decides to Read the file directly instead of trusting the truncated DIFF block), so it is not a deterministic 100%-bypass, but it is a repeatable structural weakness in the truncation logic itself, independent of model behavior.

### Recommendation
Replace the flat `diff_text[:8000]` slice in `build_refute_prompt` with a candidate-aware selection: for each candidate, ensure the diff hunk for its `filePath` is included (e.g., by extracting only the per-file diff blocks referenced by `candidates` and truncating unrelated/off-diff-anchor files first), or clearly mark truncated sections so the model does not treat an absent citation as proof of "PRE-EXISTING," and add a "insufficient diff context — do not refute on PRE-EXISTING grounds; open the file instead" fallback instruction when a candidate's file/lines are known to have been truncated out.

### Proof of Concept
Unit test in `plugins/security-guidance/hooks/review_api.py` test suite:
1. Construct `diff_files` with two files: `aaa_padding.py` containing ~9000 bytes of benign added lines, and `zzz_vuln.py` containing a single attacker-introduced dangerous `+` line (e.g., `+ os.system(user_input)`).
2. Build `diff_text` the same way `agentic_review`/callers do (concatenate `=== DIFF: {fp} ===` blocks in file order) and pass a `candidates` list containing one candidate citing `zzz_vuln.py`'s dangerous line.
3. Call `build_refute_prompt(candidates, diff_text)` and assert that the dangerous `+ os.system(user_input)` line does NOT appear within the first 8000 characters of the returned prompt (demonstrating it is invisible to the refute model) — i.e., assert `"os.system(user_input)" not in build_refute_prompt(candidates, diff_text)[: prompt.index("DIFF:") + 8000]`.
4. Assert this violates the invariant "truncation must not consistently drop the high-risk lines the user expects to be reviewed" — the test should fail once a fix ensures candidate-relevant hunks are preserved regardless of byte offset.

### Citations

**File:** plugins/security-guidance/hooks/review_api.py (L27-64)
```python
DIFF_PER_FILE_BYTES = int(os.environ.get("DIFF_PER_FILE_BYTES", "80000"))
DIFF_TOTAL_BYTES = int(os.environ.get("DIFF_TOTAL_BYTES", "400000"))


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

**File:** plugins/security-guidance/hooks/review_api.py (L210-214)
```python
def build_refute_prompt(candidates: list[dict[str, Any]], diff_text: str) -> str:
    return (
        "You previously flagged these candidate vulnerabilities:\n\n"
        + json.dumps(candidates, indent=2)
        + "\n\nDIFF:\n" + diff_text[:8000]
```

**File:** plugins/security-guidance/hooks/review_api.py (L232-236)
```python
        "Then Read the cited file and refute with cited file:line "
        "evidence if ANY of these holds:\n"
        "- PRE-EXISTING: the cited vulnerableCode does NOT appear on "
        "any + line in the DIFF block above — it is unchanged context "
        "in a touched file. The diff did not introduce it.\n"
```

**File:** plugins/security-guidance/hooks/llm.py (L1455-1458)
```python
        refute_prompt = (
            "You previously flagged these candidate vulnerabilities:\n\n"
            + json.dumps(candidates, indent=2)
            + "\n\nDIFF:\n" + diff_text[:8000]
```
