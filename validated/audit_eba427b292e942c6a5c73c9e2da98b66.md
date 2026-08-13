### Title
Hard 8000-char truncation in `build_refute_prompt` silently drops attacker-positioned diff evidence, causing the self-refute stage to wrongly discard true findings - (File: `plugins/security-guidance/hooks/review_api.py`)

### Summary
`build_refute_prompt` truncates the diff text passed to the adversarial self-refute stage with a hard `diff_text[:8000]` slice that ignores file boundaries and inserts no truncation marker, unlike `cap_diff_for_prompt` which caps per-file/total bytes and marks truncation explicitly. Because the refute prompt instructs the model to REFUTE any candidate whose cited `vulnerableCode` "does NOT appear on any + line in the DIFF block above," any finding whose evidence lands past byte 8000 of the joined diff is systematically discarded as a false "PRE-EXISTING" refutation, even when it was genuinely introduced by the change.

### Finding Description
`build_refute_prompt` (`plugins/security-guidance/hooks/review_api.py:210-283`) is the stage-2 self-refute prompt builder for the two-stage agentic review (investigate → self-refute). It receives `diff_text` — already capped to `DIFF_TOTAL_BYTES` (400000 bytes by default) by `cap_diff_for_prompt`/`_cap_files_for_prompt` — and re-slices it with `diff_text[:8000]` [1](#0-0)  before embedding it into the refute prompt's `DIFF:` block. This slice is not file-aware, adds no `[truncated by security-guidance...]` marker, and is applied to a diff that stage 1 (`build_investigate_prompt`) sees in its much larger, per-file-marked form via `cap_diff_for_prompt` [2](#0-1) .

The refute prompt's own logic then instructs the model: "REFUTE with cited file:line evidence if ... PRE-EXISTING: the cited vulnerableCode does NOT appear on any + line in the DIFF block above — it is unchanged context in a touched file. The diff did not introduce it." [3](#0-2)  Because evidence for files/hunks positioned after the 8000-character cutoff is invisible to the model, a legitimate, newly-introduced vulnerability whose diff hunk falls past that boundary satisfies this PRE-EXISTING criterion by construction and gets wrongly refuted (dropped).

The identical unmarked, non-file-aware `diff_text[:8000]` truncation exists in the production hook code path in `agentic_review`'s inline `refute_prompt` construction [4](#0-3) , confirming this is not merely a docstring/library-surface issue but affects the actual Stop-hook review flow that gates whether findings are surfaced to the user.

Since an attacker (or prompt-injected agent behavior) fully controls the diff content reviewed in a turn, they can pad the diff with a large early file (or reorder touched files, since `diff_files` order follows the underlying git diff order) so that the genuinely malicious hunk is pushed past byte 8000 in the joined `diff_text`. Even without deliberate padding, any turn touching several files whose combined diff exceeds 8000 characters already has this failure mode for later files — the self-refute stage will "REFUTE" as pre-existing any stage-1 finding whose cited code lies past the cutoff, dropping valid findings from the final report with no marker indicating truncation occurred.

### Impact Explanation
This breaks the stated invariant that truncation must not consistently drop the high-risk lines the user expects to be reviewed. The self-refute stage is the last mechanical/LLM gate before findings are surfaced or suppressed; a systematically-triggerable false REFUTE means dangerous code changes (e.g., a backdoor, a removed authz check, or an SSRF sink) introduced later in a large diff can pass the security review silently, since stage 2 discards the stage-1 finding on the (false) grounds that the diff doesn't show the change. This matches the Immunefi impact category "Sensitive code, prompt, token, diff, or local file disclosure to an unintended local or remote sink" in the sense that dangerous code changes escape detection and land un-flagged.

### Likelihood Explanation
No privileged access is required — this triggers for any diff whose combined content, once joined with `=== DIFF: <path> ===` headers, exceeds 8000 characters, which is common for multi-file or moderately-sized changes. An attacker with the ability to influence what gets committed/edited in a reviewed turn (e.g., via prompt-injected repository content directing the agent to make certain edits) can deliberately position or pad diff content to push the target hunk past the cutoff, making this both naturally occurring and deliberately exploitable.

### Recommendation
Replace the raw `diff_text[:8000]` slice in `build_refute_prompt` (and the duplicated logic in `agentic_review`'s `refute_prompt` in `llm.py`) with a file-aware cap analogous to `cap_diff_for_prompt`/`_cap_files_for_prompt`: cap per-file and total bytes for the refute-stage diff specifically, and always insert an explicit truncation marker when content is cut so the model does not mistake truncation for absence-of-evidence. Additionally, consider prioritizing the diff hunks that directly correspond to `candidates` in the refute prompt window rather than raw prefix-truncating the full diff, so cited evidence for each candidate is guaranteed to be present regardless of diff size or ordering.

### Proof of Concept
Unit test plan against `review_api.build_refute_prompt`:
1. Construct `diff_files` with two entries: a large benign file `("aaa_padding.py", "x"*9000)` and a small malicious file `("zzz_evil.py", "+os.system(user_input)")` such that when joined via `cap_diff_for_prompt`, the malicious `+` line lands after byte 8000 of the joined text.
2. Build `diff_text` the same way `agentic_review`/callers do (`"\n\n".join(f"=== DIFF: {fp} ===\n{c}" for fp, c in cap_diff_for_prompt(diff_files)[0])`).
3. Call `build_refute_prompt(candidates=[{"filePath": "zzz_evil.py", "vulnerableCode": "os.system(user_input)", ...}], diff_text=diff_text)`.
4. Assert that the string `"os.system(user_input)"` is **not** present in the returned prompt's `DIFF:` section (demonstrating the evidence was truncated away) — this is the failure condition: the invariant "truncation must not consistently drop the high-risk lines the user expects to be reviewed" is violated.
5. As a regression check for the fix, assert that after applying a file-aware cap with markers, either (a) the malicious `+` line remains present in the refute prompt regardless of preceding file sizes, or (b) an explicit truncation marker is present so the adversarial-verifier prompt cannot silently treat the missing hunk as "does not appear in diff."

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
