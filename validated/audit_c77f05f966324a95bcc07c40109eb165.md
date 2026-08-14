### Title
Fixed 8000-character truncation in `build_refute_prompt` lets attacker-padded diffs cause valid vulnerability findings to be dropped as "PRE-EXISTING" - (File: `plugins/security-guidance/hooks/review_api.py`)

### Summary
`build_refute_prompt` truncates the diff to a hard `diff_text[:8000]` character slice before handing it to the adversarial self-refute stage, with no attempt to keep the truncated window anchored around the flagged candidates' vulnerable lines. An attacker who controls diff content (e.g. a large agentic-coding session or PR whose diff Claude is asked to review) can front-load the diff with filler content so that the genuinely dangerous `+` line lands after byte 8000, at which point the refute model's own "PRE-EXISTING: vulnerableCode does NOT appear on any + line in the DIFF block above" rule fires and incorrectly discards the true finding.

### Finding Description
`build_refute_prompt` in `plugins/security-guidance/hooks/review_api.py` builds the stage-2 adversarial-refute prompt as: [1](#0-0) 
Note the `+ "\n\nDIFF:\n" + diff_text[:8000]` slice and the accompanying instruction telling the model to REFUTE any candidate whose `vulnerableCode` does not appear on a `+` line "in the DIFF block above." The identical pattern exists in the production caller in `llm.py`'s `agentic_review`, which builds `refute_prompt` the same way from `diff_text[:8000]`: [2](#0-1) 

This truncation is a plain positional character cutoff — unlike `cap_diff_for_prompt`/`_cap_files_for_prompt`, which cap per-file and total bytes proportionally across all files with in-content truncation markers [3](#0-2) , the stage-2 refute slice takes only the first 8000 characters of the already-joined `diff_text`, with no per-candidate anchoring, no prioritization of files that contain flagged `vulnerableCode`, and no truncation marker warning the model that content past 8000 chars is missing.

Exploit flow: an attacker who controls the diff content (large refactor, generated files, verbose scaffolding, or an attacker-influenced commit that Claude is asked to review) places substantial diff content — even benign, low-risk files — ahead of the file containing the real vulnerability in the unified diff ordering. Stage 1 (`build_investigate_prompt` / `agentic_review`'s investigate pass, which uses the properly capped `cap_diff_for_prompt`/`_cap_files_for_prompt`) still sees the full diff and correctly flags the candidate. But stage 2's `diff_text[:8000]` slice, built from the *same* `diff_text` string, cuts off before reaching the actual `+` line that justified the finding. The refute model, following its own explicit instruction ("the cited vulnerableCode does NOT appear on any + line in the DIFF block above ... refute"), then refutes the true finding as pre-existing/off-diff noise, and the finding is silently dropped from `survived`, never reaching `format_findings`/the user.

### Impact Explanation
This breaks the security-review tool's core guarantee: that dangerous newly-introduced code changes are surfaced to the user before being committed/merged. By controlling ordering/size of unrelated diff content, an attacker can suppress detection of a real vulnerability they introduce elsewhere in the same diff, causing the security-guidance hook to silently pass a dangerous change through review. This is a review-bypass / false-negative issue in the guardrail itself rather than a direct RCE or cross-tenant mutation — it does not on its own achieve "cross-repo, cross-session, or wrong-target mutation," but it does degrade the tool's ability to catch such mutations when they are the actual payload of the diff, which is the closest matching impact class available (silent security-control bypass allowing attacker-introduced vulnerabilities to reach the user undetected).

### Likelihood Explanation
Feasible without special privilege: any diff review request (including large or attacker-influenced diffs a coding agent is asked to process) can be shaped to exceed 8000 characters ahead of the dangerous hunk — trivial to construct (padding files, verbose imports, generated code, or simply ordering files alphabetically/positionally so the vulnerable file sorts after other diff content). It requires no compromise of the hook, no admin privilege, and is fully within the "attacker controls diff content" threat model. Repeatability is high: the 8000-char cutoff is deterministic and hardcoded, so any diff exceeding it before the vulnerable line will reproduce the drop consistently, not probabilistically.

### Recommendation
Replace the flat `diff_text[:8000]` slice with a budget-aware selection that guarantees the diff excerpt sent to the refute stage includes the specific hunks/files referenced by each candidate's `filePath`/`vulnerableCode` (e.g., build a per-candidate excerpt or prioritize/anchor the truncated window around cited files, similar to `_prioritize_diff_files` in `gitutil.py`), and add an explicit truncation marker so the refute model is told when content is missing rather than assuming absence implies "pre-existing."

### Proof of Concept
Unit test plan (pytest) in `plugins/security-guidance/hooks/`:
1. Construct `candidates = [{"filePath": "b/vuln.py", "vulnerableCode": "os.system(user_input)", ...}]`.
2. Construct `diff_files` where `a/padding.py` contains >8000 characters of benign diff content, followed by `b/vuln.py` containing the `+os.system(user_input)` line.
3. Build `diff_text = "\n\n".join(f"=== DIFF: {fp} ===\n{content}" for fp, content in diff_files)` (mirroring `agentic_review`).
4. Call `build_refute_prompt(candidates, diff_text)` and assert that `"os.system(user_input)"` is **absent** from the returned prompt's `diff_text[:8000]` slice — demonstrating the anchoring failure.
5. Assert (fast validation per the task) that a corrected implementation must keep `"os.system(user_input)"` present in the prompt sent for refutation whenever it exists in any candidate's `vulnerableCode`, regardless of its position in the overall diff — i.e., `assert "os.system(user_input)" in generated_prompt` should hold after the fix but fails today.

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

**File:** plugins/security-guidance/hooks/review_api.py (L210-236)
```python
def build_refute_prompt(candidates: list[dict[str, Any]], diff_text: str) -> str:
    return (
        "You previously flagged these candidate vulnerabilities:\n\n"
        + json.dumps(candidates, indent=2)
        + "\n\nDIFF:\n" + diff_text[:8000]
        + "\n\nNow adversarially try to DISPROVE each one. For each "
        "candidate, FIRST identify the attacker (who controls the "
        "input) and the victim (who is harmed). REFUTE if the only "
        "victim is the attacker themselves on their own machine. KEEP "
        "if the attacker is a legitimate user/tenant but the impact "
        "reaches other users/tenants, shared infra, or server-side "
        "resources.\n\n"
        "DIFF-ANCHOR: candidates are sorted `in_diff` first, then "
        "`off_diff`. Process them in order. `in_diff` candidates "
        "use the standard KEEP/REFUTE bar above. `off_diff` "
        "candidates require STRICTER evidence: you must identify "
        "the specific +/- line in the diff that ENABLES the "
        "off-diff sink (a removed guard, a new caller, a changed "
        "argument feeding it). If you cannot name that enabling "
        "diff line, REFUTE the off_diff candidate. Additionally, "
        "REFUTE any off_diff candidate whose sink is already "
        "covered by a surviving in_diff candidate.\n\n"
        "Then Read the cited file and refute with cited file:line "
        "evidence if ANY of these holds:\n"
        "- PRE-EXISTING: the cited vulnerableCode does NOT appear on "
        "any + line in the DIFF block above — it is unchanged context "
        "in a touched file. The diff did not introduce it.\n"
```

**File:** plugins/security-guidance/hooks/llm.py (L1455-1483)
```python
        refute_prompt = (
            "You previously flagged these candidate vulnerabilities:\n\n"
            + json.dumps(candidates, indent=2)
            + "\n\nDIFF:\n" + diff_text[:8000]
            + "\n\nNow adversarially try to DISPROVE each one. For each "
            "candidate, FIRST identify the attacker (who controls the "
            "input) and the victim (who is harmed). REFUTE if the only "
            "victim is the attacker themselves on their own machine. KEEP "
            "if the attacker is a legitimate user/tenant but the impact "
            "reaches other users/tenants, shared infra, or server-side "
            "resources.\n\n"
            "DIFF-ANCHOR: candidates are sorted `in_diff` first, then "
            "`off_diff`. Process them in order. `in_diff` candidates "
            "use the standard KEEP/REFUTE bar above. `off_diff` "
            "candidates require STRICTER evidence: you must identify "
            "the specific +/- line in the diff that ENABLES the "
            "off-diff sink (a removed guard, a new caller, a changed "
            "argument feeding it). If you cannot name that enabling "
            "diff line, REFUTE the off_diff candidate. Additionally, "
            "REFUTE any off_diff candidate whose sink is already "
            "covered by a surviving in_diff candidate.\n\n"
            "Then Read the cited file and refute with cited file:line "
            "evidence if ANY of these holds:\n"
            "- PRE-EXISTING: the cited vulnerableCode does NOT appear on "
            "any + line in the DIFF block above — it is unchanged context "
            "in a touched file. The diff did not introduce it.\n"
            "- A sanitizer/validator/authz check prevents the described "
            "exploit.\n"
            "- The sink is non-dangerous: typed-schema decoder (msgspec/"
```
