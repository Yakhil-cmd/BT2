### Title
Fixed 8000-char diff truncation in `build_refute_prompt` causes the adversarial verifier to spuriously self-refute genuinely-introduced vulnerabilities on diffs larger than the cutoff - (File: `plugins/security-guidance/hooks/review_api.py`)

### Summary
`build_refute_prompt` truncates the full formatted diff text to a hard `diff_text[:8000]` character window before handing it to the stage-2 "adversarial refuter" model, with no attempt to keep the specific file/lines referenced by each candidate finding inside that window. Because the refuter's own instructions tell it to REFUTE any candidate whose `vulnerableCode` "does NOT appear on any + line in the DIFF block above" (the PRE-EXISTING rule), an attacker who controls the diff (any commit/PR author) can push the vulnerable file's `+` lines past the 8000-character cutoff and cause the reviewer to discard a real, newly-introduced vulnerability as a false positive.

### Finding Description
`build_refute_prompt` in `plugins/security-guidance/hooks/review_api.py` builds the stage-2 refute prompt like this: [1](#0-0) 

The relevant excerpt:
```
+ "\n\nDIFF:\n" + diff_text[:8000]
...
"- PRE-EXISTING: the cited vulnerableCode does NOT appear on "
"any + line in the DIFF block above — it is unchanged context "
"in a touched file. The diff did not introduce it.\n"
```

This is a straight slice of the already-assembled `diff_text` string — the same object built by `build_investigate_prompt` via `cap_diff_for_prompt`, which allows up to `DIFF_PER_FILE_BYTES=80000` per file and `DIFF_TOTAL_BYTES=400000` total [2](#0-1) . The refute stage re-truncates that same text down to only 8000 characters, with no per-candidate anchoring, no prioritization of the files actually referenced by `candidates`, and no signal to the model that the DIFF block may have been cut mid-file. `tag_diff_anchor` (the only other consumer of `diff_text` in this module) similarly scans the same un-truncated `diff_text` for token overlap but is not used to select which slice survives into `build_refute_prompt` [3](#0-2) .

Because file ordering in a diff is attacker-controlled (the diff/commit author decides file paths, ordering, and padding), an attacker can:
1. Introduce a genuinely dangerous change in file B.
2. Ensure file A (alphabetically or by diff order earlier) or bloated/verbose content earlier in the same diff consumes most/all of the first 8000 characters.
3. The refute-stage prompt's DIFF block never shows the `+` lines for file B's dangerous change, even though the earlier investigate stage (with its 80000/400000-byte caps) did see and correctly flag it as a candidate.
4. The refuter, faithfully following its own PRE-EXISTING rule, cites "does not appear on any + line in the DIFF block above" and REFUTEs a real finding — not because the model was fooled by injected instructions, but because the mechanical truncation removed the evidence it needs to keep the candidate.

This breaks the stated invariant that prompt assembly must not let untrusted repo content suppress review of dangerous changes: the size/shape of the attacker-authored diff alone (no prompt-injection wording needed) can deterministically blind the refute stage to the very evidence it is supposed to check for.

### Impact Explanation
This causes the self-refute adjudication stage to drop legitimate high/critical findings from `agentic_review`'s output before they are ever surfaced to the user in `security_reminder_hook.py`'s commit review flow [4](#0-3) . That is a logic-level bypass of a required guard (the "keep findings unless refuted with concrete evidence" adjudication default) driven purely by attacker-controlled diff size/shape, matching the "Logic-level service disruption caused by bypassing a required guard" impact category — real security findings silently vanish from review output on any commit whose diff exceeds ~8000 characters before the vulnerable lines.

### Likelihood Explanation
Any contributor authoring a commit/PR fully controls file ordering, file count, and diff size — reaching this path requires no privilege beyond being able to submit a diff that goes through the agentic commit review. Diffs of moderate size (multiple touched files, or even one file with substantial context) commonly exceed 8000 characters, so this is not a contrived edge case; it is a low-effort, repeatable condition (pad/order the diff so the vulnerable hunk lands past offset 8000).

### Recommendation
Instead of a blind `diff_text[:8000]` slice, build the refute-stage DIFF block by extracting/prioritizing the hunks for the files referenced by `candidates` (similar to how `tag_diff_anchor` already correlates `vulnerableCode` against diff lines), or raise the cap to match `DIFF_TOTAL_BYTES`/investigate-stage sizing, and explicitly mark truncation inline so the model cannot apply the PRE-EXISTING rule to content it never actually saw.

### Proof of Concept
Unit test plan for `plugins/security-guidance/hooks/review_api.py::build_refute_prompt`:
1. Construct `diff_files` with a large low-risk file A (~9000 chars of diff) followed by a small file B containing an obviously dangerous `+` line (e.g. `os.system(user_input)`).
2. Run `build_investigate_prompt`/simulate that investigate stage returns one candidate with `filePath="B"`, `vulnerableCode` equal to the dangerous line.
3. Call `build_refute_prompt(candidates, diff_text)` where `diff_text` is the same full formatted diff used upstream.
4. Assert (mechanically, no LLM call needed) that the dangerous line/file B text is **not** present in the resulting prompt string (`"os.system(user_input)" not in prompt`), proving the evidence needed to keep the candidate was truncated away — i.e., the invariant "the dangerous file or path remains present and correctly anchored after truncation" fails.
5. As a regression guard, assert instead that for diffs whose formatted length exceeds 8000 chars, `build_refute_prompt` always retains each candidate's `filePath`'s hunk (or flags truncation) rather than naive head-truncation.

### Citations

**File:** plugins/security-guidance/hooks/review_api.py (L27-28)
```python
DIFF_PER_FILE_BYTES = int(os.environ.get("DIFF_PER_FILE_BYTES", "80000"))
DIFF_TOTAL_BYTES = int(os.environ.get("DIFF_TOTAL_BYTES", "400000"))
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

**File:** plugins/security-guidance/hooks/review_api.py (L291-343)
```python
def tag_diff_anchor(
    candidates: list[dict[str, Any]], diff_text: str
) -> list[dict[str, Any]]:
    """SOFT diff-intersect: tag each candidate ``_diff_anchor: "in_diff" |
    "off_diff"`` and sort in_diff first; do NOT drop.

    Investigate reads full files and often cites pre-existing patterns in
    unchanged context (the largest false-positive source).  Hard-dropping
    those also discards correct findings whose sink is off-diff but
    enabled by an in-diff change.  The refute pass's DIFF-ANCHOR block
    keys on the ``_diff_anchor`` tag to apply stricter evidence to
    off_diff candidates instead of dropping them.

    Mutates ``candidates`` in place; returns it for chaining.
    """
    added = [
        ln[1:]
        for ln in diff_text.splitlines()
        if ln.startswith("+") and not ln.startswith("+++")
    ]
    removed = [
        ln[1:]
        for ln in diff_text.splitlines()
        if ln.startswith("-") and not ln.startswith("---")
    ]

    def _norm(s: str) -> str:
        return " ".join(t for t in " ".join(s.split()).split() if len(t) > 2)

    added_norm = _norm("\n".join(added))
    removed_norm = _norm("\n".join(removed))

    def _intersects(cand: dict[str, Any]) -> bool:
        vc = _norm(" ".join(str(cand.get("vulnerableCode") or "").split()))
        if len(vc) < 8:
            return True
        toks = vc.split()
        for i in range(max(1, len(toks) - 2)):
            if " ".join(toks[i : i + 3]) in added_norm:
                return True
        for ln in added:
            ln_n = _norm(ln)
            if len(ln_n) >= 8 and ln_n in vc:
                return True
        if len(added) < len(removed):
            for i in range(max(1, len(toks) - 2)):
                if " ".join(toks[i : i + 3]) in removed_norm:
                    return True
        return False

    for c in candidates:
        c["_diff_anchor"] = "in_diff" if _intersects(c) else "off_diff"
    candidates.sort(key=lambda c: c.get("_diff_anchor") != "in_diff")
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1268-1273)
```python
    # `survived` is the raw self-refute count BEFORE the high/critical-only
    # severity filter; `survived_after_sev` is the count the user actually
    # sees. Include `survived_after_sev` ONLY when the filter actually
    # dropped candidates — otherwise it's redundant with `survived` and eats
    # into CC's 10-key emit cap, pushing files_reviewed/review_ms out of the
    # emitted metrics.
```
