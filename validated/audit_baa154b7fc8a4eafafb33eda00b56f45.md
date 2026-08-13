### Title
Set-based line matching in `filter_preexisting_from_diff` lets a decoy removed line mask an unrelated newly-added malicious line from the security reviewer - ([File: plugins/security-guidance/hooks/gitutil.py])

### Summary
`filter_preexisting_from_diff` deduplicates added vs. removed lines using a flat, position-agnostic `set` of `.strip()`-normalized text rather than per-hunk/positional matching. Any added line whose stripped text equals *any* removed line's stripped text anywhere in the same file-diff is silently converted to a context line, even if the two lines are semantically and positionally unrelated. Because the Write tool's full-file rewrite puts both the entire old content (as `-` lines) and entire new content (as `+` lines) into a single diff that this function processes, an attacker who controls (or has previously influenced) both the pre-rewrite content and the rewritten content can place a genuinely new, dangerous line so that its stripped text collides with an unrelated pre-existing removed line, causing it to be hidden from the LLM security reviewer.

### Finding Description
`filter_preexisting_from_diff` builds `removed_lines` as a `set` of stripped `-` line text and `added_lines` as a list of stripped `+` line text: [1](#0-0) 

It then rebuilds the diff, converting any `+` line to a context (` `) line whenever its stripped text is present in `removed_lines` — a pure set-membership test with no positional/hunk correlation: [2](#0-1) 

The function's own docstring acknowledges this as a known, accepted imprecision ("the set lets one removal mask N additions of the same stripped text"), relying on "the diff-review prompt's previous-findings recheck" as the only backstop: [3](#0-2) 

This function is invoked on the output of `get_git_diff`/`parse_diff_into_files` for Write-tool full-file rewrites, which is exactly the scenario where the whole file appears as `-`/`+` pairs: [4](#0-3) 

Exploit flow: an attacker who can influence file content that Claude later fully rewrites (e.g., prior injected content in a repo file, or content from an earlier compromised turn) plants an innocuous-looking line — e.g., a commented-out or dead-code example such as `os.system(cmd)` inside documentation/test scaffolding. When the file is later fully rewritten via the Write tool and that exact stripped text is reused as a genuinely new, *live* dangerous statement (now reachable with attacker-controlled `cmd`), the set-based matcher sees the stripped text present in `removed_lines` and converts the new dangerous `+` line into a context line. The LLM reviewer that consumes the filtered diff never sees this line as an addition, so it is not flagged, even though it is a brand-new, exploitable statement in the rewritten file.

No positional, hunk-boundary, or semantic check exists to prevent this — the check is a single global `in removed_lines` test across the entire file's diff.

### Impact Explanation
This breaks the review/export consent invariant: content that the user authorized for LLM security review can have attacker-influenced malicious lines silently hidden from that reviewer, allowing a malicious full-file rewrite to evade the security-guidance plugin's LLM analysis. This matches the "unauthorized file action evades review" / trust-boundary-bypass class of impact for Claude Code's security-guidance hooks — the entire purpose of `filter_preexisting_from_diff` and its caller pipeline is to ensure the reviewer sees genuinely new code, and this defect lets truly new, attacker-crafted code slip through as "preexisting."

### Likelihood Explanation
Requires the attacker to control (directly or via earlier prompt injection) both some pre-existing line in the file being rewritten and the new content written via the Write tool, and to engineer stripped-text equality between an old benign/dead line and a new dangerous live line. This is a deliberate craft, not accidental collision, but is fully within reach of anyone who can influence repository content that Claude ingests and later fully rewrites (e.g., staged "example" or "template" code containing dangerous calls, later "activated" verbatim during a rewrite). It is reliably reproducible: any such crafted repo state deterministically triggers the masking behavior on every Write-tool full rewrite of that file.

### Recommendation
Replace the global stripped-text `set` matching with positional/anchored matching (e.g., diff a proper LCS/sequence alignment between old and new file content, or require unchanged-line matches to be at the same or a nearby line number/hunk) so that only lines that are truly unchanged (same content, same relative position) are converted to context. At minimum, cap how many times a single stripped-text value may mask an addition (e.g., only mask up to the count of times it was removed, matched in original file order) instead of treating any occurrence anywhere in the file as equivalent.

### Proof of Concept
Unit test in the style of the existing test suite for `filter_preexisting_from_diff`:

```python
def test_decoy_removed_line_does_not_mask_new_malicious_line():
    diff_content = (
        "@@ -1,3 +1,4 @@\n"
        "-import os\n"
        "-os.system(cmd)  # example, dead code\n"
        "-def run():\n"
        "+import os\n"
        "+def run():\n"
        "+    cmd = user_input()\n"
        "+    os.system(cmd)  # example, dead code\n"  # genuinely new, now LIVE and dangerous
    )
    filtered = filter_preexisting_from_diff(
        [("app.py", diff_content)], cwd="/repo", baseline_sha="deadbeef"
    )
    _, new_content = filtered[0]
    # The newly added dangerous line must remain visible to the reviewer as an
    # addition ('+'), NOT be converted to a context line (' ').
    assert "+    os.system(cmd)  # example, dead code" in new_content
    assert " os.system(cmd)  # example, dead code" not in new_content.splitlines()
```

Expected (current buggy) behavior: the assertion fails because the matcher converts the new `+os.system(cmd)  # example, dead code` line into a context line since its stripped text matches the unrelated removed line `os.system(cmd)  # example, dead code`, hiding it from the reviewer.

### Citations

**File:** plugins/security-guidance/hooks/gitutil.py (L657-666)
```python
def filter_preexisting_from_diff(diff_files, cwd, baseline_sha):
    """
    Filter out pre-existing content from diff files.
    When a file is fully rewritten (Write tool replaces entire content),
    git shows all lines as removed (-) then re-added (+). This function
    detects such rewrites and strips lines from the + section that also
    appeared in the - section, so the LLM reviewer only sees truly new code.
    """
    if not baseline_sha:
        return diff_files
```

**File:** plugins/security-guidance/hooks/gitutil.py (L672-679)
```python
        # Collect removed and added lines (stripping the +/- prefix)
        removed_lines = set()
        added_lines = []
        for line in lines:
            if line.startswith('-') and not line.startswith('---'):
                removed_lines.add(line[1:].strip())
            elif line.startswith('+') and not line.startswith('+++'):
                added_lines.append(line[1:].strip())
```

**File:** plugins/security-guidance/hooks/gitutil.py (L694-700)
```python
        # Rebuild diff with pre-existing lines converted to context (space prefix).
        # Known imprecision: .strip() matches across indentation (so reindented
        # code is treated as unchanged) and the set lets one removal mask N
        # additions of the same stripped text. Accepted trade-off — this filter
        # exists for the full-file Write rewrite case where exact-match would
        # miss everything; the diff-review prompt's previous-findings recheck
        # is the backstop.
```

**File:** plugins/security-guidance/hooks/gitutil.py (L701-716)
```python
        new_lines = []
        for line in lines:
            if line.startswith('+') and not line.startswith('+++'):
                content = line[1:].strip()
                if content in removed_lines:
                    # Convert to context line (pre-existing, not new)
                    new_lines.append(' ' + line[1:])
                else:
                    new_lines.append(line)
            elif line.startswith('-') and not line.startswith('---'):
                content = line[1:].strip()
                if content in added_lines_set:
                    # Skip removed lines that were re-added (they become context)
                    continue
                else:
                    new_lines.append(line)
```
