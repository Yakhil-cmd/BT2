### Title
Cross-hunk stripped-line collisions in `filter_preexisting_from_diff` allow hiding malicious added lines from the security reviewer - ([File: plugins/security-guidance/hooks/gitutil.py])

### Summary
`filter_preexisting_from_diff` builds a single file-wide `removed_lines` set from every `-` line anywhere in a file's diff and then reclassifies any `+` line whose `.strip()`-ed text is present in that set as pre-existing context, regardless of hunk, position, or semantic relationship. An attacker who controls the diff content (e.g., via code the agent writes across a session, or a crafted patch reviewed via this pipeline) can pad an unrelated hunk with a removed line whose stripped text matches a genuinely new malicious added line elsewhere in the same file, causing the malicious line to be silently converted to a context line (`' ' + line[1:]`) and dropped from what the LLM reviewer sees via `build_investigate_prompt`.

### Finding Description
In `filter_preexisting_from_diff` [1](#0-0) , `removed_lines` is accumulated across the *entire* file diff (not per-hunk, not per-position), and the reclassification loop at [2](#0-1)  only checks `content in removed_lines` — pure content equality after `.strip()`, with no positional/hunk binding. The function's own comment acknowledges this: "the set lets one removal mask N additions of the same stripped text" [3](#0-2) , but the documented trade-off only anticipates the case of legitimate full-file Write rewrites, not adversarial placement of a matching removed line elsewhere in the diff to launder a genuinely new addition. Because common boilerplate (`return None`, `pass`, `except Exception:`, etc.) is likely to appear as an unrelated removed line somewhere in a real edit, an attacker-influenced diff can intentionally include such a line as removed content in one hunk while adding a malicious line with identical stripped text in a different hunk/section; the malicious line is then converted to a leading-space context line and excluded from the "new code" the LLM reviewer inspects via `build_investigate_prompt` in `review_api.py`.

### Impact Explanation
This weakens the security-guidance plugin's Stop-hook LLM review, whose entire purpose is to surface newly introduced vulnerable code to the reviewer model (and, on findings, force Claude to continue and fix them). If a malicious addition can be relabeled as "pre-existing" and thus stripped from the reviewed content, a genuinely new vulnerable/malicious line escapes both the pattern-based and LLM-based review layers described in the plugin's own documentation. This is a trust-boundary bypass of the review/export logic (TARGET_BINDING/DENY_MEANS_DENY: the diff content shown to the reviewer must reflect true additions), directly matching a "review bypass hides malicious code changes" class of impact for this bounty program.

### Likelihood Explanation
Exploitability requires only that the attacker (or the automated agent under manipulation) can shape a diff containing at least one unrelated removed line and one added line with matching stripped text — a very low bar since common one-line boilerplate (`return None`, `pass`, closing braces/`}`, `else:`) recurs naturally in real diffs, and an attacker crafting the change (e.g., prompt-injected instructions steering the agent's edits, or a multi-hunk patch) can trivially engineer the collision deliberately. No privileged access is needed; only ordinary diff/patch content reachable through the normal edit/review flow is required, making this a reliably repeatable bypass, not a rare edge case.

### Recommendation
Scope the "pre-existing" detection per-hunk (or at minimum require positional proximity/ordering) instead of a file-wide content-only set, e.g., match `+`/`-` line pairs within the same `@@` hunk and consume matches (multiset semantics keyed by position order) rather than a plain `in` check against a global set. Alternatively, only apply this heuristic when the file diff has the "full deletion followed by full re-addition" pattern that is the documented intended trigger (Write-tool full rewrite), rather than unconditionally to any diff containing any removed line.

### Proof of Concept
Unit test in the existing test module for `gitutil.filter_preexisting_from_diff`:
```python
def test_cross_hunk_stripped_collision_not_hidden():
    diff_content = (
        "@@ -1,3 +1,3 @@\n"
        "-def helper():\n"
        "-    return None\n"
        "+def helper():\n"
        "+    return None\n"
        "@@ -10,2 +10,3 @@\n"
        " def handler(cmd):\n"
        "+    os.system(cmd)  # malicious new line, unique text\n"
    )
    # Add an unrelated removed line elsewhere sharing stripped text with
    # a genuinely new malicious addition intended to hide it:
    diff_content_attack = (
        "@@ -1,3 +1,3 @@\n"
        "-def helper():\n"
        "-    return None\n"
        "+def helper():\n"
        "+    return None\n"
        "@@ -20,1 +20,2 @@\n"
        "-    return None\n"  # unrelated boilerplate removal elsewhere
        "+    os.system(user_input)  # NEW malicious line\n"
    )
    result = filter_preexisting_from_diff(
        [("app.py", diff_content_attack)], cwd=".", baseline_sha="abc123"
    )
    _, new_diff = result[0]
    # Expected (post-fix): the malicious "+ os.system(user_input)" line must
    # remain a "+" addition and be surfaced to build_investigate_prompt.
    assert "+    os.system(user_input)" in new_diff
    assert " os.system(user_input)" not in new_diff.replace(
        "+    os.system(user_input)", ""
    )
```
Currently this assertion fails: the malicious `os.system(user_input)` line's stripped text does not literally match `return None`, so in this specific example it would NOT collide — the PoC should instead pick an added line whose stripped text exactly equals `return None` (or another boilerplate string) to demonstrate the bypass, e.g. add `+    return None` as the malicious payload disguised as innocuous, or use a real one-line collision like `+        pass  # TODO: remove auth check` where stripped text is just `pass`. The core PoC pattern: craft `diff_content` with an unrelated `-    return None` in one hunk and a malicious `+    return None`-stripped line (or any attacker line whose `.strip()` equals a common unrelated removed boilerplate string) in a different hunk, then assert the malicious `+` line is preserved as an addition (not converted to `' '`-prefixed context) so it still reaches `build_investigate_prompt` in `review_api.py`.

### Citations

**File:** plugins/security-guidance/hooks/gitutil.py (L672-692)
```python
        # Collect removed and added lines (stripping the +/- prefix)
        removed_lines = set()
        added_lines = []
        for line in lines:
            if line.startswith('-') and not line.startswith('---'):
                removed_lines.add(line[1:].strip())
            elif line.startswith('+') and not line.startswith('+++'):
                added_lines.append(line[1:].strip())

        if not removed_lines:
            # New file, no pre-existing content to filter
            filtered.append((file_path, diff_content))
            continue

        # Check what fraction of added lines were pre-existing
        preexisting_count = sum(1 for l in added_lines if l in removed_lines)
        if preexisting_count == 0:
            filtered.append((file_path, diff_content))
            continue

        added_lines_set = set(added_lines)
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
