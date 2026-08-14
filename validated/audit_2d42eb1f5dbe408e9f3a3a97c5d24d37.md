### Title
Position-independent stripped-line matching in `filter_preexisting_from_diff` lets an attacker relocate/duplicate dangerous code verbatim into a new, more dangerous location while it is hidden from the security reviewer - ([File: plugins/security-guidance/hooks/gitutil.py])

### Summary
`filter_preexisting_from_diff` builds a single `removed_lines` set from every `-` line in a full-file-rewrite diff (stripped of leading/trailing whitespace) and converts any `+` line whose stripped text is in that set into a context line, with no regard to the line's original position or how many times it is reused. Because the matching is purely a set-membership test over the *entire* file rather than a per-hunk/positional comparison, a line that existed anywhere in the old file (e.g. in a dead branch, comment, or unreachable helper) can be duplicated verbatim into a newly reachable/dangerous location by a full-file `Write` rewrite and it will be collapsed to context, hiding a security-relevant change from the LLM reviewer while it ships in the actual commit.

### Finding Description
In `filter_preexisting_from_diff` [1](#0-0)  the function collects `removed_lines` as a `set()` of every `-` line's `.strip()`'d text across the whole file diff, then for each `+` line checks `content in removed_lines` to decide whether to demote it to a context line [2](#0-1) . This has two properties acknowledged in the code's own comment as an "accepted trade-off": (1) `.strip()` ignores indentation/whitespace differences, and (2) the set "lets one removal mask N additions of the same stripped text" [3](#0-2) . Critically, matching is *position-independent* — a removed line from one part of the file can mask an added line anywhere else in the file, because both are just members of flat sets/lists with no line-number or hunk correlation.

Exploit flow: an attacker rewrites a tracked file end-to-end with the `Write` tool so git emits an all-`-`/all-`+` diff. If the pre-rewrite file already contains some line L elsewhere (a comment, dead code path, disabled feature flag block, low-privilege helper) whose stripped text is functionally dangerous when reachable, the attacker can insert that exact same text L verbatim at a newly reachable/high-privilege call site in the rewritten file. Since L's stripped text is already in `removed_lines` (because the whole file was "removed" during the full rewrite), the freshly added occurrence of L gets converted to a `' ' + line[1:]` context line and disappears from the reviewer's diff view, even though its new location fundamentally changes its exploitability (e.g., moved from an admin-gated function to a public one). The reviewer LLM only ever sees the filtered diff produced by `filter_preexisting_from_diff`, which is invoked after `get_git_diff` → `parse_diff_into_files` in `security_reminder_hook.py`.

Existing checks do not stop this: there is no positional/hunk-aware comparison, no cap on how many additions one removed line can mask, and no verification that a matched line is truly unchanged in context/reachability — only raw stripped-string equality.

### Impact Explanation
This suppresses a genuinely new, security-relevant code change from the automated review that the plugin exists to perform, while the change is committed to the repository unreviewed. This matches "reviewer must see all genuinely new content that could contain secrets or vulnerabilities" (SECRET_ISOLATION) being violated, letting a relocated dangerous call/line ship without triggering the intended security-guidance review, i.e., a review-bypass / detection-evasion impact on Claude Code's security-guidance plugin.

### Likelihood Explanation
The precondition is narrow: the exact byte content (modulo leading/trailing whitespace) of the newly "dangerous-in-context" line must already exist verbatim somewhere in the pre-rewrite file. This is realistic for real-world code (common lines like `os.system(cmd)`, `eval(x)`, a helper call, or a previously-dead/commented block being reactivated elsewhere) but cannot be used to smuggle in arbitrary novel secret values, since the internal (non-leading/trailing) content must match byte-for-byte — an attacker cannot make an arbitrary new API key collide with unrelated old text. The attack is fully reproducible: it only requires a single `Write`-tool full-file rewrite, no special privileges, and is deterministic given the documented set-based matching logic.

### Recommendation
Make the pre-existing-content filter positional/order-aware instead of a flat set/count-agnostic membership test — e.g., use a sequence-alignment (LCS/diff-of-diffs) approach that matches removed→added lines in relative order and only demotes a bounded, one-to-one correspondence of matches, or require the match to preserve multiplicity (Counter-based subtraction rather than a bare `set`) so that a line can only be treated as "pre-existing" as many times as it was actually removed, and only within a limited positional window. At minimum, cap the masking so one removed line cannot suppress multiple, differently-located additions, and document/enforce that the LLM reviewer's "previous-findings recheck" backstop is actually exercised for every full-file rewrite.

### Proof of Concept
Unit test in the existing test module for `gitutil`:
1. Construct a synthetic diff for one file where the old version contains a benign, unreachable line, e.g. `# disabled: os.system(cmd)` inside a dead `if False:` block, and other unrelated lines.
2. Construct the new version (full rewrite) where that same stripped text `os.system(cmd)` (after removing the `# disabled:` prefix is NOT needed — use the literal identical stripped text) is placed at a newly reachable location, e.g. directly inside a request handler.
3. Build a unified diff string with the corresponding `-`/`+` lines (all lines removed, all lines re-added, standard full-rewrite git diff shape).
4. Call `filter_preexisting_from_diff([(file_path, diff_content)], cwd, baseline_sha)`.
5. Assert that the resulting diff content still contains the relocated line as a `+` (added) line rather than having been converted to a `' '`-prefixed context line — i.e., assert `'+os.system(cmd)' in result` and `' os.system(cmd)' not in result`, proving the filter currently fails this assertion (converts it to context) and thereby demonstrating the bypass.

### Citations

**File:** plugins/security-guidance/hooks/gitutil.py (L657-692)
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

    filtered = []
    for file_path, diff_content in diff_files:
        lines = diff_content.split('\n')

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

**File:** plugins/security-guidance/hooks/gitutil.py (L694-720)
```python
        # Rebuild diff with pre-existing lines converted to context (space prefix).
        # Known imprecision: .strip() matches across indentation (so reindented
        # code is treated as unchanged) and the set lets one removal mask N
        # additions of the same stripped text. Accepted trade-off — this filter
        # exists for the full-file Write rewrite case where exact-match would
        # miss everything; the diff-review prompt's previous-findings recheck
        # is the backstop.
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
            else:
                new_lines.append(line)

        filtered.append((file_path, '\n'.join(new_lines)))
```
