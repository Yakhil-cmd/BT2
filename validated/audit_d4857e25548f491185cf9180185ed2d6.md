### Title
Security-guidance Stop-hook diff-filter uses set-based (non-positional) line matching, letting a duplicated line mask genuinely new vulnerable code from the LLM reviewer - (File: `plugins/security-guidance/hooks/gitutil.py`)

### Summary
`filter_preexisting_from_diff()` decides which `+` lines in a full-file-rewrite diff are "pre-existing" (and should be hidden from the LLM security reviewer as context) versus truly new. It makes this decision by checking whether a stripped line's *text* is contained in a `set()` of stripped removed lines, rather than tracking a 1:1 (positional/count-based) correspondence between a specific removed occurrence and a specific added occurrence. This is the same bug class as the Solady `decodeBatch()` finding: a validation/decoding step that checks derived/aliased values (content equality) instead of the actual distinct occurrences, so multiple items that alias to the same value are all treated identically even though only one of them should pass.

### Finding Description
`filter_preexisting_from_diff()` in `plugins/security-guidance/hooks/gitutil.py` is invoked from the Stop hook (`security_reminder_hook.py`, `handle_stop_hook`) specifically to handle the case where the `Write` tool rewrites a whole file, so `git diff` shows every line as removed then re-added: [1](#0-0) 

The implementation builds a `set` of removed lines and a `list` of added lines, then masks any added line whose stripped text is present in that `set`: [2](#0-1) 

```python
removed_lines = set()
added_lines = []
for line in lines:
    if line.startswith('-') and not line.startswith('---'):
        removed_lines.add(line[1:].strip())
    elif line.startswith('+') and not line.startswith('+++'):
        added_lines.append(line[1:].strip())
...
preexisting_count = sum(1 for l in added_lines if l in removed_lines)
```

and later, when rebuilding the diff shown to the LLM: [3](#0-2) 

```python
for line in lines:
    if line.startswith('+') and not line.startswith('+++'):
        content = line[1:].strip()
        if content in removed_lines:
            # Convert to context line (pre-existing, not new)
            new_lines.append(' ' + line[1:])
        else:
            new_lines.append(line)
```

Because `removed_lines` is a *set* (an aliasing structure with no notion of "how many times" or "which specific occurrence"), a single removed line can mask an unlimited number of added lines with identical stripped text — the code comment even acknowledges this: "the set lets one removal mask N additions of the same stripped text." This is functionally identical to the Solady root cause: a check validates a derived/aliased quantity (content equality) instead of validating each concrete occurrence independently, so multiple aliased items simultaneously satisfy a check meant to gate only one of them.

The consequence reaches a real trust boundary: the masked (converted-to-context) lines are then fed into `analyze_code_security()` in `llm.py`, whose prompt explicitly instructs the reviewer model to treat context (space-prefixed) lines as pre-existing and to skip them even if they contain vulnerabilities: [4](#0-3) 

### Impact Explanation
An agent turn (potentially driven by a prompt-injected instruction from an untrusted file/tool result the agent was told to act on) that rewrites a file with the `Write` tool can hide a genuinely new dangerous line from the automated security reviewer, as long as that exact line's text already occurs once elsewhere in the old version of the file. Example: if the old file already contained one instance of a distinctive line (e.g. a shell/eval call, a debug flag, a permission-bypass string, or a secret-logging statement), the rewritten file can add a *second*, genuinely new instance of that same line in a fresh, dangerous context (e.g. reachable from a new attacker-controlled sink) and the filter will convert both instances to "context," so the LLM reviewer never evaluates the newly introduced occurrence as a `+` line — defeating the Stop-hook's security review and letting insecure code land without a flagged finding. This is a hook-bypass in the security-guidance trust boundary that the repo relies on to catch newly introduced vulnerabilities before a turn completes.

### Likelihood Explanation
This requires no special privilege beyond the ability to get the agent to rewrite a file with `Write` (a common, everyday action) and to control content that duplicates an existing line's exact text — both are easily attacker/agent-influenceable (e.g., via prompt injection steering the agent's edits, or a contributor deliberately shaping a change to slip past review). The docstring/comment on the function shows the authors were aware of this imprecision as an "accepted trade-off," but did not bound the aliasing to prevent it from masking a legitimately new, security-relevant duplicate.

### Recommendation
Replace the set-membership check with a positional/multiset (count-based) correspondence: use a `collections.Counter` for `removed_lines` and decrement counts as each matching added line is consumed, so only as many added occurrences as were actually removed get masked; any additional occurrences beyond the original count must remain marked as new (`+`) and be reviewed. This mirrors the Solady fix's approach of validating the actual number/position of occurrences rather than relying on content aliasing.

### Proof of Concept
1. Start with a file containing exactly one occurrence of a distinctive line, e.g. `run_shell(cmd)`.
2. Have the agent (or a prompt-injection-driven edit) fully rewrite the file via `Write`, keeping that one line but adding a second, new call to `run_shell(cmd)` in a different function that now receives attacker-controlled `cmd` from a new, unsafe source.
3. `git diff` against baseline shows the file as fully removed then fully re-added (standard `Write` full-rewrite diff shape).
4. `filter_preexisting_from_diff()` builds `removed_lines = {..., "run_shell(cmd)", ...}` and iterates the two added `run_shell(cmd)` lines; because `"run_shell(cmd)" in removed_lines` is `True` for both, both are converted to context lines.
5. The diff handed to `analyze_code_security()` no longer shows either `run_shell(cmd)` line as a `+` addition; per the reviewer prompt's explicit instruction to ignore context lines, the newly introduced dangerous call is never flagged, and the Stop hook's `_skip`/no-finding path allows the turn to complete without a security warning.

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

**File:** plugins/security-guidance/hooks/gitutil.py (L668-692)
```python
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

**File:** plugins/security-guidance/hooks/llm.py (L750-761)
```python
    if is_diff:
        diff_instruction = """Note: You are reviewing a unified diff. Unmarked lines (starting with a space) are UNCHANGED context — they were already in the file before this session. Lines starting with + are ADDITIONS made in this session. Lines starting with - are REMOVALS.

CRITICAL: ONLY flag vulnerabilities that are NEWLY INTRODUCED in + lines. Do NOT flag:
- Issues in unmarked context lines (space-prefixed = pre-existing code). Even if a context line contains SECRET_KEY = 'hardcoded', DEBUG=True, hardcoded passwords, SQL injection, or any other vulnerability — it is PRE-EXISTING and must be ignored.
- Issues where the SAME pattern existed in the removed (-) lines and was re-added in + lines (this means the code was rewritten/reformatted but the pattern is pre-existing)
- Pre-existing patterns that Claude simply preserved when rewriting a file
- Any vulnerability whose vulnerable code snippet appears in context (space-prefixed) lines
- Vulnerabilities in the ORIGINAL/STARTER code that the developer was given to work with. If a file was fully rewritten (all lines show as - then +), compare the + content against the - content. Only flag NEWLY INTRODUCED patterns that did NOT exist in the - lines.
- Issues OUTSIDE THE SCOPE of what the developer was asked to do. If the task was "add logging middleware" and the starter code has a hardcoded SECRET_KEY, that is pre-existing and out of scope — do NOT flag it.

A vulnerability is ONLY new if the + lines introduce a pattern that did NOT exist anywhere in the - lines or context lines of the same file.
```
