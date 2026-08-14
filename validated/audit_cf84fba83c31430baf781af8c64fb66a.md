### Title
`filter_preexisting_from_diff` uses exact stripped-line matching (not semantic/positional) to mark diff lines as "pre-existing," letting an attacker-planted baseline mask genuinely new vulnerable code from the Stop-hook LLM review - ([File: plugins/security-guidance/hooks/gitutil.py])

### Summary
`filter_preexisting_from_diff` (gitutil.py:657-722) decides whether an added `+` line is "pre-existing" purely by checking if its whitespace-stripped text is present in the set of whitespace-stripped removed `-` lines from the same diff, with no regard to surrounding context, reachability, or hunk position. An attacker who controls repository content (e.g., a cloned/forked repo, dead code, comments, or string literals) can seed textually-identical "boilerplate" that later gets removed-and-readded as part of a real edit, causing `handle_stop_hook` to demote genuinely new, dangerous lines to context and strip them from what `analyze_code_security` sees.

### Finding Description
`handle_stop_hook` computes the diff since `baseline_sha` (captured at UserPromptSubmit via `capture_git_baseline`), parses it with `parse_diff_into_files`, and then calls: [1](#0-0) 
to strip pre-existing content before invoking `analyze_code_security`.

The filter itself works purely on line-text set membership: [2](#0-1) 
and converts matched `+` lines to context (hiding them from the reviewer) and drops the matching `-` lines: [3](#0-2) 

The code's own comment acknowledges the imprecision as an accepted trade-off: [4](#0-3) 

This comment frames the risk as benign (reindented code being treated as unchanged), but the same mechanism is adversarially exploitable: if a repository (attacker-controlled content, e.g. a forked/cloned project or content influenced via prompt injection) contains a "baseline" occurrence of a dangerous-looking line — e.g. buried in an unreachable branch, comment, or string literal — that line will land in `removed_lines` when the file is subsequently rewritten (the Write tool triggers whole-file rewrites that frequently manifest as full remove+add blocks, which is exactly the scenario this function was built to handle, per its docstring at gitutil.py:657-664). If Claude's real edit later reintroduces the *exact same stripped text* in a genuinely dangerous, reachable context (e.g., moving the line out of the dead branch, or reusing the same call signature verbatim), `filter_preexisting_from_diff` matches on text alone and converts that `+` line to a context line — removing it from the diff payload sent to `analyze_code_security`. Nothing in the review pipeline compensates for this: the matching has no concept of surrounding lines, function/branch reachability, or semantic diff meaning.

### Impact Explanation
This blinds the Stop-hook's LLM-based security review (`analyze_code_security`) to a real, newly introduced vulnerability whenever its line text overlaps with attacker-planted baseline boilerplate. Since the Stop hook is a primary enforcement point that forces Claude to fix flagged issues (exit code 2 + `sys.exit(2)` at security_reminder_hook.py:1946-1947), suppressing its findings is a direct security-review bypass — the review coverage silently fails to track the true content diff, exactly the invariant the question calls out.

### Likelihood Explanation
Requires the attacker to control repository content the victim clones/works in (ordinary repo content — in scope) and for the victim's Claude session to perform a full-file rewrite (Write tool) that reintroduces attacker-planted text verbatim in a dangerous new context. This is a plausible but non-trivial precondition: it depends on git's diff algorithm actually emitting the planted line as part of a `-`/`+` block (not matched as unchanged context by the LCS diff), and on the malicious edit reusing identical (stripped) text rather than paraphrased code. Feasibility is moderate — the trade-off is explicitly acknowledged in the code as a known imprecision, but its adversarial framing (deliberate baseline poisoning) does not appear to have been considered/mitigated.

### Recommendation
Replace the pure line-text-set matching with a position/hunk-aware or AST/semantic diff so that only lines that are truly unchanged (same content **and** same structural role/location, e.g. via a proper diff/patience algorithm comparison of old-file vs new-file rather than the git-produced remove/add blocks) are treated as pre-existing. At minimum, require the matched removed and added lines to be part of a contiguous unchanged block already recognized by git's own diff (i.e., don't do a second pass of text-only matching across the whole file/diff) and log/flag when a "same-text" match is used to suppress a diff line so it can be independently audited or backstopped by a dedicated review pass.

### Proof of Concept
Unit test targeting `filter_preexisting_from_diff` directly:
1. Construct a synthetic diff (`diff_files`) for one file where:
   - Baseline (removed, `-`) contains an unreachable/dead line, e.g. `    exec(user_input)  # unreachable, guarded by if False`, stripped text `exec(user_input)  # unreachable, guarded by if False` — actually use identical *stripped* text on both sides, e.g. removed line `if False:` + `    exec(user_input)`, added lines `if user_controlled:` + `    exec(user_input)`.
2. Call `filter_preexisting_from_diff([(file_path, diff_content)], cwd, baseline_sha)`.
3. Assert that the resulting diff still contains `+    exec(user_input)` as an added (`+`) line rather than being converted to a context line — i.e., assert `"+" + " exec(user_input)".strip()` (or equivalent) is present in the filtered diff, proving the newly-reachable dangerous line is not silently dropped from review.
4. A failing assertion (line converted to context/removed) demonstrates the bypass: the same PoC can be extended to run through `handle_stop_hook`/`analyze_code_security` end-to-end (with a stubbed LLM) to confirm the vulnerable line never reaches the reviewer prompt.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1846-1847)
```python
    # Filter out pre-existing content from file rewrites
    diff_files = filter_preexisting_from_diff(diff_files, cwd, baseline_sha)
```

**File:** plugins/security-guidance/hooks/gitutil.py (L670-691)
```python
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

**File:** plugins/security-guidance/hooks/gitutil.py (L701-720)
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
            else:
                new_lines.append(line)

        filtered.append((file_path, '\n'.join(new_lines)))
```
