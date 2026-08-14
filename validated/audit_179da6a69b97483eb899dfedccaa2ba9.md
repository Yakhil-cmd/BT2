### Title
Content-based (not position-based) pre-existing-line filtering in `filter_preexisting_from_diff` lets attacker-injected `+` lines be masked as pre-existing context, hiding new vulnerabilities from the Stop-hook LLM review - ([File: plugins/security-guidance/hooks/gitutil.py])

### Summary
`filter_preexisting_from_diff` reclassifies a `+` line as pre-existing context whenever its `.strip()`'d text matches *any* `-` line's stripped text anywhere in the file, regardless of line position or surrounding context. An attacker who controls file content via a full-file `Write` (e.g. a malicious subagent, tool response, or MCP-returned content applied by Claude) can place a genuinely new dangerous line whose stripped text duplicates an unrelated pre-existing line that also gets removed in the same full-file rewrite, causing the filter to demote the malicious `+` line to a space-prefixed context line before it ever reaches the LLM reviewer.

### Finding Description
`get_git_diff` (`plugins/security-guidance/hooks/gitutil.py:391-427`) produces a standard unified diff of the working tree against the turn's baseline SHA. When the `Write` tool fully rewrites a file, git's diff algorithm often shows large contiguous blocks of `-` (old) lines followed by `+` (new) lines rather than fine-grained context matching, because the entire blob changed.

`filter_preexisting_from_diff` (`plugins/security-guidance/hooks/gitutil.py:657-722`) is meant to compensate for this by detecting lines that are unchanged text but appear as `-`/`+` pairs due to the rewrite, and converting the corresponding `+` lines back to context so the "LLM reviewer only sees truly new code" (per its own docstring). Its matching is purely content-based: [1](#0-0) 

- `removed_lines` is a **set** of all `.strip()`'d `-` line contents in the whole file diff (no positional pairing).
- Any `+` line whose stripped content is in `removed_lines` is rewritten with a leading space, turning it into a context line: `plugins/security-guidance/hooks/gitutil.py:701-716`.

The function's own comment acknowledges the imprecision: `.strip()` ignores indentation and "the set lets one removal mask N additions of the same stripped text" (`plugins/security-guidance/hooks/gitutil.py:694-700`), but treats this only as an accepted trade-off for the common Write-rewrite case, not as a security boundary.

Exploit flow:
1. Attacker-controlled content (via `Write`) fully rewrites a tracked file that already contains some generic/boilerplate line, or a currently-benign occurrence of a dangerous call (e.g. `subprocess.run(cmd, shell=True)` inside unreachable/dead code, or simply a common string that recurs elsewhere in the file).
2. Because the file is fully rewritten, git shows essentially the whole old file as `-` and the whole new file as `+`.
3. The attacker inserts a **new**, reachable, malicious line whose `.strip()`'d text is identical to some **unrelated** `-` line elsewhere in the file (the harmless/dead occurrence, a comment, or any boilerplate text that also got removed).
4. `filter_preexisting_from_diff` finds this stripped text in `removed_lines` and rewrites the attacker's new `+` line as a space-prefixed context line.
5. The stripped-down diff goes to `analyze_code_security` (`plugins/security-guidance/hooks/llm.py`), whose diff-review prompt explicitly instructs: "Do NOT flag: Issues in unmarked context lines (space-prefixed = pre-existing code)... it is PRE-EXISTING and must be ignored" (`plugins/security-guidance/hooks/llm.py:751-761`).
6. The LLM reviewer, following its own instructions, skips the line. `handle_stop_hook` (`plugins/security-guidance/hooks/security_reminder_hook.py:1846-1857`) then sees no finding and the Stop hook exits without blocking (`sys.exit(2)` only fires when `concrete_guidance` is non-empty).

Existing safeguards do not close this gap:
- The "EXCEPTION — data flow to pre-existing sinks" instruction in the prompt (`plugins/security-guidance/hooks/llm.py:763`) only helps when the sink line is visibly marked as **context** while the *call/data-flow* line is a visible `+` line. Here, the mechanical filter erases the `+` marking from the sink/malicious line itself, so the LLM has no signal at all that this exact line is new — it looks like ordinary unchanged code, defeating the exception's intended safety net.
- There is no positional/hunk-aware pairing, and no verification that the masked `+` line's surrounding lines were also matched from the same original hunk — a single unrelated boilerplate `-` line anywhere in the file is enough to mask arbitrarily many new attacker `+` lines with the same stripped text.

### Impact Explanation
This is a trust-boundary bypass of the plugin's core enforcement mechanism: the Stop-hook LLM security review is the gate that is supposed to catch dangerous code introduced during a session and force Claude to fix it (`sys.exit(2)`). By exploiting `filter_preexisting_from_diff`'s content-based masking, an attacker (via any Claude Code compromise path that can influence file content applied through `Write`, e.g. malicious subagent output, poisoned tool/MCP response) can get newly introduced vulnerable code (command injection, hardcoded secrets reused verbatim, SSRF, etc.) mechanically hidden from the LLM reviewer, allowing unsafe code to be smuggled past the review gate silently. This matches the "approval/validation bypass allowing unsafe code to pass automated security review" impact category for Claude Code's security-guidance plugin.

### Likelihood Explanation
Preconditions are realistic and already assumed by the audit scope: attacker-controlled content reaching a `Write` tool call during a session (malicious subagent, tool/MCP response text applied verbatim by Claude), and a full-file rewrite of a pre-existing tracked file (common when refactoring or regenerating a file). Constructing a duplicate stripped-text line is trivial — many code files already contain repeatable boilerplate (`pass`, `return None`, `except Exception:`, common imports, log statements, or example/comment text) that an attacker can reuse verbatim as their malicious payload text or intentionally duplicate. No special privileges beyond normal file-write capability within the session are required, and the technique is fully repeatable/deterministic (it depends only on git's diff output and a pure string-set matching algorithm).

### Recommendation
Replace the content-only set matching in `filter_preexisting_from_diff` with position-aware / hunk-aware matching, e.g.:
- Only treat a `+` line as pre-existing when it can be matched 1:1 (not many-to-one) against a `-` line, e.g. via a sequence alignment (like Python's `difflib.SequenceMatcher`) between the removed and added blocks of the same hunk, so duplicated generic text can mask at most one corresponding line.
- Additionally require that masked lines are not adjacent to/interleaved with other newly added lines that materially change control flow reaching that line (or drop the masking entirely and instead rely on `full_context` diffing plus letting the LLM's own "pre-existing" instructions do the semantic filtering, since mechanical demotion strips information the LLM needs).
- At minimum, cap how many `+` lines a single `-` line's stripped text can mask (e.g. 1:1) to eliminate the explicitly-acknowledged "one removal masks N additions" weakness.

### Proof of Concept
Unit test in the style of the existing `gitutil` test suite, targeting `filter_preexisting_from_diff`:

```python
def test_filter_preexisting_does_not_mask_new_dangerous_line_with_duplicate_text():
    # Simulates a full-file Write rewrite: the old file had a benign/dead
    # occurrence of a dangerous call; the attacker's rewrite keeps that dead
    # occurrence AND adds a genuinely new, reachable call with identical text.
    diff_content = (
        "@@ -1,4 +1,5 @@\n"
        "-def dead_code():\n"
        "-    if False:\n"
        "-        subprocess.run(cmd, shell=True)\n"
        "-\n"
        "+def dead_code():\n"
        "+    if False:\n"
        "+        subprocess.run(cmd, shell=True)\n"
        "+\n"
        "+def handle_request(user_input):\n"
        "+    cmd = user_input\n"
        "+    subprocess.run(cmd, shell=True)\n"
    )
    diff_files = [("app.py", diff_content)]

    filtered = filter_preexisting_from_diff(diff_files, cwd=".", baseline_sha="HEAD")
    _, filtered_diff = filtered[0]

    # The attacker's NEW call site (inside handle_request) must still be
    # surfaced as an added (+) line to the reviewer, not silently converted
    # to context.
    new_call_lines = [
        line for line in filtered_diff.split("\n")
        if "subprocess.run(cmd, shell=True)" in line
    ]
    assert any(line.startswith("+") for line in new_call_lines), (
        "attacker-injected dangerous call was masked as pre-existing context "
        "even though it is reachable from a brand-new function"
    )
```

Expected current (vulnerable) behavior: both occurrences of `subprocess.run(cmd, shell=True)` get converted to `' '`-prefixed context lines because the stripped text is in `removed_lines`, so the assertion fails — demonstrating that the genuinely new, reachable, attacker-controlled sink call is hidden from the LLM security reviewer.

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
