### Title
Pattern-based content rules silently skipped for `NotebookEdit` and other unhandled tool shapes despite hook firing - ([File: plugins/security-guidance/hooks/security_reminder_hook.py])

### Summary
The PostToolUse hook is explicitly wired to fire on `NotebookEdit` (and any other write-capable tool matching the hooks.json matcher), but `extract_content_from_input()` only knows how to pull code content out of `Write`, `Edit`, and `MultiEdit` tool_input shapes. For any other tool name — including `NotebookEdit`, which is in the same PostToolUse matcher — the function falls through to `return ""`, so `check_patterns(file_path, '')` only evaluates path-based rules and silently skips every substrings/regex rule (`child_process_exec`, `eval_injection`, `pickle_deserialization`, etc.).

### Finding Description
`hooks.json` registers the PostToolUse hook with `"matcher": "Edit|Write|MultiEdit|NotebookEdit"` [1](#0-0) , so Claude Code does dispatch `security_reminder_hook.py` for `NotebookEdit` calls. Inside the hook, content to scan is derived via `extract_content_from_input(tool_name, tool_input)`:

```
def extract_content_from_input(tool_name, tool_input):
    if tool_name == "Write":
        return tool_input.get("content", "")
    elif tool_name == "Edit":
        return tool_input.get("new_string", "")
    elif tool_name == "MultiEdit":
        edits = tool_input.get("edits", [])
        if edits:
            return " ".join(edit.get("new_string", "") for edit in edits)
        return ""
    return ""
``` [2](#0-1) 

`NotebookEdit`'s tool_input uses different field names (e.g. `new_source`/`cell_type`), which are not enumerated, so the function returns `''` for that call path. `check_patterns()` then only evaluates `path_check`/`path_filter` rules; all `substrings`/`regex` conditions are gated by `if ... and content:` and are skipped entirely when content is empty:

```
if not matched and "substrings" in pattern and content:
    ...
if not matched and "regex" in pattern and content:
    ...
``` [3](#0-2) 

No fallback, warning, or "unknown write tool" flag exists for this case — the hook exits normally as if the content were clean. This is a genuine gap in the hardcoded tool-name allowlist versus the actual matcher-enumerated set of tools that invoke the hook (`hooks.json` explicitly includes `NotebookEdit`, but the Python enumeration does not).

### Impact Explanation
Dangerous code (e.g., `subprocess`/`eval`/`pickle.loads` patterns) written into a Jupyter notebook cell via `NotebookEdit` bypasses all content-based pattern detection, defeating the plugin's core security-guidance purpose for a tool that Claude Code natively supports and that the plugin's own hooks.json matcher targets. This is a scoped detection/guard bypass in a security-tooling plugin rather than an RCE or sandbox escape, matching a "guard enforcement bound to a hardcoded allowlist instead of the true set of file-mutating tool paths" class of finding.

### Likelihood Explanation
Highly feasible and fully repeatable: `NotebookEdit` is a standard first-party Claude Code tool already enumerated in the plugin's own `hooks.json` matcher, so no unusual configuration or attacker privilege is required — any session in which Claude uses `NotebookEdit` to write unsafe code into a notebook cell reliably hits this gap.

### Recommendation
Extend `extract_content_from_input` to handle `NotebookEdit` (map its `new_source`/relevant field) and any other tools present in the PostToolUse matcher, or better, derive supported tool names from the same list used to build the hooks.json matcher so the two never drift apart. Consider also emitting a debug/telemetry signal (not necessarily blocking) when a matched tool name has no known content-extraction branch, so future tool-shape additions don't silently degrade coverage.

### Proof of Concept
Integration test:
1. Simulate a PostToolUse event with `tool_name="NotebookEdit"` and `tool_input={"notebook_path": "x.ipynb", "cell_id": "1", "new_source": "import subprocess; subprocess.call(['rm','-rf','/'])", "cell_type": "code"}`.
2. Call `extract_content_from_input("NotebookEdit", tool_input)` and assert it returns `''` (demonstrating the gap).
3. Call `check_patterns(file_path, extract_content_from_input(...))` and assert none of the `substrings`/`regex`-based rules (e.g. `child_process_exec`) fire, even though the same content passed through `check_patterns(file_path, tool_input["new_source"])` directly does fire.
4. Assert this contradicts expected behavior: the fix should make step 2 return the actual code content (or the hook should flag "unrecognized tool content" rather than silently returning empty).

### Citations

**File:** plugins/security-guidance/hooks/hooks.json (L25-34)
```json
    "PostToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bash \"${CLAUDE_PLUGIN_ROOT}/hooks/sg-python.sh\" \"${CLAUDE_PLUGIN_ROOT}/hooks/security_reminder_hook.py\""
          }
        ],
        "matcher": "Edit|Write|MultiEdit|NotebookEdit"
      },
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L411-422)
```python
        if not matched and "substrings" in pattern and content:
            for substring in pattern["substrings"]:
                if substring in content:
                    matched = True
                    break

        if not matched and "regex" in pattern and content:
            try:
                if re.search(pattern["regex"], content):
                    matched = True
            except Exception:
                pass
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L429-440)
```python
def extract_content_from_input(tool_name, tool_input):
    """Extract content to check from tool input based on tool type."""
    if tool_name == "Write":
        return tool_input.get("content", "")
    elif tool_name == "Edit":
        return tool_input.get("new_string", "")
    elif tool_name == "MultiEdit":
        edits = tool_input.get("edits", [])
        if edits:
            return " ".join(edit.get("new_string", "") for edit in edits)
        return ""
    return ""
```
