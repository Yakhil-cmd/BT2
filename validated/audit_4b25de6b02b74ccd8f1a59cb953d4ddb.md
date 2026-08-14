### Title
Hookify `file` event rules bypassed when dangerous content is written via a tool not covered by `_extract_field`/`_matches_tool` (e.g. `NotebookEdit`) - ([File: plugins/hookify/core/rule_engine.py])

### Finding Description
`RuleEngine._rule_matches` gates rule application on `_matches_tool`, which requires an **exact string match** of `tool_name` against the pipe-separated list in `rule.tool_matcher` (or the `event`→tool mapping done upstream in `pretooluse.py`/`posttooluse.py`, which only maps `Bash`→`bash` and `Edit`/`Write`/`MultiEdit`→`file`) [1](#0-0) [2](#0-1) . `_extract_field` then only knows how to pull semantic fields (`command`, `content`, `new_text`/`new_string`, `old_text`/`old_string`, `file_path`) for the tool names `Bash`, `Write`, `Edit`, and `MultiEdit` [3](#0-2) .

Any other Claude Code tool that can also mutate files or execute code — for example `NotebookEdit` (writes/replaces notebook cell source) — is not in this hardcoded list. Because of this:
1. A `file`-scoped rule (`event: file`, matching `Edit|Write|MultiEdit`) never fires for `NotebookEdit`, since `_matches_tool`/the upstream event filter only recognizes `Bash`, `Edit`, `Write`, `MultiEdit` [4](#0-3) .
2. Even a rule with `tool_matcher: "*"` checking `field: new_text` or `field: content` fails to extract any value for `NotebookEdit`, because the direct-field lookup (`if field in tool_input`) only succeeds if the tool's actual JSON key literally matches the rule's `field` name, and the tool-specific fallback branch does not include `NotebookEdit` at all [5](#0-4) . `_extract_field` returns `None` and `_check_condition` treats that as non-match, so the rule silently never blocks [6](#0-5) .

The user-facing skill documentation reinforces the (incomplete) mental model that "file" events cover "Edit/Write/MultiEdit" only, with no mention of `NotebookEdit` or other content-writing tools [7](#0-6) , meaning rule authors reasonably believe a `pattern: eval\(` or `event: file` block rule protects "all file edits," when in fact it only recognizes one fixed representation of "editing a file."

An attacker (via prompt injection embedded in repository content, an issue/PR, or an MCP tool response) that induces the agent to perform the same dangerous write through `NotebookEdit` instead of `Write`/`Edit` completely evades any hookify block/warn rule aimed at file-content or dangerous-pattern protection, even though the resulting artifact (a `.ipynb` file containing the malicious code/string) is functionally equivalent to a bypassed `Write`/`Edit`.

Additionally, `MultiEdit` content extraction concatenates all edits' `new_string` values with a single space (`' '.join(...)`) [8](#0-7) , so a dangerous pattern (e.g. `eval(`, `rm\s+-rf`) split across two `MultiEdit` edit entries can fail to match a regex that expects the pattern as a contiguous substring, providing a second, related bypass technique within the same function that is reachable purely by how the attacker structures a normal `MultiEdit` tool call.

### Impact Explanation
This is a genuine Security-control bypass: hookify's blocking rules are the mechanism repo maintainers rely on to deny dangerous Bash commands or file edits (e.g. blocking `eval(`, secrets in `.env`, `rm -rf`). Because the rule engine's tool/field coverage is incomplete and hardcoded, an attacker who can influence which tool the agent uses (via prompt injection from untrusted repo content) can silently route the exact same dangerous operation around a configured `block` rule, defeating the review/permission boundary the plugin is meant to enforce, without triggering any warning or block message.

### Likelihood Explanation
Feasible under the plugin's own threat model: any workflow where an agent processes untrusted repository content (issues, PR text, files) and is nudged to prefer `NotebookEdit` over `Write`/`Edit`, or to split a dangerous edit across multiple `MultiEdit` fragments, achieves the bypass with no special privileges — it only requires the ordinary hook input schema for those tools. It is fully repeatable since the gap is structural (hardcoded tool/field list), not a race condition or timing issue.

### Recommendation
- Make `_extract_field` field extraction schema-driven/generic rather than hardcoded per tool name: fall back to a configurable map of tool→field aliases that includes `NotebookEdit` (`new_source`/`source`), and any other content-producing tools, or better, attempt extraction from all plausible keys regardless of `tool_name`.
- Change `_matches_tool`/event mapping to treat unknown-but-content-producing tools conservatively (e.g., default unclassified tools that mutate files to the `file` event) rather than silently excluding them.
- For `MultiEdit`, evaluate each edit's `new_string` individually against conditions (or join without a separator / preserve original adjacency) so cross-edit pattern splitting cannot evade regex/contains checks.
- Document explicitly in `SKILL.md` which tools are (and are not) covered by `event: file`, and add tests enumerating all Claude Code tools capable of writing content.

### Proof of Concept
Unit test to add to `plugins/hookify/core/rule_engine.py` test suite:
```python
def test_notebookedit_bypasses_file_rule():
    rule = Rule(
        name="block-eval",
        enabled=True,
        event="file",
        tool_matcher="Edit|Write|MultiEdit",
        conditions=[Condition(field="new_text", operator="regex_match", pattern=r"eval\(")],
        action="block",
        message="eval() blocked"
    )
    engine = RuleEngine()

    # Baseline: Edit tool is correctly blocked
    edit_input = {"tool_name": "Edit", "tool_input": {"file_path": "a.py", "old_string": "x", "new_string": "eval(x)"}}
    assert engine.evaluate_rules([rule], edit_input).get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

    # NotebookEdit performs an equivalent dangerous write but is NOT blocked
    notebook_input = {"tool_name": "NotebookEdit", "tool_input": {"notebook_path": "n.ipynb", "cell_id": "1", "new_source": "eval(x)"}}
    result = engine.evaluate_rules([rule], notebook_input)
    assert result == {}  # BUG: should also deny, but silently allows

def test_multiedit_split_pattern_bypass():
    rule = Rule(
        name="block-eval",
        enabled=True,
        event="file",
        tool_matcher="MultiEdit",
        conditions=[Condition(field="new_text", operator="regex_match", pattern=r"eval\(")],
        action="block",
        message="eval() blocked"
    )
    engine = RuleEngine()
    multiedit_input = {
        "tool_name": "MultiEdit",
        "tool_input": {"file_path": "a.py", "edits": [
            {"old_string": "a", "new_string": "eval"},
            {"old_string": "b", "new_string": "(x)"},
        ]}
    }
    result = engine.evaluate_rules([rule], multiedit_input)
    assert result == {}  # BUG: joined as "eval (x)" fails eval\( regex, silently allows
```
Both assertions demonstrate that a block rule intended to deny dangerous content is bypassed purely by choosing an equivalent, uncovered representation of the same operation (different tool, or fragmented edits), confirming the invariant violation.

### Citations

**File:** plugins/hookify/core/rule_engine.py (L127-142)
```python
    def _matches_tool(self, matcher: str, tool_name: str) -> bool:
        """Check if tool_name matches the matcher pattern.

        Args:
            matcher: Pattern like "Bash", "Edit|Write", "*"
            tool_name: Actual tool name

        Returns:
            True if matches
        """
        if matcher == '*':
            return True

        # Split on | for OR matching
        patterns = matcher.split('|')
        return tool_name in patterns
```

**File:** plugins/hookify/core/rule_engine.py (L158-160)
```python
        field_value = self._extract_field(condition.field, tool_name, tool_input, input_data)
        if field_value is None:
            return False
```

**File:** plugins/hookify/core/rule_engine.py (L195-254)
```python
        # Direct tool_input fields
        if field in tool_input:
            value = tool_input[field]
            if isinstance(value, str):
                return value
            return str(value)

        # For Stop events and other non-tool events, check input_data
        if input_data:
            # Stop event specific fields
            if field == 'reason':
                return input_data.get('reason', '')
            elif field == 'transcript':
                # Read transcript file if path provided
                transcript_path = input_data.get('transcript_path')
                if transcript_path:
                    try:
                        with open(transcript_path, 'r') as f:
                            return f.read()
                    except FileNotFoundError:
                        print(f"Warning: Transcript file not found: {transcript_path}", file=sys.stderr)
                        return ''
                    except PermissionError:
                        print(f"Warning: Permission denied reading transcript: {transcript_path}", file=sys.stderr)
                        return ''
                    except (IOError, OSError) as e:
                        print(f"Warning: Error reading transcript {transcript_path}: {e}", file=sys.stderr)
                        return ''
                    except UnicodeDecodeError as e:
                        print(f"Warning: Encoding error in transcript {transcript_path}: {e}", file=sys.stderr)
                        return ''
            elif field == 'user_prompt':
                # For UserPromptSubmit events
                return input_data.get('user_prompt', '')

        # Handle special cases by tool type
        if tool_name == 'Bash':
            if field == 'command':
                return tool_input.get('command', '')

        elif tool_name in ['Write', 'Edit']:
            if field == 'content':
                # Write uses 'content', Edit has 'new_string'
                return tool_input.get('content') or tool_input.get('new_string', '')
            elif field == 'new_text' or field == 'new_string':
                return tool_input.get('new_string', '')
            elif field == 'old_text' or field == 'old_string':
                return tool_input.get('old_string', '')
            elif field == 'file_path':
                return tool_input.get('file_path', '')

        elif tool_name == 'MultiEdit':
            if field == 'file_path':
                return tool_input.get('file_path', '')
            elif field in ['new_text', 'content']:
                # Concatenate all edits
                edits = tool_input.get('edits', [])
                return ' '.join(e.get('new_string', '') for e in edits)

        return None
```

**File:** plugins/hookify/hooks/pretooluse.py (L42-49)
```python
        # For PreToolUse, we use tool_name to determine "bash" vs "file" event
        tool_name = input_data.get('tool_name', '')

        event = None
        if tool_name == 'Bash':
            event = 'bash'
        elif tool_name in ['Edit', 'Write', 'MultiEdit']:
            event = 'file'
```

**File:** plugins/hookify/skills/writing-rules/SKILL.md (L147-149)
```markdown
### file Events

Match Edit/Write/MultiEdit operations:
```
