### Title
`RuleEngine._extract_field` silently fails to extract `old_text`/`old_string` for `MultiEdit`, letting matching block rules miss dangerous edits performed via `MultiEdit` - (File: `plugins/hookify/core/rule_engine.py`)

### Summary
`RuleEngine._extract_field` has explicit per-tool branches to derive condition fields for `Bash`, `Write`/`Edit`, and `MultiEdit`, but the `MultiEdit` branch only implements `file_path` and `new_text`/`content` extraction — it never implements `old_text`/`old_string`. A hookify rule authored to block dangerous edits by inspecting the text being removed/replaced (`old_string`) will match when the agent uses `Edit`, but will never match the semantically identical operation performed via `MultiEdit`, because `_extract_field` returns `None` for that field and `_check_condition` treats `None` as non-matching. [1](#0-0) [2](#0-1) 

### Finding Description
`_rule_matches` first checks `rule.tool_matcher` against `tool_name` via `_matches_tool`, which for a matcher like `"Edit|Write|MultiEdit"` simply checks `tool_name in patterns` — all three tool names are treated as equivalent, interchangeable representations of "a file edit." [3](#0-2) 

For each condition, `_check_condition` calls `_extract_field(condition.field, tool_name, tool_input, input_data)`, and if the returned value is `None`, the condition (and therefore the whole rule) fails to match, regardless of whether a dangerous pattern is actually present. [2](#0-1) 

In `_extract_field`, the `Write`/`Edit` branch explicitly supports `old_text`/`old_string` by reading `tool_input.get('old_string', '')`: [4](#0-3) 

But the `MultiEdit` branch only supports `file_path` and `new_text`/`content` (aggregated across the `edits` list) — there is no handling of `old_text`/`old_string`, and the generic direct-lookup at the top of the function (`if field in tool_input`) also cannot find it, since for `MultiEdit` the old/new strings live nested inside each dict of the `edits` list, not as a top-level `tool_input` key: [1](#0-0) [5](#0-4) 

As a result, `_extract_field` returns `None` for `field='old_text'`/`'old_string'` whenever `tool_name == 'MultiEdit'`, and the condition — and thus the entire block rule — silently fails to fire. A maintainer who writes a `.claude/hookify.*.local.md` rule such as `tool_matcher: "Edit|Write|MultiEdit"` with a condition on `old_string` (e.g., to block removal of a security check, guard clause, or credential-scrubbing line) believes the rule covers all three "file edit" tools equally, since `_matches_tool` treats them as interchangeable at the tool-name level. In reality, the same removal performed through `MultiEdit` bypasses the rule entirely because the field-extraction layer treats the three tools' `tool_input` shapes inconsistently. If the agent is steered (e.g. via prompt injection from repository/issue/PR content processed during normal operation) to prefer `MultiEdit` for the sensitive edit instead of `Edit`, the intended block never triggers, and `evaluate_rules` returns `{}` (allow), even though the exact same content mutation via `Edit` would have been denied. [6](#0-5) 

No other layer compensates for this: `PreToolUse`/`PostToolUse` hooks pass the raw `input_data` straight to `evaluate_rules` with no separate old-text normalization, and both hooks fail open (`sys.exit(0)` in a `finally` block) on any error, so there is no fallback denial. [7](#0-6) 

### Impact Explanation
This is a tool-matcher/field-extraction inconsistency that lets a "dangerous edit" evade an intended `block` rule purely by using `MultiEdit` instead of `Edit`, breaking the invariant that a matching block rule reliably denies the protected operation. This maps to unauthorized local file mutation bypassing the plugin's approval/deny control layer for edit operations that rely on `old_text`/`old_string` conditions. The impact is scoped to `MultiEdit`-based edits and only affects rules written to key on the removed/old content rather than the new content or file path — it does not affect `Bash` command blocking (`command` field is handled uniformly) nor rules keyed on `new_text`/`content`/`file_path`, which are correctly aggregated/extracted for `MultiEdit`.

### Likelihood Explanation
Requires: (1) a hookify block rule exists that inspects `old_text`/`old_string` with a tool matcher including `MultiEdit` (a reasonable and expected configuration, since the README/matcher semantics treat `Edit|Write|MultiEdit` as equivalent "file edit" tools), and (2) the agent performs the sensitive edit via `MultiEdit` rather than `Edit`. Since `MultiEdit` is a normal, unprivileged Claude Code tool the agent may choose for ordinary multi-location edits (and could be nudged toward via prompt-injected instructions in repo content), this is realistically reachable without any special privileges, and is deterministic/repeatable given the code path shown.

### Recommendation
In `_extract_field`, add `old_text`/`old_string` handling for `MultiEdit` analogous to `new_text`/`content`, e.g. aggregate `edits[i].get('old_string', '')` the same way `new_string` is aggregated, so that any condition field supported for `Edit`/`Write` is also supported for `MultiEdit`. More generally, refactor the per-tool field-extraction branches into a single field-name-to-extraction-strategy mapping shared across all "file edit" tools recognized by a given `tool_matcher`, so new/old content fields cannot silently diverge between tool variants again.

### Proof of Concept
Unit test to add to a hookify test suite (e.g. `test_rule_engine.py`):
```python
from hookify.core.config_loader import Rule, Condition
from hookify.core.rule_engine import RuleEngine

rule = Rule(
    name="block-remove-guard",
    enabled=True,
    event="file",
    tool_matcher="Edit|Write|MultiEdit",
    conditions=[Condition(field="old_string", operator="contains", pattern="SECURITY_CHECK")],
    action="block",
    message="Removing security check is not allowed",
)
engine = RuleEngine()

# Case 1: Edit tool - rule correctly blocks
edit_input = {
    "tool_name": "Edit",
    "tool_input": {"file_path": "a.py", "old_string": "if SECURITY_CHECK(): ...", "new_string": ""},
}
assert engine.evaluate_rules([rule], edit_input).get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

# Case 2: identical removal via MultiEdit - rule silently fails to block (bug)
multiedit_input = {
    "tool_name": "MultiEdit",
    "tool_input": {
        "file_path": "a.py",
        "edits": [{"old_string": "if SECURITY_CHECK(): ...", "new_string": ""}],
    },
}
result = engine.evaluate_rules([rule], multiedit_input)
assert result == {}, "MultiEdit bypassed the old_string block rule"  # demonstrates the bypass
```
Expected (fixed) behavior: both `Edit` and `MultiEdit` invocations removing the `SECURITY_CHECK` string should return a `deny` `hookSpecificOutput`. Current behavior: the `MultiEdit` case returns `{}` (allow), confirming the bypass via `_extract_field`'s missing `old_text`/`old_string` handling for `MultiEdit`.

### Citations

**File:** plugins/hookify/core/rule_engine.py (L93-94)
```python
        # No matches - allow operation
        return {}
```

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

**File:** plugins/hookify/core/rule_engine.py (L157-161)
```python
        # Extract the field value to check
        field_value = self._extract_field(condition.field, tool_name, tool_input, input_data)
        if field_value is None:
            return False

```

**File:** plugins/hookify/core/rule_engine.py (L195-200)
```python
        # Direct tool_input fields
        if field in tool_input:
            value = tool_input[field]
            if isinstance(value, str):
                return value
            return str(value)
```

**File:** plugins/hookify/core/rule_engine.py (L235-244)
```python
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
```

**File:** plugins/hookify/core/rule_engine.py (L246-254)
```python
        elif tool_name == 'MultiEdit':
            if field == 'file_path':
                return tool_input.get('file_path', '')
            elif field in ['new_text', 'content']:
                # Concatenate all edits
                edits = tool_input.get('edits', [])
                return ' '.join(e.get('new_string', '') for e in edits)

        return None
```

**File:** plugins/hookify/hooks/pretooluse.py (L35-70)
```python
def main():
    """Main entry point for PreToolUse hook."""
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)

        # Determine event type for filtering
        # For PreToolUse, we use tool_name to determine "bash" vs "file" event
        tool_name = input_data.get('tool_name', '')

        event = None
        if tool_name == 'Bash':
            event = 'bash'
        elif tool_name in ['Edit', 'Write', 'MultiEdit']:
            event = 'file'

        # Load rules
        rules = load_rules(event=event)

        # Evaluate rules
        engine = RuleEngine()
        result = engine.evaluate_rules(rules, input_data)

        # Always output JSON (even if empty)
        print(json.dumps(result), file=sys.stdout)

    except Exception as e:
        # On any error, allow the operation and log
        error_output = {
            "systemMessage": f"Hookify error: {str(e)}"
        }
        print(json.dumps(error_output), file=sys.stdout)

    finally:
        # ALWAYS exit 0 - never block operations due to hook errors
        sys.exit(0)
```
