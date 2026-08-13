### Title
`RuleEngine._extract_field` cannot resolve `old_text`/`old_string` (or `new_string`) for `MultiEdit`, letting equivalent tool calls silently evade content-based block rules - (File: `plugins/hookify/core/rule_engine.py`)

### Summary
`RuleEngine._check_condition` relies on `_extract_field` to pull the value of a condition's `field` out of `tool_input`. For the `MultiEdit` tool, `_extract_field` only implements `file_path` and `new_text`/`content` (concatenated across all edits); it has no branch for `old_text`/`old_string`, and the `new_text`/`content` branch is also the only representation supported (it doesn't recognize `new_string`, which `Edit`-targeted rules commonly use). Any rule that keys off `old_text`, `old_string`, or `new_string` will always receive `None` for `MultiEdit` operations, causing the condition — and therefore the whole rule — to silently fail to match even though the identical dangerous content change is being made.

### Finding Description
`hookify` documents (`plugins/hookify/skills/writing-rules/SKILL.md` lines 43-44, 88, 370) that the `file` event and its conditions cover `Edit`, `Write`, and `MultiEdit` uniformly, and lists `old_text` as a valid field for file rules.

The actual extraction logic in `_extract_field` is tool-specific and inconsistent between `Edit`/`Write` and `MultiEdit`: [1](#0-0) 

For `Edit`/`Write`, `old_text`/`old_string` maps to `tool_input.get('old_string', '')`, and `new_text`/`new_string` maps to `tool_input.get('new_string', '')`. For `MultiEdit`, however, only `file_path` and `new_text`/`content` (aggregated from the `edits` list) are handled — there is no case for `old_text`, `old_string`, or the literal field name `new_string`.

In `_check_condition`, when `_extract_field` returns `None` the condition is unconditionally treated as not matching: [2](#0-1) 

Because `_rule_matches` requires *all* conditions to match, a single unresolved `old_text`/`old_string`/`new_string` condition on a `MultiEdit` call makes the whole rule silently fail: [3](#0-2) 

Exploit flow: a project defines a hookify block rule intended to catch dangerous content changes, e.g. removing an `if is_admin` check or reverting a fix, using `field: old_text` (a documented, valid field per `SKILL.md`) with `tool_matcher` covering file edits. When the same textual edit is performed via the `Edit` tool, the rule correctly extracts `old_string` and blocks it. When the exact same edit is performed via `MultiEdit` (which Claude Code — or an attacker steering it via prompt injection in repository content — can freely choose over `Edit` for functionally identical edits), `_extract_field` returns `None` for the `old_text` field, `_check_condition` returns `False`, and `evaluate_rules` returns `{}` (no block, no warning), allowing the dangerous change through undetected.

### Impact Explanation
This breaks the stated invariant "a matching block rule must reliably deny the protected operation." Any hookify rule that a repo/organization writes to gate sensitive file edits by inspecting the removed text (`old_text`/`old_string`) — a documented and reasonable pattern (e.g., blocking removal of security checks, blocking deletion of `.gitignore` entries, blocking removal of validation code) — can be bypassed purely by having the edit performed with `MultiEdit` instead of `Edit`, with no change to tool_matcher or attacker privilege needed. This matches "Security-control bypass that silently disables or routes around blocking, review, or permission boundaries," since the block silently fails to fire (no error, no warning) rather than failing safe.

### Likelihood Explanation
Highly feasible and repeatable: no special privileges are needed beyond the ability to have the assistant use `MultiEdit` (a standard tool available in normal Claude Code flows) rather than `Edit` for the same file change. This requires no exploitation of the YAML parser or `tool_matcher` string, is fully deterministic, and reproduces on every invocation given a rule using `old_text`/`old_string`/`new_string` fields against `MultiEdit`.

### Recommendation
Make `_extract_field`'s `MultiEdit` branch symmetric with `Edit`/`Write`: support `old_text`/`old_string` (aggregated across `edits[].old_string`) and accept `new_string` as an alias for `new_text`/`content`, so condition semantics are identical regardless of which tool performed the edit. Consider centralizing field-name normalization (aliasing `new_text`↔`new_string`, `old_text`↔`old_string`) in one place shared by all file-editing tools to prevent this class of divergence from recurring.

### Proof of Concept
Unit test added to `plugins/hookify/core/rule_engine.py` test harness (or a new `test_rule_engine.py`):
```python
rule = Rule(
    name="block-remove-admin-check",
    enabled=True,
    event="file",
    tool_matcher="Edit|MultiEdit",
    action="block",
    conditions=[
        Condition(field="old_text", operator="contains", pattern="is_admin")
    ],
    message="Removing admin check!"
)
engine = RuleEngine()

# Case 1: via Edit -> should block
edit_input = {
    "tool_name": "Edit",
    "tool_input": {"file_path": "app.py", "old_string": "if is_admin:", "new_string": ""}
}
assert engine.evaluate_rules([rule], edit_input) != {}   # blocked as expected

# Case 2: identical change via MultiEdit -> currently NOT blocked (bug)
multiedit_input = {
    "tool_name": "MultiEdit",
    "tool_input": {
        "file_path": "app.py",
        "edits": [{"old_string": "if is_admin:", "new_string": ""}]
    }
}
result = engine.evaluate_rules([rule], multiedit_input)
assert result != {}, "MultiEdit bypasses old_text-based block rule"  # currently fails, proving the bypass
```
Expected: with the current code, the second assertion fails because `evaluate_rules` returns `{}` for the `MultiEdit` case, demonstrating that the identical dangerous edit is not blocked when performed via `MultiEdit` instead of `Edit`.

### Citations

**File:** plugins/hookify/core/rule_engine.py (L120-125)
```python
        # All conditions must match
        for condition in rule.conditions:
            if not self._check_condition(condition, tool_name, tool_input, input_data):
                return False

        return True
```

**File:** plugins/hookify/core/rule_engine.py (L157-160)
```python
        # Extract the field value to check
        field_value = self._extract_field(condition.field, tool_name, tool_input, input_data)
        if field_value is None:
            return False
```

**File:** plugins/hookify/core/rule_engine.py (L235-252)
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

        elif tool_name == 'MultiEdit':
            if field == 'file_path':
                return tool_input.get('file_path', '')
            elif field in ['new_text', 'content']:
                # Concatenate all edits
                edits = tool_input.get('edits', [])
                return ' '.join(e.get('new_string', '') for e in edits)
```
