### Title
Hookify tool matcher / field extractor treats Edit, Write, and MultiEdit inconsistently, letting MultiEdit bypass block rules - (File: plugins/hookify/core/rule_engine.py)

### Summary
`RuleEngine._matches_tool` performs a strict, exact-string membership check (`tool_name in patterns`) against the `tool_matcher` list, and `RuleEngine._extract_field` implements per-tool field extraction that is incomplete for `MultiEdit` (missing `old_text`/`old_string`, and `file_path`-only/`new_text`/`content` support). Because `Edit`, `Write`, and `MultiEdit` are functionally equivalent file-write primitives but are not treated as fully interchangeable by the engine, a block/warn rule authored against `Edit|Write` (or relying on the `old_text` field) can be silently bypassed by performing the identical dangerous file write/edit via `MultiEdit` instead.

### Finding Description
`_rule_matches` (`plugins/hookify/core/rule_engine.py:96-125`) first checks `rule.tool_matcher` via `_matches_tool` (`:127-142`), which does `tool_name in matcher.split('|')` — an exact string match with no normalization or knowledge that `Edit`, `Write`, and `MultiEdit` are equivalent write-capable tools. If a rule's `tool_matcher` is written as `"Edit|Write"` (a natural, documented pattern for "file" rules) but omits `MultiEdit`, then any request using the `MultiEdit` tool for the exact same write operation causes `_matches_tool` to return `False`, so `_rule_matches` short-circuits at line 112-113 and the rule never even reaches `_check_condition` — a matching block rule is silently skipped.

Separately, `_extract_field` (`:182-254`) hard-codes per-tool field support: for `Write`/`Edit` it supports `content`, `new_text`/`new_string`, `old_text`/`old_string`, and `file_path`, but for `MultiEdit` it only supports `file_path` and `new_text`/`content` (concatenated from `edits[].new_string`) — there is no `old_text`/`old_string` extraction for `MultiEdit` (`:246-252`). Since `_check_condition` immediately returns `False` when `field_value is None` (`:158-160`), any rule condition on `old_text`/`old_string` will never match when the acting tool is `MultiEdit`, even though `MultiEdit`'s `edits` array carries the same `old_string` data that `Edit` exposes directly.

An attacker who can influence Claude's tool choice (e.g., via prompt injection in repository content, issue/PR text, or other automation the agent reads) can induce the agent to prefer `MultiEdit` over `Edit`/`Write` when performing a sensitive file modification, causing user-configured hookify block rules scoped by `tool_matcher: "Edit|Write"` or keyed on the `old_text` field to be bypassed entirely, while the write still executes with `permissionDecision` allowed.

### Impact Explanation
This breaks the stated invariant that "a matching block rule must reliably deny the protected operation." A user who configures a hookify rule to block edits to sensitive files (e.g., `.env`, credentials, protected paths) using `tool_matcher: "Edit|Write"` or a condition on `old_text` believes that protection is comprehensive for file edits, but `MultiEdit` traffic slips through untouched. This can result in unauthorized file writes/edits outside the intended protected scope, matching the "Unauthorized file read or write outside the user-approved workspace or target scope" impact category.

### Likelihood Explanation
This requires: (1) a hookify rule that either sets an explicit `tool_matcher` not including `MultiEdit`, or relies on the `old_text`/`old_string` field, and (2) the acting agent choosing `MultiEdit` instead of `Edit`/`Write` for the operation. Explicit `tool_matcher` overrides are documented as a supported feature and plausible for hand-written or `/hookify`-generated rules targeting file edits. Tool choice between `Edit`, `Write`, and `MultiEdit` is influenceable by conversational/content-based prompting (a normal, no-privilege vector), making this a repeatable bypass once such a rule exists.

### Recommendation
- In `_matches_tool`, canonicalize equivalent write-capable tools (treat `Edit`, `Write`, `MultiEdit` as members of a shared "file" tool group) so a matcher like `Edit|Write` implicitly also covers `MultiEdit`, or document and enforce that `file`-event rules always expand to the full tool set regardless of an explicit `tool_matcher`.
- In `_extract_field`, add `old_text`/`old_string` support for `MultiEdit` by concatenating `edits[].old_string`, mirroring the existing `new_text` handling, so conditions behave consistently across all three tools.
- Add a warning/validation step when a rule's `tool_matcher` is a strict subset of the tools valid for its `event` type (e.g. `file` event with `tool_matcher` missing `MultiEdit`), to alert rule authors of unintended gaps.

### Proof of Concept
Unit test in the style of `plugins/hookify/core/rule_engine.py`'s existing `__main__` block:
```python
from hookify.core.config_loader import Rule, Condition
from hookify.core.rule_engine import RuleEngine

rule = Rule(
    name="block-env-edit",
    enabled=True,
    event="file",
    tool_matcher="Edit|Write",
    action="block",
    conditions=[Condition(field="file_path", operator="regex_match", pattern=r"\.env$")],
    message="Blocked edit to .env file"
)

engine = RuleEngine()

# Case 1: Edit tool -> correctly blocked
edit_input = {"tool_name": "Edit", "tool_input": {"file_path": ".env", "old_string": "X", "new_string": "Y"}}
assert engine.evaluate_rules([rule], edit_input).get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

# Case 2: MultiEdit tool performing the identical write -> bypasses the block rule
multiedit_input = {
    "tool_name": "MultiEdit",
    "tool_input": {"file_path": ".env", "edits": [{"old_string": "X", "new_string": "Y"}]}
}
result = engine.evaluate_rules([rule], multiedit_input)
assert result == {}  # BUG: dangerous edit is allowed instead of denied
```
Expected (secure) behavior: both `Edit` and `MultiEdit` invocations against `.env` should return a `deny` decision; the observed behavior is that `MultiEdit` returns `{}` (allowed), demonstrating the bypass. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** plugins/hookify/core/rule_engine.py (L144-160)
```python
    def _check_condition(self, condition: Condition, tool_name: str,
                        tool_input: Dict[str, Any], input_data: Dict[str, Any] = None) -> bool:
        """Check if a single condition matches.

        Args:
            condition: Condition to check
            tool_name: Tool being used
            tool_input: Tool input dict
            input_data: Full hook input data (for Stop events, etc.)

        Returns:
            True if condition matches
        """
        # Extract the field value to check
        field_value = self._extract_field(condition.field, tool_name, tool_input, input_data)
        if field_value is None:
            return False
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

**File:** plugins/hookify/hooks/pretooluse.py (L42-50)
```python
        # For PreToolUse, we use tool_name to determine "bash" vs "file" event
        tool_name = input_data.get('tool_name', '')

        event = None
        if tool_name == 'Bash':
            event = 'bash'
        elif tool_name in ['Edit', 'Write', 'MultiEdit']:
            event = 'file'

```
