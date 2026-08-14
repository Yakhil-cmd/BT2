### Title
Explicit `conditions:` frontmatter silently disables block rules due to unvalidated `field` names, unlike legacy `pattern:` rules - (File: `plugins/hookify/core/config_loader.py`)

### Summary
`Rule.from_dict` and `Condition.from_dict` in `plugins/hookify/core/config_loader.py` treat the legacy `pattern:` field and the explicit `conditions:` list with different levels of trust: legacy mode always derives a correct, event-appropriate `field` name internally, while explicit mode blindly accepts whatever `field` string appears in attacker/author-controlled frontmatter, with no validation against the actual event/tool schema. Because `rule_engine.RuleEngine._extract_field` returns `None` for any unrecognized field (causing the condition, and therefore the whole rule, to silently never match), a `.claude/hookify.*.local.md` rule file using the "advanced" `conditions:` form with an incorrect/mismatched `field` will parse successfully, display as `enabled: true, action: block`, yet never actually block anything.

### Finding Description
`Rule.from_dict` (`plugins/hookify/core/config_loader.py:44-84`) has two code paths:
- Legacy: if `pattern:` is set and no `conditions` present, the field is *inferred* from `event` (`command` for bash, `new_text` for file, `content` otherwise) — this is always a valid key that `RuleEngine._extract_field` (`plugins/hookify/core/rule_engine.py:182-254`) knows how to resolve.
- Explicit: if `conditions:` is present, each item is passed through `Condition.from_dict` (`plugins/hookify/core/config_loader.py:22-29`), which does `field=data.get('field', '')` with **no validation** that the field name is meaningful for the declared `event`/tool.

At evaluation time, `_check_condition` (`plugins/hookify/core/rule_engine.py:144-160`) calls `_extract_field`; if the field is unrecognized (typo, wrong case, wrong event mapping, or simply omitted so it defaults to `''`), `_extract_field` returns `None`, and `_check_condition` returns `False` unconditionally — the condition (and hence the whole rule, since `RuleEngine._rule_matches` at `plugins/hookify/core/rule_engine.py:96-124` requires *all* conditions to match) can never fire. `load_rule_file` (`plugins/hookify/core/config_loader.py:244-274`) performs no schema/field validation and only catches I/O/parse exceptions, so a rule with a bad field silently loads as a normal, "enabled", "block" rule — no warning is emitted.

This creates an attacker-reachable differential: a rule file authored via the `/hookify` generation flow (which an LLM could be steered to produce incorrectly through prompt injection embedded in repo content it reads while generating the rule) or a rule file shipped directly in the repository (there is no `.gitignore` exclusion for `hookify.*.local.md` files, so they can be committed and pulled by downstream users) can look like a legitimate `event: bash / action: block` protection (e.g., against `rm -rf`) while using `conditions: - field: content` instead of `field: command`. Every future Bash invocation this rule was intended to block will pass through un-blocked, and nothing in the loader or hook execution path surfaces this as broken.

### Impact Explanation
This is a Security-control bypass that silently disables a hookify block rule without any error, warning, or visible difference in the rule file's declared configuration (`enabled: true`, `action: block` remain intact). A victim relying on such a repo-shipped or `/hookify`-generated rule to block dangerous Bash commands, sensitive file edits, or Stop-event completion checks will believe the guard is active while it never actually evaluates true, allowing the exact operations it was meant to block (e.g., `rm -rf`, hardcoded secret writes) to proceed unhindered.

### Likelihood Explanation
No special privilege is required beyond the ability to place or influence a `.claude/hookify.*.local.md` file — either by committing one into a shared repository (no `.gitignore` protection exists for these files) or by getting `/hookify` generation to emit a subtly mismatched `field` (e.g. via repo content the agent reads while authoring the rule). The bug is 100% deterministic once such a file is loaded: `_extract_field` will always return `None` for the mismatched field, so the condition, and the rule, never match. This requires no race condition or timing and reproduces on every hook invocation.

### Recommendation
- In `Condition.from_dict` / `Rule.from_dict`, validate that `field` is one of the known, event-appropriate field names (e.g. maintain an explicit allow-list per `event` type) and raise/log a loud warning (not silently swallowed) if it isn't recognized, rather than allowing the rule to silently degrade to "never matches."
- Consider making `load_rule_file` fail closed (skip/flag the rule as invalid, or default to blocking) rather than fail open when a condition's field can never be resolved, especially for `action: block` rules.
- Unify the legacy and explicit code paths so both are validated identically, eliminating the semantic gap between the two rule-authoring styles.

### Proof of Concept
Unit test to add near `plugins/hookify/core/config_loader.py` / `rule_engine.py` tests:
```python
from hookify.core.config_loader import Rule
from hookify.core.rule_engine import RuleEngine

# Legacy form: field inferred correctly -> blocks
legacy_fm = {"name": "r1", "enabled": True, "event": "bash",
             "pattern": "rm\\s+-rf", "action": "block"}
legacy_rule = Rule.from_dict(legacy_fm, "danger")

# Explicit form with a plausible-but-wrong field (mismatched vs. event=bash)
explicit_fm = {"name": "r1", "enabled": True, "event": "bash", "action": "block",
               "conditions": [{"field": "content", "operator": "regex_match", "pattern": "rm\\s+-rf"}]}
explicit_rule = Rule.from_dict(explicit_fm, "danger")

engine = RuleEngine()
input_data = {
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "rm -rf /important"},
}

assert engine.evaluate_rules([legacy_rule], input_data)["hookSpecificOutput"]["permissionDecision"] == "deny"
# Explicit rule silently fails to block the same dangerous command:
assert engine.evaluate_rules([explicit_rule], input_data) == {}
```
Expected result confirms the invariant violation: the legacy rule blocks `rm -rf`, while the semantically-equivalent explicit-conditions rule (same intent, same event, same action) silently allows it due to the unvalidated `field` mismatch. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** plugins/hookify/core/config_loader.py (L15-29)
```python
@dataclass
class Condition:
    """A single condition for matching."""
    field: str  # "command", "new_text", "old_text", "file_path", etc.
    operator: str  # "regex_match", "contains", "equals", etc.
    pattern: str  # Pattern to match

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Condition':
        """Create Condition from dict."""
        return cls(
            field=data.get('field', ''),
            operator=data.get('operator', 'regex_match'),
            pattern=data.get('pattern', '')
        )
```

**File:** plugins/hookify/core/config_loader.py (L44-84)
```python
    @classmethod
    def from_dict(cls, frontmatter: Dict[str, Any], message: str) -> 'Rule':
        """Create Rule from frontmatter dict and message body."""
        # Handle both simple pattern and complex conditions
        conditions = []

        # New style: explicit conditions list
        if 'conditions' in frontmatter:
            cond_list = frontmatter['conditions']
            if isinstance(cond_list, list):
                conditions = [Condition.from_dict(c) for c in cond_list]

        # Legacy style: simple pattern field
        simple_pattern = frontmatter.get('pattern')
        if simple_pattern and not conditions:
            # Convert simple pattern to condition
            # Infer field from event
            event = frontmatter.get('event', 'all')
            if event == 'bash':
                field = 'command'
            elif event == 'file':
                field = 'new_text'
            else:
                field = 'content'

            conditions = [Condition(
                field=field,
                operator='regex_match',
                pattern=simple_pattern
            )]

        return cls(
            name=frontmatter.get('name', 'unnamed'),
            enabled=frontmatter.get('enabled', True),
            event=frontmatter.get('event', 'all'),
            pattern=simple_pattern,
            conditions=conditions,
            action=frontmatter.get('action', 'warn'),
            tool_matcher=frontmatter.get('tool_matcher'),
            message=message.strip()
        )
```

**File:** plugins/hookify/core/config_loader.py (L244-274)
```python
def load_rule_file(file_path: str) -> Optional[Rule]:
    """Load a single rule file.

    Returns:
        Rule object or None if file is invalid.
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()

        frontmatter, message = extract_frontmatter(content)

        if not frontmatter:
            print(f"Warning: {file_path} missing YAML frontmatter (must start with ---)", file=sys.stderr)
            return None

        rule = Rule.from_dict(frontmatter, message)
        return rule

    except (IOError, OSError, PermissionError) as e:
        print(f"Error: Cannot read {file_path}: {e}", file=sys.stderr)
        return None
    except (ValueError, KeyError, AttributeError, TypeError) as e:
        print(f"Error: Malformed rule file {file_path}: {e}", file=sys.stderr)
        return None
    except UnicodeDecodeError as e:
        print(f"Error: Invalid encoding in {file_path}: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error: Unexpected error parsing {file_path} ({type(e).__name__}): {e}", file=sys.stderr)
        return None
```

**File:** plugins/hookify/core/rule_engine.py (L96-124)
```python
    def _rule_matches(self, rule: Rule, input_data: Dict[str, Any]) -> bool:
        """Check if rule matches input data.

        Args:
            rule: Rule to evaluate
            input_data: Hook input data

        Returns:
            True if rule matches, False otherwise
        """
        # Extract tool information
        tool_name = input_data.get('tool_name', '')
        tool_input = input_data.get('tool_input', {})

        # Check tool matcher if specified
        if rule.tool_matcher:
            if not self._matches_tool(rule.tool_matcher, tool_name):
                return False

        # If no conditions, don't match
        # (Rules must have at least one condition to be valid)
        if not rule.conditions:
            return False

        # All conditions must match
        for condition in rule.conditions:
            if not self._check_condition(condition, tool_name, tool_input, input_data):
                return False

```

**File:** plugins/hookify/core/rule_engine.py (L144-180)
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

        # Apply operator
        operator = condition.operator
        pattern = condition.pattern

        if operator == 'regex_match':
            return self._regex_match(pattern, field_value)
        elif operator == 'contains':
            return pattern in field_value
        elif operator == 'equals':
            return pattern == field_value
        elif operator == 'not_contains':
            return pattern not in field_value
        elif operator == 'starts_with':
            return field_value.startswith(pattern)
        elif operator == 'ends_with':
            return field_value.endswith(pattern)
        else:
            # Unknown operator
            return False
```

**File:** plugins/hookify/core/rule_engine.py (L182-254)
```python
    def _extract_field(self, field: str, tool_name: str,
                      tool_input: Dict[str, Any], input_data: Dict[str, Any] = None) -> Optional[str]:
        """Extract field value from tool input or hook input data.

        Args:
            field: Field name like "command", "new_text", "file_path", "reason", "transcript"
            tool_name: Tool being used (may be empty for Stop events)
            tool_input: Tool input dict
            input_data: Full hook input (for accessing transcript_path, reason, etc.)

        Returns:
            Field value as string, or None if not found
        """
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
