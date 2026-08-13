Based on the code, there's a genuine bug in `RuleEngine._extract_field` that causes rules targeting the `new_text` field to silently fail to match `Write` tool calls, even though the plugin's own documentation states `new_text` applies to both `Edit` and `Write`.This confirms the documented contract: `new_text` is documented to apply to both `Edit` **and** `Write` events [1](#0-0) , but the implementation in `_extract_field` breaks this for `Write` operations.

### Title
Hookify block rules on `new_text` field silently bypassed for `Write` tool calls due to incomplete field aliasing in `_extract_field` - (File: `plugins/hookify/core/rule_engine.py`)

### Summary
`RuleEngine._extract_field` maps the documented `new_text` field to `tool_input.get('new_string', '')` for both `Write` and `Edit` tools, but the `Write` tool never populates `new_string` — it uses `content` instead. As a result, any hookify rule (simple-pattern `file` event rules, or explicit `field: new_text` conditions) that is meant to block dangerous content being written to disk correctly fires for `Edit` but silently returns an empty string — and thus never matches — for `Write`, letting the exact same dangerous content through when Claude uses `Write` instead of `Edit`.

### Finding Description
`Rule.from_dict` infers the condition field for simple-pattern `file`-event rules as `new_text` [2](#0-1) , and the plugin's own documentation states this field applies to both `Edit` and `Write` [1](#0-0) .

In `RuleEngine._extract_field`, the branch handling `Write`/`Edit` tools maps `new_text`/`new_string` exclusively to `tool_input.get('new_string', '')`: [3](#0-2) 

`Write` tool calls populate `content`, not `new_string` — this is handled correctly only for the `content` field alias two lines above (`tool_input.get('content') or tool_input.get('new_string', '')`), but not for `new_text`/`new_string`. So when a rule is written against `new_text` (either explicitly, or implicitly via a simple `pattern:` rule under `event: file`), `_extract_field` returns `''` for any `Write` tool call. Back in `_check_condition`, this empty string is not `None`, so the condition is evaluated normally, but `regex_match`/`contains`/etc. against an empty string will never match real dangerous content, so `_rule_matches` returns `False` and the rule is treated as non-matching for `Write` operations, even though the equivalent `Edit` operation with identical injected content would be correctly blocked [4](#0-3) .

Because `pretooluse.py` and `posttooluse.py` route both `Edit` and `Write` into the same `'file'` event bucket and rely entirely on this rule-engine matching to decide `block` vs `warn`/allow [5](#0-4) , this is a real enforcement gap: an operator who deploys a `.claude/hookify.*.local.md` block rule intending to catch secrets/dangerous content in any file mutation gets full coverage for `Edit` but zero coverage for `Write`.

The attack path requires an untrusted content source (a file, issue/PR text, or other input Claude reads) to bias the agent toward using `Write` rather than `Edit` for the dangerous mutation (e.g., "create this file with the following full contents" rather than "append this line") — a normal, unprivileged prompt-injection-style influence over tool choice, not any direct code execution or admin privilege.

### Impact Explanation
This breaks the invariant that "a matching block rule must reliably deny the protected operation." A defender relying on hookify to block, e.g., secret-leaking writes or credential injection into `.env`/config files, can be bypassed simply by the dangerous content arriving via `Write` (new file / full overwrite) instead of `Edit` (partial replace). This is a genuine security-control bypass with cross-file/cross-session mutation impact (unauthorized file content written despite an active block rule), matching the "wrong-target/dangerous mutation not denied" class of impact.

### Likelihood Explanation
Highly feasible and repeatable: it requires no special privilege, only that the dangerous content be introduced via the `Write` tool instead of `Edit`. Since prompt-injected or attacker-influenced content routinely determines whether Claude edits an existing file or writes a new one, this is a deterministic, 100%-reproducible bypass, not a probabilistic race condition.

### Recommendation
In `_extract_field`, when `tool_name == 'Write'`, alias `new_text` (and `new_string`) to `tool_input.get('content', '')` just as is already done for the `content` field, so all three aliases (`content`, `new_text`, `new_string`) resolve consistently regardless of tool. Additionally, consider normalizing `Write`'s single `content` field against both `old_text`/`new_text` semantics explicitly in documentation/tests to avoid future silent drift.

### Proof of Concept
Unit test against `plugins/hookify/core/rule_engine.py`:
```python
from hookify.core.config_loader import Rule, Condition
from hookify.core.rule_engine import RuleEngine

rule = Rule(
    name="block-secret-write",
    enabled=True,
    event="file",
    action="block",
    conditions=[Condition(field="new_text", operator="contains", pattern="API_KEY")],
    message="Blocked"
)
engine = RuleEngine()

edit_input = {
    "tool_name": "Edit",
    "tool_input": {"file_path": "x.env", "old_string": "", "new_string": "API_KEY=secret"}
}
write_input = {
    "tool_name": "Write",
    "tool_input": {"file_path": "x.env", "content": "API_KEY=secret"}
}

edit_result = engine.evaluate_rules([rule], edit_input)
write_result = engine.evaluate_rules([rule], write_input)

assert edit_result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
# BUG: this currently fails — write_result == {} (allowed) despite identical dangerous content
assert write_result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
```
Expected (post-fix) behavior: both `Edit` and `Write` invocations carrying the same dangerous `API_KEY` content are denied identically.

### Citations

**File:** plugins/hookify/README.md (L249-253)
```markdown
**For file events:**
- `file_path`: Path to file being edited
- `new_text`: New content being added (Edit, Write)
- `old_text`: Old content being replaced (Edit only)
- `content`: File content (Write only)
```

**File:** plugins/hookify/core/config_loader.py (L60-67)
```python
            # Infer field from event
            event = frontmatter.get('event', 'all')
            if event == 'bash':
                field = 'command'
            elif event == 'file':
                field = 'new_text'
            else:
                field = 'content'
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

**File:** plugins/hookify/hooks/pretooluse.py (L41-56)
```python
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
```
