### Title
`contains`/`equals`/`not_contains`/`starts_with`/`ends_with` operators perform case-sensitive, non-normalized raw string ops, allowing trivial case/Unicode obfuscation to bypass `block` rules - (File: `plugins/hookify/core/rule_engine.py`)

### Summary
`_check_condition` in `plugins/hookify/core/rule_engine.py` dispatches `contains`, `equals`, `not_contains`, `starts_with`, and `ends_with` operators to raw Python string methods (`in`, `==`, `.startswith()`, `.endswith()`) with no case-folding or Unicode normalization, unlike the `regex_match` operator which is compiled with `re.IGNORECASE` via `compile_regex`. Any Bash command text that differs from the configured pattern only in letter case (or through Unicode homoglyphs/alternate whitespace producing a distinct code-point sequence) will not match, allowing a `block` rule to be silently bypassed for an effectively identical dangerous command.

### Finding Description
In `_check_condition` [1](#0-0) , the `regex_match` branch calls `compile_regex(pattern)`, which is always compiled with `re.IGNORECASE` [2](#0-1) . In contrast, the `contains`, `equals`, `not_contains`, `starts_with`, and `ends_with` branches operate directly on `field_value` with no `.lower()`/`.casefold()`/Unicode normalization (`unicodedata.normalize`) applied to either `pattern` or `field_value` [3](#0-2) .

`field_value` for Bash commands is extracted verbatim from `tool_input['command']` via `_extract_field` [4](#0-3)  with no sanitization. A `block` rule configured with `operator: contains, pattern: rm -rf` (as documented as a supported/recommended pattern in the README's Operators Reference and examples) [5](#0-4)  will only match the exact-case, exact-code-point substring `rm -rf`. A command like `RM -RF /important` or `rm${IFS}-rf` (variant whitespace which Bash still executes identically due to shell expansion, but which no longer contains the literal substring `rm -rf`) will fail the `pattern in field_value` check and pass through `evaluate_rules` unblocked, even though the two commands are functionally/effectively identical to the shell.

This is a genuine asymmetry in the rule engine: the two operator families ("regex" vs "plain string") enforce different-strength matching semantics, but the README documents both as interchangeable ways to write the same kind of deny rule, with no warning that non-regex operators are case-sensitive and not resilient to trivial textual variation.

### Impact Explanation
This is a defense-bypass finding scoped to hookify's own enforcement mechanism: a rule author intends to `block` a destructive Bash command (e.g., `rm -rf`), but the actual runtime check silently fails to fire for a functionally equivalent command that merely differs in case or whitespace representation, allowing Claude to execute the blocked destructive command. This matches a "hook/guardrail bypass leading to unauthorized destructive command execution" impact class — the deny rule that was supposed to be the last line of defense against a dangerous Bash invocation does not fire, and the operation proceeds.

### Likelihood Explanation
Feasibility is high and requires no special privilege: any user or automation flow that ends up asking Claude to run a command with different letter-casing (`RM -rf`, `Rm -Rf`) will bypass a `contains`/`equals`/`starts_with`/`ends_with` rule targeting the lowercase form, without any adversarial intent needed — this can happen organically or via minor prompt-injection-driven wording changes in repository content that influences what command text Claude generates. It is fully repeatable and deterministic given the code path shown above.

### Recommendation
Normalize both `pattern` and `field_value` consistently for the non-regex operators — e.g., apply `.casefold()` to both sides for `contains`/`equals`/`not_contains`/`starts_with`/`ends_with` (matching the `IGNORECASE` behavior already used for `regex_match`), and document in the README that these are case-insensitive to keep operator semantics consistent. Alternatively, treat case sensitivity as an explicit, opt-in rule field so behavior is predictable, but the current default (silently case-sensitive for string ops vs. case-insensitive for regex ops) should be fixed since it directly undermines `block` rules with no documented caveat.

### Proof of Concept
Add a parametrized test in the hookify test suite (e.g. `plugins/hookify/tests/test_rule_engine.py` or equivalent) exercising `RuleEngine.evaluate_rules`:

```python
import pytest
from hookify.core.config_loader import Rule, Condition
from hookify.core.rule_engine import RuleEngine

@pytest.mark.parametrize("command_variant", [
    "rm -rf /tmp/test",   # canonical form
    "RM -RF /tmp/test",   # case variant
    "Rm -Rf /tmp/test",   # mixed case
])
def test_block_rule_case_bypass(command_variant):
    rule = Rule(
        name="block-rm",
        enabled=True,
        event="bash",
        conditions=[Condition(field="command", operator="contains", pattern="rm -rf")],
        action="block",
        message="Dangerous rm command!",
    )
    engine = RuleEngine()
    input_data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command_variant},
    }
    result = engine.evaluate_rules([rule], input_data)
    # Expected: deny fires identically for all effectively-equivalent commands
    assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
```

Running this today shows the canonical-case test passes (deny fires) while the `RM -RF`/`Rm -Rf` variants return `{}` (no deny), proving the `block` rule is bypassed for functionally identical destructive commands due to the missing case normalization in `_check_condition`'s non-regex operator branches [3](#0-2) .

### Citations

**File:** plugins/hookify/core/rule_engine.py (L14-24)
```python
@lru_cache(maxsize=128)
def compile_regex(pattern: str) -> re.Pattern:
    """Compile regex pattern with caching.

    Args:
        pattern: Regex pattern string

    Returns:
        Compiled regex pattern
    """
    return re.compile(pattern, re.IGNORECASE)
```

**File:** plugins/hookify/core/rule_engine.py (L166-180)
```python
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

**File:** plugins/hookify/core/rule_engine.py (L230-233)
```python
        # Handle special cases by tool type
        if tool_name == 'Bash':
            if field == 'command':
                return tool_input.get('command', '')
```

**File:** plugins/hookify/README.md (L235-242)
```markdown
### Operators Reference

- `regex_match`: Pattern must match (most common)
- `contains`: String must contain pattern
- `equals`: Exact string match
- `not_contains`: String must NOT contain pattern
- `starts_with`: String starts with pattern
- `ends_with`: String ends with pattern
```
