### Title
Hookify `RuleEngine._extract_field` fails to expose `old_string`/`old_text` for `MultiEdit`, letting block rules be bypassed via tool-representation mismatch - (File: `plugins/hookify/core/rule_engine.py`)

### Summary
`RuleEngine._extract_field` implements per-tool field mapping for `Write`/`Edit`/`MultiEdit`, but only the single-edit `Edit`/`Write` branch exposes `old_text`/`old_string`; the `MultiEdit` branch only supports `file_path` and `new_text`/`content`. A block rule authored to inspect `old_text`/`old_string` (e.g., to prevent removal of a security check, guard clause, or credential-scrubbing line) will silently never match when the same logical file mutation is performed via `MultiEdit` instead of `Edit`, even though both tools produce an identical resulting file diff.

### Finding Description
`_rule_matches` calls `_check_condition`, which calls `_extract_field(condition.field, tool_name, tool_input, input_data)` [1](#0-0) [2](#0-1) .

Inside `_extract_field`, the tool-specific dispatch is:
- For `Write`/`Edit`, `old_text`/`old_string` is explicitly returned from `tool_input.get('old_string', '')` [3](#0-2) .
- For `MultiEdit`, only `file_path` and `new_text`/`content` (concatenated from the `edits` list) are handled; there is no branch returning any `old_string`/`old_text` value from the `edits` array [4](#0-3) .

Since none of the field name literals matches, execution falls through to `return None` at the end of the function [5](#0-4) . Back in `_check_condition`, a `None` field value causes the condition (and therefore the whole rule, since all conditions must match) to evaluate to `False` [6](#0-5) .

Consequently, a rule such as:
```yaml
tool_matcher: "Edit|Write|MultiEdit"
conditions:
  - field: old_text
    operator: contains
    pattern: "verify_signature("
action: block
```
intended to block removal of a security-relevant line, will correctly deny the operation when the agent uses `Edit`, but will **never match** and silently allow the identical semantic change when the same replacement is issued through `MultiEdit`'s `edits` array — because `MultiEdit` is a normal, first-class Claude Code tool that any repository-content-driven agent action (including prompt-injected instructions from untrusted repo content) can freely choose to invoke instead of `Edit` for the exact same file mutation. Both `Bash`/`Edit`/`Write`/`Stop` events are standard, attacker-reachable tool invocations processed by `plugins/hookify/hooks/pretooluse.py`, so no privilege beyond normal agent tool usage is required to select `MultiEdit` over `Edit`.

### Impact Explanation
This breaks the stated invariant that "a matching block rule must reliably deny the protected operation." Any hookify guard rule written against `old_text`/`old_string` for edit-type tools is trivially bypassed by using `MultiEdit` instead of `Edit`, letting a dangerous file mutation (e.g., stripping out a safety check, credential redaction, or a `sudo`/`rm` guard from a script) proceed undetected. This is a logic-level bypass of a security guard (Claude Code Immunefi impact category: "Logic-level service disruption caused by bypassing a required guard").

### Likelihood Explanation
Highly feasible and repeatable: it requires no special privileges, only that the acting agent (which can be steered via repository content/prompt injection, a documented accepted vector) issues a `MultiEdit` call instead of `Edit` with the same `old_string`/`new_string` pair. Since `MultiEdit` is functionally interchangeable with `Edit` for single replacements and is a normal tool available in ordinary sessions, this bypass path is deterministic and does not depend on any race condition or unusual environment.

### Recommendation
In `_extract_field`, add `old_text`/`old_string` handling for `MultiEdit` mirroring the `new_text`/`content` handling — e.g., concatenate `e.get('old_string', '')` across `tool_input.get('edits', [])` — so that any condition field supported for `Edit` is symmetrically supported for `MultiEdit`. More generally, normalize all `Edit`/`Write`/`MultiEdit` field extraction through a single shared mapping table so no field is representation-specific, preventing future asymmetric gaps.

### Proof of Concept
Unit test to add to a hookify test suite (using `RuleEngine` directly):
```python
from hookify.core.config_loader import Rule, Condition
from hookify.core.rule_engine import RuleEngine

rule = Rule(
    name="protect-verify",
    enabled=True,
    event="all",
    tool_matcher="Edit|Write|MultiEdit",
    conditions=[Condition(field="old_text", operator="contains", pattern="verify_signature(")],
    action="block",
    message="Do not remove signature verification"
)
engine = RuleEngine()

edit_input = {
    "tool_name": "Edit",
    "tool_input": {"file_path": "x.py", "old_string": "verify_signature(data)", "new_string": "pass"}
}
multiedit_input = {
    "tool_name": "MultiEdit",
    "tool_input": {"file_path": "x.py", "edits": [{"old_string": "verify_signature(data)", "new_string": "pass"}]}
}

assert engine.evaluate_rules([rule], edit_input) != {}       # correctly blocked
assert engine.evaluate_rules([rule], multiedit_input) == {}  # BUG: bypassed, should also be blocked
```
Expected (fixed) behavior: both invocations return a non-empty `hookSpecificOutput`/`permissionDecision: deny` response; current behavior shows `MultiEdit` silently returns `{}` (allowed), confirming the bypass.

### Citations

**File:** plugins/hookify/core/rule_engine.py (L121-123)
```python
        for condition in rule.conditions:
            if not self._check_condition(condition, tool_name, tool_input, input_data):
                return False
```

**File:** plugins/hookify/core/rule_engine.py (L157-160)
```python
        # Extract the field value to check
        field_value = self._extract_field(condition.field, tool_name, tool_input, input_data)
        if field_value is None:
            return False
```

**File:** plugins/hookify/core/rule_engine.py (L241-242)
```python
            elif field == 'old_text' or field == 'old_string':
                return tool_input.get('old_string', '')
```

**File:** plugins/hookify/core/rule_engine.py (L246-252)
```python
        elif tool_name == 'MultiEdit':
            if field == 'file_path':
                return tool_input.get('file_path', '')
            elif field in ['new_text', 'content']:
                # Concatenate all edits
                edits = tool_input.get('edits', [])
                return ' '.join(e.get('new_string', '') for e in edits)
```

**File:** plugins/hookify/core/rule_engine.py (L254-254)
```python
        return None
```
