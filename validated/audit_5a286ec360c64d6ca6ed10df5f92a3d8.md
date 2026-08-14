### Title
Hookify's `new_text` field extraction silently never matches for the `Write` tool, causing documented block/warn rules to fail open - ([File: plugins/hookify/core/rule_engine.py])

### Summary
The `hookify` plugin lets a user write PreToolUse/PostToolUse block/warn rules keyed on a `field` such as `new_text`, documented to cover both the `Edit` and `Write` tools. In `RuleEngine._extract_field`, the `new_text`/`new_string` branch only reads the `new_string` key, which exists on `Edit` tool_input but never on `Write` tool_input (Write uses `content`). Consequently, any rule of the form `field: new_text` silently returns an empty string for every `Write` call, so its condition (`regex_match`, `contains`, etc.) can never match and the rule never fires — exactly mirroring the underlying report's root cause: the code skips/void-transforms a specific, valid input value (here, "field is absent for this tool" → treated as `''`/no-match) instead of surfacing the mismatch, letting a security control silently do nothing while looking fully configured and valid to the user who wrote it.

### Finding Description
`Rule.from_dict` and the README both document `new_text` as valid for both `Edit` and `Write` file events: [1](#0-0) 

But `RuleEngine._extract_field` implements the `new_text`/`new_string` field by reading only `tool_input.get('new_string', '')`, a key that is populated for `Edit` (`old_string`/`new_string`) but is never present in `Write` tool_input (which instead carries `content`): [2](#0-1) 

Because `tool_input.get('new_string', '')` defaults to `''` rather than raising or returning `None` when the key is absent, `_check_condition` treats it as a normal (empty) string value rather than a "field extraction failed" signal: [3](#0-2) 

For a `Write` call, `field_value` is always `''`, so `regex_match('secret_pattern', '')`, `contains`, etc. all evaluate to `False` — the condition can never be satisfied, and the rule (block or warn) never triggers for `Write`, regardless of what content is actually being written. This is the same failure shape as the Putty bug: a specific value (here, "field not populated for this tool") is passed through a check unconditionally instead of being special-cased, and the person relying on the check (the user who authored a hookify rule expecting it to cover `Write`, per the documented `new_text` behavior) has no way to know their protection is void until it's too late.

### Impact Explanation
A user who configures a hookify `block` rule such as "deny writing files whose `new_text` contains `API_KEY=` " believes — per the plugin's own documentation — that this rule protects both `Edit` and `Write` operations. In practice it silently never fires for `Write`. Any content written via the `Write` tool (e.g., by Claude acting on a prompt-injected instruction from an untrusted file, PR, or web page it was asked to process) that would otherwise be blocked instead passes through with no warning, no block, and no indication to the user that the rule failed to apply. This is a concrete hook-bypass of a user-configured, unprivileged security control (Priority Attack Surface: hook bypass / command approval), giving an attacker who understands this quirk (e.g., via prompt injection instructing the agent to prefer `Write` over `Edit`) a reliable way to defeat the user's own guardrails for secret/credential leakage or dangerous-content prevention.

### Likelihood Explanation
Likelihood is moderate-to-high: hookify is a first-party plugin shipped in this repository and its README explicitly advertises `new_text` as valid for `Write`, so realistic user configurations (copy-pasted from the docs) trigger the gap by default — no unusual configuration is required, only using the documented feature with the `Write` tool.

### Recommendation
In `_extract_field`, make the `Write`/`Edit` field mapping explicit and tool-aware instead of relying on a shared default: for `Write`, `new_text`/`new_string` should read `tool_input.get('content', '')` (mirroring `content`'s own fallback logic), or the extractor should return `None` (not `''`) when the requested field genuinely does not apply to the tool, so `_check_condition`'s existing `if field_value is None: return False` path is reached deliberately and, ideally, a warning is logged so the misconfiguration is visible instead of silently succeeding as "no match."

### Proof of Concept
1. Create `.claude/hookify.block-secret-write.local.md`:
```markdown
---
name: block-secret-write
enabled: true
event: file
action: block
conditions:
  - field: new_text
    operator: contains
    pattern: API_KEY
---
Blocked: secret detected in new content.
```
2. Ask Claude to use `Edit` to insert `API_KEY=xxxx` into a file — the rule fires and blocks it (matches `new_string`).
3. Ask Claude to use `Write` to create a new file whose content is `API_KEY=xxxx` — `_extract_field` returns `''` for `new_text` (Write has no `new_string` key), `contains` evaluates `False`, and the write proceeds with no block and no warning, despite the identical secret content and identical rule configuration. [2](#0-1) [4](#0-3)

### Citations

**File:** plugins/hookify/README.md (L249-253)
```markdown
**For file events:**
- `file_path`: Path to file being edited
- `new_text`: New content being added (Edit, Write)
- `old_text`: Old content being replaced (Edit only)
- `content`: File content (Write only)
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
