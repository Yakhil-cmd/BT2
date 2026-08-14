Found a concrete analog in `plugins/hookify/core/rule_engine.py`. The `MultiEdit` field-extraction branch in `_extract_field()` handles only `file_path`, `new_text`, and `content` — it has **no case for `old_text`/`old_string`** on `MultiEdit`. Since the function falls through to `return None` for that combination, and `_check_condition()` treats a `None` field value as "condition does not match" (`if field_value is None: return False`), any hookify rule written to gate on `old_text`/`old_string` for a `MultiEdit` operation silently never matches — the block/warn rule is unconditionally bypassed for that tool, while the identical rule works correctly for `Edit`/`Write`. This is the same bug class as the report: a security-relevant condition is written against one identifier/field, but the code path that resolves that field for the actual multi-target operation silently diverges, causing the gate to be evaluated against the wrong (here, nonexistent) value while the real operation proceeds unchecked.

### Title
Hookify `RuleEngine` gate silently no-ops for `old_text`/`old_string` conditions on `MultiEdit`, bypassing block rules - (File: `plugins/hookify/core/rule_engine.py`)

### Summary
`RuleEngine._extract_field()` is the single field-resolution function that all hookify `PreToolUse` rules rely on to decide whether a `block`/`warn` condition matches. For the `MultiEdit` tool it only implements `file_path`, `new_text`, and `content` extraction; there is no branch returning the concatenated `old_string` values from `tool_input["edits"]`. Because `_check_condition()` immediately returns `False` (no match) whenever `_extract_field()` returns `None`, any rule authored with `field: old_text` or `field: old_string` and `tool_matcher`/`event: file` targeting `MultiEdit` is unconditionally inert — it can never block or warn, regardless of the content being edited.

### Finding Description
`_extract_field()` [1](#0-0)  resolves a condition's `field` against `tool_input`. For `Write`/`Edit` it explicitly maps `old_text`/`old_string` to `tool_input.get('old_string', '')` [2](#0-1) . The `MultiEdit` branch, however, only handles `file_path` and `new_text`/`content` [3](#0-2) ; there is no equivalent extraction of `old_string` from `tool_input["edits"]`. The function falls through and returns `None` for any other field/tool combination [4](#0-3) .

`_check_condition()` treats that `None` as "field absent, condition fails" [5](#0-4) , and `_rule_matches()` requires *all* conditions of a rule to match before the rule is considered triggered [6](#0-5) . Consequently a rule such as:
```yaml
event: file
conditions:
  - field: old_text
    operator: contains
    pattern: SAFE_MARKER
action: block
```
will correctly gate `Edit`/`Write` calls, but for `MultiEdit` the condition can never be satisfied, so `blocking_rules` stays empty and `evaluate_rules()` returns `{}` (allow) unconditionally [7](#0-6) . The gate is evaluated against a field that structurally cannot be populated for the tool actually being invoked — the same "gate reads one thing, the operation acts on another" mismatch as the referenced report's `executionData.tokenId` vs. `loan.nftCollateralTokenId` bug.

### Impact Explanation
An unprivileged user (or an untrusted skill/plugin/prompt-injected instruction directing Claude to prefer `MultiEdit` over `Edit`) can have Claude perform the exact multi-file edit a project's hookify rules are meant to block/warn on, simply because the tool used is `MultiEdit` instead of `Edit`/`Write`. Any project relying on `old_text`/`old_string`-based hookify rules (e.g., "block edits that remove a security marker/guard comment," "warn when a specific safeguard line is being deleted") loses that protection with no error, no warning, and no indication in the transcript that the rule failed to evaluate — since the hook always exits 0 and never surfaces the missing-field case [8](#0-7) .

### Likelihood Explanation
Likelihood is moderate-to-high in any project that has adopted the `hookify` plugin and written `old_text`-scoped file rules: `MultiEdit` is a commonly used, unprivileged, first-party Claude Code tool, and nothing about invoking it looks anomalous — it's simply the normal multi-hunk edit path. No special permissions or bypass flags are required; the gap is purely in the plugin's own field-resolution completeness.

### Recommendation
Add a `MultiEdit` branch in `_extract_field()` for `old_text`/`old_string` that concatenates `e.get('old_string', '')` across `tool_input.get('edits', [])`, mirroring the existing `new_text`/`content` handling. More generally, change the fail-open default: when a condition's `field` is not resolvable for the tool being evaluated, log/warn loudly (or fail closed for `block`-action rules) instead of silently returning `False` from `_check_condition()`, so gaps in field coverage for new tools don't silently disable existing rules.

### Proof of Concept
1. Create `.claude/hookify.protect-marker.local.md`:
```markdown
---
name: protect-safety-marker
enabled: true
event: file
conditions:
  - field: old_text
    operator: contains
    pattern: SECURITY_GUARD
action: block
---
Do not remove the SECURITY_GUARD line.
```
2. Ask Claude to remove a line containing `SECURITY_GUARD` using `Edit` — the `PreToolUse` hook correctly extracts `old_string`, matches, and blocks (`hookSpecificOutput.permissionDecision: "deny"`).
3. Ask Claude to perform the identical removal using `MultiEdit` with one edit entry whose `old_string` contains `SECURITY_GUARD`. `_extract_field('old_text', 'MultiEdit', tool_input, ...)` returns `None` (no matching branch), `_check_condition()` returns `False`, the rule never fires, and `evaluate_rules()` returns `{}` — the edit proceeds unblocked.

### Citations

**File:** plugins/hookify/core/rule_engine.py (L86-94)
```python
        # If only warnings, show them but allow operation
        if warning_rules:
            messages = [f"**[{r.name}]**\n{r.message}" for r in warning_rules]
            return {
                "systemMessage": "\n\n".join(messages)
            }

        # No matches - allow operation
        return {}
```

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

**File:** plugins/hookify/hooks/pretooluse.py (L58-70)
```python
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
