Note: I was unable to fully verify `_extract_field` (lines ~182-255 of `plugins/hookify/core/rule_engine.py`) before running out of tool calls, so the exact type-coercion behavior for non-string `tool_input` fields is not 100% confirmed. The analysis below is based on the confirmed code in `rule_engine.py:1-181`, `config_loader.py`, and the hook entrypoints (`pretooluse.py`, `stop.py`, `posttooluse.py`, `userpromptsubmit.py`).

### Title
Hookify PreToolUse/Stop hooks fail open on rule-evaluation exceptions, silently bypassing "block" rules - (File: plugins/hookify/hooks/pretooluse.py)

### Summary
The OtterSec report's root cause is that unvalidated instruction data lets a check that is supposed to gate a privileged operation pass trivially (zero-valued swap amounts satisfy the slippage check), so the guarded action is repeated with no real effect except fee extraction. The structural analog in `claude-code--017` is the `hookify` plugin's hook executors: any exception raised while evaluating rules against attacker/agent-controlled `tool_input` is swallowed by a blanket `except Exception` and the process **always exits 0**, which Claude Code treats as "allow." A `tool_input` value that is malformed in a way the condition operators don't expect (e.g., a non-string field where `contains`/`starts_with`/`equals` are applied) throws inside `_check_condition`/`_regex_match`, propagates out of `evaluate_rules` uncaught, and is caught only by the hook script's outer handler — which converts the failure into an implicit approval instead of the intended `"decision": "block"` / `"permissionDecision": "deny"`.

### Finding Description
`RuleEngine.evaluate_rules` (`plugins/hookify/core/rule_engine.py:35-94`) has no internal exception handling around condition checks. `_check_condition` (`rule_engine.py:144-180`) dispatches on `condition.operator` and directly performs Python operations (`pattern in field_value`, `field_value.startswith(pattern)`, etc.) on whatever value `_extract_field` returns from `tool_input`. Because `tool_input` is JSON supplied by the running tool call (and, for `file`/`bash` events, ultimately reflects content the agent/attacker is asking Claude Code to execute), a field that a rule author expects to be a string can instead be missing, `null`, a number, or a nested object depending on how the tool call is structured. This raises `TypeError`/`AttributeError`, which is not caught anywhere inside `rule_engine.py` or `config_loader.py`.

Every hook entrypoint (`plugins/hookify/hooks/pretooluse.py:35-70`, `stop.py:30-55`) wraps the whole evaluation in a single broad `try/except Exception` whose `finally` block unconditionally calls `sys.exit(0)`:
```
except Exception as e:
    error_output = {"systemMessage": f"Hookify error: {str(e)}"}
    print(json.dumps(error_output), file=sys.stdout)
finally:
    sys.exit(0)
```
On exception, the hook emits only a `systemMessage` — it never emits `hookSpecificOutput.permissionDecision: "deny"` or `"decision": "block"`. Since Claude Code's hook contract treats the absence of a deny/block decision as approval, any condition that triggers this exception path causes a would-be-blocking hookify rule to be silently skipped, and the underlying tool call (e.g. a dangerous `Bash` command, or a `Write`/`Edit` to a sensitive path) proceeds.

This mirrors OS-SYM-ADV-01/02's pattern precisely: a validation gate (`SlippageError` check / hookify `block` rule) is bypassable by supplying data that the gate's implementation cannot correctly evaluate, causing the gate to be defeated while the guarded action still runs (rebalance still charges a fee / tool call still executes).

### Impact Explanation
If a user has configured a `hookify.*.local.md` rule with `action: block` to prevent destructive `Bash` commands or edits to sensitive files (this is the plugin's advertised primary use case — see `plugins/hookify/skills/writing-rules/SKILL.md`), a crafted or unusual `tool_input` shape that trips an exception in condition evaluation causes that block to be bypassed and the operation to execute anyway. This is a concrete approval-bypass / hook-bypass in the PreToolUse trust boundary: the very mechanism the plugin exists to enforce ("block dangerous commands") fails open instead of failing closed, defeating the security control without any indication to the user beyond a generic "Hookify error" message that most workflows won't surface as a denial.

### Likelihood Explanation
Moderate. It requires (a) a project to be relying on hookify `block` rules for enforcement, and (b) a tool call whose `tool_input` shape doesn't match the rule author's assumption about field types (e.g. a `file_path` condition applied to a tool that doesn't set that key as expected, or nested/array data leaking into a field). This can occur with ordinary agent behavior (not necessarily an "attacker" in the classic sense — it can be Claude itself constructing an unusual tool call), and does not require special privileges, matching the "unprivileged-user" hook-bypass scope.

### Recommendation
Wrap each condition check (or at minimum `evaluate_rules`) in its own error handling that fails closed for `block`-action rules — i.e., if a blocking rule cannot be evaluated due to malformed input, deny/ask rather than defaulting to allow. At minimum, coerce/validate `field_value` to `str` before applying string operators, and distinguish "no match" from "evaluation error" so evaluation errors don't silently downgrade to full approval in `pretooluse.py`/`stop.py`.

### Proof of Concept
1. Configure a hookify rule with `action: block`, `event: bash`, matching on a condition operator such as `contains` against a field the rule author assumes is always a plain string (e.g. `command`).
2. Trigger a `Bash` tool call whose `tool_input` yields a non-string value for that field where the rule engine's `_extract_field` logic returns something other than a `str` for that key (exact reachability depends on `_extract_field`'s implementation at `rule_engine.py:182-255`, which could not be fully verified in this pass — a Devin session with full file access should confirm which fields/tool types can produce non-string values).
3. `_check_condition` raises an unhandled exception (e.g. `TypeError: argument of type 'X' is not iterable`).
4. `pretooluse.py`'s outer `except Exception` catches it, prints only a `systemMessage`, and `sys.exit(0)` — no deny decision is emitted.
5. The Bash command executes despite the configured `block` rule, confirming the fail-open bypass. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** plugins/hookify/core/rule_engine.py (L35-94)
```python
    def evaluate_rules(self, rules: List[Rule], input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate all rules and return combined results.

        Checks all rules and accumulates matches. Blocking rules take priority
        over warning rules. All matching rule messages are combined.

        Args:
            rules: List of Rule objects to evaluate
            input_data: Hook input JSON (tool_name, tool_input, etc.)

        Returns:
            Response dict with systemMessage, hookSpecificOutput, etc.
            Empty dict {} if no rules match.
        """
        hook_event = input_data.get('hook_event_name', '')
        blocking_rules = []
        warning_rules = []

        for rule in rules:
            if self._rule_matches(rule, input_data):
                if rule.action == 'block':
                    blocking_rules.append(rule)
                else:
                    warning_rules.append(rule)

        # If any blocking rules matched, block the operation
        if blocking_rules:
            messages = [f"**[{r.name}]**\n{r.message}" for r in blocking_rules]
            combined_message = "\n\n".join(messages)

            # Use appropriate blocking format based on event type
            if hook_event == 'Stop':
                return {
                    "decision": "block",
                    "reason": combined_message,
                    "systemMessage": combined_message
                }
            elif hook_event in ['PreToolUse', 'PostToolUse']:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": hook_event,
                        "permissionDecision": "deny"
                    },
                    "systemMessage": combined_message
                }
            else:
                # For other events, just show message
                return {
                    "systemMessage": combined_message
                }

        # If only warnings, show them but allow operation
        if warning_rules:
            messages = [f"**[{r.name}]**\n{r.message}" for r in warning_rules]
            return {
                "systemMessage": "\n\n".join(messages)
            }

        # No matches - allow operation
        return {}
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

**File:** plugins/hookify/skills/writing-rules/SKILL.md (L48-51)
```markdown
**action** (optional): What to do when rule matches
- `warn`: Show message but allow operation (default)
- `block`: Prevent operation (PreToolUse) or stop session (Stop events)
- If omitted, defaults to `warn`
```
