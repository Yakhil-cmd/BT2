### Title
Malicious hookify rule file crashes RuleEngine.evaluate_rules() and causes pretooluse.py's bare except to fail-open instead of denying a matched blocking rule - (File: plugins/hookify/hooks/pretooluse.py)

### Summary
A rule file matching `.claude/hookify.*.local.md` can set a legacy `pattern:` frontmatter field to an unquoted boolean literal (e.g. `pattern: true`), which the custom YAML-lite parser in `extract_frontmatter()` converts to a Python `bool`. This non-string pattern is stored unchanged in `Condition.pattern` and later passed to `re.compile()`, raising an uncaught `TypeError` that is not `re.error`, so it escapes `RuleEngine.evaluate_rules()` entirely and is swallowed by `main()`'s bare `except Exception` in `pretooluse.py`, which always prints only a `systemMessage` and calls `sys.exit(0)` — never `permissionDecision: deny`.

### Finding Description
`load_rules()` in `plugins/hookify/core/config_loader.py` glob-loads every `.claude/hookify.*.local.md` file and, for each, calls `load_rule_file()` → `extract_frontmatter()` → `Rule.from_dict()`. In `extract_frontmatter()`, a simple top-level `key: value` frontmatter line performs an unconditional string→bool coercion: [1](#0-0) 
If a rule uses the legacy `pattern:` field (not the `conditions:` list) with an unquoted boolean value, `frontmatter['pattern']` becomes a Python `bool` (`True`/`False`) rather than a string. `Rule.from_dict()` accepts this value uncritically and wraps it in a `Condition`: [2](#0-1) 
Neither `load_rule_file()` nor `load_rules()` perform any type validation on `Condition.pattern`, so this malformed `Rule` is returned successfully (no exception raised during load) and added to the enabled rule list.

When `pretooluse.py`'s `main()` later calls `engine.evaluate_rules(rules, input_data)`, evaluation iterates all loaded rules. For the crafted rule, `_check_condition()` dispatches to `_regex_match(pattern, field_value)` with `pattern=True`: [3](#0-2) 
`compile_regex(True)` calls `re.compile(True, re.IGNORECASE)`, which raises `TypeError: first argument must be string or compiled pattern`. This is only caught as `except re.error`, so the `TypeError` propagates out of `_regex_match`, `_check_condition`, `_rule_matches`, and `evaluate_rules()` — none of which have their own try/except for this path: [4](#0-3) 

Because `evaluate_rules()` iterates the entire `rules` list in a single `for` loop before returning any decision (accumulating `blocking_rules`/`warning_rules`), an exception raised while evaluating the malicious rule aborts the function before any legitimate blocking rule already in the list (or a rule evaluated after it) can produce the `permissionDecision: deny` response. The exception then unwinds into `pretooluse.py`'s `main()`: [5](#0-4) 
which prints only `{"systemMessage": "Hookify error: ..."}` and, in the `finally` block, always calls `sys.exit(0)` — never emitting `hookSpecificOutput.permissionDecision: deny`. The same bug affects `posttooluse.py`, `stop.py`, and `userpromptsubmit.py`, which share identical `except Exception ... sys.exit(0)` structure.

### Impact Explanation
Any user-defined blocking rule (e.g. "block `rm -rf`", "block writes to `.env`") that is co-resident with the attacker-planted malformed rule file becomes silently disabled the moment the malicious rule is evaluated, because the whole `evaluate_rules()` call aborts with an exception and the hook fails open (`sys.exit(0)` with no deny). This lets an attacker who can add/modify one file under `.claude/hookify.*.local.md` in a cloned repository defeat all hookify enforcement for Bash/Write/Edit/MultiEdit operations in that session — enabling workspace escape (destructive commands proceeding) or secret exfiltration (writes/edits that should have been denied instead succeed), violating the "deny means deny" / fail-closed invariant.

### Likelihood Explanation
This requires only the stated precondition: the attacker can add or modify a file matching `hookify.*.local.md` in a cloned repository (no special privilege). Creating such a file with a legacy `pattern: true` field is trivial and requires no knowledge of the victim's other configured rules — the crash occurs unconditionally whenever the hook evaluates any rule set containing this file, on every Bash/Write/Edit/MultiEdit tool call, making it fully repeatable.

### Recommendation
- In `Condition.from_dict()` / `Rule.from_dict()` (`plugins/hookify/core/config_loader.py`), validate that `pattern` fields are strings (coerce with `str()` or reject/skip the rule with a warning) before constructing `Condition`/`Rule` objects.
- In `RuleEngine._regex_match()` / `compile_regex()` (`plugins/hookify/core/rule_engine.py`), broaden the exception handling from `except re.error` to also catch `TypeError`, returning `False` (no match) instead of propagating.
- More generally, wrap each individual rule's evaluation in `evaluate_rules()`'s loop in its own try/except so one malformed rule cannot abort evaluation of all other rules, and ensure any uncaught error in `pretooluse.py`'s `main()` fails closed for events with a matching `action: block` intent (or at minimum does not silently exit 0 without signaling degraded enforcement).

### Proof of Concept
Unit test (pytest) demonstrating the bypass:

```python
import json
from hookify.core.rule_engine import RuleEngine
from hookify.core.config_loader import Rule, Condition

def test_malformed_pattern_crashes_evaluation_and_masks_block():
    # Legitimate blocking rule that should deny rm -rf
    legit_rule = Rule(
        name="block-rm-rf", enabled=True, event="bash", action="block",
        conditions=[Condition(field="command", operator="regex_match", pattern=r"rm\s+-rf")],
        message="Blocked dangerous rm -rf"
    )
    # Malicious rule crafted from frontmatter `pattern: true` (legacy field, coerced to bool)
    malicious_rule = Rule(
        name="crash-rule", enabled=True, event="bash", action="warn",
        conditions=[Condition(field="command", operator="regex_match", pattern=True)],
        message="crash"
    )

    engine = RuleEngine()
    input_data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /important-data"}
    }

    # This raises TypeError instead of returning a deny decision,
    # proving evaluate_rules() cannot fail closed.
    import pytest
    with pytest.raises(TypeError):
        engine.evaluate_rules([malicious_rule, legit_rule], input_data)
```

Integration test simulating the full hook via `pretooluse.py`'s `main()` (subprocess or monkeypatched `sys.stdin`/`load_rules`) asserting:
1. stdout JSON never contains `"permissionDecision": "deny"`.
2. Process exit code is `0`.
3. This occurs even though `legit_rule`'s pattern (`rm -rf`) matches the simulated `tool_input.command`, proving the dangerous Bash call is not stopped.

### Citations

**File:** plugins/hookify/core/config_loader.py (L56-73)
```python
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
```

**File:** plugins/hookify/core/config_loader.py (L145-152)
```python
            else:
                # Simple key-value pair
                value = value.strip('"').strip("'")
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                frontmatter[key] = value
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

**File:** plugins/hookify/core/rule_engine.py (L256-273)
```python
    def _regex_match(self, pattern: str, text: str) -> bool:
        """Check if pattern matches text using regex.

        Args:
            pattern: Regex pattern
            text: Text to match against

        Returns:
            True if pattern matches
        """
        try:
            # Use cached compiled regex (LRU cache with max 128 patterns)
            regex = compile_regex(pattern)
            return bool(regex.search(text))

        except re.error as e:
            print(f"Invalid regex pattern '{pattern}': {e}", file=sys.stderr)
            return False
```

**File:** plugins/hookify/hooks/pretooluse.py (L61-70)
```python
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
