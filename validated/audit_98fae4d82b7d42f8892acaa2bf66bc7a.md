### Title
Hookify `evaluate_rules` silently downgrades any non-literal `'block'` action to a permissive warning, allowing prompt-injected or malformed rule files to bypass intended blocking - (File: plugins/hookify/core/rule_engine.py)

### Finding Description
`RuleEngine.evaluate_rules` classifies a matched rule as blocking only via a strict string equality check, `if rule.action == 'block':`, and routes every other value — including typos, alternate casing, unsupported synonyms (`deny`, `Block`, `BLOCK`), or missing/malformed values — into `warning_rules`, which only attaches a `systemMessage` and returns without setting `permissionDecision: deny` [1](#0-0) . The warning path allows the operation to proceed while merely displaying a message [2](#0-1) . `Rule.action` is loaded directly from the YAML frontmatter without validation against an allowed set: `action=frontmatter.get('action', 'warn')` accepts any string as-is [3](#0-2) .

The `/hookify` command's conversation-analysis flow builds rule frontmatter (`action: {warn|block}`) from an LLM-driven summary of the current conversation, which can include text originating from issue/PR content the user pasted or referenced [4](#0-3) . Because the generator is natural-language driven rather than a fixed enum selection enforced in code, attacker-influenced conversation content can cause the written `action:` value to deviate from the literal `block` string (e.g., different casing, a close synonym, or omission) while the accompanying human-readable message still claims the operation is blocked. `pretooluse.py` passes the parsed rule straight into `evaluate_rules` with no secondary validation of `action`, and any exception during rule loading is swallowed and treated as an allow (`sys.exit(0)` after printing an error) [5](#0-4) , compounding the same "fail open on ambiguity" pattern.

The root cause is that the deny/allow boundary is determined by an un-validated, non-enum string field with an implicit fallback to the permissive branch, rather than validating against `{'block','warn'}` and failing safe (deny or explicit error) for anything else.

### Impact Explanation
A hookify rule the user believes is `action: block` (intended to prevent a dangerous Bash/file operation) can silently behave as `action: warn`, letting the operation execute while only showing a message the user may not read before the tool call completes. This is an unauthorized command/file-action execution the user reasonably believed was blocked by their own configured guardrail — matching the "hook enforcement bypass" / "approval-decision downgrade" class of impact, scoped to the local hookify PreToolUse/PostToolUse/Stop enforcement rather than any remote compromise.

### Likelihood Explanation
Requires: (1) the user runs `/hookify` and its conversation-analysis path incorporates attacker-influenced text (e.g., pasted issue/PR content) into rule generation, and (2) the generated `action` value deviates from the exact literal `block` string. Because `hookify.md` documents a fixed two-option selection (`warn`/`block`) via `AskUserQuestion`, the most reliable trigger is any code path or manual/LLM-authored `.local.md` edit that writes an `action` value with different casing, whitespace, or a synonym — plausible but not the primary generation path, making exploitation feasible but not the most direct route. The underlying weakness (silent fallback rather than validation) is deterministic and always reachable via crafted rule files regardless of the generation path.

### Recommendation
In `Rule.from_dict`/`evaluate_rules`, normalize and validate the `action` field against an explicit allowlist (`{'block', 'warn'}`), e.g. lowercase/strip the value and raise or default to the safer `block` (or reject the rule entirely with a loud stderr warning and skip loading it) when the value is unrecognized, instead of silently treating anything non-`'block'` as `warn`.

### Proof of Concept
```python
# test_rule_engine_action_validation.py
from hookify.core.config_loader import Rule, Condition
from hookify.core.rule_engine import RuleEngine

def make_rule(action_value):
    return Rule(
        name="test-block-typo",
        enabled=True,
        event="bash",
        action=action_value,  # simulates malformed/ambiguous frontmatter value
        conditions=[Condition(field="command", operator="regex_match", pattern=r"rm\s+-rf")],
        message="This should be BLOCKED",
    )

def test_unrecognized_action_does_not_silently_allow():
    engine = RuleEngine()
    input_data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
    }
    for bad_action in ["Block", "BLOCK", " block", "deny", "blck", None]:
        result = engine.evaluate_rules([make_rule(bad_action)], input_data)
        # Expected (fixed) behavior: deny or explicit error, NOT silent allow-with-message
        assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny", (
            f"action={bad_action!r} unexpectedly fell through to warn/allow: {result}"
        )
```
Current behavior: for every `bad_action` value the assertion fails because `evaluate_rules` returns only `{"systemMessage": ...}` (warning branch) instead of `permissionDecision: deny`, confirming the silent downgrade.

### Citations

**File:** plugins/hookify/core/rule_engine.py (L53-58)
```python
        for rule in rules:
            if self._rule_matches(rule, input_data):
                if rule.action == 'block':
                    blocking_rules.append(rule)
                else:
                    warning_rules.append(rule)
```

**File:** plugins/hookify/core/rule_engine.py (L86-91)
```python
        # If only warnings, show them but allow operation
        if warning_rules:
            messages = [f"**[{r.name}]**\n{r.message}" for r in warning_rules]
            return {
                "systemMessage": "\n\n".join(messages)
            }
```

**File:** plugins/hookify/core/config_loader.py (L75-84)
```python
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

**File:** plugins/hookify/commands/hookify.md (L82-107)
```markdown
### Step 3: Generate Rule Files

For each confirmed behavior, create a `.claude/hookify.{rule-name}.local.md` file:

**Rule naming convention:**
- Use kebab-case
- Be descriptive: `block-dangerous-rm`, `warn-console-log`, `require-tests-before-stop`
- Start with action verb: block, warn, prevent, require

**File format:**
```markdown
---
name: {rule-name}
enabled: true
event: {bash|file|stop|prompt|all}
pattern: {regex pattern}
action: {warn|block}
---

{Message to show Claude when rule triggers}
```

**Action values:**
- `warn`: Show message but allow operation (default)
- `block`: Prevent operation or stop session

```

**File:** plugins/hookify/hooks/pretooluse.py (L52-70)
```python
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
