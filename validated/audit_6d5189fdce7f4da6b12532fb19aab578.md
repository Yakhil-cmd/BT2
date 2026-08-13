### Title
Case-sensitive `action == 'block'` comparison silently downgrades block rules to warnings - ([File: plugins/hookify/core/rule_engine.py])

### Finding Description
`RuleEngine.evaluate_rules` classifies a matched rule as blocking only via a strict, case-sensitive equality check: `if rule.action == 'block':` [1](#0-0) . The `action` value originates from YAML frontmatter parsed by `extract_frontmatter`/`Rule.from_dict` in `config_loader.py`, which only special-cases the string values `"true"`/`"false"` (booleans) — it never normalizes or lowercases the `action` field, and strips only surrounding quotes: `frontmatter[key] = value` after `value.strip('"').strip("'")` [2](#0-1) , and `action=frontmatter.get('action', 'warn')` is assigned verbatim [3](#0-2) .

Consequently any casing/whitespace variant of `block` (`Block`, `BLOCK`, `" block"` with a leading space introduced by non-trimmed multi-line dict continuation parsing, etc.) fails the `== 'block'` check and the rule falls into `warning_rules`, which only returns `{"systemMessage": ...}` with no `hookSpecificOutput.permissionDecision: "deny"` and no `decision: "block"` for Stop events [4](#0-3) . `pretooluse.py main()` forwards this result verbatim to Claude Code via stdout and always exits 0 [5](#0-4) , so the tool call (e.g. a dangerous `Bash`/`Write` operation matching the rule's condition) proceeds — only a warning message is shown, not an enforced deny.

The exploit path: an attacker submits a PR that adds or edits a `.claude/hookify.*.local.md` rule file for a repo that a victim checks out and runs Claude Code against. The diff can present a rule that appears to intend blocking (e.g. `action: Block`) — visually indistinguishable from the correct enforcing value to a reviewer skimming the PR — while the case-sensitive comparison silently treats it as `warn`. No existing validation checks the `action` value against the allowed set (`warn`/`block`); there's no schema validation, no case-normalization, and no warning printed when an unrecognized action string is used.

### Impact Explanation
A rule that appears to be authored/reviewed as a hard "block" of dangerous `Bash`/`Write` tool_input silently degrades to a non-blocking warning. This breaks the invariant that "deny means deny": the dangerous command or file write executes despite a rule that was intended (and appears, textually) to block it. This is a silent security-control degradation / trust-boundary bypass in Claude Code's hook enforcement, matching bounty categories for approval-bypass / unauthorized command or file action.

### Likelihood Explanation
Requires only that a hookify rule file's `action` field contains anything other than the exact lowercase string `block` (including plausible near-miss values like `Block`, `BLOCK`, or a leading/trailing-space value produced by the hand-rolled YAML parser's inline/continuation handling). This is trivially reachable by anyone who can influence a checked-in `.claude/hookify.*.local.md` file via PR, and is not caught by any existing test, schema check, or normalization logic in `config_loader.py` or `rule_engine.py`.

### Recommendation
Normalize the `action` field when parsing (`action=str(frontmatter.get('action', 'warn')).strip().lower()`) and validate it against the allowed set `{"warn", "block"}`, logging/rejecting (or defaulting to the safer `block`) on any unrecognized value instead of silently treating it as `warn`. Apply the same case-insensitive comparison in `RuleEngine.evaluate_rules`.

### Proof of Concept
Unit test in `plugins/hookify/core/rule_engine.py` test harness / pytest:
```python
from hookify.core.config_loader import Rule, Condition
from hookify.core.rule_engine import RuleEngine

def make_rule(action):
    return Rule(name="r", enabled=True, event="bash", action=action,
                conditions=[Condition(field="command", operator="regex_match", pattern="rm -rf")],
                message="danger")

engine = RuleEngine()
tool_input = {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}

for action in ["BLOCK", "Block", " block", "block "]:
    result = engine.evaluate_rules([make_rule(action)], tool_input)
    assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny", \
        f"action={action!r} did not enforce deny: {result}"
```
Expected (current buggy) behavior: assertion fails for all four near-miss values — they return only `systemMessage` with no `permissionDecision: deny`, proving the block rule silently degrades to a warning.

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

**File:** plugins/hookify/core/config_loader.py (L146-152)
```python
                # Simple key-value pair
                value = value.strip('"').strip("'")
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                frontmatter[key] = value
```

**File:** plugins/hookify/hooks/pretooluse.py (L51-70)
```python
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
