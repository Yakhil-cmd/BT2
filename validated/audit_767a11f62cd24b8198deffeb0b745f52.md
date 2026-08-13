### Title
Frontmatter boolean coercion silently disables hookify block rules whose `pattern` value is the literal string "true"/"false" - ([File: plugins/hookify/core/config_loader.py])

### Summary
`extract_frontmatter` coerces *any* top-level scalar frontmatter value that textually equals `"true"`/`"false"` (case-insensitively, after quote-stripping) into a Python `bool`, with no type/key awareness. When this coercion hits the legacy `pattern:` field of a hookify rule, the resulting rule silently loses all its match conditions and can never fire, defeating the enforcement the rule was written to provide, with no error, warning, or exception surfaced anywhere in the hook pipeline.

### Finding Description
In `extract_frontmatter` (`plugins/hookify/core/config_loader.py`), every top-level `key: value` line is parsed generically: [1](#0-0) 
```
value = value.strip('"').strip("'")
if value.lower() == 'true':
    value = True
elif value.lower() == 'false':
    value = False
frontmatter[key] = value
```
This coercion is applied blindly to *every* key, including the legacy `pattern:` field. `Rule.from_dict` treats `pattern` as a plain string that gets turned into a `Condition` only if it is truthy: [2](#0-1) 

If a rule author writes a legacy-style rule whose pattern is exactly the text `false` (e.g. quoted as `pattern: "false"`, meant to detect the literal word `false` appearing in a bash command such as `test "$x" = false` or `echo false`), the quote-stripping plus boolean coercion converts `"false"` into the Python boolean `False`. Since `simple_pattern` is now falsy, the `if simple_pattern and not conditions:` branch never executes, so `conditions` stays empty. The resulting `Rule` object has `conditions=[]`.

Downstream in `RuleEngine._rule_matches` (`plugins/hookify/core/rule_engine.py`): [3](#0-2) 
```
if not rule.conditions:
    return False
```
A rule with no conditions can never match, so the rule silently becomes a permanent no-op — even though `enabled: true` and `action: block` are set correctly in the frontmatter. No exception is thrown, no warning is logged; the hook pipeline (`pretooluse.py`/`posttooluse.py`/`stop.py`) simply returns `{}` (allow) for every invocation, exactly as if the rule did not exist. This is a trust-boundary failure: the file appears to define an active blocking rule, but the enforcement layer never evaluates it, so any attacker-controlled command/content matching the intended pattern text (`false`/`true`) sails through with no detection or block, and the maintainer has no visibility that the control silently failed.

### Impact Explanation
This is a silent security-control bypass in Claude Code's own hook-enforcement plugin: a hookify rule that is supposed to block or warn on dangerous bash commands / file edits containing the literal pattern text `true` or `false` is coerced into a non-functional rule at load time with zero conditions, and thus never blocks anything, without any error surfaced to the user or maintainer. This directly undermines an approval/allowlist-style safety mechanism (hookify block rules), letting an attacker's command execute unimpeded through the trust boundary the rule was meant to enforce.

### Likelihood Explanation
Preconditions: a `.claude/hookify.*.local.md` rule file using the legacy `pattern:` field (not the newer `conditions:` list) with a pattern value that, after quote-stripping, equals `true`/`False`/`TRUE`/etc. This is a realistic authoring mistake since `pattern` is a free-form regex/string field and the legacy single-pattern style is explicitly documented/supported. The bug is 100% deterministic and reproducible — no race conditions, no privilege needed, and no error message hints at the failure, making it plausible the rule silently stops protecting long after being authored.

### Recommendation
Restrict the `true`/`false` string-to-bool coercion in `extract_frontmatter` to known boolean keys only (e.g. `enabled`), rather than applying it to every scalar value including `pattern`, `name`, `tool_matcher`, etc. Alternatively, perform the coercion after key-specific typing is known (in `Rule.from_dict`), keeping `extract_frontmatter` type-agnostic (all values as strings) and letting each consumer coerce only the fields it expects to be boolean.

### Proof of Concept
Add a unit test to `plugins/hookify/core/config_loader.py` test suite:
```python
def test_pattern_field_not_coerced_to_bool():
    content = '''---
name: block-false-literal
enabled: true
event: bash
pattern: "false"
action: block
---
Block commands containing the word false.
'''
    frontmatter, message = extract_frontmatter(content)
    rule = Rule.from_dict(frontmatter, message)

    # Bug: pattern becomes Python bool False, not the string "false"
    assert isinstance(frontmatter['pattern'], str), (
        f"pattern was coerced to {type(frontmatter['pattern'])}"
    )
    # Bug: rule ends up with zero conditions and can never match
    assert len(rule.conditions) == 1, "rule silently lost its condition"

    from hookify.core.rule_engine import RuleEngine
    engine = RuleEngine()
    input_data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "test $x = false"}
    }
    result = engine.evaluate_rules([rule], input_data)
    # Bug: block rule never fires, result is {} (allowed) instead of a deny decision
    assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
```
Expected current (buggy) behavior: `frontmatter['pattern']` is `False` (bool), `rule.conditions == []`, and `evaluate_rules` returns `{}` (command allowed) instead of denying — demonstrating the silent bypass.

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

**File:** plugins/hookify/core/rule_engine.py (L115-118)
```python
        # If no conditions, don't match
        # (Rules must have at least one condition to be valid)
        if not rule.conditions:
            return False
```
