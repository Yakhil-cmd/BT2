### Title
Fragile hand-rolled frontmatter parser silently drops explicit `conditions` fields (via flow-mapping YAML), causing block rules to become permanently inert — unlike the robust legacy `pattern` path - ([File: `plugins/hookify/core/config_loader.py`])

### Summary
`extract_frontmatter()` implements a hand-rolled, partial YAML parser to turn `.claude/hookify.*.local.md` frontmatter into a dict that is fed to `Rule.from_dict`/`Condition.from_dict`. When the explicit `conditions:` list is written using valid, ordinary YAML flow-mapping syntax (e.g. `- {field: command, operator: contains, pattern: rm -rf}`), the parser mis-splits the item on commas and produces a malformed key (`"{field"` instead of `"field"`), so `Condition.from_dict` silently defaults `field` to `''`. The legacy `pattern:` scalar form has no such fragility. The result is a rule that loads successfully, appears `enabled` with `action: block`, but never matches anything and therefore never blocks.

### Finding Description
The reachable path is: hook execution (`plugins/hookify/hooks/pretooluse.py` and friends) → `load_rules()` → `load_rule_file()` → `extract_frontmatter()` → `Rule.from_dict()` → `Condition.from_dict()` [1](#0-0) .

`extract_frontmatter` implements only two shapes for a list item that contains a colon: an "inline comma-separated dict" split naively on `,` then `:` per part, or a "multi-line dict item" continuation [2](#0-1) . For an item written as ordinary YAML flow-mapping, e.g. `- {field: command, operator: contains, pattern: rm -rf}`, the code takes the "inline comma-separated dict" branch and blindly splits on `,` then `:` without stripping the leading `{` / trailing `}`, so the emitted dict is effectively `{"{field": "command", "operator": "contains", "pattern": "rm -rf}"}` — the `field` key is corrupted to `"{field"`.

`Condition.from_dict` then reads `data.get('field', '')`, which silently returns `''` instead of raising or warning [3](#0-2) . Downstream, `RuleEngine._check_condition` calls `_extract_field('', ...)`, which matches none of the direct `tool_input` keys nor any of the special-cased field names, returning `None`; `_check_condition` then returns `False` unconditionally for that condition [4](#0-3) . Because `_rule_matches` requires **all** conditions to match, and there is no error surfaced anywhere in this chain, a rule with `action: block` becomes permanently inert while still being reported as loaded/enabled — no exception is thrown, no warning is printed, and `rule.conditions` is non-empty (so the `if not rule.conditions: return False` fail-open guard doesn't even trigger a visible signal) [5](#0-4) .

By contrast, the legacy `pattern:` scalar form is parsed by the simple `key: value` top-level branch with no comma-splitting hazards, and is converted deterministically into a single well-formed `Condition` [6](#0-5) . This creates exactly the differential the question describes: identical *intended* semantics (block dangerous command X) expressed via legacy `pattern` reliably blocks, while the same intent expressed via explicit `conditions` using ordinary flow-mapping YAML silently degrades to "never blocks," with no indication to the rule author/reviewer that anything is wrong.

No existing validation catches this: `load_rule_file` only checks that `frontmatter` is non-empty and catches `(ValueError, KeyError, AttributeError, TypeError)`/generic exceptions around parsing, none of which fire here since the malformed dict is a perfectly valid (if wrong-keyed) Python dict [7](#0-6) .

### Impact Explanation
This is a Security-control bypass: a `.claude/hookify.*.local.md` rule intended to block a dangerous Bash command, file edit, or Stop condition can be rendered permanently non-functional purely by how its `conditions:` YAML is formatted — a form an LLM-driven `/hookify` rule-generation flow, or a rule file contributed via a repository (e.g. a PR), could plausibly produce or be induced to produce. The user/maintainer sees the rule file present, `enabled: true`, `action: block`, believes they are protected, and the hook silently allows the exact operation the rule was meant to stop — with zero error output during load or evaluation.

### Likelihood Explanation
Preconditions: the attacker (or a flawed generation flow) needs to get a `hookify.*.local.md` file with an explicit `conditions:` list using flow-mapping (`{...}`) list-item syntax into `.claude/` — either by convincing `/hookify` to emit it that way, or by shipping such a rule file in repo content that gets adopted. This requires no privilege escalation, no code execution, and no bypass of any existing guard, because no guard currently exists for this parsing path. It is fully deterministic and reproducible with a single crafted frontmatter block.

### Recommendation
- Replace the hand-rolled frontmatter parser with a real YAML parser (e.g. `PyYAML` safe_load) so flow-mappings, quoting, and indentation are handled per the YAML spec instead of ad-hoc comma/colon splitting.
- If a custom parser must be kept, strip `{`/`}` before/after splitting flow-mapping items and validate resulting keys against the expected `Condition` schema (`field`, `operator`, `pattern`), raising a loud parse error (not silently defaulting) on unexpected keys.
- In `Condition.from_dict`, reject/warn on empty/missing `field` rather than silently defaulting to `''`, and in `load_rule_file`, refuse to load (or explicitly warn and disable) any `action: block` rule that resolves to zero effectively-matchable conditions.
- Add a startup/self-check (e.g. `/hookify` doctor command) that re-evaluates every loaded rule against a synthetic matching input to confirm `action: block` rules can actually match before treating them as active.

### Proof of Concept
Unit test to add to `plugins/hookify/core/` test suite:

```python
from hookify.core.config_loader import extract_frontmatter, Rule
from hookify.core.rule_engine import RuleEngine

def test_flow_mapping_condition_is_corrupted_and_rule_never_blocks():
    content = """---
name: block-rm-rf
enabled: true
event: bash
action: block
conditions:
  - {field: command, operator: contains, pattern: rm -rf}
---

Blocked dangerous rm -rf command!
"""
    frontmatter, message = extract_frontmatter(content)
    rule = Rule.from_dict(frontmatter, message)

    # Bug: the parsed condition's field is corrupted, not 'command'
    assert rule.conditions[0].field != 'command'  # demonstrates corruption

    engine = RuleEngine()
    result = engine.evaluate_rules([rule], {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"}
    })

    # Expected (secure) behavior: block
    # Actual (buggy) behavior: {} -- rule never matches, command is allowed
    assert result != {}, "Block rule silently failed to fire due to frontmatter parsing differential"
```

Running this against current code shows `result == {}` for a command (`rm -rf /`) the rule was explicitly written to block, while an equivalent legacy-form rule (`pattern: "rm -rf"` with the same `event: bash`) correctly blocks — confirming the semantic divergence between legacy and explicit condition parsing.

### Citations

**File:** plugins/hookify/core/config_loader.py (L22-29)
```python
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Condition':
        """Create Condition from dict."""
        return cls(
            field=data.get('field', ''),
            operator=data.get('operator', 'regex_match'),
            pattern=data.get('pattern', '')
        )
```

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

**File:** plugins/hookify/core/config_loader.py (L163-181)
```python
            # Check if this is an inline dict (key: value on same line)
            if ':' in item_text and ',' in item_text:
                # Inline comma-separated dict: "- field: command, operator: regex_match"
                item_dict = {}
                for part in item_text.split(','):
                    if ':' in part:
                        k, v = part.split(':', 1)
                        item_dict[k.strip()] = v.strip().strip('"').strip("'")
                current_list.append(item_dict)
                in_dict_item = False
            elif ':' in item_text:
                # Start of multi-line dict item: "- field: command"
                in_dict_item = True
                k, v = item_text.split(':', 1)
                current_dict = {k.strip(): v.strip().strip('"').strip("'")}
            else:
                # Simple list item
                current_list.append(item_text.strip('"').strip("'"))
                in_dict_item = False
```

**File:** plugins/hookify/core/config_loader.py (L244-268)
```python
def load_rule_file(file_path: str) -> Optional[Rule]:
    """Load a single rule file.

    Returns:
        Rule object or None if file is invalid.
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()

        frontmatter, message = extract_frontmatter(content)

        if not frontmatter:
            print(f"Warning: {file_path} missing YAML frontmatter (must start with ---)", file=sys.stderr)
            return None

        rule = Rule.from_dict(frontmatter, message)
        return rule

    except (IOError, OSError, PermissionError) as e:
        print(f"Error: Cannot read {file_path}: {e}", file=sys.stderr)
        return None
    except (ValueError, KeyError, AttributeError, TypeError) as e:
        print(f"Error: Malformed rule file {file_path}: {e}", file=sys.stderr)
        return None
```

**File:** plugins/hookify/core/rule_engine.py (L115-125)
```python
        # If no conditions, don't match
        # (Rules must have at least one condition to be valid)
        if not rule.conditions:
            return False

        # All conditions must match
        for condition in rule.conditions:
            if not self._check_condition(condition, tool_name, tool_input, input_data):
                return False

        return True
```

**File:** plugins/hookify/core/rule_engine.py (L144-167)
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
```
