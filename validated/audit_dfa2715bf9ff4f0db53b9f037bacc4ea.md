Confirmed: the parsing bug exists exactly as described, and it feeds directly into the rule-blocking path.

### Title
Inline frontmatter list-dict parser truncates comma-containing patterns, silently weakening block rules - ([File: plugins/hookify/core/config_loader.py])

### Summary
`extract_frontmatter`'s inline-dict branch for list items (`- field: command, operator: regex_match, pattern: rm -rf,dd if=`) splits the entire item text on every comma before splitting on `:`, so any comma embedded inside a `pattern` value truncates the pattern at the first comma. The resulting `Condition.pattern` (built via `Condition.from_dict`) is silently shorter than the rule author intended, weakening detection in `RuleEngine._check_condition`.

### Finding Description
In `extract_frontmatter`, when a YAML list item under `conditions:` is written inline and contains both `:` and `,`, the parser takes the "inline comma-separated dict" branch: [1](#0-0) 
It does `item_text.split(',')` first, then for each comma-delimited `part` splits on `:` once. If the `pattern` field's value itself contains a comma — a very natural thing for a "match multiple dangerous substrings" pattern like `rm -rf,dd if=` or a regex alternation intended to be written with commas — the value gets cut at the first comma, and everything after it becomes a bogus extra "key" fragment with no `:` (silently dropped, since only parts containing `:` are kept: `if ':' in part`). The truncated dict `{'field': 'command', 'operator': 'regex_match', 'pattern': 'rm -rf'}` is what reaches `Condition.from_dict`: [2](#0-1) 
This `Condition` is then evaluated in `RuleEngine._check_condition`, which uses `condition.pattern` directly for `regex_match`/`contains`/etc: [3](#0-2) 
If the rule's `action` is `block`, this silently-truncated pattern is what gates the block decision in `evaluate_rules`: [4](#0-3) 
So a rule author intending to block `rm -rf` OR `dd if=` variants ends up with a rule that only catches `rm -rf`, with no error, warning, or validation raised anywhere in `load_rule_file`/`load_rules`.

### Impact Explanation
This is a silent security-control degradation: a rule author (project maintainer trying to configure a `hookify` block rule) writes a condition intended to catch multiple dangerous command variants separated by commas in a single `pattern`, but the parser truncates it, and the loaded rule looks/behaves correctly in the common case (`rm -rf` alone) while failing to catch the very variant the comma was meant to add (`dd if=...`). Since these `hookify.*.local.md` rule files are ordinary repo content, an attacker able to influence rule content (e.g. via a PR modifying `.claude/hookify.*.local.md`, or a shared/template rule file) could introduce this exact inline-comma pattern under the guise of a legitimate-looking multi-pattern rule, causing block-rule matching to have a reduced match surface without any indication of failure — a scoped detection-bypass/weakened-block-condition impact within `hookify`'s own hook enforcement.

### Likelihood Explanation
High feasibility: writing a `pattern` containing a comma in the inline single-line list form is a natural, unremarkable authoring choice (patterns like `rm -rf,dd if=` or comma-based alternation lists are exactly the kind of thing someone would write). No special privileges are needed beyond being able to add/edit a `.claude/hookify.*.local.md` file, and the bug triggers on every such inline-comma pattern deterministically and silently — no error is logged from `load_rule_file`.

### Recommendation
In `extract_frontmatter`, do not use `item_text.split(',')` to delimit key/value pairs. Instead, either: (1) restrict the inline-dict comma-split to occur only on `, ` sequences that are followed by a recognized field name and `:` (e.g. via regex `(?=,\s*\w+\s*:)` lookahead split), or (2) require/prefer the multi-line dict-item form for any pattern containing a comma and document/validate that inline single-line conditions must not contain literal commas within field values, raising a parse warning when a `pattern` value looks truncated. A more robust fix is to replace this ad-hoc parser with a proper YAML library (e.g. `yaml.safe_load`) for frontmatter parsing, eliminating this whole class of comma/colon ambiguity bugs.

### Proof of Concept
Unit test in `plugins/hookify/core/config_loader.py` style:
```python
from hookify.core.config_loader import extract_frontmatter, Rule

content = """---
name: block-dangerous
enabled: true
event: bash
action: block
conditions:
  - field: command, operator: regex_match, pattern: rm -rf,dd if=
---

Blocked dangerous command.
"""

fm, msg = extract_frontmatter(content)
rule = Rule.from_dict(fm, msg)
cond = rule.conditions[0]

# Expected (intended by rule author):
assert cond.pattern == "rm -rf,dd if="
# Actual (bug):
# cond.pattern == "rm -rf"  -> "dd if=" silently dropped from the pattern
```
Assert that `cond.pattern` equals the full intended pattern string; the test currently fails, demonstrating that `dd if=...` commands would not be blocked even though the rule author intended them to be.

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

**File:** plugins/hookify/core/config_loader.py (L163-171)
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
```

**File:** plugins/hookify/core/rule_engine.py (L53-63)
```python
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
```

**File:** plugins/hookify/core/rule_engine.py (L162-177)
```python
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
```
