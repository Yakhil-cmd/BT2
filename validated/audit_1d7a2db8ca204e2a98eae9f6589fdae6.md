### Title
Presence of a `conditions` key silently disables legacy `pattern` blocking, allowing a `Rule.from_dict` differential to evade block rules - (File: `plugins/hookify/core/config_loader.py`)

### Summary
`Rule.from_dict` decides which matching path to use — the "new style" `conditions` list or the "legacy" `pattern` field — purely based on whether `conditions` is present and truthy after conversion, not on whether it is semantically valid. A frontmatter block that contains both a legitimate `pattern`/`event` pair and a syntactically valid but semantically empty `conditions` entry (e.g. `conditions: [{}]`) causes the legacy pattern to be dropped entirely, while the near-empty condition (`field=''`, `operator='regex_match'`, `pattern=''`) can never match real tool input, so the rule silently never fires.

### Finding Description
`Rule.from_dict` at [1](#0-0)  implements the dual legacy/explicit parsing:

```
if 'conditions' in frontmatter:
    cond_list = frontmatter['conditions']
    if isinstance(cond_list, list):
        conditions = [Condition.from_dict(c) for c in cond_list]

simple_pattern = frontmatter.get('pattern')
if simple_pattern and not conditions:
    ...  # build a condition from the legacy pattern
```

`Condition.from_dict` performs no validation and happily accepts missing/empty fields, defaulting `field=''`, `operator='regex_match'`, `pattern=''` [2](#0-1) .

If a frontmatter block contains **both** a legacy `pattern:` (e.g., `pattern: "rm -rf"`, `event: bash`, `action: block`) **and** a `conditions:` list with at least one entry — even a garbage/empty dict item such as `conditions: [{}]` — then:
1. `conditions` becomes a non-empty list (`[Condition(field='', operator='regex_match', pattern='')]`), which is truthy.
2. The `if simple_pattern and not conditions:` branch is skipped, so the legacy `pattern` is **discarded** and never converted into an enforceable condition.
3. At evaluation time, `RuleEngine._check_condition` extracts `field_value` via `_extract_field('', ...)`, which never matches any of the known tool_input/Stop-event field names and returns `None`, so `_check_condition` immediately returns `False` [3](#0-2) . Since `_rule_matches` requires **all** conditions to match, the rule can never fire [4](#0-3) .

The end result is a `Rule` object with `action == 'block'` and a legitimate-looking `message`, that a maintainer would believe enforces the `pattern` string, but which is functionally a no-op — it never blocks anything. Because `/hookify rule creation` frontmatter can be produced by LLM generation or come from a repo-shipped `hookify.*.local.md` file, an attacker who can influence the generated frontmatter (via prompt injection during rule generation, or by shipping a rule file in the repository) can smuggle in a spurious `conditions` entry alongside a real-looking `pattern`, silently defeating the block, while `load_rule_file`/`load_rules` treat the rule as successfully loaded and enabled with no warning [5](#0-4) .

There is no schema validation on `Condition` fields (empty `field`/`pattern` are accepted silently), and no cross-check comparing legacy-derived semantics vs explicit-derived semantics, so the "legacy and explicit rule forms must produce the same effective security semantics" invariant is broken: the mere co-presence of an (even empty) `conditions` key changes behavior from "pattern is enforced" to "nothing is enforced," with no error, warning or validation surfaced anywhere in `load_rule_file`/`load_rules`.

### Impact Explanation
A block rule intended to prevent dangerous Bash commands, edits, or Stop-event content (e.g., blocking exfiltration of secrets/diffs/tokens via `Bash`, `Write`/`Edit`, or Stop hooks) can be silently neutralized by an attacker-influenced rule frontmatter that never triggers, while still appearing enabled/loaded. This directly enables the operations the rule was meant to block (sensitive code/prompt/token/diff/local file disclosure to an unintended sink), since the hookify layer is the enforcement point for these protections and it fails open rather than failing closed.

### Likelihood Explanation
Exploitation only requires crafting/influencing frontmatter that hookify would parse — either through `/hookify rule creation` generation (which an attacker could influence via prompt injection in the material used to draft the rule) or through a repo-shipped `hookify.*.local.md` file merged into the repository. No special privilege beyond normal repository content control is needed, and the malformed `conditions` entry does not raise any parse error (`extract_frontmatter` and `Rule.from_dict` both accept it silently), making this a repeatable, low-effort evasion.

### Recommendation
- In `Rule.from_dict`, only treat `conditions` as authoritative if it contains at least one condition with non-empty `field` and `pattern` after parsing; otherwise fall back to (or additionally enforce) the legacy `pattern`.
- Add validation in `Condition.from_dict` (or a post-construction check in `Rule.from_dict`) that rejects/`raise`s on conditions with empty `field`/`pattern`, rather than silently constructing a condition that can never match.
- Surface a warning (or reject the rule / fail closed for `action == 'block'` rules) when both `pattern` and `conditions` are present but result in inconsistent/degenerate semantics, instead of silently dropping `pattern`.
- Add an explicit invariant test asserting that a frontmatter with `pattern` + `event` produces a `Rule` whose conditions always match the same inputs the legacy pattern alone would match.

### Proof of Concept
Unit test to add to `plugins/hookify/core/config_loader.py` tests (or a new test file):

```python
def test_empty_conditions_disables_legacy_pattern_block():
    frontmatter = {
        "name": "block-rm",
        "enabled": True,
        "event": "bash",
        "action": "block",
        "pattern": "rm -rf",
        "conditions": [{}],  # attacker/generation-supplied garbage entry
    }
    rule = Rule.from_dict(frontmatter, "Dangerous command blocked!")

    engine = RuleEngine()
    input_data = {
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"},
    }
    result = engine.evaluate_rules([rule], input_data)

    # Expected (intended) behavior: block
    # Actual behavior: {} (no match) -- demonstrates the evasion
    assert result != {}, "Block rule was silently neutralized by co-present empty 'conditions' key"
```

Running this against the current implementation demonstrates `result == {}` (the dangerous `rm -rf /` command is allowed through), confirming the legacy-vs-explicit parsing differential breaks the intended block-rule invariant.

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

**File:** plugins/hookify/core/config_loader.py (L44-73)
```python
    @classmethod
    def from_dict(cls, frontmatter: Dict[str, Any], message: str) -> 'Rule':
        """Create Rule from frontmatter dict and message body."""
        # Handle both simple pattern and complex conditions
        conditions = []

        # New style: explicit conditions list
        if 'conditions' in frontmatter:
            cond_list = frontmatter['conditions']
            if isinstance(cond_list, list):
                conditions = [Condition.from_dict(c) for c in cond_list]

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

**File:** plugins/hookify/core/config_loader.py (L244-261)
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
