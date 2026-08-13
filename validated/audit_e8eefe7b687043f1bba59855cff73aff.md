## Finding: Legacy `pattern` field inference silently fails to block Write-tool operations, evading `event: file` block rules

The vulnerability is real and reproducible from the code. `Rule.from_dict` infers a default `field` for legacy-style rules based only on `event`, and that inferred field does not match how `RuleEngine._extract_field` actually reads data for the `Write` tool, producing a rule that looks like a working block rule but never fires against `Write` calls.

### Root cause [1](#0-0) 

For `event: file` legacy rules, `Rule.from_dict` always sets `field = 'new_text'`, regardless of whether the triggering tool is `Edit` or `Write`. [2](#0-1) 

But in `_extract_field`, for `tool_name in ['Write', 'Edit']`, the `field == 'content'` branch checks `tool_input.get('content') or tool_input.get('new_string', '')` (covers both tools), while the `field == 'new_text'` branch only reads `tool_input.get('new_string', '')` — the key `Write` tool calls never populate (`Write` uses `content`, not `new_string`). Since `Write`'s `tool_input` has no `new_text`/`new_string` key, the direct-lookup fast path at the top of `_extract_field` (`if field in tool_input`) also misses, and the function falls through to return an **empty string** (not `None`) for `Write` operations. [3](#0-2) 

Because the returned value is `''` rather than `None`, `_rule_matches` does not treat it as "no field" — it proceeds to `_check_condition`, which runs `regex_match('', pattern)`/`contains` etc. against an empty string, which fails for any realistic dangerous-content pattern. The block rule therefore **silently never matches `Write` tool calls**, while the same rule written using the explicit `conditions:` form with `field: content` (the form documented for "advanced" rules) works correctly for both `Edit` and `Write`.

### Why this differs from explicit conditions and is attacker-reachable

`/hookify rule creation` and the writing-rules skill both document and generate the **simple `pattern:` format** as the primary/default rule style for `event: file` rules: [4](#0-3) [5](#0-4) 

A repo-shipped `.claude/hookify.*.local.md` file, or a rule generated via `/hookify rule creation` using this documented default `pattern:` syntax with `event: file` and `action: block`, is loaded unmodified by `load_rule_file` → `Rule.from_dict`: [6](#0-5) 

No validation exists anywhere in `config_loader.py` or `rule_engine.py` that checks whether the inferred `field` actually corresponds to a real key produced by the matched tool. The mismatch is silent: the rule loads successfully, is marked `enabled`, and appears functional, but any dangerous content injected via the `Write` tool (e.g. writing a malicious script, hardcoded secret, or `curl|bash` payload to a new file) will not trigger the intended `block` action, whereas the identical content via `Edit` would correctly trigger it. This breaks the stated invariant that default field inference must not weaken enforcement relative to the explicit `conditions:` form.

### Impact

A user (or an automated `/hookify` flow) who creates a "block dangerous file content" rule using the default/documented `pattern:` shorthand for `event: file` gets a rule that is silently inert for all `Write` tool invocations. This allows dangerous content — malicious scripts, secrets, exploit payloads — to be written to disk via `Write` without the intended block/deny enforcement firing, defeating the local guardrail the user configured, even though the same content edited via `Edit` would be correctly blocked. This is a real weakening of enforcement caused directly by the default field-inference logic in `Rule.from_dict`, not by user misconfiguration.

### Recommendation

In `Rule.from_dict`, either (a) infer `field='content'` instead of `field='new_text'` for `event: file` legacy rules so it matches both `Write` and `Edit` via the already-correct `content` branch in `_extract_field`, or (b) fix `_extract_field`'s `new_text` branch to fall back to `tool_input.get('content', '')` when `new_string` is absent, matching the `content` branch's behavior. Additionally, `_extract_field` should return `None` (not `''`) when a field genuinely doesn't apply to the tool, so `_rule_matches` treats it as non-matching rather than silently evaluating against an empty string.

### Proof of Concept

Unit test plan for `plugins/hookify/core/rule_engine.py` / `config_loader.py`:
1. Build frontmatter: `{name: 'block-secret-write', enabled: True, event: 'file', pattern: 'API_KEY', action: 'block'}`.
2. `rule = Rule.from_dict(frontmatter, "blocked")` → assert `rule.conditions == [Condition(field='new_text', operator='regex_match', pattern='API_KEY')]`.
3. Simulate a `Write` tool call: `input_data = {'tool_name': 'Write', 'tool_input': {'file_path': 'x.py', 'content': 'API_KEY = "abc123"'}}`.
4. Call `RuleEngine()._rule_matches(rule, input_data)` → currently returns `False` (bug: block rule doesn't fire).
5. Compare against the same dangerous content via `Edit`: `input_data2 = {'tool_name': 'Edit', 'tool_input': {'file_path': 'x.py', 'new_string': 'API_KEY = "abc123"'}}` → `_rule_matches` returns `True`, proving the differential between tools for an identical logical rule.
6. Compare against an equivalent explicit-conditions rule with `field: content` → correctly matches both `Write` and `Edit`, confirming the legacy/explicit semantic divergence.

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

**File:** plugins/hookify/core/rule_engine.py (L117-125)
```python
        if not rule.conditions:
            return False

        # All conditions must match
        for condition in rule.conditions:
            if not self._check_condition(condition, tool_name, tool_input, input_data):
                return False

        return True
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

**File:** plugins/hookify/commands/hookify.md (L91-102)
```markdown
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
```

**File:** plugins/hookify/skills/writing-rules/SKILL.md (L52-62)
```markdown

**pattern** (simple format): Regex pattern to match
- Used for simple single-condition rules
- Matches against command (bash) or new_text (file)
- Python regex syntax

**Example:**
```yaml
event: bash
pattern: rm\s+-rf
```
```
