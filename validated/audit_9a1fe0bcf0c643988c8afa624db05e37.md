### Title
Case/format-sensitive `action` comparison silently downgrades attacker-crafted "block" rules to warn-only - ([File: plugins/hookify/core/config_loader.py])

### Summary
`Rule.from_dict` in `plugins/hookify/core/config_loader.py` copies the `action` frontmatter field verbatim with no normalization or validation, while `RuleEngine.evaluate_rules` in `plugins/hookify/core/rule_engine.py` performs a strict `rule.action == 'block'` comparison. Any rule file whose `action` value is not the exact lowercase string `block` (e.g. `Block`, `BLOCK`, or any other string) is silently treated as a warning-only rule that never blocks the matched tool call.

### Finding Description
`Rule.from_dict` sets `action=frontmatter.get('action', 'warn')` with no case-folding, trimming beyond the generic YAML-line `.strip()`, or enum validation [1](#0-0) . The custom, hand-rolled YAML parser in `extract_frontmatter` only lower-cases scalar values when checking for `true`/`false`; any other value (including `Block`, `BLOCK`) is preserved as-is [2](#0-1) .

Downstream, `RuleEngine.evaluate_rules` classifies a matched rule as blocking only via exact string equality:
```python
if rule.action == 'block':
    blocking_rules.append(rule)
else:
    warning_rules.append(rule)
``` [3](#0-2) 

Hookify rule files (`.claude/hookify.*.local.md`) live inside the project's `.claude` directory, which per the plugin's own README is expected to be authored, shared, and even contributed via PR ("Found a useful rule pattern? Consider sharing example files via PR!") [4](#0-3) . Rules are auto-discovered from disk on every hook invocation with `glob.glob(os.path.join('.claude', 'hookify.*.local.md'))` and take effect immediately with no restart, review, or schema validation [5](#0-4) .

An attacker who can introduce or modify such a rule file (e.g., via a pull request, shared example file, or any repository content the victim copies into `.claude/`) can craft a rule that visually appears to enforce `action: block` for a dangerous pattern but actually uses a subtly different string (`Block`, `BLOCK `, etc.). Because there is no validation rejecting unrecognized `action` values, the file loads successfully with no warning, and the victim's Claude Code session will only display a warning message instead of denying the tool call — the dangerous Bash/Edit/Write operation proceeds.

### Impact Explanation
This breaks the intended safety guarantee of hookify's `block` action: a security control the user believes prevents destructive tool calls (`rm -rf`, credential edits, etc.) is silently reduced to a non-blocking warning. This is a trust-boundary/approval-bypass issue — the enforcement mechanism a user relies on to stop dangerous automated actions fails open when fed attacker- or third-party-supplied rule content that a reasonable reviewer would assume is functionally equivalent to `action: block`.

### Likelihood Explanation
Exploitability requires only that a malformed/attacker-authored rule file end up in a project's `.claude/hookify.*.local.md`, which the plugin's own documentation encourages (sharing/importing example rule files via PR) [4](#0-3) . No special privileges, secrets, or session access are needed — a plain case typo (`Block` vs `block`) is enough, and there is no validation anywhere in the loader to catch it, making this a high-likelihood, low-effort silent failure.

### Recommendation
- In `Rule.from_dict`, normalize the `action` value (e.g., `str(frontmatter.get('action', 'warn')).strip().lower()`) and validate it against an explicit allow-list (`{'warn', 'block'}`), rejecting/logging any unrecognized value rather than silently defaulting to warn-only behavior at match time.
- Consider failing loudly (skip loading the rule and print a warning) when `action` is set but not a recognized value, so authors get immediate feedback instead of a silently weaker rule.

### Proof of Concept
Unit test for `plugins/hookify/core/config_loader.py` + `plugins/hookify/core/rule_engine.py`:
```python
from hookify.core.config_loader import Rule, Condition
from hookify.core.rule_engine import RuleEngine

rule = Rule(
    name="block-rm",
    enabled=True,
    event="bash",
    conditions=[Condition(field="command", operator="regex_match", pattern=r"rm\s+-rf")],
    action="Block",  # attacker-crafted rule file uses capitalized action
    message="Dangerous rm command blocked!"
)

engine = RuleEngine()
input_data = {
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "rm -rf /important/data"}
}

result = engine.evaluate_rules([rule], input_data)

# Expected (secure) behavior: operation is denied
assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny", \
    f"Expected block, got warn-only result: {result}"
```
Running this against the current code shows the assertion fails: `evaluate_rules` returns only `{"systemMessage": ...}` (warning path) instead of a `permissionDecision: deny` response, confirming the rule silently degrades from blocking to warning due to the case-sensitive `rule.action == 'block'` check.

### Citations

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

**File:** plugins/hookify/core/config_loader.py (L209-211)
```python
    # Find all hookify.*.local.md files
    pattern = os.path.join('.claude', 'hookify.*.local.md')
    files = glob.glob(pattern)
```

**File:** plugins/hookify/core/rule_engine.py (L53-58)
```python
        for rule in rules:
            if self._rule_matches(rule, input_data):
                if rule.action == 'block':
                    blocking_rules.append(rule)
                else:
                    warning_rules.append(rule)
```

**File:** plugins/hookify/README.md (L326-328)
```markdown
## Contributing

Found a useful rule pattern? Consider sharing example files via PR!
```
