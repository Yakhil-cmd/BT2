### Title
Trailing inline `#` comment on `action: block` line silently downgrades a hookify rule to non-blocking - ([File: plugins/hookify/core/config_loader.py])

### Summary
The hand-rolled YAML parser in `extract_frontmatter` only strips comment lines that start with `#` after full-line stripping, but never strips trailing inline comments from a key's value on a `key: value` line. A hookify rule file containing `action: block  # <any comment>` therefore stores the literal string `"block  # <any comment>"` as `Rule.action` instead of `"block"`, causing `RuleEngine.evaluate_rules` to treat the rule as a non-blocking warning instead of a blocking deny.

### Finding Description
`extract_frontmatter` handles top-level `key: value` lines at [1](#0-0) 
Only the beginning-of-line comment check on line 118 (`stripped.startswith('#')`) skips whole-line comments; the value assigned on line 138 (`value = value.strip()`) is never truncated at a later `#`, unlike a real YAML parser which strips unquoted trailing comments. Quote-stripping on line 147 only removes leading/trailing quote characters and does nothing to remove an appended comment.

Consequently, a line such as:
```
action: block  # blocks destructive rm -rf commands
```
produces `frontmatter['action'] == "block  # blocks destructive rm -rf commands"`. `Rule.from_dict` passes this raw string through unchanged: [2](#0-1) 

`RuleEngine.evaluate_rules` performs a strict equality check `rule.action == 'block'`: [3](#0-2) 
Since the stored value is no longer exactly `"block"`, the rule falls into `warning_rules` instead of `blocking_rules`, so `PreToolUse`/`PostToolUse`/`Stop` handling in `evaluate_rules` (lines 61-91) never returns `permissionDecision: "deny"` for the matched dangerous command — it only emits a `systemMessage`, and the tool call proceeds.

This is exploitable through the normal repo-content trust boundary: `load_rules` glob-loads every `.claude/hookify.*.local.md` file in the repo and `load_rule_file` feeds its content straight into `extract_frontmatter`: [4](#0-3) 
An attacker who can land a change to a `.claude/hookify.*.local.md` file (e.g., via a "harmless" PR that adds a trailing explanatory comment to an existing `action: block` rule, or a contributed new rule file that visually appears to declare `action: block`) can rely on a reviewer's normal-YAML intuition (where trailing `#` comments are legitimate and inert) to get the change approved, while the plugin's non-standard parser silently converts the block rule into a no-op warning rule.

### Impact Explanation
This breaks the "deny means deny" invariant for hookify's bash/file/stop guard rules: a rule that is supposed to block a dangerous operation (e.g., `rm -rf`, destructive file edits, forced pushes) is silently reduced to a mere warning, allowing the operation to execute. This matches a security-control bypass impact: a security-blocking mechanism is rendered ineffective without any visible change in intent, enabling downstream dangerous command execution that the rule author explicitly meant to prevent.

### Likelihood Explanation
- Precondition matches the given attacker model exactly: the attacker only needs to get content into a repo-tracked `.claude/hookify.*.local.md` file (via a contributed rule file or an edit to an existing one), no local-only config, no elevated privileges needed.
- The trigger is a single, innocuous-looking trailing comment appended to an `action: block` line — something a human reviewer using normal-YAML mental model would consider a no-op stylistic addition, making it highly likely to pass review undetected.
- The bug is 100% deterministic given the malformed-relative-to-parser input; no race conditions or timing dependencies are involved.

### Recommendation
Rewrite `extract_frontmatter` to strip unquoted trailing `#` comments from scalar values (respecting quoted strings), or replace the hand-rolled parser with a real YAML library (`yaml.safe_load`) restricted to the frontmatter block. Additionally, `RuleEngine`/`Rule.from_dict` should normalize/validate `action` and `enabled` against an explicit allow-list (`{"warn", "block"}` / boolean) and fail closed (treat unrecognized/malformed `action` values as `block`, or reject the rule file entirely) rather than silently defaulting to the permissive interpretation.

### Proof of Concept
Unit test in `plugins/hookify/core/config_loader.py`'s test module (or a new pytest file):
```python
from hookify.core.config_loader import extract_frontmatter, Rule
from hookify.core.rule_engine import RuleEngine

content = """---
name: block-rm
enabled: true
event: bash
action: block  # blocks destructive rm -rf commands
pattern: "rm -rf"
---
Dangerous command blocked!
"""

fm, msg = extract_frontmatter(content)
rule = Rule.from_dict(fm, msg)

# Expected (reference YAML behavior): action == "block"
assert rule.action == "block", f"action corrupted to: {rule.action!r}"

engine = RuleEngine()
result = engine.evaluate_rules([rule], {
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "rm -rf /tmp/x"}
})

# Expected: permissionDecision == "deny"
assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny", \
    f"Blocking rule was downgraded to warning: {result}"
```
Running this against the current implementation fails both assertions: `rule.action` is `"block  # blocks destructive rm -rf commands"` and `evaluate_rules` returns only a `systemMessage` (warning), never `permissionDecision: "deny"`, confirming the silent block→warn downgrade. A broader fuzz harness can generate random combinations of trailing `#`/quote characters after `action:`/`enabled:` values and assert parity against `yaml.safe_load` for the `action` and `enabled` fields specifically.

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

**File:** plugins/hookify/core/config_loader.py (L136-152)
```python
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()

            if not value:
                # Empty value - list or nested structure follows
                current_key = key
                in_list = True
                current_list = []
            else:
                # Simple key-value pair
                value = value.strip('"').strip("'")
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                frontmatter[key] = value
```

**File:** plugins/hookify/core/config_loader.py (L209-226)
```python
    # Find all hookify.*.local.md files
    pattern = os.path.join('.claude', 'hookify.*.local.md')
    files = glob.glob(pattern)

    for file_path in files:
        try:
            rule = load_rule_file(file_path)
            if not rule:
                continue

            # Filter by event if specified
            if event:
                if rule.event != 'all' and rule.event != event:
                    continue

            # Only include enabled rules
            if rule.enabled:
                rules.append(rule)
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
