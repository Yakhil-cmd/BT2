### Title
Custom YAML frontmatter parser in `extract_frontmatter` silently drops indented keys, allowing `action: block` to be downgraded to default `warn` (or the whole rule to be dropped) via cosmetic whitespace - ([File: plugins/hookify/core/config_loader.py])

### Summary
`extract_frontmatter` in `plugins/hookify/core/config_loader.py` implements a hand-rolled, non-standard YAML parser instead of using a real YAML library. Its top-level key detection requires `indent == 0` exactly, and any frontmatter line that does not satisfy one of its three narrow branch conditions (top-level key, list item, or indented dict-item continuation) is silently discarded with no error. A frontmatter line such as `" action: block"` (single leading space) or other minor indentation/format deviations is therefore dropped entirely, so `Rule.from_dict` falls back to its default `action="warn"` even though the file visually reads as a blocking rule.

### Finding Description
`load_rules()` → `load_rule_file()` → `extract_frontmatter()` is invoked unconditionally on every `Bash`/`Edit`/`Write`/`MultiEdit`/`Stop` tool use by the hookify hooks (`pretooluse.py`, `posttooluse.py`, `stop.py`) for every file matching `.claude/hookify.*.local.md` in the working directory: [1](#0-0) .

Inside `extract_frontmatter`, top-level key/value pairs are only recognized when `indent == 0`: [2](#0-1) . Lines that don't match this exact indentation, don't start with `-` while inside a list, and aren't a deeply-indented (`indent > 2`) dict-item continuation are simply skipped in the `for line in lines` loop — there is no `else` branch and no error is raised. A single stray leading space before `action: block` (or any other top-level key) causes that key/value pair to vanish from the resulting `frontmatter` dict with zero warning.

`Rule.from_dict` then defaults the missing `action` field to `"warn"`: [3](#0-2) . In `RuleEngine.evaluate_rules`, only rules with `action == 'block'` are placed into `blocking_rules`, which is what produces `permissionDecision: "deny"`/`decision: "block"`; everything else becomes a non-blocking `systemMessage` warning that an agent (or automation) can proceed past: [4](#0-3) .

Because `hookify.*.local.md` files are ordinary repository content (created via `/hookify`, but equally plantable directly in a repo/PR since they are just markdown files under `.claude/`), an attacker who can influence such a file (e.g., via a crafted PR, a cloned malicious repo, or prompt-injected content fed into the `/hookify`-driven conversation-analyzer that writes the file) can introduce a cosmetically negligible formatting difference (one extra leading space, wrong indent depth, etc.) that a human reviewer is very unlikely to notice, while functionally converting a supposed `block` rule into `warn` or removing it from `frontmatter` (and if the `---` delimiters themselves are malformed such that `len(parts) < 3`, `load_rule_file` treats the file as having no frontmatter at all and drops the rule silently, only logging to stderr, which is not surfaced to the user in normal flow): [5](#0-4) [6](#0-5) .

### Impact Explanation
A rule author (or reviewer) sees a rule file that appears to `action: block` a dangerous `Bash` command pattern (e.g. `rm\s+-rf`, `curl | sh`, etc.), believing it is enforced as a hard stop. Due to the parser bug, the rule silently degrades to `warn` (message shown, operation still allowed) or is dropped entirely (`load_rule_file` returns `None`), letting the matched dangerous tool invocation execute unopposed. This directly breaks the invariant that "rule semantics must not change because of formatting ambiguity" and results in unauthorized local command execution that bypasses the intended hookify-based block/deny control — matching the "Unauthorized local command execution that bypasses Claude Code approval or deny controls" bounty impact class.

### Likelihood Explanation
The trigger requires only a benign-looking, one-character whitespace difference in a `.claude/hookify.*.local.md` file, which is easily introduced accidentally (copy/paste, editor auto-indent, merge artifacts) or deliberately by an attacker contributing such a file via a PR or a cloned repository. No special privileges, admin access, or social engineering beyond ordinary repository content review is required, and the hooks (`pretooluse.py`, etc.) load and evaluate these files automatically and unconditionally on every relevant tool call, so the downgrade is 100% reproducible once the malformed file is present. The failure mode is silent (no exception, no user-facing error) which makes detection during review unlikely.

### Recommendation
Replace the hand-rolled frontmatter parser with a proper YAML parser (e.g. Python's `yaml.safe_load` on the text between the first two `---` delimiters), and add strict validation: reject/log loudly (and fail closed by treating unparsable `action` fields as `block`, not `warn`) when a rule's `action` field is ambiguous, missing where expected, or when the file cannot be unambiguously split into exactly frontmatter + body via `---`. Additionally, add a self-check that re-serializes the parsed frontmatter and diffs semantically against a strict YAML parse of the same text, refusing to load rules where the two disagree.

### Proof of Concept
Add a unit test to `config_loader.py`'s test suite (or a new `test_config_loader.py`):
```python
from plugins.hookify.core.config_loader import extract_frontmatter, Rule

content = """---
name: block-rm-rf
enabled: true
event: bash
pattern: rm\\s+-rf
 action: block
---

This should BLOCK rm -rf.
"""

frontmatter, message = extract_frontmatter(content)
rule = Rule.from_dict(frontmatter, message)

# Vulnerability: the file visually specifies action: block,
# but the parser drops the indented "action" key entirely,
# so the Rule silently defaults to "warn".
assert 'action' not in frontmatter          # key silently dropped
assert rule.action == 'warn'                # should have been 'block'
```
Integration PoC: place the above content at `.claude/hookify.block-rm.local.md` in a cloned repo, then invoke `plugins/hookify/hooks/pretooluse.py` with a `Bash` tool call whose `command` is `rm -rf /tmp/x`, feeding it JSON on stdin (`tool_name: "Bash", tool_input: {"command": "rm -rf /tmp/x"}`). Expected (buggy) output: `{"systemMessage": ...}` (warn-only, no `permissionDecision: deny`), demonstrating that a visually "block" rule fails to deny the dangerous command.

### Citations

**File:** plugins/hookify/hooks/pretooluse.py (L42-56)
```python
        # For PreToolUse, we use tool_name to determine "bash" vs "file" event
        tool_name = input_data.get('tool_name', '')

        event = None
        if tool_name == 'Bash':
            event = 'bash'
        elif tool_name in ['Edit', 'Write', 'MultiEdit']:
            event = 'file'

        # Load rules
        rules = load_rules(event=event)

        # Evaluate rules
        engine = RuleEngine()
        result = engine.evaluate_rules(rules, input_data)
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

**File:** plugins/hookify/core/config_loader.py (L94-100)
```python
    if not content.startswith('---'):
        return {}, content

    # Split on --- markers
    parts = content.split('---', 2)
    if len(parts) < 3:
        return {}, content
```

**File:** plugins/hookify/core/config_loader.py (L121-152)
```python
        # Check indentation level
        indent = len(line) - len(line.lstrip())

        # Top-level key (no indentation or minimal)
        if indent == 0 and ':' in line and not line.strip().startswith('-'):
            # Save previous list/dict if any
            if in_list and current_key:
                if in_dict_item and current_dict:
                    current_list.append(current_dict)
                    current_dict = {}
                frontmatter[current_key] = current_list
                in_list = False
                in_dict_item = False
                current_list = []

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

**File:** plugins/hookify/core/config_loader.py (L255-261)
```python

        if not frontmatter:
            print(f"Warning: {file_path} missing YAML frontmatter (must start with ---)", file=sys.stderr)
            return None

        rule = Rule.from_dict(frontmatter, message)
        return rule
```

**File:** plugins/hookify/core/rule_engine.py (L53-94)
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
