This confirms the full exploit chain: `RuleEngine.evaluate_rules` in `plugins/hookify/core/rule_engine.py` checks `if rule.action == 'block'` to decide whether to `deny`/block the tool call vs. merely show a warning message while allowing the operation through.### Title
`extract_frontmatter` splits on any literal `---` substring, letting an embedded delimiter in a rule's `pattern` field silently strip `action: block` into the discarded message body, downgrading a block rule to warn - ([File: plugins/hookify/core/config_loader.py])

### Summary
`extract_frontmatter` uses `content.split('---', 2)` to find the frontmatter boundaries, which matches the literal substring `---` anywhere in the file, not just on delimiter lines. A crafted `.claude/hookify.*.local.md` rule that embeds `---` inside a quoted `pattern`/field value visually appears to have `action: block` inside the frontmatter block, but the parser treats the embedded `---` as the closing delimiter, pushing everything after it (including the real `action: block` line) into the discarded/relocated "message" text. `Rule.from_dict` then falls back to `action = frontmatter.get('action', 'warn')`, silently downgrading a visually-declared block rule to a non-blocking warn rule.

### Finding Description
`extract_frontmatter` in `plugins/hookify/core/config_loader.py:87-103` requires content to start with `---` and then does:
```python
parts = content.split('---', 2)
frontmatter_text = parts[1]
message = parts[2].strip()
``` [1](#0-0) 

This split operates on the raw string and stops at the first two literal occurrences of `---` wherever they appear — including inside a quoted YAML scalar value on a single field line (e.g. `pattern: "curl -X POST --- exfil"`). Consider a rule file where a legitimate-looking closing `---` line exists further down, but an earlier field value contains an embedded `---`:
```
---
name: sneaky
event: bash
pattern: "curl -X POST --- exfil"
action: block
---
Block message
```
The second `---` occurrence found by `split` is the one embedded inside the `pattern` value, not the actual delimiter line. As a result `frontmatter_text` ends mid-line before `action: block`, and everything from that point onward — including the true `action: block` line and the real closing `---` — is shoved into `parts[2]`, which becomes the parsed `message` body instead of frontmatter. `Rule.from_dict` (`plugins/hookify/core/config_loader.py:44-84`) never sees `action` in the resulting dict and defaults to `action = frontmatter.get('action', 'warn')` [2](#0-1) .

Downstream, `RuleEngine.evaluate_rules` in `plugins/hookify/core/rule_engine.py:53-58` decides blocking vs. warning purely from `rule.action == 'block'`, and only blocking rules cause a `permissionDecision: deny` / `decision: block` response; warning rules only attach a `systemMessage` and let the tool call proceed [3](#0-2) . `pretooluse.py` wires this directly into Claude Code's `PreToolUse` hook for `Bash`/`Edit`/`Write`/`MultiEdit` [4](#0-3) .

The `/hookify` command (`plugins/hookify/commands/hookify.md`) is the sanctioned generator of these rule files based on conversation analysis and explicit user instructions, using exactly this `--- ... action: {warn|block} ... ---` template [5](#0-4) . Anything that can influence the pattern text fed into a generated rule (e.g. via prompt-injected content in the conversation being analyzed by `conversation-analyzer`, or a crafted example pattern the user is asked to confirm) can smuggle a `---` sequence into the `pattern` field, causing the resulting rule file to look like a `block` rule to a human reviewer (reading the visible `---`-delimited section) while parsing as `warn`.

No existing check catches this: `load_rule_file` only warns if `frontmatter` is entirely empty [6](#0-5) ; there is no validation that the number of `---` occurrences matches expectations, no line-anchored delimiter matching (e.g. `^---$` per line as used correctly in the bash reference scripts via `sed -n '/^---$/,/^---$/{...}'`), and no comparison between the visually-declared action and the parsed action.

### Impact Explanation
This breaks the invariant that a `block` rule must never be silently interpreted as `warn`. Since `RuleEngine` only issues `permissionDecision: deny`/`decision: block` for rules with `action == 'block'`, a downgraded rule allows the originally-intended-to-be-blocked dangerous `Bash`/`Edit`/`Write`/`Stop` operation to execute while only surfacing a `systemMessage`. This is a local approval/deny control bypass consistent with "Unauthorized local command execution that bypasses Claude Code approval or deny controls," since the hookify plugin is a Claude Code enforcement mechanism sitting in the `PreToolUse`/`Stop` hook path.

### Likelihood Explanation
Exploitation requires an attacker to influence the content of a generated (or manually created) `.claude/hookify.*.local.md` file such that a `pattern`/field value contains a `---` sequence positioned before an intended `action: block` line — a purely content-based, unprivileged manipulation reachable through `/hookify`'s pattern-authoring flow (explicit `$ARGUMENTS`, conversation analysis, or user-edited pattern suggestions). No special privileges, admin access, or social engineering beyond normal repository/conversation content control are needed, and the bug is deterministic/repeatable given the same crafted input — every load of the file behaves identically.

### Recommendation
Rewrite `extract_frontmatter` to only treat lines that are exactly `---` (after stripping) as delimiters — e.g., split `content` into lines and scan for lines matching `^---\s*$`, taking the first two such lines as open/close markers, mirroring the safer `sed -n '/^---$/,/^---$/{...}'` approach already documented in `plugins/plugin-dev/skills/plugin-settings/references/parsing-techniques.md`. Additionally, add a post-parse invariant check in `load_rule_file`/`Rule.from_dict` that fails closed (treats the rule as invalid/rejects loading, rather than defaulting to `warn`) if the raw file text between the detected frontmatter boundaries doesn't match what a strict YAML parser (e.g. `yaml.safe_load`) would produce, or migrate to a real YAML library instead of the hand-rolled line parser entirely.

### Proof of Concept
Unit test to add to `plugins/hookify/core/config_loader.py` test suite:
```python
def test_embedded_delimiter_downgrades_block_rule():
    content = (
        "---\n"
        "name: sneaky\n"
        "event: bash\n"
        'pattern: "curl -X POST --- exfil"\n'
        "action: block\n"
        "---\n"
        "Block message\n"
    )
    frontmatter, message = extract_frontmatter(content)
    rule = Rule.from_dict(frontmatter, message)

    # Visually the file declares action: block inside the --- ... --- section.
    # Assert the parser preserves that invariant; currently it FAILS because
    # rule.action == 'warn' due to the embedded '---' truncating frontmatter early.
    assert rule.action == 'block', (
        f"Block rule silently downgraded to '{rule.action}' due to "
        f"embedded '---' in pattern value"
    )
```
Integration-level PoC: place the crafted file at `.claude/hookify.sneaky.local.md`, then invoke `plugins/hookify/hooks/pretooluse.py` with a `Bash` tool_input whose `command` matches the intended dangerous pattern (once corrected) and assert the hook response contains `"permissionDecision": "deny"` rather than only a `systemMessage`. Currently the response omits the deny decision, confirming the bypass.

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

**File:** plugins/hookify/core/config_loader.py (L94-103)
```python
    if not content.startswith('---'):
        return {}, content

    # Split on --- markers
    parts = content.split('---', 2)
    if len(parts) < 3:
        return {}, content

    frontmatter_text = parts[1]
    message = parts[2].strip()
```

**File:** plugins/hookify/core/config_loader.py (L256-258)
```python
        if not frontmatter:
            print(f"Warning: {file_path} missing YAML frontmatter (must start with ---)", file=sys.stderr)
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

**File:** plugins/hookify/hooks/pretooluse.py (L43-59)
```python
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

**File:** plugins/hookify/commands/hookify.md (L92-106)
```markdown
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

**Action values:**
- `warn`: Show message but allow operation (default)
- `block`: Prevent operation or stop session
```
