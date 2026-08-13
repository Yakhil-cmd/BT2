### Title
`extract_frontmatter`'s naive substring-based `---` split lets an embedded delimiter inside a frontmatter value silently strip `action: block`, downgrading a rule to `warn` - (File: `plugins/hookify/core/config_loader.py`)

### Finding Description
`extract_frontmatter` locates the frontmatter/body boundary with `content.split('---', 2)`, which finds the first two *literal substring* occurrences of `---` anywhere in the file, not the first two `---` lines acting as YAML document delimiters. [1](#0-0) 

If any frontmatter value between the opening `---` and the intended closing `---` itself contains the three-character substring `---` (e.g. a `pattern:` regex like `rm\s+-rf|.*---.*`, a quoted string, or any value with a literal `---`), the second split point lands on that embedded occurrence instead of the real closing delimiter. Everything after that point — including subsequent lines such as `action: block` — is placed into `parts[2]`, which becomes the `message` body, not the parsed `frontmatter_text`.

`Rule.from_dict` then builds the `Rule` from the truncated frontmatter dict, and since `action` was never seen, it falls back to the documented default of `"warn"`: [2](#0-1) 

`RuleEngine.evaluate_rules` uses `rule.action == 'block'` to decide between denying the tool call (`permissionDecision: deny`) versus just emitting a `systemMessage` and allowing the operation: [3](#0-2) 

`pretooluse.py` (and the `Stop`/`UserPromptSubmit` equivalents) invoke `load_rules()` → `load_rule_file()` → `extract_frontmatter()` on every `Bash`/`Edit`/`Write`/`MultiEdit`/`Stop` event, so any rule file affected by this parsing quirk changes real enforcement behavior on every subsequent tool call: [4](#0-3) [5](#0-4) 

The `/hookify` command itself instructs the model to author files exactly in this vulnerable shape (`pattern:` on one line, `action: block` on a following line, single opening/closing `---` delimiters), and explicitly tells users that `block` "prevents execution": [6](#0-5) 

### Assessment of exploitability under the stated constraints
The rule engine's own defaults already fail closed to `warn`, not `block` — `action` defaults to `"warn"` both in `Rule.from_dict` and in the dataclass field, and the plugin's own docs describe `block` as a "(future)" / secondary option. The realistic attack surface is: an attacker who can influence the *content* fed into `/hookify` (e.g., poisoned conversation text, repo content, or a crafted pattern suggestion that a maintainer accepts) could get a rule pattern containing an embedded `---` written into the `.claude/hookify.*.local.md` file. A maintainer who visually inspects the file would still see `action: block` present in the text, and would reasonably believe the rule blocks the dangerous command — but the parser's substring split silently reclassifies it as a no-op `warn`, because the `action: block` line falls after the corrupted second delimiter and never enters the parsed dict. This is a directly reproducible parser bug (`str.split('---', 2)` is not YAML-document-boundary aware) with exact `Rule` object divergence from what a human reading the file would expect, matching the invariant "rule semantics must not change because of formatting ambiguity."

However, I could not fully verify within this exploration whether an unprivileged attacker (no maintainer/admin/commit access, no social engineering) has a realistic, existing pathway to get such crafted content written verbatim into a project's `.claude/hookify.*.local.md` file without any human review step catching the anomaly (e.g. blank body content, misplaced `action:` line visible after the closing fence in the rendered markdown). The `/hookify` flow is LLM-mediated and interactive (`AskUserQuestion` steps), which reduces — but does not eliminate — the chance of smuggling this through the assistant's rule-generation step. I did not find independent confirmation that the file-writing step performs additional format validation that would catch a misplaced `---` before persisting the rule.

### Impact Explanation
If an intended `block` rule (e.g., blocking `rm -rf`, blocking edits to `.env`, or blocking `Stop` without tests) is silently downgraded to `warn`, `RuleEngine.evaluate_rules` will return only a `systemMessage` instead of `permissionDecision: deny`, allowing the dangerous `Bash`/`Edit`/`Stop` action to proceed. This matches "Unauthorized local command execution that bypasses Claude Code approval or deny controls" in scope, but only for operations gated purely by Hookify rules, not Claude Code's core built-in approval/permission system.

### Likelihood Explanation
Low-to-medium. It requires (a) a rule author to include a pattern/value containing a literal `---` substring in the frontmatter before the `action: block` line, and (b) that malformed file to be accepted/committed without a reviewer noticing the body content looks wrong (the "message" body would visibly contain the `action: block` and closing fence text, which is a fairly conspicuous artifact). This makes silent, unnoticed exploitation less likely than the pure parser flaw would suggest, though the bug itself is trivially reproducible in isolation.

### Recommendation
Replace the naive `content.split('---', 2)` with a line-anchored frontmatter delimiter check, e.g. only treat a line consisting solely of `---` (optionally with trailing whitespace) as a delimiter, using `re.split(r'(?m)^---\s*$', content, maxsplit=2)` or by splitting on `content.splitlines()` and tracking delimiter lines explicitly. Additionally, use a real YAML parser (`yaml.safe_load`) instead of the hand-rolled indentation-based parser to eliminate this and related ambiguity classes, and add a post-load sanity check in `load_rule_file` that warns/rejects if `action` appears in the raw file text but not in the parsed frontmatter dict (mismatch detection).

### Proof of Concept
Unit test to add to `plugins/hookify/core/config_loader.py` tests (or a new test file):

```python
from hookify.core.config_loader import extract_frontmatter, Rule

def test_embedded_delimiter_downgrades_block_rule():
    content = """---
name: block-dangerous-rm
enabled: true
event: bash
pattern: "rm\\s+-rf|.*---.*"
action: block
---

This should block rm -rf.
"""
    frontmatter, message = extract_frontmatter(content)
    rule = Rule.from_dict(frontmatter, message)

    # Expected (intended) behavior: action should be "block"
    # Actual behavior due to the bug: action falls back to default "warn"
    # because "action: block" line was split into the message body.
    assert rule.action == "block", (
        f"Rule action downgraded to '{rule.action}' due to embedded '---' "
        f"in pattern value; frontmatter={frontmatter}"
    )
```

Expected result: the assertion fails on current code (`rule.action == "warn"`), demonstrating that the parsed `Rule` object diverges from the human-visible file content, and that `RuleEngine.evaluate_rules` would subsequently return `{"systemMessage": ...}` instead of `{"hookSpecificOutput": {"permissionDecision": "deny"}}` for a matching `Bash` command such as `rm -rf /`.

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

**File:** plugins/hookify/hooks/pretooluse.py (L35-59)
```python
def main():
    """Main entry point for PreToolUse hook."""
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)

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

**File:** plugins/hookify/commands/hookify.md (L91-106)
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

**Action values:**
- `warn`: Show message but allow operation (default)
- `block`: Prevent operation or stop session
```
