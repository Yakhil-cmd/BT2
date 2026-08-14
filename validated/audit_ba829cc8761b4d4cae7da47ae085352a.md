### Title
Naive substring-based `---` delimiter split in `extract_frontmatter` lets a `---` inside a frontmatter value silently truncate the frontmatter, downgrading `action: block` rules to the default `warn` - (File: `plugins/hookify/core/config_loader.py`)

### Summary
`extract_frontmatter` locates the frontmatter block with `content.split('---', 2)`, a literal-substring split rather than a line-anchored delimiter match. If any frontmatter *value* (e.g. `pattern:`) contains the three-character substring `---` anywhere in it, that occurrence is consumed as the closing delimiter, truncating the parsed frontmatter dict before later keys (such as `action: block`) are read. Because `Rule.from_dict` defaults `action` to `"warn"` when the key is absent [1](#0-0) , a rule file that visibly says `action: block` on disk is silently loaded and enforced as `action: warn`.

### Finding Description
`extract_frontmatter` only checks that the content starts with `---` and then does a raw substring split: [2](#0-1) 

This split is performed on the entire file content, not per-line, and with `maxsplit=2` it stops as soon as it finds the second literal occurrence of `---` anywhere in the text — including inside a `pattern:` (or other) value on a single frontmatter line, not just on a delimiter line by itself.

If a rule author (or content injected via repo files/issue/PR text and later turned into a suggested pattern by the `conversation-analyzer` agent used by `/hookify`, see [3](#0-2) ) ends up with a pattern value containing `---` (e.g. a regex like `rm\s+-rf---force` or any pattern that happens to include three consecutive dashes), the frontmatter is cut off mid-line right after that `---`. Everything after it — including a subsequent `action: block` line — is pushed into `parts[2]`, which becomes the rule's `message` body and is never parsed as YAML key/value data at all: [4](#0-3) 

`Rule.from_dict` then builds the `Rule` object from the truncated `frontmatter` dict, and since `action` is missing it falls back to the default `"warn"`: [1](#0-0) 

`RuleEngine.evaluate_rules` treats any rule whose `action != 'block'` as a warning-only rule that does not deny the tool call: [5](#0-4) 

So a rule file on disk that a user (or Claude, acting on injected repo/issue content) believes blocks a dangerous `Bash`/`Edit`/`Write` operation is loaded and enforced as a mere warning — the `PreToolUse` hook will emit `permissionDecision` deny only for `blocking_rules`; here the rule lands in `warning_rules` instead, and the tool call proceeds: [6](#0-5) 

No validation anywhere checks that the two `---` markers are on their own line, that the frontmatter parses as well-formed YAML, or that the resulting `Rule.action` matches what is textually present in the file — `load_rule_file` only guards against missing frontmatter (`if not frontmatter:`), not malformed/truncated frontmatter: [7](#0-6) 

### Impact Explanation
This breaks the stated invariant that "rule semantics must not change because of formatting ambiguity." A user-authored (or Claude-authored, via `/hookify`) block rule intended to stop dangerous `Bash` commands or sensitive file edits (e.g. writes to `.env`, `rm -rf`, credential exfiltration patterns) silently degrades to a non-blocking warning whenever its pattern text contains a literal `---` substring. Since hookify rules are the mechanism that governs `PreToolUse` denial of `Bash`/`Edit`/`Write`/`MultiEdit` and `Stop` decisions, this can result in unauthorized command execution or file read/write outside the intended block scope, matching the "Unauthorized file read or write outside the user-approved workspace or target scope" impact category.

### Likelihood Explanation
The trigger condition is simple and plausible: any regex pattern authored for a rule that happens to contain three consecutive dashes (a common regex/range construct, e.g. character ranges, IP/version patterns, or option flags like `--force`) will reproduce this. It requires no special privilege beyond being able to get a `.claude/hookify.*.local.md` file written with such a pattern — reachable through normal `/hookify` usage, `/hookify` acting on conversation/repo content analyzed by `conversation-analyzer`, or direct manual authoring by a user who copies a pattern from repository/issue content without realizing the delimiter collision. It is fully deterministic and reproducible with a single crafted file.

### Recommendation
Replace the substring-based split with a line-anchored, regex-based delimiter match (e.g. `re.split(r'(?m)^---\s*$', content, maxsplit=2)` or an explicit line-by-line scan that only treats a line consisting solely of `---` as a delimiter). Additionally, after parsing, validate that the frontmatter block actually contained a closing delimiter line before end-of-file, and add a self-consistency check in `load_rule_file`/`Rule.from_dict` that raises/warns rather than silently defaulting `action` to `warn` when required keys are unexpectedly absent from a non-empty frontmatter block, so malformed rule files fail loudly instead of down-grading to a less restrictive mode.

### Proof of Concept
Unit test to add to a test suite for `plugins/hookify/core/config_loader.py`:

```python
from hookify.core.config_loader import extract_frontmatter, Rule

def test_dash_in_pattern_truncates_frontmatter_and_downgrades_block_to_warn():
    content = """---
name: block-dangerous-thing
enabled: true
event: bash
pattern: rm\\s+-rf---force
action: block
---

This should block rm -rf --force but the message shows it did not.
"""
    frontmatter, message = extract_frontmatter(content)
    rule = Rule.from_dict(frontmatter, message)

    # Visible file clearly states action: block
    assert "action: block" in content

    # BUG: parsed Rule silently loses the action field and defaults to "warn"
    assert rule.action == "warn"   # demonstrates downgrade from intended "block"
```

Integration-level PoC: write the same content to `.claude/hookify.block-dangerous-thing.local.md` in a scratch repo, then invoke `plugins/hookify/hooks/pretooluse.py` with stdin `{"tool_name": "Bash", "tool_input": {"command": "rm -rf --force /"}, "hook_event_name": "PreToolUse"}` and assert the JSON output does **not** contain `"permissionDecision": "deny"` (only a `systemMessage` warning), even though the rule file on disk specifies `action: block`.

### Citations

**File:** plugins/hookify/core/config_loader.py (L75-83)
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

**File:** plugins/hookify/core/config_loader.py (L105-152)
```python
    # Simple YAML parser that handles indented list items
    frontmatter = {}
    lines = frontmatter_text.split('\n')

    current_key = None
    current_list = []
    current_dict = {}
    in_list = False
    in_dict_item = False

    for line in lines:
        # Skip empty lines and comments
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

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

**File:** plugins/hookify/commands/hookify.md (L29-58)
```markdown
**To analyze conversation:**
Use the Task tool to launch conversation-analyzer agent:
```
{
  "subagent_type": "general-purpose",
  "description": "Analyze conversation for unwanted behaviors",
  "prompt": "You are analyzing a Claude Code conversation to find behaviors the user wants to prevent.

Read user messages in the current conversation and identify:
1. Explicit requests to avoid something (\"don't do X\", \"stop doing Y\")
2. Corrections or reversions (user fixing Claude's actions)
3. Frustrated reactions (\"why did you do X?\", \"I didn't ask for that\")
4. Repeated issues (same problem multiple times)

For each issue found, extract:
- What tool was used (Bash, Edit, Write, etc.)
- Specific pattern or command
- Why it was problematic
- User's stated reason

Return findings as a structured list with:
- category: Type of issue
- tool: Which tool was involved
- pattern: Regex or literal pattern to match
- context: What happened
- severity: high/medium/low

Focus on the most recent issues (last 20-30 messages). Don't go back further unless explicitly asked."
}
```
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

**File:** plugins/hookify/core/rule_engine.py (L60-91)
```python
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
```
