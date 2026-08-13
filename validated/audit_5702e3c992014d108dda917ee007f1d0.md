### Title
`extract_frontmatter` uses naive `content.split('---', 2)` instead of line-anchored delimiters, letting a `---` substring in a rule's own pattern text truncate frontmatter and silently downgrade `action: block` to the `warn` default - ([File: plugins/hookify/core/config_loader.py])

### Summary
`extract_frontmatter` in `plugins/hookify/core/config_loader.py` locates the frontmatter boundary by doing a raw substring split (`content.split('---', 2)`) rather than matching `---` only on its own line, which is the convention used everywhere else in the repo (e.g. the bash reference parser uses `sed -n '/^---$/,/^---$/'`). If any value inside the frontmatter block (most plausibly a `pattern`/regex field) itself contains the literal three-character sequence `---`, the split terminates early, silently dropping everything after it — including a subsequent `action: block` line — into the message body instead of the parsed dict.

### Finding Description
`extract_frontmatter` [1](#0-0)  splits the whole file content on the literal string `---` with `maxsplit=2`, assuming exactly two delimiter occurrences bound the frontmatter. This assumption breaks whenever a frontmatter value itself contains `---` (e.g. a regex pattern intended to catch merge-conflict markers, horizontal rules, or any dash-heavy content such as `rm\s+---\s+rf`). The split's second occurrence is then found *inside* the pattern value, not at the intended closing delimiter, so:
- `frontmatter_text` (`parts[1]`) ends prematurely, before any fields written after the injected `---` (such as `action: block`).
- `message` (`parts[2]`) now begins with the truncated tail of the pattern plus all subsequent lines (`action: block`, the real closing `---`, and the intended message body), which are never re-parsed as YAML — they become inert plain text in the rule's displayed message.

`Rule.from_dict` [2](#0-1)  then reads `frontmatter.get('action', 'warn')`; since `action` was pushed out of the frontmatter dict, it silently defaults to `'warn'`. `load_rule_file` [3](#0-2)  does not detect this — the frontmatter dict is non-empty (it still contains `name`, `pattern`, etc.), so no error/warning is emitted; the rule loads "successfully" as a warn-only rule.

`RuleEngine.evaluate_rules` [4](#0-3)  routes rules into `blocking_rules` only if `rule.action == 'block'`; a downgraded rule falls into `warning_rules`, so the corresponding `PreToolUse` hook never returns `permissionDecision: deny` and instead only emits a `systemMessage`, allowing the dangerous Bash/Edit/Write operation to proceed [5](#0-4) . Meanwhile a human or Claude reading the raw `.claude/hookify.*.local.md` file still sees `action: block` in the visible text (it's just relocated into the message body section), creating a dangerous mismatch between the file's apparent intent and its actual enforced behavior.

The `/hookify` slash command and its `conversation-analyzer` agent are the practical entrypoint: they auto-generate `pattern:` values from conversation content/regex suggestions [6](#0-5) [7](#0-6) , and nothing in that flow rejects or escapes a `---` sequence inside a pattern before it is written into the frontmatter block by the Write tool.

### Impact Explanation
A rule authored (or auto-suggested and accepted) with `action: block` and a pattern containing `---` is silently enforced as `warn` instead. This breaks the stated invariant that "a deny rule must never be parsed into a non-blocking configuration." For `PreToolUse`-scoped `bash`/`file` rules, this means a dangerous `Bash` command or file `Edit`/`Write` that was intended to be hard-blocked (e.g., destructive `rm`, writes to `.env`/secrets, `chmod 777`) instead executes with only a warning message, enabling unauthorized file read/write or command execution outside the intended guardrails — matching the "Unauthorized file read or write outside the user-approved workspace or target scope" impact category.

### Likelihood Explanation
Feasibility depends on a rule's `pattern` (or other frontmatter value) containing the literal substring `---`. This is plausible but not trivial to hit by accident — it requires patterns explicitly targeting dash-heavy content (merge-conflict markers, horizontal rules, multi-dash CLI flags like `---foo`, YAML document separators) or a deliberately crafted rule (e.g., via a compromised/malicious suggestion surfaced by the conversation-analyzer flow, or a user pasting an attacker-supplied "recommended rule" pattern from external content into `/hookify`). It requires no privileged access — only the ability to get a matching pattern string written into a `.claude/hookify.*.local.md` file, which any workspace user (or content that influences `/hookify`'s auto-generated suggestions) can trigger. It is fully repeatable and deterministic given the same input.

### Recommendation
Rewrite `extract_frontmatter` to detect frontmatter delimiters only on lines that are exactly `---` (matching the convention already documented/used by the bash reference implementations), e.g. split `content` into lines and find the first two lines equal to `---` (after stripping trailing whitespace), rather than doing a raw substring split on the whole file. This prevents any `---` occurring inside a field value from being mistaken for a delimiter, and ensures `action: block` and other trailing fields are never silently excluded from the parsed frontmatter dict.

### Proof of Concept
Unit test to add to `plugins/hookify/core/config_loader.py`'s test suite:
```python
from hookify.core.config_loader import extract_frontmatter, Rule

def test_dash_in_pattern_does_not_downgrade_block():
    content = (
        "---\n"
        "name: block-conflict-markers\n"
        "enabled: true\n"
        "event: bash\n"
        "pattern: rm\\s+---\\s+rf\n"
        "action: block\n"
        "---\n"
        "Blocked dangerous command\n"
    )
    frontmatter, message = extract_frontmatter(content)
    rule = Rule.from_dict(frontmatter, message)

    # Expected (correct) behavior: action must remain 'block'
    assert frontmatter.get('action') == 'block'
    assert rule.action == 'block'
```
Running this against the current implementation is expected to fail: `frontmatter` will be missing the `action` key entirely (it defaults `rule.action` to `'warn'`), demonstrating that the parsed `Rule` object diverges from the visible file content and that a `block` rule is silently converted into a non-blocking `warn` rule.

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

**File:** plugins/hookify/agents/conversation-analyzer.md (L60-77)
```markdown
### 3. Create Regex Patterns

Convert behaviors into matchable patterns:

**Bash command patterns:**
- `rm\s+-rf` for dangerous deletes
- `sudo\s+` for privilege escalation
- `chmod\s+777` for permission issues

**Code patterns (Edit/Write):**
- `console\.log\(` for debug logging
- `eval\(|new Function\(` for dangerous eval
- `innerHTML\s*=` for XSS risks

**File path patterns:**
- `\.env$` for environment files
- `/node_modules/` for dependency files
- `dist/|build/` for generated files
```
