### Title
Naive literal `---` splitting in `extract_frontmatter` silently truncates YAML frontmatter, downgrading `action: block` rules to default `warn` - ([File: plugins/hookify/core/config_loader.py])

### Summary
`extract_frontmatter` in `plugins/hookify/core/config_loader.py` locates the frontmatter/body boundary using a literal `str.split('---', 2)` rather than a line-based delimiter match. If any frontmatter field value (most plausibly the `pattern` regex, which is attacker-influenced via `/hookify`-generated rules meant to detect dangerous commands) contains the literal substring `---`, the second occurrence is mistaken for the closing `---` delimiter. Everything after that point—including a later `action: block` line—is shifted into the parsed "message" text instead of the frontmatter dict, so `Rule.from_dict` falls back to its default `action = frontmatter.get('action', 'warn')`, silently turning a block rule into a warn rule.

### Finding Description
`extract_frontmatter` (`plugins/hookify/core/config_loader.py:87-195`) does:
```python
parts = content.split('---', 2)
frontmatter_text = parts[1]
message = parts[2].strip()
``` [1](#0-0) 
This treats the *first two literal occurrences* of the 3-character string `---` anywhere in the file as the frontmatter delimiters, with no requirement that `---` appear alone on its own line. Any frontmatter value (e.g., a `pattern:` regex meant to match a dangerous command containing `---`, such as heredoc/YAML-style delimiters, `curl ... ---data`, git conflict markers, etc.) that itself contains the substring `---` will be misinterpreted as the closing fence.

`Rule.from_dict` then reads `action` from whatever frontmatter dict was actually parsed, defaulting to `warn` when the key is missing:
```python
action=frontmatter.get('action', 'warn'),
``` [2](#0-1) 

Because the template used by `/hookify` (per `plugins/hookify/commands/hookify.md`) places `action:` *after* `pattern:` in the frontmatter block, any embedded `---` inside an earlier field (most commonly `pattern`) truncates the frontmatter before the `action` line is reached, so it is dropped from the parsed dict and the rule silently reverts to `warn` even though the raw, human-visible file still says `action: block`.

`load_rule_file` calls `extract_frontmatter` then `Rule.from_dict`, and `load_rules`/`pretooluse.py` feed the resulting `Rule` objects straight into `RuleEngine.evaluate_rules`, which decides `permissionDecision: deny` only for `rule.action == 'block'`: [3](#0-2) 
A rule downgraded from `block` to `warn` by the parser only produces a `systemMessage`, and the dangerous tool invocation (e.g., `Bash`, `Edit`) is still allowed to execute. [4](#0-3) 

Nothing in `load_rule_file` or `extract_frontmatter` validates that the parsed frontmatter actually reflects the full intended field set (e.g., no re-check that a visible `action: block` line was captured), so this parsing defect passes silently — the hook still returns a valid JSON response and exits 0.

### Impact Explanation
An attacker able to influence the content that becomes a `pattern:` (or other frontmatter) value in a generated `.claude/hookify.*.local.md` rule — e.g., via `/hookify <description containing "---">` or via conversation content that `/hookify`'s no-argument mode auto-analyzes — can cause a rule the user/Claude believes is `action: block` to actually enforce as `action: warn`. This breaks the deny-rule invariant: a dangerous `Bash`/`Edit`/`Stop` operation that should be blocked is instead allowed to proceed with only a warning message, enabling exfiltration of code, prompts, tokens, diffs, or local files to an unintended sink that the block rule was meant to prevent.

### Likelihood Explanation
This requires no special privileges beyond normal `/hookify` usage or normal repository/conversation content that gets turned into a rule's `pattern` field. Any regex intended to catch commands or content containing a literal `---` (a common construct: heredocs, git conflict markers, YAML/markdown horizontal rules, multi-dash CLI flags/data blobs) triggers the bug deterministically and repeatably — it is a pure string-parsing defect, not a race condition or timing issue.

### Recommendation
Rewrite `extract_frontmatter` to detect frontmatter delimiters only on lines that are exactly `---` (optionally with trailing whitespace), e.g. split `content` into lines and locate the first and second lines matching `^---\s*$`, rather than using `str.split('---', 2)` on the raw text. Additionally, `load_rule_file` should validate that if the raw file contains an `action:` line, the parsed `Rule.action` matches it (fail closed / reject the rule) rather than silently defaulting to `warn`.

### Proof of Concept
Add a unit test in the hookify test suite:
```python
from plugins.hookify.core.config_loader import extract_frontmatter, Rule

content = """---
name: block-curl-exfil
enabled: true
event: bash
pattern: curl.*---data
action: block
---

Blocked: possible exfiltration via curl with --- delimiter
"""

frontmatter, message = extract_frontmatter(content)
rule = Rule.from_dict(frontmatter, message)

# Visible file clearly states action: block
assert "action: block" in content
# But parsed Rule silently defaults to warn because 'action' line
# was shifted into the message body by the premature '---' split
assert rule.action == "warn"   # demonstrates the downgrade
assert "action" not in frontmatter
```
Expected result: the assertions pass, proving that a rule file explicitly authored (and visually appearing) as `action: block` is parsed and enforced as `action: warn`, so `RuleEngine.evaluate_rules` would classify it as a `warning_rule` instead of a `blocking_rule`, allowing the dangerous tool call to execute.

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

**File:** plugins/hookify/core/rule_engine.py (L53-58)
```python
        for rule in rules:
            if self._rule_matches(rule, input_data):
                if rule.action == 'block':
                    blocking_rules.append(rule)
                else:
                    warning_rules.append(rule)
```

**File:** plugins/hookify/core/rule_engine.py (L86-94)
```python
        # If only warnings, show them but allow operation
        if warning_rules:
            messages = [f"**[{r.name}]**\n{r.message}" for r in warning_rules]
            return {
                "systemMessage": "\n\n".join(messages)
            }

        # No matches - allow operation
        return {}
```
