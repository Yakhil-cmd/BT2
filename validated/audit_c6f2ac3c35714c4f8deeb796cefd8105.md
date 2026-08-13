### Title
Extra `---` delimiter in hookify rule frontmatter silently truncates parsed fields, turning a `block` rule into an inert/non-matching rule - ([File: plugins/hookify/core/config_loader.py])

### Summary
`extract_frontmatter` splits rule file content with `content.split('---', 2)`, so only the text between the *first two* `---` occurrences is treated as YAML frontmatter [1](#0-0) . If a third `---` line appears before the file's intended closing delimiter, every frontmatter key defined after that extra delimiter (including `action: block` and the `conditions` list) is silently dropped into the message body and never parsed, while `Rule.from_dict` fills in permissive defaults (`action` defaults to `"warn"`, `conditions` defaults to `[]`) without raising any error [2](#0-1) .

### Finding Description
`load_rule_file` reads a `.claude/hookify.*.local.md` file and calls `extract_frontmatter(content)` [3](#0-2) . `extract_frontmatter` only checks `if len(parts) < 3: return {}, content` and otherwise unconditionally treats `parts[1]` (text between delimiter #1 and #2) as the whole frontmatter, dumping everything after delimiter #2 (including any further `---` and the fields after it) into `message` [4](#0-3) .

Because `load_rule_file` only warns when the resulting `frontmatter` dict is completely empty (`if not frontmatter: ... return None`) [5](#0-4) , a file that still has *some* early keys (e.g. `name`, `enabled`, `event`) but lost `action`/`conditions` after an injected `---` produces no warning and loads "successfully."

`Rule.from_dict` then applies safe-looking defaults: `action=frontmatter.get('action', 'warn')` and empty `conditions=[]` when no `conditions` key was found [6](#0-5) . In `RuleEngine._rule_matches`, a rule with no conditions is explicitly forced to never match: `if not rule.conditions: return False` [7](#0-6) , and even in cases where the `action` key alone is lost while conditions survive on the far side, `evaluate_rules` treats anything not equal to `'block'` as a `warning_rules` entry that "allow[s] the operation" [8](#0-7) .

The attacker input is a single extra `---` line inserted into the frontmatter body of an existing (or newly introduced) `.claude/hookify.*.local.md` rule file — reachable through ordinary repository content (e.g., a pull request that modifies or adds this file, which the victim clones and Claude Code's hookify plugin auto-loads via `load_rules()`'s glob over `.claude/hookify.*.local.md`) [9](#0-8) . Because the visible `action: block` text and the intended `pattern`/`conditions` remain physically present in the file (just relocated after the spurious delimiter into the unparsed message body), a code reviewer scanning the diff for "action: warn" or removed rules would not notice the rule has been neutered.

### Impact Explanation
A hookify rule intended to `block` a dangerous `Bash`/`Edit`/`Write` invocation (e.g., blocking destructive commands or writes outside an approved path) can be silently downgraded to a non-matching/no-op rule purely by a delimiter formatting change, without altering the visible `action: block` or pattern text. This lets a dangerous tool invocation proceed unblocked, enabling unauthorized file read/write or command execution outside the intended workspace scope that the block rule was meant to prevent — matching the "Unauthorized file read or write outside the user-approved workspace or target scope" impact.

### Likelihood Explanation
Exploitation only requires the ability to introduce or modify a `.claude/hookify.*.local.md` file in a repository that the victim later clones and uses with Claude Code (ordinary repository/PR content, no admin privileges needed). The change needed (adding one `---` line) is minimal and can be disguised as an innocuous formatting artifact, making it plausible to slip past casual review. The bug is deterministic and 100% reproducible given the crafted file.

### Recommendation
Rewrite `extract_frontmatter` to only treat the *first* line that is exactly `---` (after the opening delimiter) as the closing delimiter, using a line-based scan rather than a 2-way `str.split('---', 2)`, and reject/raise a hard, non-silent error if additional stray `---` lines are found within the frontmatter/message boundary detection logic. Additionally, `load_rule_file` should fail loudly (not silently default) when a rule declares `action` conceptually but the parser cannot find expected keys (`conditions`/`pattern`) — e.g., validate that `action == 'block'` rules always have non-empty `conditions`/`pattern`, and error out instead of loading a permissive default.

### Proof of Concept
Add a unit test in `plugins/hookify/core/config_loader.py`'s test suite (or a new pytest file):
```python
from hookify.core.config_loader import extract_frontmatter, Rule

content = """---
name: block-rm
enabled: true
event: bash
---
action: block
conditions:
  - field: command
    operator: regex_match
    pattern: "rm -rf"
---

Blocked!
"""

frontmatter, message = extract_frontmatter(content)
rule = Rule.from_dict(frontmatter, message)

# Vulnerable behavior (current code):
assert rule.action != 'block'          # silently downgraded to default 'warn'
assert rule.conditions == []           # conditions lost -> rule never matches

# Expected/secure behavior:
# assert rule.action == 'block'
# assert len(rule.conditions) == 1
```
Integration PoC: place the crafted file at `.claude/hookify.block-rm.local.md` in a cloned repo, then invoke `plugins/hookify/hooks/pretooluse.py` with a `Bash` tool call `{"command": "rm -rf /"}`. Assert the hook response is `{}` (allowed) instead of the expected `permissionDecision: deny`, confirming the deny rule was parsed into a non-blocking (in fact non-matching) configuration.

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

**File:** plugins/hookify/core/config_loader.py (L209-211)
```python
    # Find all hookify.*.local.md files
    pattern = os.path.join('.claude', 'hookify.*.local.md')
    files = glob.glob(pattern)
```

**File:** plugins/hookify/core/config_loader.py (L250-261)
```python
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

**File:** plugins/hookify/core/rule_engine.py (L115-118)
```python
        # If no conditions, don't match
        # (Rules must have at least one condition to be valid)
        if not rule.conditions:
            return False
```
