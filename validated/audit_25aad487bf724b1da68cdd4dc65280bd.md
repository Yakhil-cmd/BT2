### Title
Rule action string comparison is case-sensitive/unstripped, silently downgrading intended `Block` rules to warnings - (File: plugins/hookify/core/rule_engine.py)

### Summary
`RuleEngine.evaluate_rules` routes matched rules by checking `if rule.action == 'block'`, an exact case-sensitive, unstripped string comparison. `Rule.action` is populated directly from user-authored YAML frontmatter with no normalization (`action=frontmatter.get('action', 'warn')` in `config_loader.py`), so any variation such as `Block`, `BLOCK`, or `" block"` silently falls into the warning branch instead of the blocking branch, even though the rule was clearly authored to block.

### Finding Description
The rule loading path is: `pretooluse.py` (and the other hook entrypoints) call `load_rules()` in `plugins/hookify/core/config_loader.py`, which parses a hand-written, minimal YAML-like frontmatter parser and builds a `Rule` dataclass via `Rule.from_dict` [1](#0-0) . The `action` field is taken verbatim from the frontmatter with a default of `"warn"` and no `.strip()` or `.lower()` normalization: `action=frontmatter.get('action', 'warn')` [2](#0-1) .

That `Rule` object is then evaluated in `RuleEngine.evaluate_rules`, which decides whether a matched rule goes into `blocking_rules` or `warning_rules` using a strict equality check: `if rule.action == 'block': blocking_rules.append(rule) else: warning_rules.append(rule)` [3](#0-2) . If `blocking_rules` is non-empty, the function returns `hookSpecificOutput.permissionDecision: "deny"` for `PreToolUse`/`PostToolUse` events [4](#0-3) ; otherwise, if only `warning_rules` matched, it returns only a `systemMessage` and the tool call is allowed to proceed [5](#0-4) .

Because there is no case-folding or whitespace trimming anywhere in this pipeline, any deviation from the exact lowercase literal `block` (e.g. `Block`, `BLOCK`, `" block"`, `"block "`) causes the rule to be silently treated as a warning. The rule's own message/name can still say "block" and its author's intent is clearly to deny the operation, but the actual enforcement outcome is "allow with a warning message" — the dangerous `Bash`/`Edit`/`Write` operation proceeds. There is no other validation, schema check, or fail-closed default anywhere in `config_loader.py` or `rule_engine.py` that would catch or normalize this mismatch.

### Impact Explanation
A rule file merged into the repository under `.claude/hookify.*.local.md` that is intended to hard-block a dangerous operation (e.g., `rm -rf`, writing to a sensitive path) but uses any non-exact-lowercase spelling of `block` in its `action` field will not actually deny the operation — it will only emit a warning message while allowing the tool call to execute. This breaks the "deny means deny" invariant of the hook enforcement layer: a rule that appears in the repository as a security control is silently downgraded to advisory-only, without any error, log, or indication to the rule author or reviewer that enforcement failed. This matches an approval/enforcement bypass class of impact — a supposed blocking guardrail does not block.

### Likelihood Explanation
This requires only that a plausible-looking rule file (with `action: Block`, `BLOCK`, or similar) be merged into the repository — a normal contribution path for `.claude/hookify.*.local.md` rule files, not requiring any elevated privilege, credential leakage, or social engineering. Given how easy it is to author YAML with inconsistent casing (and that the existing docstring in `config_loader.py` even shows `action: str = "warn"  # "warn" or "block" (future)` [6](#0-5)  without documenting case sensitivity), this is a highly repeatable and easily triggered defect — deterministic given any non-exact-match action string.

### Recommendation
Normalize `action` at load time and validate it against an explicit enum, e.g. in `Rule.from_dict`: `action=frontmatter.get('action', 'warn').strip().lower()`, and reject/log rules whose normalized `action` is not one of `{"warn", "block"}` (fail closed by treating unrecognized actions as `block`, or reject the rule file outright with a loud warning) rather than silently defaulting to `warn`. Apply the same normalization/equality check consistently in `RuleEngine.evaluate_rules`.

### Proof of Concept
Unit test in `plugins/hookify/core/rule_engine.py`'s test harness or a new test file:
```python
from hookify.core.config_loader import Rule, Condition
from hookify.core.rule_engine import RuleEngine

for action_value in ["Block", " block", "BLOCK", "block "]:
    rule = Rule(
        name="block-rm-rf",
        enabled=True,
        event="bash",
        conditions=[Condition(field="command", operator="regex_match", pattern=r"rm\s+-rf")],
        action=action_value,
        message="This should be BLOCKED"
    )
    engine = RuleEngine()
    result = engine.evaluate_rules([rule], {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"}
    })
    # Expected (currently fails): dangerous command must be denied
    assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny", (
        f"action={action_value!r} was NOT enforced as block, got: {result}"
    )
```
Currently this assertion fails for all four action-value variants — `evaluate_rules` returns only a `systemMessage` (warning) with no `hookSpecificOutput.permissionDecision: "deny"`, confirming the dangerous `rm -rf /` command would be allowed to execute.

### Citations

**File:** plugins/hookify/core/config_loader.py (L40-40)
```python
    action: str = "warn"  # "warn" or "block" (future)
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

**File:** plugins/hookify/core/rule_engine.py (L53-58)
```python
        for rule in rules:
            if self._rule_matches(rule, input_data):
                if rule.action == 'block':
                    blocking_rules.append(rule)
                else:
                    warning_rules.append(rule)
```

**File:** plugins/hookify/core/rule_engine.py (L72-79)
```python
            elif hook_event in ['PreToolUse', 'PostToolUse']:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": hook_event,
                        "permissionDecision": "deny"
                    },
                    "systemMessage": combined_message
                }
```

**File:** plugins/hookify/core/rule_engine.py (L86-91)
```python
        # If only warnings, show them but allow operation
        if warning_rules:
            messages = [f"**[{r.name}]**\n{r.message}" for r in warning_rules]
            return {
                "systemMessage": "\n\n".join(messages)
            }
```
