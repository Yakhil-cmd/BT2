### Title
Fragile explicit-`conditions` YAML parsing lets a malformed block rule silently degrade into a no-op, unlike robust legacy `pattern` rules - (File: `plugins/hookify/core/config_loader.py`)

### Summary
`Rule.from_dict` treats the legacy `pattern` field and the explicit `conditions` list as semantically equivalent inputs, but only the legacy path guarantees a valid, matchable `Condition` because the target `field` is computed in Python code from the `event` type. The explicit `conditions` path depends entirely on the hand-rolled mini-YAML parser (`extract_frontmatter`) correctly reconstructing nested `field:`/`operator:`/`pattern:` keys, and on `Condition.from_dict` silently defaulting missing/misparsed keys to empty strings instead of failing. A rule file that looks like a valid `action: block` rule using the "advanced" conditions format can therefore be parsed into a `Rule` whose conditions never match anything (or whose entire load throws and the rule is dropped), causing the block to silently never fire.

### Finding Description
`Rule.from_dict` in `plugins/hookify/core/config_loader.py:44-84` builds `conditions` in two ways:
- Legacy: `simple_pattern = frontmatter.get('pattern')` and a hard-coded, code-driven `field` inference (`command`/`new_text`/`content` based on `event`) at [1](#0-0) . This path is immune to YAML-list parsing bugs because `pattern` is a simple top-level scalar.
- Explicit: `cond_list = frontmatter['conditions']`, list-of-dicts parsed by `Condition.from_dict`, which defaults an absent `field` key to `''` rather than raising [2](#0-1) .

The nested list-of-dicts under `conditions:` is reconstructed by a fragile, hand-written parser in `extract_frontmatter` that relies on exact indentation depth (`indent > 2`) to associate continuation lines like `operator:`/`pattern:` with the current dict item [3](#0-2) . If a `conditions` item's sub-keys use an indentation the parser doesn't expect (e.g., 2-space continuation instead of >2), those keys are silently dropped, leaving `Condition.field` empty.

At evaluation time, `RuleEngine._check_condition` extracts `field_value = self._extract_field(condition.field, ...)`; an empty/incorrect `field` never matches any key in `tool_input` or the special-cased tool/event fields, so `field_value` is `None` and the condition (and therefore the whole `AND`-ed rule) never matches [4](#0-3) . Because `_rule_matches` requires `rule.conditions` to be non-empty and all to match, a `block` rule with a silently emptied `field` becomes permanently inert without any error being surfaced to the user [5](#0-4) .

A related, more severe failure mode: if a `conditions` list item is malformed in a way that raises inside `Condition.from_dict` (e.g., a non-dict list entry causing `AttributeError`), `load_rule_file` catches the exception, prints a warning to stderr, and returns `None`, dropping the *entire* rule file, not just the bad condition [6](#0-5) . The stderr warning is not surfaced in the normal Claude Code hook UX, so the user has no visible indication that their `block` rule stopped protecting them.

Both `/hookify` rule generation (`plugins/hookify/commands/hookify.md`, which instructs an LLM to hand-write these YAML-like frontmatter blocks) [7](#0-6)  and any repo-shipped `.claude/hookify.*.local.md` file are the untrusted sources of this frontmatter, and neither validates that `conditions` parsed into non-empty, correctly-fielded `Condition` objects before treating the rule as an active `block` policy.

### Impact Explanation
A rule author (or the generation flow) believing they have deployed a `block` rule (e.g., blocking `.env`/credential reads, blocking `curl`/exfiltration commands) can end up with a rule object whose `conditions` are empty or unmatchable due to parser/indentation fragility, while the rule file still reports as "enabled" with no visible error to the operator. This defeats the safety invariant that legacy (`pattern`) and explicit (`conditions`) rule authoring produce equivalent enforcement, silently reopening the exact dangerous operations (sensitive file edits, dangerous bash commands, prompt/diff exfiltration to a remote sink) the rule was meant to block — matching the "sensitive code/prompt/token/diff/local file disclosure to an unintended sink" impact category, since the hook that was supposed to gate the action never denies it.

### Likelihood Explanation
This requires no special privilege: an attacker only needs to influence the content of a `.claude/hookify.*.local.md` file that will be committed/reviewed/cloned in an ordinary repo workflow, or to phrase a `/hookify` generation request such that the LLM emits the "advanced" `conditions` block with non-canonical indentation. Because the mini-YAML parser's indentation handling is undocumented and brittle, and LLM-authored markdown frequently varies whitespace, this is a plausible, repeatable outcome rather than a contrived edge case. The failure is also silent (no warning shown in typical UX), so it is unlikely to be caught by casual review of "does this rule look right."

### Recommendation
- Replace the hand-rolled frontmatter/list parser in `extract_frontmatter` with a real YAML parser (e.g., `yaml.safe_load`) to eliminate indentation-dependent silent data loss.
- Make `Condition.from_dict` fail loudly (raise `ValueError`) when required keys (`field`, `pattern`) are missing or empty, instead of defaulting to `''`.
- Make `Rule.from_dict`/`load_rule_file` treat a rule with `action == 'block'` and zero effective conditions as a load error (refuse to enable), rather than silently loading an inert rule.
- Surface parse/validation warnings for rule files through a visible channel (not just stderr), e.g., a `systemMessage` on first hook invocation, so operators know a `block` rule failed to load or is a no-op.
- Add a regression/invariant test asserting that a semantically-equivalent legacy `pattern` rule and explicit `conditions` rule always produce the same `Rule.conditions`/matching behavior for the same intended field/pattern.

### Proof of Concept
Unit test plan (pytest) in the style of `plugins/hookify/core/config_loader.py`'s own `__main__` self-test:

1. **Legacy baseline (works):**
```python
fm_legacy = {"name": "block-rm", "enabled": True, "event": "bash",
             "pattern": r"rm\s+-rf", "action": "block"}
rule = Rule.from_dict(fm_legacy, "blocked")
assert rule.conditions == [Condition(field="command", operator="regex_match", pattern=r"rm\s+-rf")]
engine = RuleEngine()
assert engine.evaluate_rules([rule], {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})["hookSpecificOutput"]["permissionDecision"] == "deny"
```

2. **Explicit conditions with mis-indented sub-key (simulating malformed/LLM-generated frontmatter) — expect same block, but observe bypass:**
```python
content = """---
name: block-rm
enabled: true
event: bash
action: block
conditions:
  - field: command
  operator: regex_match
  pattern: rm\\s+-rf
---
blocked
"""
fm, msg = extract_frontmatter(content)
rule = Rule.from_dict(fm, msg)
# BUG: field key lost due to indent<=2 continuation handling
assert rule.conditions[0].field == ""   # should be "command"
result = RuleEngine().evaluate_rules([rule], {"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
assert result == {}   # BUG: dangerous command is NOT blocked, contradicting the legacy-equivalent rule
```

3. **Malformed condition entry drops the entire rule:**
```python
fm_bad = {"name": "block-rm", "enabled": True, "event": "bash", "action": "block",
          "conditions": ["not-a-dict"]}
try:
    Rule.from_dict(fm_bad, "blocked")
    assert False, "expected exception per current Condition.from_dict/list handling"
except AttributeError:
    pass  # via load_rule_file this becomes a silently dropped rule (None), losing all protection
```

Expected assertions demonstrate that the explicit `conditions` form produces a strictly weaker (bypassable) rule than the semantically identical legacy `pattern` form, violating the stated invariant.

### Citations

**File:** plugins/hookify/core/config_loader.py (L22-29)
```python
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Condition':
        """Create Condition from dict."""
        return cls(
            field=data.get('field', ''),
            operator=data.get('operator', 'regex_match'),
            pattern=data.get('pattern', '')
        )
```

**File:** plugins/hookify/core/config_loader.py (L56-73)
```python
        # Legacy style: simple pattern field
        simple_pattern = frontmatter.get('pattern')
        if simple_pattern and not conditions:
            # Convert simple pattern to condition
            # Infer field from event
            event = frontmatter.get('event', 'all')
            if event == 'bash':
                field = 'command'
            elif event == 'file':
                field = 'new_text'
            else:
                field = 'content'

            conditions = [Condition(
                field=field,
                operator='regex_match',
                pattern=simple_pattern
            )]
```

**File:** plugins/hookify/core/config_loader.py (L183-188)
```python
        # Continuation of dict item (indented under list item)
        elif indent > 2 and in_dict_item and ':' in line:
            # This is a field of the current dict item
            k, v = stripped.split(':', 1)
            current_dict[k.strip()] = v.strip().strip('"').strip("'")

```

**File:** plugins/hookify/core/config_loader.py (L260-271)
```python
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
```

**File:** plugins/hookify/core/rule_engine.py (L115-125)
```python
        # If no conditions, don't match
        # (Rules must have at least one condition to be valid)
        if not rule.conditions:
            return False

        # All conditions must match
        for condition in rule.conditions:
            if not self._check_condition(condition, tool_name, tool_input, input_data):
                return False

        return True
```

**File:** plugins/hookify/core/rule_engine.py (L157-160)
```python
        # Extract the field value to check
        field_value = self._extract_field(condition.field, tool_name, tool_input, input_data)
        if field_value is None:
            return False
```

**File:** plugins/hookify/commands/hookify.md (L108-124)
```markdown
**For more complex rules (multiple conditions):**
```markdown
---
name: {rule-name}
enabled: true
event: file
conditions:
  - field: file_path
    operator: regex_match
    pattern: \.env$
  - field: new_text
    operator: contains
    pattern: API_KEY
---

{Warning message}
```
```
