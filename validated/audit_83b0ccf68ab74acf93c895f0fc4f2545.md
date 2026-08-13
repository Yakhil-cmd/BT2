### Title
Ad-hoc frontmatter parser silently drops multi-line dict fields at indent==2, causing hookify security rules to silently never match (`Condition.field`/`pattern` diverge from file content) - ([File: plugins/hookify/core/config_loader.py])

### Summary
`extract_frontmatter`'s hand-rolled state machine only treats a continuation line as belonging to the current dict item when `indent > 2` (config_loader.py:184), which silently discards any field written with exactly 2 spaces of extra indentation relative to a `-` marker at column 0 — a natural and common YAML style. The dropped field falls back to `Condition.from_dict`'s empty-string defaults (config_loader.py:26-28), producing a `Condition` whose `field`/`pattern` differ from what a human reviewer sees in the file, with no warning or error raised anywhere in the load path.

### Finding Description
`extract_frontmatter` (`plugins/hookify/core/config_loader.py:87-195`) parses YAML-like frontmatter line-by-line using mutable `current_dict`/`current_list` state and an `indent` computed as `len(line) - len(line.lstrip())` [1](#0-0) .

Three branches handle lines: top-level key (`indent == 0`), a new list item (`stripped.startswith('-')`), and a continuation field of the current dict item, gated by `elif indent > 2 and in_dict_item and ':' in line` [2](#0-1) .

If a rule author writes a `conditions` list where the `-` marker sits at column 0 and continuation lines are indented by exactly 2 spaces (the most natural indentation for a dash followed by aligned fields), those continuation lines have `indent == 2`, which fails all three branches and is silently dropped — no exception, no log message, no fallback handling.

Example crafted `.local.md`:
```
---
name: block-rm
enabled: true
event: bash
action: block
conditions:
- pattern: "rm -rf"
  field: command
  operator: regex_match
---
Block dangerous rm -rf!
```
Trace:
1. `- pattern: "rm -rf"` (indent=0) starts `current_dict = {'pattern': 'rm -rf'}`, `in_dict_item = True`.
2. `  field: command` and `  operator: regex_match` both have `indent == 2` → dropped silently by the `indent > 2` continuation check.
3. Final `current_dict` = `{'pattern': 'rm -rf'}` only, appended to `conditions`.
4. `Condition.from_dict` fills missing keys with defaults: `field=''`, `operator='regex_match'` [3](#0-2) .
5. In `RuleEngine._check_condition` → `_extract_field(field='', ...)` never matches any branch (`field in tool_input` is false for `''`, none of the special-cased field names equal `''`) and returns `None` [4](#0-3) .
6. `_check_condition` returns `False` whenever `field_value is None` [5](#0-4) , so this condition — and hence the whole rule (`_rule_matches` requires all conditions true) — never matches, regardless of the actual Bash command executed.

The result: a rule that a human reviewer reads as "block any `rm -rf` command" is silently inert forever. No validation step anywhere in `load_rule_file`/`load_rules` detects the missing `field` or empty `pattern`; errors are only caught for I/O/type exceptions, not for this kind of silent data loss [6](#0-5) .

Conversely, if the `field`/`operator` lines survive but `pattern` is the one dropped, `Condition.pattern` defaults to `''`, and `regex_match` against an empty pattern via `re.search('', text)` always matches (over-broad match, not a bypass) [7](#0-6) . The security-relevant direction is the bypass case shown above, where `field` is the one silently lost.

Note: `current_dict` itself is not aliased across list items (a fresh dict literal is assigned on each new `-` item at config_loader.py:177), so there is no cross-item value leakage between unrelated list entries via shared mutable references; the vulnerability is data loss (silent field dropping) at the indent boundary, not field bleeding between two different condition entries.

### Impact Explanation
Hookify rules in `.claude/hookify.*.local.md` are the mechanism by which a repository defines its own PreToolUse/PostToolUse/Stop/UserPromptSubmit guardrails (e.g., blocking dangerous Bash commands or file edits) [8](#0-7) . If an attacker contributes such a rule file (e.g., in a PR proposing a "security hardening" rule) using the natural 2-space continuation style, a reviewer approving the visible YAML believes a specific dangerous pattern is blocked, while the actual parsed `Rule` never triggers `action: block` for anything. This is a silent, stealthy guard bypass / false-negative security rule enabled purely by an ad-hoc parser's indentation-boundary bug, matching the "guard bypass or false-negative security rule due to parser differential" impact category. It does not grant new privileges directly, but it defeats a security control the project relies on without any detectable error.

### Likelihood Explanation
Preconditions are low: only an ordinary, unprivileged contributor needs to get a `.claude/hookify.*.local.md` file with this specific (and very plausible) indentation style into the target repository — no admin/maintainer privilege, no exploit of trust beyond a normal review of a rule file's readable YAML content. The bug is deterministic and 100% reproducible given the described indentation; it does not depend on race conditions or environment specifics. The main risk-limiting factor is that a careful reviewer diffing the rule's actual enforced behavior (rather than just reading the YAML) could notice the rule never fires, but the code itself provides no automated detection or warning of the silent field-drop.

### Recommendation
Replace the hand-rolled frontmatter parser with a real YAML parser (e.g., `yaml.safe_load`) for the frontmatter block, eliminating the ad-hoc indent-based state machine entirely. If the custom parser must be kept for compatibility, at minimum:
- Change the continuation condition to be based on indentation *relative to the list item's own indent* (tracked per-item) rather than a hardcoded literal `> 2`, so any indentation strictly greater than the `-` marker's indent is accepted.
- Add validation after parsing: reject/log/error when a `Condition` dict is missing required keys (`field`, `pattern`) rather than silently defaulting to empty strings in `Condition.from_dict`.
- Add a round-trip self-check in `load_rule_file` that compares the number of expected `:` key lines under a list item to the number of keys actually captured in the resulting dict, warning loudly on mismatch.

### Proof of Concept
```python
# test_frontmatter_indent_bug.py
from hookify.core.config_loader import extract_frontmatter, Rule
from hookify.core.rule_engine import RuleEngine

CONTENT = """---
name: block-rm
enabled: true
event: bash
action: block
conditions:
- pattern: "rm -rf"
  field: command
  operator: regex_match
---
Block dangerous rm -rf!
"""

def test_indent_2_drops_fields():
    fm, msg = extract_frontmatter(CONTENT)
    cond = fm['conditions'][0]
    # A human reading the file expects field == 'command' and pattern == 'rm -rf'
    # but the parser silently drops the 2-space-indented continuation lines.
    assert cond == {'pattern': 'rm -rf'}  # 'field' and 'operator' silently lost
    assert 'field' not in cond

def test_rule_never_blocks_due_to_bug():
    fm, msg = extract_frontmatter(CONTENT)
    rule = Rule.from_dict(fm, msg)
    assert rule.conditions[0].field == ''       # should have been 'command'
    engine = RuleEngine()
    input_data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /"}
    }
    result = engine.evaluate_rules([rule], input_data)
    # Expected by reviewer: blocked. Actual: silently allowed.
    assert result == {}
```
Fuzz/property test plan: generate random dict-item field sets (`field`, `operator`, `pattern`) with randomized continuation indentation in `{1,2,3,4,5,8}` spaces and tabs, feed through `extract_frontmatter`, and assert the resulting dict has all three keys present with values matching those declared in the source text; flag any run where a key present in the source is absent from the parsed dict (parser-differential divergence) as a failure.

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

**File:** plugins/hookify/core/config_loader.py (L120-122)
```python

        # Check indentation level
        indent = len(line) - len(line.lstrip())
```

**File:** plugins/hookify/core/config_loader.py (L183-187)
```python
        # Continuation of dict item (indented under list item)
        elif indent > 2 and in_dict_item and ':' in line:
            # This is a field of the current dict item
            k, v = stripped.split(':', 1)
            current_dict[k.strip()] = v.strip().strip('"').strip("'")
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

**File:** plugins/hookify/core/rule_engine.py (L157-161)
```python
        # Extract the field value to check
        field_value = self._extract_field(condition.field, tool_name, tool_input, input_data)
        if field_value is None:
            return False

```

**File:** plugins/hookify/core/rule_engine.py (L182-254)
```python
    def _extract_field(self, field: str, tool_name: str,
                      tool_input: Dict[str, Any], input_data: Dict[str, Any] = None) -> Optional[str]:
        """Extract field value from tool input or hook input data.

        Args:
            field: Field name like "command", "new_text", "file_path", "reason", "transcript"
            tool_name: Tool being used (may be empty for Stop events)
            tool_input: Tool input dict
            input_data: Full hook input (for accessing transcript_path, reason, etc.)

        Returns:
            Field value as string, or None if not found
        """
        # Direct tool_input fields
        if field in tool_input:
            value = tool_input[field]
            if isinstance(value, str):
                return value
            return str(value)

        # For Stop events and other non-tool events, check input_data
        if input_data:
            # Stop event specific fields
            if field == 'reason':
                return input_data.get('reason', '')
            elif field == 'transcript':
                # Read transcript file if path provided
                transcript_path = input_data.get('transcript_path')
                if transcript_path:
                    try:
                        with open(transcript_path, 'r') as f:
                            return f.read()
                    except FileNotFoundError:
                        print(f"Warning: Transcript file not found: {transcript_path}", file=sys.stderr)
                        return ''
                    except PermissionError:
                        print(f"Warning: Permission denied reading transcript: {transcript_path}", file=sys.stderr)
                        return ''
                    except (IOError, OSError) as e:
                        print(f"Warning: Error reading transcript {transcript_path}: {e}", file=sys.stderr)
                        return ''
                    except UnicodeDecodeError as e:
                        print(f"Warning: Encoding error in transcript {transcript_path}: {e}", file=sys.stderr)
                        return ''
            elif field == 'user_prompt':
                # For UserPromptSubmit events
                return input_data.get('user_prompt', '')

        # Handle special cases by tool type
        if tool_name == 'Bash':
            if field == 'command':
                return tool_input.get('command', '')

        elif tool_name in ['Write', 'Edit']:
            if field == 'content':
                # Write uses 'content', Edit has 'new_string'
                return tool_input.get('content') or tool_input.get('new_string', '')
            elif field == 'new_text' or field == 'new_string':
                return tool_input.get('new_string', '')
            elif field == 'old_text' or field == 'old_string':
                return tool_input.get('old_string', '')
            elif field == 'file_path':
                return tool_input.get('file_path', '')

        elif tool_name == 'MultiEdit':
            if field == 'file_path':
                return tool_input.get('file_path', '')
            elif field in ['new_text', 'content']:
                # Concatenate all edits
                edits = tool_input.get('edits', [])
                return ' '.join(e.get('new_string', '') for e in edits)

        return None
```

**File:** plugins/hookify/core/rule_engine.py (L256-273)
```python
    def _regex_match(self, pattern: str, text: str) -> bool:
        """Check if pattern matches text using regex.

        Args:
            pattern: Regex pattern
            text: Text to match against

        Returns:
            True if pattern matches
        """
        try:
            # Use cached compiled regex (LRU cache with max 128 patterns)
            regex = compile_regex(pattern)
            return bool(regex.search(text))

        except re.error as e:
            print(f"Invalid regex pattern '{pattern}': {e}", file=sys.stderr)
            return False
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
