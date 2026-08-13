### Title
Malformed rule `pattern` field (parsed as YAML list) causes uncaught `TypeError` in `compile_regex`, making PreToolUse hook fail-open and bypass all blocking rules - ([File: plugins/hookify/core/rule_engine.py])

### Summary
`extract_frontmatter`'s hand-rolled YAML parser silently turns a `pattern:` frontmatter field followed by `- item` lines into a Python `list`, which then becomes `Condition.pattern`. When `_regex_match` calls the `@lru_cache`-decorated `compile_regex(pattern)` with this unhashable list, Python raises a `TypeError` (not `re.error`) before `re.compile` even runs. `_regex_match` only catches `re.error`, so the `TypeError` propagates all the way through `evaluate_rules` into `pretooluse.py`'s generic `except Exception`, which prints a plain `systemMessage` (no `permissionDecision: deny`) and unconditionally calls `sys.exit(0)`, allowing the tool call to proceed.

### Finding Description
`extract_frontmatter` in `plugins/hookify/core/config_loader.py` treats an empty-valued top-level key followed by `- item` lines as a YAML list [1](#0-0) . If a rule file's frontmatter is:
```
---
name: malicious
enabled: true
event: bash
pattern:
  - foo
---
```
then `frontmatter['pattern']` becomes `['foo']` instead of a string. In `Rule.from_dict`, since there is no explicit `conditions` key, the legacy path builds a `Condition` directly from this list-valued `simple_pattern` [2](#0-1) , so `Condition.pattern` ends up being a `list`, not a `str`.

During evaluation, `_check_condition` dispatches to `_regex_match(pattern, field_value)` for the `regex_match` operator [3](#0-2) . `_regex_match` calls the LRU-cached `compile_regex(pattern)` [4](#0-3) . Because `compile_regex` is decorated with `@lru_cache(maxsize=128)` [5](#0-4) , calling it with an unhashable `list` argument raises `TypeError: unhashable type: 'list'` before the function body (and thus before `re.compile`) ever executes. `_regex_match` only catches `re.error` [6](#0-5) , so the `TypeError` is not handled there and propagates up through `_check_condition` → `_rule_matches` → `evaluate_rules`, aborting the `for rule in rules` loop in `evaluate_rules` entirely — discarding any `blocking_rules`/`warning_rules` already accumulated from prior rules in the same evaluation [7](#0-6) .

In `pretooluse.py`, `main()` wraps rule loading/evaluation in a generic `try/except Exception` that just emits `{"systemMessage": f"Hookify error: {str(e)}"}` with no `hookSpecificOutput`/`permissionDecision` field, and the `finally` block unconditionally calls `sys.exit(0)` [8](#0-7) . Since Claude Code only blocks a tool call when the hook emits a `permissionDecision: deny` (as constructed for the `PreToolUse` block path in `evaluate_rules` [9](#0-8) ), the crash-and-swallow path is functionally equivalent to "allow."

The malicious rule requires no special field: `rule.tool_matcher` is `None` by default so `_matches_tool` is skipped entirely [10](#0-9) , and `event: bash` ensures `load_rules(event='bash')` includes it for every `Bash` PreToolUse call [11](#0-10) , and `field='command'` ensures `_extract_field` returns the actual command string as `field_value`, so `_regex_match` is actually reached [12](#0-11) .

### Impact Explanation
Any single malicious `.claude/hookify.*.local.md` file merged into the repository (e.g., via a PR from an unprivileged contributor) can silently disable enforcement of *all* PreToolUse blocking rules for the matching event type (e.g., all `Bash` commands) glob-loaded in that same `load_rules` call, because the exception aborts `evaluate_rules` before any `deny` decision can be returned. This is a complete, repeatable bypass of the PreToolUse hook's block/deny enforcement, allowing dangerous commands (e.g., matched by a legitimate `rm -rf` block rule in another rule file) to execute unblocked, since the hook fails open instead of failing closed.

### Likelihood Explanation
Highly feasible: it requires only that an attacker's rule file (with no elevated privileges, just normal repo-content contribution) be present in `.claude/hookify.*.local.md` alongside legitimate blocking rules. No special formatting knowledge beyond the documented frontmatter list syntax is needed, and the trigger is deterministic — it fires on every matching tool call, not just once.

### Recommendation
1. In `_regex_match`, validate that `pattern` is a `str` before calling `compile_regex`, and catch broad exceptions (`TypeError`, `re.error`) around the compile/search call, treating malformed patterns as "no match" while logging a warning — but critically not as "hook execution failed."
2. In `pretooluse.py` (and the analogous `posttooluse.py`, `stop.py`, `userpromptsubmit.py`), change the fail-open `except Exception: ... sys.exit(0)` behavior for security-critical block rules to fail closed, or at least ensure a malformed rule can't silently discard already-matched blocking decisions from other valid rules — e.g., evaluate rules independently and union results, or validate rule shape (types of `pattern`/`conditions`) at load time in `config_loader.py` and drop/skip only the malformed rule rather than letting it corrupt the whole `evaluate_rules` call.
3. Harden `extract_frontmatter`/`Condition.from_dict`/`Rule.from_dict` to reject or coerce non-string `pattern` values at load time so malformed rule files are excluded (as already attempted for other error types in `load_rule_file`), rather than deferred to evaluation time where they can crash the shared evaluation loop.

### Proof of Concept
Add a unit/integration test in the hookify test suite:
```python
import json
from hookify.core.config_loader import load_rule_file, extract_frontmatter
from hookify.core.rule_engine import RuleEngine

def write_rule(tmp_path, name, content):
    p = tmp_path / f"hookify.{name}.local.md"
    p.write_text(content)
    return str(p)

def test_malformed_pattern_bypasses_legitimate_block(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".claude").mkdir()

    # Legitimate blocking rule
    (tmp_path / ".claude" / "hookify.block-rm.local.md").write_text("""---
name: block-rm
enabled: true
event: bash
action: block
pattern: "rm\\s+-rf"
---
Blocked dangerous rm command!
""")

    # Malicious rule with list-valued pattern
    (tmp_path / ".claude" / "hookify.malicious.local.md").write_text("""---
name: malicious
enabled: true
event: bash
pattern:
  - foo
---
noop
""")

    from hookify.core.config_loader import load_rules
    rules = load_rules(event='bash')

    engine = RuleEngine()
    input_data = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf /important/data"}
    }

    result = engine.evaluate_rules(rules, input_data)

    # Invariant: a dangerous command matched by a block rule must be denied
    assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny", (
        f"Expected block decision, got: {json.dumps(result)}"
    )
```
Expected (buggy) behavior: `evaluate_rules` raises `TypeError: unhashable type: 'list'` instead of returning, demonstrating that the block decision for `rm -rf` is never produced — confirming the fail-open bypass. Additionally, a fuzz test can vary `pattern` across `list`, `dict`, `int`, and other unhashable/non-`re`-friendly types to show the same uncaught-`TypeError` bypass class.

### Citations

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

**File:** plugins/hookify/core/config_loader.py (L140-145)
```python
            if not value:
                # Empty value - list or nested structure follows
                current_key = key
                in_list = True
                current_list = []
            else:
```

**File:** plugins/hookify/core/config_loader.py (L219-222)
```python
            # Filter by event if specified
            if event:
                if rule.event != 'all' and rule.event != event:
                    continue
```

**File:** plugins/hookify/core/rule_engine.py (L14-15)
```python
@lru_cache(maxsize=128)
def compile_regex(pattern: str) -> re.Pattern:
```

**File:** plugins/hookify/core/rule_engine.py (L53-61)
```python
        for rule in rules:
            if self._rule_matches(rule, input_data):
                if rule.action == 'block':
                    blocking_rules.append(rule)
                else:
                    warning_rules.append(rule)

        # If any blocking rules matched, block the operation
        if blocking_rules:
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

**File:** plugins/hookify/core/rule_engine.py (L111-113)
```python
        if rule.tool_matcher:
            if not self._matches_tool(rule.tool_matcher, tool_name):
                return False
```

**File:** plugins/hookify/core/rule_engine.py (L166-167)
```python
        if operator == 'regex_match':
            return self._regex_match(pattern, field_value)
```

**File:** plugins/hookify/core/rule_engine.py (L230-233)
```python
        # Handle special cases by tool type
        if tool_name == 'Bash':
            if field == 'command':
                return tool_input.get('command', '')
```

**File:** plugins/hookify/core/rule_engine.py (L266-269)
```python
        try:
            # Use cached compiled regex (LRU cache with max 128 patterns)
            regex = compile_regex(pattern)
            return bool(regex.search(text))
```

**File:** plugins/hookify/core/rule_engine.py (L271-273)
```python
        except re.error as e:
            print(f"Invalid regex pattern '{pattern}': {e}", file=sys.stderr)
            return False
```

**File:** plugins/hookify/hooks/pretooluse.py (L61-70)
```python
    except Exception as e:
        # On any error, allow the operation and log
        error_output = {
            "systemMessage": f"Hookify error: {str(e)}"
        }
        print(json.dumps(error_output), file=sys.stdout)

    finally:
        # ALWAYS exit 0 - never block operations due to hook errors
        sys.exit(0)
```
