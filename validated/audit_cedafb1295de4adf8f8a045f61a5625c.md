### Title
Malformed MultiEdit `edits` entries crash rule evaluation and bypass PreToolUse block decisions - ([File: plugins/hookify/hooks/pretooluse.py])

### Summary
`RuleEngine._extract_field` assumes every element of a `MultiEdit` tool_input's `edits` list is a dict and unconditionally calls `.get('new_string', '')` on each element. If any entry is a non-dict value (string, int, `None`, list, etc.), this raises `AttributeError` inside `evaluate_rules`, which is caught by the top-level bare `except Exception` in `pretooluse.py`'s `main()`. The `finally: sys.exit(0)` then always returns exit code 0 with only a benign `systemMessage`, so any block rule that would have matched the dangerous `MultiEdit` never gets to emit its `permissionDecision: deny`, and Claude Code proceeds with the operation as if unblocked.

### Finding Description
In `plugins/hookify/core/rule_engine.py`, `_extract_field` handles `MultiEdit` field extraction as: [1](#0-0) 
`edits = tool_input.get('edits', [])` followed by `' '.join(e.get('new_string', '') for e in edits)`. This is invoked from `_check_condition` → `_rule_matches`, which is called for every rule (including blocking rules) inside the main loop of `evaluate_rules`: [2](#0-1) 
If `edits` contains any non-dict item, `e.get(...)` raises `AttributeError` while the engine is still iterating rules — i.e., before the `blocking_rules` list can be finalized and before the `deny` response dict is constructed and returned.

In `plugins/hookify/hooks/pretooluse.py`, the entire rule evaluation call is wrapped in a bare `except Exception`, and a `finally` block unconditionally exits 0: [3](#0-2) 
This means the exception raised mid-evaluation is swallowed, only a generic `{"systemMessage": "Hookify error: ..."}` is printed (no `hookSpecificOutput.permissionDecision: deny`), and the process exits 0. Claude Code interprets an exit-0 hook output without a deny decision as "allow", so the guarded/dangerous `MultiEdit` operation that a block rule was designed to stop executes anyway.

The trigger only requires a `MultiEdit` tool call whose `tool_input.edits` list contains at least one non-dict element (e.g., a bare string or `null`) alongside content that a configured block rule's field/pattern would otherwise match against `new_text`/`content` on `MultiEdit`.

### Impact Explanation
This is a hook-enforcement bypass: a security/guardrail rule (e.g., blocking edits that write secrets, disable protections, or inject malicious code) that a repo maintainer configured via `.claude/hookify.*.local.md` silently fails to block a matching dangerous `MultiEdit` call whenever the `edits` array is malformed in this specific way, because the failure mode of the entire hook is "fail open" by design (`finally: sys.exit(0)`) combined with an unhandled crash occurring before the deny path is reached. This directly defeats the intended approval/blocking trust boundary the hookify plugin exists to enforce for tool calls.

### Likelihood Explanation
Exploitability depends on whether the attacker (via prompt injection in repository content, issue/PR text, or a compromised MCP/tool response feeding the model) can induce Claude to invoke `MultiEdit` with an `edits` array containing a non-dict element (e.g., `["", {"old_string": "x", "new_string": "malicious"}]`). Since tool_input construction is model-driven and influenced by untrusted context that the model reads, this is plausible in scenarios where prompt injection steers the assistant to make malformed tool calls, and it is deterministic and 100% repeatable once such a call occurs — no timing or race conditions are required.

### Recommendation
In `_extract_field` for `MultiEdit`, defensively filter/validate `edits` entries, e.g. `' '.join(e.get('new_string', '') for e in edits if isinstance(e, dict))`, and more generally replace the bare `except Exception: ... sys.exit(0)` fail-open behavior in `pretooluse.py` (and the other hook scripts) with a fail-closed or at least fail-safe path for exceptions raised specifically during rule matching (as opposed to import/setup failures), so a crash during evaluation cannot silently downgrade a would-be `deny` into an implicit allow.

### Proof of Concept
Unit test in `rule_engine`/`pretooluse` test suite:
1. Define a blocking `Rule` with `tool_matcher="MultiEdit"` and a condition on field `new_text`/`content` with a pattern that matches a malicious string (e.g. `"malicious_payload"`).
2. Construct `input_data`:
```python
{
  "hook_event_name": "PreToolUse",
  "tool_name": "MultiEdit",
  "tool_input": {
    "file_path": "/tmp/x",
    "edits": ["not_a_dict", {"old_string": "a", "new_string": "malicious_payload"}]
  }
}
```
3. Call `RuleEngine().evaluate_rules([rule], input_data)` directly and assert it raises `AttributeError` (demonstrating the crash before deny is produced).
4. Then simulate `pretooluse.main()` with this stdin JSON piped in; assert the process exits with code `0` and the printed JSON contains only `systemMessage` (an error message) with no `hookSpecificOutput.permissionDecision == "deny"`, proving the blocking rule was bypassed despite matching content being present.

### Citations

**File:** plugins/hookify/core/rule_engine.py (L53-58)
```python
        for rule in rules:
            if self._rule_matches(rule, input_data):
                if rule.action == 'block':
                    blocking_rules.append(rule)
                else:
                    warning_rules.append(rule)
```

**File:** plugins/hookify/core/rule_engine.py (L246-252)
```python
        elif tool_name == 'MultiEdit':
            if field == 'file_path':
                return tool_input.get('file_path', '')
            elif field in ['new_text', 'content']:
                # Concatenate all edits
                edits = tool_input.get('edits', [])
                return ' '.join(e.get('new_string', '') for e in edits)
```

**File:** plugins/hookify/hooks/pretooluse.py (L54-70)
```python
        # Evaluate rules
        engine = RuleEngine()
        result = engine.evaluate_rules(rules, input_data)

        # Always output JSON (even if empty)
        print(json.dumps(result), file=sys.stdout)

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
