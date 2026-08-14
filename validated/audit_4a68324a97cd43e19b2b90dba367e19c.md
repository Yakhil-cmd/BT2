### Title
Fail-open exception handling in hookify PreToolUse/Stop hooks silently bypasses user-defined "block" rules - ([File: plugins/hookify/hooks/pretooluse.py])

### Summary
The external report's bug class is: a critical protective action (foreclosure/liquidation) is entirely aborted by an unrelated failure (a reverting token transfer), turning a narrow failure into a total loss of the protective mechanism. The closest reachable analog in `Jortegata/claude-code--025` is in the `hookify` plugin's hook executors, where the protective mechanism is a user-authored "block" rule meant to deny dangerous tool calls (e.g., destructive Bash commands, sensitive file writes). Just as the spokes-v1 contract's blanket `try/catch`-free transfer let one failure defeat the entire foreclosure flow, hookify's blanket `except Exception` handlers around rule evaluation let *any* unrelated failure defeat the entire blocking decision, silently converting a "deny" outcome into an "allow" outcome.

### Finding Description
`plugins/hookify/hooks/pretooluse.py` wraps the whole rule-loading/evaluation pipeline in a single broad `try/except Exception` block: [1](#0-0) 

On any exception raised anywhere inside `load_rules()` or `RuleEngine.evaluate_rules()` — including exceptions not related to malformed rule files, such as a `KeyError`/`AttributeError` from unexpected `tool_input` shapes, an `OSError` while globbing `.claude/`, or a bug triggered by attacker-controlled `tool_input` content reaching `_extract_field`/`_check_condition` in `rule_engine.py` — the hook does not deny or ask; it prints a `systemMessage` and then unconditionally calls `sys.exit(0)`: [2](#0-1) 

Because Claude Code's `PreToolUse` hook contract only blocks when the hook emits `hookSpecificOutput.permissionDecision: "deny"` (or historically exits 2 with valid JSON), an exit-0 response with no `hookSpecificOutput` is functionally equivalent to "no opinion" → the tool call proceeds. This means a single Python exception anywhere in the rule pipeline silently disables every user-configured `block` rule for that tool call, with no exit code or transcript signal distinguishing "rule engine crashed" from "rule engine ran and found nothing to block." The same fail-open pattern exists in `plugins/hookify/hooks/stop.py`, whose `Stop`-hook block decision (`{"decision": "block", ...}`) is likewise swallowed by the same `except Exception → allow` structure: [3](#0-2) 

The rule engine itself contains plausible exception triggers reachable from attacker-controlled `tool_input`: `_extract_field` calls `.get()`/`.startswith()`/`.endswith()` on values whose types depend on tool input shape, and `MultiEdit` handling does `e.get('new_string', '')` assuming each edit is a dict: [4](#0-3) 
If an `edits` entry is not a dict (e.g. a string or null, which a malicious or malformed `tool_input` could supply), `e.get(...)` raises `AttributeError`, which propagates up and is caught by the top-level `except Exception` in `pretooluse.py`, converting what should be a `deny` verdict for a matching rule into a silent `allow`.

### Impact Explanation
This is a genuine "unprivileged-user hook bypass" analog: any user (or any agent-controlled tool call, since `tool_input` values are attacker/model-influenced) that can cause an exception in the rule pipeline effectively disables the security-guidance layer for that call. Organizations relying on hookify `block` rules (e.g., "deny writes to `.env`", "deny destructive `rm -rf`") get a false sense of protection — the block rule silently does nothing instead of erroring loudly, and there is no distinguishing signal in the transcript (both "no rule matched" and "rule engine crashed" print the same style of low-signal `systemMessage`, and both exit 0). This maps to the reported bug's severity class: a design that "fails closed to safety" on one narrow error path (transfer revert should not block a whole liquidation) is inverted here into "fails open to danger" on a broad error surface (any exception should not silently defeat a block rule) — both are consequences of collapsing all failure modes into one blanket handler.

### Likelihood Explanation
Medium: this requires (a) a project actually configuring hookify `block` rules for tool-use protection, and (b) a code path in `rule_engine.py`/`config_loader.py` that raises given specific `tool_input` shapes (e.g., malformed `MultiEdit.edits` entries, unexpected types for known fields). The `except (IOError, OSError, ValueError, KeyError, AttributeError, TypeError)` branches in `config_loader.py` show the authors are aware some inputs throw, but the outer `pretooluse.py`/`stop.py` wrappers still catch everything generically and choose "allow" as the universal fallback, by explicit design comment ("ALWAYS exit 0 - never block operations due to hook errors"). This is a deliberate fail-open design decision documented in the code itself, not a subtle bug, which increases confidence that the mechanism is real, though whether it is exploitable in a given deployment depends on which block rules are configured.

### Recommendation
Replace the universal "any exception → allow" behavior with a fail-secure default for rules already flagged as `action: block`: if a rule with `action == 'block'` was in the process of being evaluated when an exception occurred, surface a `deny`/`ask` decision (or at minimum a distinct, loud, exit-code-2 diagnostic) instead of silently exiting 0 with an ambiguous message. Narrow the outer `except Exception` in `pretooluse.py`/`posttooluse.py`/`stop.py` to catch only the specific parsing/IO exception types already handled inside `config_loader.py`, and let truly unexpected exceptions either propagate as a blocking error or be logged with a severity that makes "hook crashed" clearly distinguishable from "hook ran, nothing matched" in the transcript/telemetry.

### Proof of Concept
Conceptual PoC (not independently executed against a live Claude Code session):
1. Configure a hookify block rule such as `.claude/hookify.protect-env.local.md` with `event: file`, `action: block`, `field: new_text`, `pattern: "SECRET"`.
2. Have the agent issue a `MultiEdit` tool call where `tool_input.edits` contains a malformed entry, e.g. `{"edits": ["not-a-dict"]}`, alongside content that would otherwise match the block rule.
3. `RuleEngine._extract_field` reaches `e.get('new_string', '')` on the string element `"not-a-dict"` and raises `AttributeError: 'str' object has no attribute 'get'`. [5](#0-4) 
4. This exception propagates out of `evaluate_rules()` into `pretooluse.py`'s top-level `except Exception`, which prints a generic `systemMessage` and exits 0 with no `hookSpecificOutput.permissionDecision`. [2](#0-1) 
5. Claude Code treats the absent permission decision as non-blocking, and the `MultiEdit` (which should have been denied by the configured `block` rule) proceeds unimpeded.

Note: I was not able to execute this against a live Claude Code CLI session (no filesystem/terminal access in this mode), so step 5's exact CLI behavior on a hook returning `{}`-like output with no `hookSpecificOutput` should be confirmed empirically; the hook contract documented in `plugins/plugin-dev/skills/hook-development/SKILL.md:144-153` supports this reading.

### Citations

**File:** plugins/hookify/hooks/pretooluse.py (L35-70)
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

**File:** plugins/hookify/hooks/stop.py (L46-55)
```python
    except Exception as e:
        # On any error, allow the operation
        error_output = {
            "systemMessage": f"Hookify error: {str(e)}"
        }
        print(json.dumps(error_output), file=sys.stdout)

    finally:
        # ALWAYS exit 0
        sys.exit(0)
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
