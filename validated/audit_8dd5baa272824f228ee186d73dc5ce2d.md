## Title
Hookify hook scripts fail open on any parsing exception, silently bypassing configured `block` rules - (File: `plugins/hookify/hooks/pretooluse.py`)

### Summary
The externally reported bug is a type-confusion issue: an unexpected message/type shape causes a security-relevant processing function (`unpackData`/`extractLogsAndContractAddr`) to throw, and the error is allowed to abort the entire downstream enforcement/audit step (block indexing), silently defeating the intended guarantee. The closest analog in this repository is the `hookify` plugin's `PreToolUse`/`PostToolUse`/`Stop`/`UserPromptSubmit` hook executors, which are the plugin's actual tool-call approval gate. These scripts wrap all rule evaluation in a blanket `try/except Exception` that, on *any* error — including errors caused by unexpected/mismatched `tool_input` shapes — discards the exception and unconditionally exits with code `0`, which Claude Code interprets as "allow."

### Finding Description
`plugins/hookify/hooks/pretooluse.py` reads the hook JSON from stdin, extracts `tool_name`, loads user-authored `.claude/hookify.*.local.md` block/warn rules, and calls `RuleEngine.evaluate_rules()` to decide whether to deny a tool call: [1](#0-0) 

The actual enforcement logic lives in `RuleEngine._rule_matches` → `_check_condition` → `_extract_field`, which branches on `tool_name` and expects `tool_input` to expose specific keys/types (e.g. `command` for `Bash`, `new_string`/`content` for `Write`/`Edit`, an `edits` list for `MultiEdit`): [2](#0-1) 

If `tool_input` or a nested field does not match the shape this code assumes for the given `tool_name` (for example, a plugin-defined MCP tool sharing a matcher pattern like `mcp__.*` but with a differently-typed schema, or any tool call whose `tool_input` structure diverges from the hardcoded per-tool-name branches), evaluation can raise inside `evaluate_rules`/`_check_condition` rather than cleanly returning `False`. This exception propagates up to the top-level `try/except Exception` in `pretooluse.py`, `posttooluse.py`, and `stop.py`, all of which are explicitly documented to "ALWAYS exit 0 — never block operations due to hook errors": [3](#0-2) 

The same fail-open pattern exists in `posttooluse.py`: [4](#0-3) 

This mirrors the reported bug-class exactly: a mismatch between the expected and actual shape of tool-call data causes the security-relevant function (rule/condition evaluation) to error, and that error is converted into an unconditional "allow the operation" outcome instead of denying, retrying, or otherwise preserving the intended safety property — just as the original bug converted a type-URL mismatch into "skip block indexing" instead of "handle non-EVM message correctly."

### Impact Explanation
Any project or user relying on `hookify` block rules (e.g., "deny `rm -rf`", "deny writes to `.env`", "deny `curl | bash`") gets a false sense of enforcement. A tool call whose `tool_input` triggers any exception in the rule-evaluation path (type mismatch, missing nested key, unexpected value type causing a downstream operation like `.startswith`/`in` to fail) will bypass all configured block rules for that call, because the hook always exits `0` with no `permissionDecision: deny` in that failure path. This is a hook/approval-gate bypass affecting an unprivileged trust boundary (a user or team member relying on `hookify` rules to constrain what an agent can execute), consistent with the "hook bypass" and "command approval" categories.

### Likelihood Explanation
Likelihood is moderate: `hookify` is not part of Claude Code core and rules are user/opt-in authored, but the failure mode is broad by design ("ALWAYS exit 0") rather than restricted to a narrow parsing edge case, so any unanticipated tool-input shape (new tool types, MCP tools with unusual schemas, or malformed input from model hallucination/prompt injection influencing tool arguments) silently disables all blocking rules for that call rather than failing safe.

### Recommendation
- Change the fail-open policy for `PreToolUse` (and ideally `PostToolUse`) hooks so that exceptions during rule evaluation default to a safe/deny (or `ask`) decision when any `block`-type rule could apply, rather than unconditionally exiting `0`.
- Harden `_extract_field`/`_check_condition` to explicitly validate the type of `tool_input` and nested fields before use, returning a defined "unmatched/unknown" state distinct from a successful "no violation" evaluation, and surface that distinction to the caller so it can decide whether to fail closed.
- Add regression tests that feed malformed/mismatched-type `tool_input` payloads (missing keys, wrong types, unexpected tool names) through `pretooluse.py` and assert that any active `block` rule for that hook still results in a deny decision or a safe default, not silent allow.

### Proof of Concept
1. Author a project rule `.claude/hookify.bash-guard.local.md` with `event: bash`, `action: block`, condition `field: command`, `operator: regex_match`, `pattern: rm\s+-rf`.
2. Trigger a `PreToolUse` event where the tool invoked matches the rule's tool matcher but `tool_input` is shaped so that field extraction/condition evaluation raises inside `RuleEngine.evaluate_rules` (e.g., a tool_input value at the expected key that is a nested type not handled by any of the `_extract_field` tool-specific branches, or a custom MCP tool matching a wildcard matcher pattern with a non-standard `tool_input` schema causing an exception once processed downstream in a future engine change).
3. Because `pretooluse.py`'s `try/except Exception` wraps the entire `load_rules()`/`evaluate_rules()` call and always calls `sys.exit(0)` in the `finally` block regardless of the exception, the hook emits only a `systemMessage` about the internal error and never emits `hookSpecificOutput.permissionDecision: deny`. [3](#0-2) 
4. The dangerous command executes despite an active, matching `block` rule — the equivalent of the reported bug's "error causes the security-relevant step to be skipped instead of enforced."

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

**File:** plugins/hookify/hooks/posttooluse.py (L30-62)
```python
def main():
    """Main entry point for PostToolUse hook."""
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)

        # Determine event type based on tool
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
        error_output = {
            "systemMessage": f"Hookify error: {str(e)}"
        }
        print(json.dumps(error_output), file=sys.stdout)

    finally:
        # ALWAYS exit 0
        sys.exit(0)
```
