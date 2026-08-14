### Title
Hookify's fail-open PreToolUse/PostToolUse hooks let attacker-controlled tool input crash or hang the rule engine, silently bypassing user-defined blocking rules - ([File: plugins/hookify/hooks/pretooluse.py])

### Summary
The DeGate report describes a validator that crashes on malformed/unvalidated attacker-supplied values, degrading or defeating a security-relevant check. The `hookify` plugin exhibits an analogous pattern in claude-code: its `PreToolUse`/`PostToolUse` hook executors wrap all rule evaluation in a bare `except Exception` and unconditionally `sys.exit(0)`, and are bounded by a 10-second hook timeout. Any attacker-influenced tool input (Bash command text, file content, etc.) that raises an exception in the rule-matching code, or that triggers a slow/catastrophic-backtracking regex match against a user-authored blocking rule, causes the hook to either report no result or exceed its timeout — in both cases the intended `block`/`deny` decision is never emitted and the operation proceeds.

### Finding Description
`plugins/hookify/hooks/pretooluse.py` reads the hook JSON from stdin, loads user-authored rules via `load_rules()`, and evaluates them with `RuleEngine.evaluate_rules()`: [1](#0-0) 

Critically, the `main()` function catches *any* exception during rule loading/evaluation and always exits 0 ("ALWAYS exit 0 - never block operations due to hook errors"), so an error in the matching pipeline silently produces an empty/`systemMessage`-only result instead of the rule's intended `deny` decision: [2](#0-1) 

The condition-matching code that operates on attacker/model-controlled fields (`command`, `new_text`, `content`, etc.) calls into regex matching for `regex_match`-type rules: [3](#0-2) [4](#0-3) 

The field values fed into these checks (e.g. a Bash `command`, or `new_string`/`content` for Edit/Write) can be influenced by untrusted content the model consumed (e.g., via prompt injection from a fetched web page or MCP tool output) before being placed into a tool call, which is exactly the kind of externally-influenced string this matching logic runs against: [5](#0-4) 

Because Hookify's own guidance explicitly recommends user-authored regex patterns (e.g., `rm\s+-rf`) for exactly this kind of blocking-rule use case, a user's protective rule can itself use a regex vulnerable to catastrophic backtracking. If the attacker-influenced field value (which is untrusted) is engineered to trigger pathological backtracking against that pattern, the hook can hang past the plugin's configured 10-second timeout: [6](#0-5) 

The plugin's own documentation confirms that hook timeouts and uncaught script errors are known-but-unaddressed failure modes ("Hook times out" / "Hook fails silently"), without any guidance that a timed-out or crashed `PreToolUse` hook is treated as a deny — implying the operation is allowed to proceed when the hook does not deliver a timely block decision: [7](#0-6) 

This mirrors the DeGate root cause: a crafted, attacker-reachable input value that the "validator" (Hookify's rule engine) cannot handle causes the enforcement path to fail (crash or timeout) rather than to explicitly deny, and the system's fallback behavior on that failure is fail-open rather than fail-closed.

### Impact Explanation
Hookify is specifically marketed and documented as a way for users to author blocking safeguards (e.g., "Block rm -rf", "block secrets in .env edits", "require tests before stop"). If the enforcement engine can be forced into an exception or a timeout via attacker-controlled tool-input content, the intended block never fires and the dangerous operation (destructive Bash command, secret-containing file write, or premature session Stop) proceeds unimpeded. This is a concrete hook-bypass of a user-configured approval/blocking gate, consistent with the "hook bypass" trust-boundary category explicitly in scope. Because Hookify hooks run on every `Bash`/`Edit`/`Write`/`MultiEdit` tool call, this could be exploited repeatedly by any untrusted content the agent processes (web content, MCP tool output) that ends up echoed into a subsequent tool call the model makes, silently disabling the user's safety net for that call.

### Likelihood Explanation
Exploitation requires: (1) the user has installed Hookify and defined at least one blocking regex-based rule (a documented, encouraged usage pattern), and (2) the value of the matched field (command/content/etc.) is influenced by content that isn't fully trusted (e.g., surfaced via prompt injection or a compromised/malicious MCP server, or simply crafted by an adversarial user of a shared session). Triggering an uncaught exception or timeout is a data-shape problem, not a cryptographic break, making it a realistic, low-privilege exploitation path. However, this is a plugin bundled in the repo (not core claude-code) and depends on end users opting into user-authored, potentially ReDoS-prone patterns, which moderates likelihood.

### Recommendation
- Change the hook's failure semantics to fail-closed for `PreToolUse` blocking evaluation: on unexpected exceptions or evaluation errors, return a deny/ask decision (or at minimum a clear warning) rather than always exiting 0 with no decision.
- Enforce a hard per-regex match timeout independent of the whole-hook timeout (e.g., run `_regex_match` in a bounded subprocess/thread with a small timeout) so a single pathological pattern cannot exhaust the entire hook budget and silently disable all rules.
- Validate/lint user-authored regex patterns for catastrophic-backtracking risk at rule-load time (e.g., using a linear-time regex engine or static ReDoS detection) and warn users when a rule pattern is unsafe.
- Document and, where possible, make configurable whether a hook timeout/crash on `PreToolUse` should default to deny rather than allow, matching the "fail closed" recommendation architecture used elsewhere in claude-code's sandbox/permission code.

### Proof of Concept
1. Install the `hookify` plugin and create `.claude/hookify.block-rm.local.md`:
```markdown
---
name: block-rm
enabled: true
event: bash
pattern: (a+)+$
action: block
---
Blocked dangerous command.
```
(Illustrative ReDoS-prone pattern chosen to demonstrate the class of bug; a real-world rule such as `(.*)*/etc/passwd` or similarly nested-quantifier pattern authored by a well-meaning but regex-inexperienced user demonstrates the same effect.)
2. Get the agent (via prompt injection from fetched content, or a malicious/compromised MCP tool result) to construct a `Bash` `command` string engineered to catastrophically backtrack against the rule's pattern (e.g., a long run of `a` characters followed by a non-matching character: `"echo " + "a"*40 + "!"`).
3. Observe that `plugins/hookify/hooks/pretooluse.py`'s `re.match`/`re.search` call via `compile_regex` in `_regex_match` hangs past the 10-second hook timeout configured in `hooks.json`, or that the hook process is killed on timeout.
4. Confirm that the `Bash` tool call is executed without ever receiving the intended `deny` decision from the blocking rule, because the hook's fail-open handling (`except Exception: ... finally: sys.exit(0)`, or a plugin-level timeout) never returns the block payload in time.

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

**File:** plugins/hookify/core/rule_engine.py (L13-24)
```python
# Cache compiled regexes (max 128 patterns)
@lru_cache(maxsize=128)
def compile_regex(pattern: str) -> re.Pattern:
    """Compile regex pattern with caching.

    Args:
        pattern: Regex pattern string

    Returns:
        Compiled regex pattern
    """
    return re.compile(pattern, re.IGNORECASE)
```

**File:** plugins/hookify/core/rule_engine.py (L144-181)
```python
    def _check_condition(self, condition: Condition, tool_name: str,
                        tool_input: Dict[str, Any], input_data: Dict[str, Any] = None) -> bool:
        """Check if a single condition matches.

        Args:
            condition: Condition to check
            tool_name: Tool being used
            tool_input: Tool input dict
            input_data: Full hook input data (for Stop events, etc.)

        Returns:
            True if condition matches
        """
        # Extract the field value to check
        field_value = self._extract_field(condition.field, tool_name, tool_input, input_data)
        if field_value is None:
            return False

        # Apply operator
        operator = condition.operator
        pattern = condition.pattern

        if operator == 'regex_match':
            return self._regex_match(pattern, field_value)
        elif operator == 'contains':
            return pattern in field_value
        elif operator == 'equals':
            return pattern == field_value
        elif operator == 'not_contains':
            return pattern not in field_value
        elif operator == 'starts_with':
            return field_value.startswith(pattern)
        elif operator == 'ends_with':
            return field_value.endswith(pattern)
        else:
            # Unknown operator
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

**File:** plugins/hookify/hooks/hooks.json (L1-14)
```json
{
  "description": "Hookify plugin - User-configurable hooks from .local.md files",
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 ${CLAUDE_PLUGIN_ROOT}/hooks/pretooluse.py",
            "timeout": 10
          }
        ]
      }
    ],
```

**File:** plugins/plugin-dev/skills/hook-development/scripts/README.md (L138-157)
```markdown
## Common Issues

### Hook doesn't execute

Check:
- Script has shebang (`#!/bin/bash`)
- Script is executable (`chmod +x`)
- Path in hooks.json is correct (use `${CLAUDE_PLUGIN_ROOT}`)

### Hook times out

- Reduce timeout in hooks.json
- Optimize hook script performance
- Remove long-running operations

### Hook fails silently

- Check exit codes (should be 0 or 2)
- Ensure errors go to stderr (`>&2`)
- Validate JSON output structure
```
