### Title
Hookify PreToolUse/Stop block-rules can be forced to fail open via regex resource exhaustion, bypassing the security gate - (File: `plugins/hookify/hooks/pretooluse.py`, `plugins/hookify/core/rule_engine.py`, `plugins/hookify/hooks/hooks.json`)

### Summary
The `hookify` plugin implements a `PreToolUse`/`PostToolUse`/`Stop`/`UserPromptSubmit` hook that is meant to act as a hard, deterministic gate blocking dangerous tool calls (e.g. `rm -rf`, writes to `.env`, etc.) based on user-authored regex rules. Every hook entrypoint wraps rule evaluation in a bare `except Exception` that explicitly *allows the operation* on any failure, and the hook is invoked with a fixed 10-second timeout. Because rule matching runs unbounded `re.search()` against attacker-influenceable `tool_input` fields (`command`, `new_text`, `file_path`, etc.) with no ReDoS/complexity guard, a crafted input that triggers catastrophic backtracking against any active rule's pattern will exhaust the hook's time budget. Whether the script's own exception handler fires or the external timeout kills the process, the net effect — by design — is that the block decision is skipped and the tool call proceeds, exactly mirroring the LayerZero report's root cause: expensive computation inside the security-critical path consumes the resource budget needed for the fail-safe/blocking mechanism to complete, defeating the gate.

### Finding Description
`plugins/hookify/hooks/pretooluse.py` (and the sibling `posttooluse.py`, `stop.py`, `userpromptsubmit.py`) load user-defined rules and evaluate them with `RuleEngine.evaluate_rules`: [1](#0-0) 

The rule engine's condition checker performs unbounded regex matching directly against attacker-influenceable fields such as `command`, `new_text`, `old_text`, `file_path`: [2](#0-1) [3](#0-2) 

No ReDoS or execution-time guard exists around `regex.search(text)` — only a `re.error` catch for malformed patterns. `hooks.json` fixes the outer timeout for every hookify hook at 10 seconds: [4](#0-3) 

Critically, the hook script's own failure-handling philosophy is explicit fail-open: *any* exception (and by the code comments, any failure state) results in allowing the operation, and the process always exits 0: [5](#0-4) 

This is the same shape as the LayerZero bug: a security-critical fallback/enforcement mechanism (`storedPayload` write in LZ; the "block" decision in hookify) depends on there being enough of a shared resource budget (gas in LZ; wall-clock time under the 10s hook timeout here) left after an expensive, attacker-influenceable computation (`nonblockingLzReceive` looping over a large token array in LZ; `re.search` catastrophic backtracking over attacker-controlled `command`/`file_path`/`new_text` here) runs to completion. When that budget is exhausted, the enforcement step never executes, and the system's fallback behavior is to proceed as if nothing was denied — in LZ this blocks the channel (fails closed unintentionally elsewhere), while in hookify it fails *open*, which is strictly worse for this trust boundary: the entire purpose of the hook is to act as a deterministic "block dangerous commands" gate for an LLM agent whose tool calls can be influenced by prompt injection from untrusted content the agent reads. Per this repo's own security-review guidance, this exact class of gate is treated as a real trust boundary where "the model is the attacker, the user is the victim," and is explicitly exempted from "no privilege boundary" dismissal: [6](#0-5) 

### Impact Explanation
If a project relies on hookify `action: block` rules (as the plugin's own README and skill docs recommend, e.g. blocking `rm -rf`, writes to `.env`/credentials, `chmod 777`, etc.) as a safety net against a prompt-injected or otherwise misbehaving agent, an attacker who can influence the content of a `Bash` command or file write (via indirect prompt injection from a file/URL the agent reads) can craft a payload that triggers catastrophic regex backtracking against one of the active rule patterns. This forces the hookify hook process past its 10-second timeout, causing Claude Code to proceed without the "deny" decision the rule would otherwise have produced — the dangerous command or file write executes unblocked. This is a direct security-control bypass, not merely a performance issue, because the hook's entire reason for existing is to deterministically stop such actions.

### Likelihood Explanation
Medium: it requires (a) a project that has installed hookify with at least one `block` rule using a regex pattern susceptible to catastrophic backtracking (nested/overlapping quantifiers are easy to write unintentionally in hand-authored security patterns, and the plugin's own docs/skill encourage users to freely author arbitrary regex), and (b) an attacker capable of influencing the `tool_input` field the rule inspects (command text, file content, file path) — realistic via indirect prompt injection, which this codebase already treats as an in-scope attacker model for hook/permission gates.

### Recommendation
- Bound regex evaluation time per rule (e.g., run `_regex_match` under a hard per-call timeout, or use a regex engine/library with linear-time guarantees such as `re2`), and treat timeout/failure during rule evaluation as a **deny**, not an allow, for `action: block` rules.
- Cap total rule-evaluation time independent of the per-hook process timeout, and if the budget is exceeded, fail closed for any pending `block` rules rather than emitting `{}` (allow).
- Add static/lint-time detection (e.g., in `/hookify:configure` or `validate-hook-schema.sh`) that flags rule patterns with nested quantifiers or other well-known ReDoS constructs before they are saved as active rules.
- Reconsider the blanket "on any error, allow the operation" fallback in `pretooluse.py`/`stop.py` for rules whose `action` is `block`: fail-open should never be the default for a control whose sole purpose is denial.

### Proof of Concept
1. A project adds a hookify `block` rule intended to catch a class of dangerous content, using a regex with a vulnerable construct, e.g.:
   ```markdown
   ---
   name: guard-secrets
   enabled: true
   event: file
   action: block
   conditions:
     - field: new_text
       operator: regex_match
       pattern: (.*)+@
   ---
   Blocks writes containing something@something.
   ```
2. An attacker's content (reached via indirect prompt injection, e.g. a malicious file the agent is asked to summarize/copy) causes the agent to attempt a `Write`/`Edit` whose `new_text` is engineered to be a long string with no `@` (e.g. `"a" * 5000`), which is exactly the classic ReDoS trigger for `(.*)+` style patterns.
3. `RuleEngine._regex_match` calls `compile_regex(pattern).search(text)` on this input inside `pretooluse.py`, which blocks on catastrophic backtracking well past the 10-second `timeout` configured in `hooks.json`.
4. The hook process is killed on timeout before it can emit a `deny` decision (or, if it manages to raise, the `except Exception` branch explicitly returns an allow-shaped response and exits 0 regardless).
5. Claude Code proceeds with the `Write`/`Edit` tool call as if no blocking rule existed, defeating the intended security gate — the analog of the LZ report's "expensive operation exhausts the budget the fail-safe mechanism needed, breaking the enforcement pathway."

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

**File:** plugins/hookify/hooks/hooks.json (L1-12)
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
```

**File:** plugins/security-guidance/hooks/llm.py (L1494-1504)
```python
            "  NEVER apply NO-PRIVILEGE-BOUNDARY to: SSRF/outbound-"
            "network sinks; LLM-agent capability gates (PreToolUse/"
            "PostToolUse hooks, bash allow/denylists, workspace path "
            "jails — the model is the attacker, the user is the "
            "victim); data-exposure findings (CWE-200/359/532, secrets-"
            "in-logs — the question is who READS the sink, not who "
            "controls the input); project-working-directory config "
            "(.claude/settings, .vscode/, package.json scripts — repo "
            "author ≠ repo cloner); cross-process metadata sources "
            "(psutil.Process(...), /proc/<pid>/* — different process "
            "owner is a different principal).\n"
```
