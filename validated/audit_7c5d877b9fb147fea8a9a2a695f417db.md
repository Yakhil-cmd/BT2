I found a concrete, reachable analog. The `hookify` plugin's `PreToolUse` hook executor implements the exact same fail-mode as the reported bug: an error path is meant to signal denial/blocking but instead unconditionally signals "success" (allow), letting the guarded action (the tool call) proceed as if the block never happened.

### Title
Hookify PreToolUse hook fails open (`sys.exit(0)`) on any evaluation error, silently bypassing configured `block` rules — ([File: plugins/hookify/hooks/pretooluse.py])

### Summary
The `SwapCallLib.call()` report describes a failure path that terminates execution with `return()` instead of `revert()`, so a failed operation's state changes still take effect instead of being rolled back. The direct analog in this repo is `plugins/hookify/hooks/pretooluse.py`: when rule loading/evaluation raises *any* exception (or the module import itself fails), the hook's `finally` block unconditionally runs `sys.exit(0)` — the "operation succeeded, allow it" signal — instead of ever emitting the deny/block decision the user configured. The guarded action (the Bash/Edit/Write tool call) is not rolled back or blocked; it proceeds exactly as if no rule existed.

### Finding Description
Hookify lets an unprivileged user (the person configuring their own `.claude/hookify.*.local.md` rule files) declare `action: block` rules meant to prevent Claude from executing dangerous operations, e.g. `rm -rf` or edits to secret files, as documented in `plugins/hookify/README.md:75-96`. The enforcement logic lives in `RuleEngine.evaluate_rules()` [1](#0-0) , which returns a `hookSpecificOutput.permissionDecision: "deny"` when a blocking rule matches.

However, the executor script that Claude Code actually invokes wraps the whole load+evaluate pipeline in a `try/except Exception` that logs the error into `systemMessage` but otherwise discards it, and a `finally: sys.exit(0)` that always signals success regardless of what happened inside `try`: [2](#0-1) . There is no code path in this file that can produce exit code 2 (the documented blocking exit code, per `plugins/plugin-dev/skills/hook-development/SKILL.md:294-298`) or that can prevent `sys.exit(0)` from running. The comment even states the intent explicitly: "ALWAYS exit 0 - never block operations due to hook errors."

This means any exception between rule load and evaluation — a malformed `.claude/hookify.*.local.md` file (bad YAML frontmatter, corrupt regex, `IOError`/`OSError` on read), an `ImportError` from a broken plugin installation, or any bug in `config_loader.load_rules()` / `RuleEngine.evaluate_rules()` — silently converts an intended "deny" outcome into "allow." The identical pattern is duplicated across `posttooluse.py`, `stop.py`, and `userpromptsubmit.py`.

### Impact Explanation
This is a direct analog of the reported bug class: a failure in the enforcement mechanism does not roll back / block the guarded action — it lets it proceed. For a user who has configured `action: block` rules specifically to stop Claude from running destructive commands (the README's own flagship example is blocking `rm -rf`/`dd if=`/`mkfs`), a crafted or malformed rule condition, or any transient error in rule evaluation, causes the block to be silently skipped and the dangerous Bash command, file edit, or session-stop bypass to execute anyway. Because the failure is swallowed (`systemMessage` is informational only and not enforced by Claude Code as a block), the user has no reliable signal that their safety rule failed to apply — this is an unprivileged-user-facing "approval bypass" in the local hook-authorization trust boundary.

### Likelihood Explanation
Triggering this requires only an error inside `load_rules()`/`evaluate_rules()` — e.g., a rule file with an invalid regex pattern, a YAML parsing edge case, an unreadable transcript file for a `stop` condition (see `rule_engine.py:207-225`, which already handles several IO error types, implying such failures are anticipated), or any bug surfaced during evaluation of user-authored regex/conditions. Since Hookify rules are user-authored (potentially copied from other sources or generated via `/hookify` without careful review), a single malformed rule file is enough to degrade every subsequent PreToolUse check on that machine into an unconditional allow, with no visible error beyond a `systemMessage` that Claude Code does not treat as blocking.

### Recommendation
Change the fail-safe direction to match the security intent: on any exception during rule evaluation, the hook should fail closed for `block`-type rule sets (or at minimum surface a hard failure/exit code that the user can act on) rather than defaulting to `sys.exit(0)`. Concretely:
- Distinguish between "no rules matched" (legitimate `sys.exit(0)`) and "rule evaluation errored" (should not silently resolve to allow).
- On evaluation error, consider emitting `hookSpecificOutput.permissionDecision: "ask"` (prompt the user) instead of implicit allow, and always surface the error prominently (not just as an easily-ignored `systemMessage`).
- Apply the same fix to `posttooluse.py`, `stop.py`, and `userpromptsubmit.py`, which share the identical fail-open pattern.

### Proof of Concept
1. Configure a blocking rule, e.g. `.claude/hookify.dangerous-rm.local.md` with `action: block`, `event: bash`, `pattern: rm\s+-rf` (per `plugins/hookify/README.md:75-91`).
2. Introduce any error the current code doesn't defend against during evaluation — for example a rule condition whose `pattern` is an invalid regex is already caught inside `_regex_match` [3](#0-2) , but a bug/edge case anywhere else in `config_loader.load_rules()` (e.g. a symlinked/unreadable rule file, unexpected frontmatter type) raises an uncaught exception.
3. Claude attempts `rm -rf /important/data` via the Bash tool; Claude Code invokes `pretooluse.py` per `plugins/hookify/hooks/pretooluse.py`.
4. The exception is caught, logged into `systemMessage`, and `finally: sys.exit(0)` runs unconditionally [4](#0-3) .
5. Claude Code receives exit code 0 with no `permissionDecision: deny`, so the Bash tool proceeds to execute `rm -rf /important/data` exactly as if the user's blocking rule did not exist — the destructive action is not blocked/reverted despite the enforcement path having failed.

### Citations

**File:** plugins/hookify/core/rule_engine.py (L60-79)
```python
        # If any blocking rules matched, block the operation
        if blocking_rules:
            messages = [f"**[{r.name}]**\n{r.message}" for r in blocking_rules]
            combined_message = "\n\n".join(messages)

            # Use appropriate blocking format based on event type
            if hook_event == 'Stop':
                return {
                    "decision": "block",
                    "reason": combined_message,
                    "systemMessage": combined_message
                }
            elif hook_event in ['PreToolUse', 'PostToolUse']:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": hook_event,
                        "permissionDecision": "deny"
                    },
                    "systemMessage": combined_message
                }
```

**File:** plugins/hookify/core/rule_engine.py (L266-273)
```python
        try:
            # Use cached compiled regex (LRU cache with max 128 patterns)
            regex = compile_regex(pattern)
            return bool(regex.search(text))

        except re.error as e:
            print(f"Invalid regex pattern '{pattern}': {e}", file=sys.stderr)
            return False
```

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
