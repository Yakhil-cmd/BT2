### Title
Hookify `PreToolUse` hook fails open (silently allows the tool call) on any rule-evaluation error - (File: `plugins/hookify/hooks/pretooluse.py`)

### Summary
The external report describes a fail-open pattern: `AtlasVerification.validateUserOp` treats an unverified/failed check as "approved" whenever `isSimulation` is true, so a control that is supposed to gate an action instead defaults to allow under an exceptional condition. The `hookify` plugin's `PreToolUse` hook implements the same fail-open class of defect: whenever rule evaluation raises *any* exception, the hook does not deny or ask — it prints a diagnostic message and exits `0` with no `permissionDecision`, which Claude Code treats as "no opinion / allow."

### Finding Description
`plugins/hookify/hooks/pretooluse.py` is registered as the `PreToolUse` hook for the hookify plugin, whose entire purpose is to gate `Bash`/`Edit`/`Write`/`MultiEdit` tool calls against user-authored rules [1](#0-0) .

The `main()` function loads rules and evaluates them, but wraps the evaluation in a blanket `try/except Exception`:

```python
try:
    input_data = json.load(sys.stdin)
    ...
    rules = load_rules(event=event)
    engine = RuleEngine()
    result = engine.evaluate_rules(rules, input_data)
    print(json.dumps(result), file=sys.stdout)
except Exception as e:
    error_output = {"systemMessage": f"Hookify error: {str(e)}"}
    print(json.dumps(error_output), file=sys.stdout)
finally:
    sys.exit(0)
``` [2](#0-1) 

Note the comment explicitly documenting this as intentional design: "On any error, allow the operation and log" and "ALWAYS exit 0 - never block operations due to hook errors" [3](#0-2) . The same fail-open guard also appears earlier when the `hookify` package cannot even be imported [4](#0-3) .

Just as `AtlasVerification.sol` conflates "cannot verify" (`isSimulation == true`) with "verified/approved," this hook conflates "rule engine errored" with "rule engine approved" — the exception path emits no `permissionDecision: deny/ask`, so Claude Code's tool-call permission flow proceeds as if hookify had no objection to the pending `Bash`/`Edit`/`Write`/`MultiEdit` call.

### Impact Explanation
`hookify` exists specifically so that a project can encode blocking security rules (e.g. "deny writes under `/etc`", "deny destructive `rm -rf`") in `.claude/hookify.*.local.md` [1](#0-0) . Any condition that causes `load_rules()` or `RuleEngine.evaluate_rules()` to throw — a malformed/unparseable rule file, an unusual `tool_input` value that the engine's regex/matcher logic can't handle, an environment issue, or an unhandled edge case in rule matching — silently disables enforcement for that tool call instead of failing closed. Because the exception handler always exits `0` without a deny/ask decision, the underlying dangerous `Bash`/`Edit`/`Write` action can proceed exactly as if no security rule existed, defeating the entire purpose of the plugin for that invocation.

### Likelihood Explanation
This is not a hypothetical: the design explicitly documents "on any error, allow" as intended behavior for *both* the import-failure path and the generic exception path [4](#0-3) [3](#0-2) . Any user or agent-driven input that causes an unhandled exception during rule loading/evaluation (e.g. a crafted `tool_input.command`/`file_path` string that trips up the matcher, or a rules file with unexpected content) will reach this fail-open branch without special privilege. I was not able to fully inspect `plugins/hookify/core/rule_engine.py` and `plugins/hookify/core/config_loader.py` in this session (tool errors prevented reading them), so I cannot enumerate the exact crash-triggering inputs; that would need to be confirmed with full repository access.

### Recommendation
Change the fail-open behavior to fail-closed for security-relevant rule categories: on an unhandled exception in `load_rules`/`evaluate_rules`, emit `hookSpecificOutput.permissionDecision: "ask"` (or `"deny"` for rules marked blocking) instead of silently exiting `0` with only a `systemMessage`. At minimum, surface the failure loudly enough (non-zero/blocking exit or explicit `ask`) that the tool call does not proceed unreviewed, mirroring the report's core recommendation of never treating "could not verify" as "approved."

### Proof of Concept
Conceptual reproduction (not independently executed): configure a hookify blocking rule (e.g., deny `rm -rf`) in `.claude/hookify.bash.local.md`. Trigger a `Bash` tool call whose `tool_input` causes `RuleEngine.evaluate_rules` to raise an exception (e.g., a `tool_input.command` value that breaks the engine's parsing/matching, or a temporarily malformed rules file). Because `plugins/hookify/hooks/pretooluse.py`'s exception handler always calls `sys.exit(0)` without emitting a `permissionDecision`, the dangerous command executes despite the configured blocking rule, since Claude Code's permission pipeline sees no deny/ask decision from the hook.

### Citations

**File:** plugins/hookify/hooks/pretooluse.py (L1-6)
```python
#!/usr/bin/env python3
"""PreToolUse hook executor for hookify plugin.

This script is called by Claude Code before any tool executes.
It reads .claude/hookify.*.local.md files and evaluates rules.
"""
```

**File:** plugins/hookify/hooks/pretooluse.py (L25-32)
```python
try:
    from hookify.core.config_loader import load_rules
    from hookify.core.rule_engine import RuleEngine
except ImportError as e:
    # If imports fail, allow operation and log error
    error_msg = {"systemMessage": f"Hookify import error: {e}"}
    print(json.dumps(error_msg), file=sys.stdout)
    sys.exit(0)
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
