### Title
Hookify PostToolUse hook fails open on import/runtime errors, silently disabling deny enforcement - (File: plugins/hookify/hooks/posttooluse.py)

### Summary
`plugins/hookify/hooks/posttooluse.py`'s module-level import wrapper and `main()`'s exception handler both catch all errors, print a `systemMessage`, and unconditionally call `sys.exit(0)` without ever emitting a `"permissionDecision": "deny"` payload. Since Claude Code interprets exit code 0 plus the absence of a deny decision as "allow," any condition that raises an `ImportError` or other exception during hook execution causes the security boundary (blocking rules for `Bash`/`Edit`/`Write`/`MultiEdit`) to silently disable, letting the protected operation proceed as if no rule matched.

### Finding Description
At import time, `posttooluse.py` wraps `from hookify.core.config_loader import load_rules` and `from hookify.core.rule_engine import RuleEngine` in a `try/except ImportError`, and on failure prints `{"systemMessage": f"Hookify import error: {e}"}` then calls `sys.exit(0)` [1](#0-0) . Separately, `main()` wraps rule loading and evaluation in a broad `try/except Exception`, and in the `finally` block always calls `sys.exit(0)` regardless of whether an exception occurred [2](#0-1) .

The only way this hook communicates a block is by returning JSON containing `{"hookSpecificOutput": {"hookEventName": ..., "permissionDecision": "deny"}, ...}`, produced solely inside `RuleEngine.evaluate_rules` when a blocking rule matches [3](#0-2) . When the import fails or `load_rules`/`evaluate_rules` throws (e.g. a corrupted or malformed `.claude/hookify.*.local.md` rule file causing a parse/config error in `config_loader.load_rules`, or an unexpected exception in condition evaluation), the code paths above are triggered instead: a message is printed, but no `permissionDecision: deny` is emitted, and the process exits 0. From Claude Code's perspective this is indistinguishable from "no rules matched → allow."

Because `CLAUDE_PLUGIN_ROOT`-relative rule files (`.claude/hookify.*.local.md`) are normal repository content [4](#0-3) , an attacker who can influence repository content that gets loaded as a rule config (e.g., through a crafted PR, malicious plugin config, or a corrupted config file introduced via normal collaboration) can induce a parse/import error in `config_loader` or trigger an unhandled exception in `RuleEngine`, causing the "fail open" behavior instead of "fail closed." The bug is not gated by any additional check — `main()`'s `except`/`finally` structure has no branch that maps unexpected internal failures to a deny decision.

### Impact Explanation
This breaks the intended invariant that hookify's block enforcement (used to prevent dangerous `Bash` commands, unauthorized file edits, cross-repo/cross-session actions, etc.) must never silently disable itself. If the hook is relied upon as a security boundary against dangerous tool calls, an attacker-triggerable exception (e.g. malformed rule config, missing dependency, transient I/O error while reading transcripts) converts a would-be `deny` into an effective `allow`, permitting execution of `Bash`/`Edit`/`Write`/`MultiEdit` operations that should have been blocked — resulting in cross-repo, cross-session, or wrong-target mutation with real security impact, matching the "approval/security-boundary bypass" impact category.

### Likelihood Explanation
Feasibility is moderate to high: any error surfaced during `load_rules()` or `RuleEngine.evaluate_rules()` (malformed markdown rule file, invalid regex causing an uncaught exception path, missing plugin dependency, environment misconfiguration) reliably triggers the same fail-open behavior because it's unconditionally caught by the generic `except Exception` in `main()` or the `except ImportError` at module scope. No privileged access is required — only the ability to get a malformed/erroring rule configuration or import state loaded, which is plausible in a normal cloned-repo/plugin workflow.

### Recommendation
Change the failure-handling philosophy to fail closed for a security-relevant hook: on import failure or any exception in `main()`, emit a `hookSpecificOutput` with `"permissionDecision": "deny"` (or equivalent blocking response) rather than allowing silently, or clearly document/alert with a non-zero relevant signal so Claude Code treats the hook failure as "cannot verify → block." At minimum, distinguish "no rules matched" (return `{}`, allow) from "hook failed to evaluate rules" (should deny) instead of collapsing both into the same exit-0/no-deny output.

### Proof of Concept
Unit/integration test plan:
1. Craft a `.claude/hookify.bash.local.md` rule file with syntax that causes `config_loader.load_rules()` to raise an exception (e.g., invalid YAML/markdown frontmatter, invalid regex pattern that could bubble up as `re.error` outside `RuleEngine._regex_match`'s narrow catch).
2. Set `CLAUDE_PLUGIN_ROOT` and invoke `posttooluse.py` via stdin with a hook JSON payload representing a `Bash` command that should be blocked by a defined blocking rule, e.g. `{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}, "hook_event_name": "PostToolUse"}`.
3. Assert: process exits with code 0 (confirmed via `sys.exit(0)` in `finally`), and stdout JSON contains only `systemMessage` with no `hookSpecificOutput.permissionDecision == "deny"`.
4. Compare against expected behavior: a security-critical hook failure should not silently allow — assert the returned JSON does NOT equal an allow-equivalent response when a blocking rule was configured to match, i.e., `assert result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"` should fail, demonstrating the fail-open bug.
5. Separately simulate an `ImportError` (e.g., temporarily break `sys.path` insertion or remove `hookify.core.rule_engine`) and confirm the same exit-0 fail-open behavior at the module level.

### Citations

**File:** plugins/hookify/hooks/posttooluse.py (L12-19)
```python
# CRITICAL: Add plugin root to Python path for imports
PLUGIN_ROOT = os.environ.get('CLAUDE_PLUGIN_ROOT')
if PLUGIN_ROOT:
    parent_dir = os.path.dirname(PLUGIN_ROOT)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    if PLUGIN_ROOT not in sys.path:
        sys.path.insert(0, PLUGIN_ROOT)
```

**File:** plugins/hookify/hooks/posttooluse.py (L21-27)
```python
try:
    from hookify.core.config_loader import load_rules
    from hookify.core.rule_engine import RuleEngine
except ImportError as e:
    error_msg = {"systemMessage": f"Hookify import error: {e}"}
    print(json.dumps(error_msg), file=sys.stdout)
    sys.exit(0)
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

**File:** plugins/hookify/core/rule_engine.py (L60-84)
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
            else:
                # For other events, just show message
                return {
                    "systemMessage": combined_message
                }
```
