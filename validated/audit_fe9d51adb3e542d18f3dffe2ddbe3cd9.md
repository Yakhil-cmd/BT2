### Title
Hookify's PreToolUse/PostToolUse safety hook fails open on *any* exception, silently bypassing `block` rules - (File: plugins/hookify/hooks/pretooluse.py)

### Summary
Hookify's `PreToolUse` and `PostToolUse` hook scripts wrap the entire rule-loading/evaluation pipeline in a single blanket `except Exception` whose handler unconditionally allows the tool call and whose `finally` block unconditionally calls `sys.exit(0)`. This mirrors the root cause of the referenced Reserve finding: a catch pattern meant to gracefully recover from one narrow, "expected" failure mode is written broadly enough to also swallow unrelated, unexpected failures, and the resulting fallback behavior is unsafe rather than safe. Here, "unsafe" means fail-open: any bug or edge case anywhere in rule loading/matching silently disables the hook's `action: block` guarantee (e.g. the documented `block-dangerous-rm` / `warn-sensitive-files` rules), letting the tool call proceed exactly as if no rule existed.

### Finding Description
`plugins/hookify/hooks/pretooluse.py` is the enforcement point Claude Code invokes before executing any tool call. Its `main()` is: [1](#0-0) 

The design intent (per the in-repo comment "On any error, allow the operation and log") is presumably to handle recoverable conditions such as a malformed `.claude/hookify.*.local.md` rule file. However, the `except Exception` is unscoped: it also catches exceptions coming from `RuleEngine.evaluate_rules()` itself — the code path responsible for deciding whether to *deny* a dangerous command via `hookSpecificOutput.permissionDecision = "deny"`: [2](#0-1) 

Rule matching walks attacker/model-influenced tool-call data (`tool_input`) through `_extract_field`, which contains type-sensitive logic, e.g. for `MultiEdit` it assumes every item of `tool_input['edits']` is a dict: [3](#0-2) 

Any shape mismatch here (or any other unhandled exception anywhere downstream of `evaluate_rules`) propagates up to `pretooluse.py`'s catch-all, which converts it into an *allow* decision and then force-exits `0` in `finally` — even if the except-handler itself fails to serialize/print the error, the `sys.exit(0)` in `finally` still runs and overrides any pending exception, guaranteeing the process reports success to Claude Code.

This is the same shape as the reported bug: the developer picked a coarse "catch everything to avoid crashing" strategy for what should have been a narrowly-scoped recovery (missing/malformed rule file), and that coarse catch also absorbs exceptions from the actual security-relevant computation (the block decision), silently degrading the security control instead of surfacing the failure.

### Impact Explanation
Hookify's entire value proposition is the `action: block` capability documented for rules like `block-dangerous-rm` (blocking `rm -rf`) or `warn-sensitive-files` (secrets in `.env`). Because the enforcement point fails open on any exception rather than fail-closed or at least surfacing the failure distinctly from "no rule matched," any unexpected error in rule loading/parsing/matching — a corrupt YAML-ish frontmatter, an unexpected field type in a tool call, a transient I/O error not covered by the narrower `except` clauses in `config_loader.py`, etc. — silently disables all configured `block` rules for that single tool invocation, allowing an otherwise-blocked dangerous command (e.g. `rm -rf`) or sensitive file write to execute. This is a command-approval/hook-bypass trust-boundary issue: the security-guidance framing in this repo explicitly treats "PreToolUse/PostToolUse hooks, bash allow/denylists" as gates where the model (or malicious content it processes) is the attacker and the user is the victim, so this fail-open behavior is a genuine unauthorized-action-bypass path.

### Likelihood Explanation
Likelihood is comparable to the original finding's assessment: it requires a realistic-but-not-trivial triggering condition (an unhandled exception in the evaluation path) rather than a routine input. It is more likely to manifest than the Solidity analog because: (1) hookify's own README documents users writing free-form regex/condition rules, increasing the chance of unusual field/type combinations reaching `_extract_field`/`_check_condition`; and (2) the `finally: sys.exit(0)` guarantees fail-open even if the exception handler itself misbehaves, so there is no secondary safety net.

### Recommendation
Do not use a single unscoped `except Exception` around both "expected recoverable" errors and the actual block-decision computation. Separate the two:
- Catch only the specific, enumerable failure modes around rule *loading* (already partially done in `config_loader.load_rules`/`load_rule_file`), and let those default to "no rule matched" (i.e., empty warning, not a broad allow-everything).
- For the `evaluate_rules` call itself, either let genuine bugs surface (fail loudly to stderr while still exiting 0 for backward compatibility, but emit a distinguishable `systemMessage` such as "hookify internal error — rule evaluation did not run" so the user is aware protection was skipped), or, where feasible, choose to block/deny on evaluation failure for high-risk event types, mirroring the `_reserveGas()`-style mitigation suggested in the original report: isolate the untrusted/complex computation so its failure mode is well-defined rather than an incidental side effect of Python's exception hierarchy.

### Proof of Concept
1. Create `.claude/hookify.block-rm.local.md` with `event: bash`, `pattern: rm\s+-rf`, `action: block`.
2. Trigger a tool call whose `tool_input` shape causes an unhandled exception inside `RuleEngine._extract_field`/`_check_condition` before the `rm -rf` bash rule is evaluated — e.g. a `MultiEdit` call whose `edits` list contains a non-dict element (achievable if the assistant, potentially steered by prompt-injected content in a file it is editing, emits such a call), causing `AttributeError: 'str' object has no attribute 'get'` in: [4](#0-3) 
3. `pretooluse.py`'s `except Exception` catches this, prints a generic `systemMessage`, and the `finally` block force-exits `0`: [5](#0-4) 
4. Because no `hookSpecificOutput.permissionDecision: "deny"` was ever returned, Claude Code treats the hook result as "allow," and the tool call — which should have been evaluated (and, for a matching `rm -rf` command, blocked) — proceeds unimpeded, exactly matching the "auction fails to settle safely because the catch-all also caught an unrelated error" pattern from the source report, except here the direction of harm is worse: the safety gate is bypassed rather than merely stalled.

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
