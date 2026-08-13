Based on the analysis, there is a valid analog in this repository.

### Title
Hookify hooks fail-open on any error, silently disabling all PreToolUse/PostToolUse/Stop/UserPromptSubmit protections - (File: `plugins/hookify/hooks/pretooluse.py`)

### Summary
The `hookify` plugin's hook executors (`pretooluse.py`, `posttooluse.py`, `stop.py`, `userpromptsubmit.py`) are designed so that *any* failure — import errors, malformed rule files, JSON decode errors, or unexpected exceptions — causes the hook to unconditionally allow the operation (`sys.exit(0)` with no blocking output), rather than checking whether the security-relevant state (rules successfully loaded and evaluated) is actually valid before permitting the tool call to proceed. This mirrors the Sublime `depositCollateral` finding: an action-gating function omits a state/status check, so the action silently proceeds under conditions the developer did not intend, causing the intended protection to be lost.

### Finding Description
Each hook entry point wraps the entire rule-loading and evaluation logic in a `try/except`, and uses a `finally: sys.exit(0)` to guarantee the hook never blocks Claude Code due to an internal error: [1](#0-0) 

If the `hookify` package fails to import (e.g., `CLAUDE_PLUGIN_ROOT` unset, path issue, packaging bug), the script prints an error message and exits 0 before `main()` even runs, meaning no rules are evaluated and the tool call proceeds as if no `hookify` rules existed: [2](#0-1) 

Similarly, `load_rules()` and `load_rule_file()` in `config_loader.py` swallow `IOError`, `ValueError`, `KeyError`, `AttributeError`, `TypeError`, `UnicodeDecodeError`, and generic `Exception` per-file, silently dropping any rule file that fails to parse rather than treating a parse failure as "deny by default": [3](#0-2) 

The same fail-open pattern (`except Exception: ... finally: sys.exit(0)`) is repeated identically in `posttooluse.py`, `stop.py`, and `userpromptsubmit.py`.

Just as Sublime's `depositCollateral` never checked whether the pool's loan `status` was `COLLECTION`/`ACTIVE` before accepting a deposit — allowing collateral to be silently and irrecoverably lost into a finished pool — these hooks never check whether the rule set was actually loaded/evaluated successfully before allowing the guarded tool action to proceed. A misconfiguration, a corrupted `.claude/hookify.*.local.md` file, a `PLUGIN_ROOT` env issue, or any parsing edge case results in the security control (e.g., a `block` rule meant to stop `rm -rf`, credential edits, or destructive Bash commands) being silently bypassed with no warning surfaced to the user beyond a generic `systemMessage` that most users will not scrutinize before the (now unguarded) tool action executes.

### Impact Explanation
This is a trust-boundary/hook-bypass analog: hookify is explicitly marketed as a way to "block dangerous commands" and enforce project policy via `PreToolUse`/`Stop` hooks. Because every failure path is fail-open rather than fail-closed, any of the following silently defeats all configured guardrails for that invocation:
- A rule file with a YAML/frontmatter parsing bug (e.g., unusual indentation triggering the custom hand-rolled YAML parser's edge cases) causes `load_rule_file` to return `None` and the rule is dropped.
- Any exception in `RuleEngine.evaluate_rules` (not present in the excerpt but implied by the broad `except Exception` in each hook script) results in default allow.
- Import path issues (`CLAUDE_PLUGIN_ROOT` not set, plugin relocated) short-circuit before any rule evaluation happens at all.

In each case, the user has configured `block` rules (e.g., to prevent `rm -rf`, edits to `.env`/credentials, or destructive MCP operations) expecting protection, but the operation proceeds unguarded — an unprivileged-user-facing hook bypass with no signal that the protection failed to apply, comparable to the "external requirements" medium-severity rating given to the original finding.

### Likelihood Explanation
Moderate likelihood: the custom hand-rolled frontmatter/YAML parser in `config_loader.py` and the broad per-file/per-hook exception swallowing mean that any malformed rule file, unusual character, or environment misconfiguration (not an attacker action, but ordinary user/config error) will trigger the fail-open path. This matches the original finding's characterization as arising from "user error" / "external requirements" rather than a direct attacker-controlled exploit, but with a concrete, reachable code path in the current repo.

### Recommendation
Introduce a fail-closed mode (or at minimum surface a clear, prominent block/deny signal) when hook execution cannot complete rule loading/evaluation as expected — e.g., emit `permissionDecision: "ask"` and a loud warning instead of implicit allow, and add stricter validation/status checks (successful parse of at least the intended rule, successful import) before treating the tool call as unguarded. At minimum, distinguish "no rules configured" (safe to allow) from "rules configured but failed to load/evaluate" (should not silently allow) in `load_rules`/`load_rule_file` and the hook entry points.

### Proof of Concept
1. Configure a blocking hookify rule, e.g. `.claude/hookify.dangerous-rm.local.md` with `action: block` and `pattern: rm\s+-rf` as shown in [4](#0-3) .
2. Introduce any condition that raises inside `load_rules`/`load_rule_file` for that file (malformed frontmatter, unusual encoding, etc.) or unset `CLAUDE_PLUGIN_ROOT` so the `hookify` package import fails.
3. Invoke the guarded tool (e.g., `Bash` with `rm -rf /important/path`). The `pretooluse.py` script hits the `except`/`finally` fail-open path shown at [5](#0-4)  and exits 0 with no `permissionDecision: deny`, so Claude Code proceeds to execute the destructive command the user believed was blocked.

### Citations

**File:** plugins/hookify/hooks/pretooluse.py (L25-70)
```python
try:
    from hookify.core.config_loader import load_rules
    from hookify.core.rule_engine import RuleEngine
except ImportError as e:
    # If imports fail, allow operation and log error
    error_msg = {"systemMessage": f"Hookify import error: {e}"}
    print(json.dumps(error_msg), file=sys.stdout)
    sys.exit(0)


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

**File:** plugins/hookify/core/config_loader.py (L213-241)
```python
    for file_path in files:
        try:
            rule = load_rule_file(file_path)
            if not rule:
                continue

            # Filter by event if specified
            if event:
                if rule.event != 'all' and rule.event != event:
                    continue

            # Only include enabled rules
            if rule.enabled:
                rules.append(rule)

        except (IOError, OSError, PermissionError) as e:
            # File I/O errors - log and continue
            print(f"Warning: Failed to read {file_path}: {e}", file=sys.stderr)
            continue
        except (ValueError, KeyError, AttributeError, TypeError) as e:
            # Parsing errors - log and continue
            print(f"Warning: Failed to parse {file_path}: {e}", file=sys.stderr)
            continue
        except Exception as e:
            # Unexpected errors - log with type details
            print(f"Warning: Unexpected error loading {file_path} ({type(e).__name__}): {e}", file=sys.stderr)
            continue

    return rules
```

**File:** plugins/hookify/commands/help.md (L30-41)
```markdown
```markdown
---
name: warn-dangerous-rm
enabled: true
event: bash
pattern: rm\s+-rf
---

⚠️ **Dangerous rm command detected!**

This command could delete important files. Please verify the path.
```
```
