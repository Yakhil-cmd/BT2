### Title
Lack of input validation on the hookify `action` field allows a security-blocking rule to silently degrade to a non-blocking warning - (File: plugins/hookify/core/rule_engine.py, plugins/hookify/core/config_loader.py)

### Summary
The `hookify` plugin lets users (and anyone who can add a file to a shared repo's `.claude/` directory) define custom `PreToolUse`/`PostToolUse`/`Stop` guard rules in `.claude/hookify.*.local.md` files, whose frontmatter `action` field is supposed to control whether a match `block`s the operation or merely `warn`s. Neither the rule loader (`config_loader.py`) nor the rule engine (`rule_engine.py`) validates that `action` is one of the two accepted literal values. Any value other than the exact lower-case string `"block"` (typos, different casing, synonyms like `"deny"`/`"prevent"`) is silently treated as `"warn"`, so the intended hard block on a dangerous operation (e.g. `rm -rf`, writing to `.env`, `sudo`) never fires — the tool call proceeds and only a cosmetic message is shown. This mirrors the reported bug class of unvalidated inputs to security-relevant fields causing a control to silently become inert (e.g. the `Governance.setVotingPeriod`/`ServiceTypeManager.updateServiceType` zero-value cases), except here the "control" is a Claude Code `PreToolUse` block used to enforce local safety policy.

### Finding Description
`Rule.from_dict` reads the `action` field with no validation: [1](#0-0) 

`RuleEngine.evaluate_rules` then partitions matched rules purely by an exact string comparison against the literal `'block'`; anything else falls into the non-blocking `warning_rules` bucket: [2](#0-1) 

There is no schema check anywhere in the loader (`load_rule_file`, `load_rules`) that rejects or normalizes an `action` value outside `{"warn", "block"}`; malformed values are accepted silently and only I/O or parsing exceptions are logged: [3](#0-2) 

The `pretooluse.py` hook entry point compounds this: any exception anywhere in this pipeline (import failure, JSON parse error, or any other runtime error) results in the operation being allowed (`sys.exit(0)` with an empty/soft JSON), so a malformed rule file never even surfaces as a hard failure — it just quietly stops protecting: [4](#0-3) 

The documentation itself only tells authors to write `action: block`/`action: warn` as free text with no indication that any deviation is silently accepted as `warn`: [5](#0-4) 

### Impact Explanation
A locally-authored (or repo-committed, if `.local.md` files are not actually gitignored/reviewed) hookify rule intended to hard-block a dangerous action — e.g. blocking `rm -rf`, blocking edits to `.env`/credentials, or blocking `git push` to a protected branch — will pass validation and load successfully even if its `action` value is misspelled or cased differently, and Claude Code will treat it as a mere warning. The user or team believes a `PreToolUse` block/hook-based safety net is enforced, but the dangerous Bash command or file write is auto-approved anyway. This is a "false sense of security" degradation of a local guardrail/hook-authorization mechanism — the same root cause (accepting any value for a field that gates a critical behavior, instead of validating against an enum) as the reported Solidity bugs where unchecked inputs silently broke governance/version-check logic.

### Likelihood Explanation
Likelihood is high for accidental occurrence: `action` is free-form YAML text typed by hand in a markdown frontmatter block with no tooling feedback, and common natural variations (`Block`, `BLOCK`, `deny`, `prevent`) are all plausible author mistakes given the plugin's natural-language-first design (rules are even auto-generated from natural language via the `/hookify` command). There is no lint/validate step enforced before the rule takes effect — it is picked up on the very next tool call.

### Recommendation
- In `Rule.from_dict` (`plugins/hookify/core/config_loader.py`), validate `action` against the allowed enum `{"warn", "block"}` (case-insensitively normalize, e.g. `.strip().lower()`), and reject/raise a loud warning for any other value instead of silently defaulting to `"warn"`.
- Similarly validate `event` against its allowed enum and `operator` against the supported operator list at load time, surfacing a clear, non-swallowed error (e.g. via `systemMessage`) so users learn immediately that a rule failed to parse as intended, rather than fail open silently.
- Consider making `load_rule_file` treat an invalid `action`/`event`/`operator` as a hard error that is reported to the user (not just `print(..., file=sys.stderr)`, which is easy to miss), since these hooks are frequently run non-interactively.

### Proof of Concept
1. Create `.claude/hookify.block-rm.local.md`:
```markdown
---
name: block-dangerous-rm
enabled: true
event: bash
pattern: rm\s+-rf
action: Block
---

This should have blocked the command but did not.
```
2. Ask Claude Code to run `rm -rf /tmp/testdir`.
3. Because `action` is `"Block"` (capital B) rather than the exact literal `"block"`, `Rule.from_dict` stores it verbatim, and `evaluate_rules`'s `rule.action == 'block'` check evaluates to `False`, routing the match into `warning_rules` instead of `blocking_rules`. The command executes normally; only a non-blocking `systemMessage` is shown, defeating the intended safety guard.

### Citations

**File:** plugins/hookify/core/config_loader.py (L75-84)
```python
        return cls(
            name=frontmatter.get('name', 'unnamed'),
            enabled=frontmatter.get('enabled', True),
            event=frontmatter.get('event', 'all'),
            pattern=simple_pattern,
            conditions=conditions,
            action=frontmatter.get('action', 'warn'),
            tool_matcher=frontmatter.get('tool_matcher'),
            message=message.strip()
        )
```

**File:** plugins/hookify/core/config_loader.py (L198-241)
```python
def load_rules(event: Optional[str] = None) -> List[Rule]:
    """Load all hookify rules from .claude directory.

    Args:
        event: Optional event filter ("bash", "file", "stop", etc.)

    Returns:
        List of enabled Rule objects matching the event.
    """
    rules = []

    # Find all hookify.*.local.md files
    pattern = os.path.join('.claude', 'hookify.*.local.md')
    files = glob.glob(pattern)

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

**File:** plugins/hookify/core/rule_engine.py (L53-94)
```python
        for rule in rules:
            if self._rule_matches(rule, input_data):
                if rule.action == 'block':
                    blocking_rules.append(rule)
                else:
                    warning_rules.append(rule)

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

        # If only warnings, show them but allow operation
        if warning_rules:
            messages = [f"**[{r.name}]**\n{r.message}" for r in warning_rules]
            return {
                "systemMessage": "\n\n".join(messages)
            }

        # No matches - allow operation
        return {}
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

**File:** plugins/hookify/README.md (L93-95)
```markdown
**Action field:**
- `warn`: Shows warning but allows operation (default)
- `block`: Prevents operation from executing (PreToolUse) or stops session (Stop events)
```
