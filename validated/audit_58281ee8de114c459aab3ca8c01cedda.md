### Title
Non-Functional `block` Action on `PostToolUse` Gives False Sense of Security in Hookify Rule Engine - (File: `plugins/hookify/core/rule_engine.py`)

### Summary
The reported MultiRewardStaking bug is a "check applied to the wrong actor/wrong point in time" bug: a protective action (`_accrueRewards`) is expected to gate a state-changing operation for the party it's supposed to protect (`owner`), but the code applies it too late/to the wrong party, so the intended protection silently never takes effect and value is lost. The `hookify` plugin in this repository has a structurally identical flaw: its rule engine treats a `block` rule identically for both `PreToolUse` and `PostToolUse` events, emitting a `permissionDecision: "deny"` for both — even though by the time `PostToolUse` fires, the tool has already executed. The "block" therefore never actually prevents the dangerous action for `PostToolUse`-triggered rules; it just displays a message after the damage is already done, silently giving the user/operator false confidence that their configured protection is enforced.

### Finding Description
`hookify` is a marketplace plugin that lets a user author lightweight markdown rule files (`.claude/hookify.*.local.md`) with an `action: block` field that is documented as meaning "Prevents operation from executing" [1](#0-0) .

The plugin wires the *same* rule set into both the `PreToolUse` and `PostToolUse` hook events via `hooks.json` [2](#0-1) , and both `pretooluse.py` and `posttooluse.py` independently load rules for the same `event` category (`bash`/`file`) and feed them into the identical `RuleEngine.evaluate_rules` [3](#0-2) [4](#0-3) .

The core defect is in `RuleEngine.evaluate_rules`: for blocking rules, it branches only on `hook_event in ['PreToolUse', 'PostToolUse']` and returns the exact same `hookSpecificOutput.permissionDecision: "deny"` payload for both, with no differentiation of the fact that `PostToolUse` runs after the tool has already been executed: [5](#0-4) 

The plugin's own documentation confirms this asymmetry exists by design/oversight: it states the `block` action "Prevents operation from executing (PreToolUse) or stops session (Stop events)" [1](#0-0)  — `PostToolUse` is conspicuously absent from that list, and the hook-development skill docs describe `PostToolUse` purely as a mechanism to "react to results, provide feedback, or log," never to block [6](#0-5) . Despite this, the code path never distinguishes the two events — a rule authored for `event: bash`/`event: file` with `action: block` (e.g., the README's own example `pattern: rm\s+-rf|dd\s+if=|mkfs|format`, `action: block` [7](#0-6) ) is evaluated identically on `PostToolUse`, where returning `permissionDecision: "deny"` is a no-op because the destructive `Bash`/`Write`/`Edit` operation has already completed.

This is analogous to the MultiRewardStaking root cause: a protective check (`_accrueRewards`/`block`) that must be applied to the correct target/timing (`owner`/before-execution) is instead silently misapplied (`caller`/after-execution), so the user relying on the protection loses the expected safety guarantee without any error or warning that the protection failed.

### Impact Explanation
A user who authors a `hookify` "block dangerous commands" rule (as directly suggested by the plugin's own README quick-start and examples, e.g. blocking `rm -rf`, `dd if=`, `mkfs`, `format`, or writes to `.env`/credential files) reasonably believes that action is prevented. If Claude Code (or any component) ever routes such a check through the `PostToolUse` hook path — which `hookify` explicitly wires up alongside `PreToolUse` for the exact same rule set and event types — the destructive command executes in full before the "denied" message is shown. This can result in real data loss, secret exposure, or unauthorized file/command execution on the local workspace despite the user having configured an explicit blocking safeguard, undermining the command-approval/hook trust boundary this plugin exists to enforce.

### Likelihood Explanation
The bug is deterministic and code-guaranteed to trigger any time a `hookify` blocking rule's underlying pattern happens to be detected via the `PostToolUse` invocation path rather than (or in addition to) `PreToolUse` — for example, if `PreToolUse` fails to match (timeout, exception swallowed and fails open per `hookify/hooks/pretooluse.py:61-70`) but `PostToolUse` still evaluates the same rule set. Since both hooks are always registered together and both load identical rule sets and identical `RuleEngine` logic, any user-authored `block` rule is exposed to this false-protection condition without any additional attacker action required — the flaw is triggered purely by the plugin's own default wiring.

### Recommendation
1. In `RuleEngine.evaluate_rules`, remove `PostToolUse` from the blocking branch that returns `permissionDecision: "deny"`. `PostToolUse` cannot prevent an already-executed tool call; treat matched blocking rules on `PostToolUse` as, at most, a `warn`/`systemMessage` alert (or use the documented `exit 2` / structured-block mechanism only where it is actually honored by the host for post-execution remediation), and never advertise it as `block`.
2. Update `plugins/hookify/README.md` and `posttooluse.py` to make explicit that `action: block` has no preventive effect at `PostToolUse` time, or refuse to register `block`-action rules for `PostToolUse` matching entirely so misconfiguration is impossible.
3. Add a regression test asserting that a `block` rule evaluated with `hook_event_name: "PostToolUse"` never returns a payload implying the underlying command was prevented, and that users are warned (not falsely reassured) when relying on `PostToolUse` for enforcement.

### Proof of Concept
1. Create `.claude/hookify.block-rm.local.md`:
```
---
name: block-dangerous-rm
enabled: true
event: bash
pattern: rm\s+-rf
action: block
---
Dangerous command blocked.
```
2. Simulate a `PostToolUse` invocation of `posttooluse.py` with stdin:
```json
{"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/important"}}
```
3. Observe that `RuleEngine.evaluate_rules` (`plugins/hookify/core/rule_engine.py:60-84`) returns `{"hookSpecificOutput": {"hookEventName": "PostToolUse", "permissionDecision": "deny"}, "systemMessage": "..."}` — but because `PostToolUse` fires only after `Bash` has already run `rm -rf /tmp/important`, the destructive command has already executed; the "deny" decision is emitted for an operation that already completed, exactly mirroring how `MultiRewardStaking._withdraw` calls `_accrueRewards(caller, receiver)` after the withdrawal has already debited `owner`'s shares, permanently losing the protection that was supposed to apply to `owner`.

### Citations

**File:** plugins/hookify/README.md (L93-96)
```markdown
**Action field:**
- `warn`: Shows warning but allows operation (default)
- `block`: Prevents operation from executing (PreToolUse) or stops session (Stop events)

```

**File:** plugins/hookify/README.md (L152-169)
```markdown
### Example 1: Block Dangerous Commands

```markdown
---
name: block-destructive-ops
enabled: true
event: bash
pattern: rm\s+-rf|dd\s+if=|mkfs|format
action: block
---

🛑 **Destructive operation detected!**

This command can cause data loss. Operation blocked for safety.
Please verify the exact path and use a safer approach.
```

**This rule blocks the operation** - Claude will not be allowed to execute these commands.
```

**File:** plugins/hookify/hooks/hooks.json (L1-25)
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
    "PostToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 ${CLAUDE_PLUGIN_ROOT}/hooks/posttooluse.py",
            "timeout": 10
          }
        ]
      }
    ],
```

**File:** plugins/hookify/hooks/posttooluse.py (L30-52)
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
```

**File:** plugins/hookify/hooks/pretooluse.py (L35-59)
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

**File:** plugins/plugin-dev/skills/hook-development/SKILL.md (L155-157)
```markdown
### PostToolUse

Execute after tool completes. Use to react to results, provide feedback, or log.
```
