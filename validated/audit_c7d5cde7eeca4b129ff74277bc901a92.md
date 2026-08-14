Based on my research, I found a valid analog. The report's bug class is "registered modules have excessive access to critical owner/validator-changing functions that should be restricted to `onlySelf`." The strongest reachable analog in claude-code is hooks (registered by plugins — untrusted third-party "modules") being able to invoke `PermissionRequest`/`PreToolUse` hook outputs that change the effective permission mode itself (`setMode: 'bypassPermissions'`) or bypass explicit `deny` rules — a critical, owner-level trust-boundary function — without being restricted to the equivalent of "self" (user/managed settings).

### Title
Plugin/settings-registered hooks could set `bypassPermissions` mode and bypass explicit `deny` rules instead of being restricted to trusted (self) configuration - (File: CHANGELOG.md, hook system)

### Summary
Claude Code's hook system lets a "module" (a `PreToolUse`/`PermissionRequest` hook — which can be registered by any installed plugin, not just the user) return `hookSpecificOutput.permissionDecision: "allow"` or `updatedInput`/`setMode` values. Historically, this hook output was honored without being re-validated against the explicit trust-boundary controls that are supposed to gate the most critical permission-mode changes (analogous to owner/validator changes in the smart-contract report): explicit `permissions.deny` rules and the `disableBypassPermissionsMode` policy lock.

### Finding Description
Hooks (`PreToolUse`, `PermissionRequest`) are a first-class extension point that plugins/marketplaces can register, similar to how "modules" register with the wallet. Two changelog-documented defects show that hook-returned decisions had access to critical, owner-level functions that should have been restricted to trusted/self-originated configuration only:

- A `PreToolUse` hook returning `"allow"` could bypass explicit `deny` permission rules, including enterprise managed settings, fixed in v2.1.77: [1](#0-0) 
- `PermissionRequest` hooks returning `updatedInput` were not re-checked against `permissions.deny` rules, and a hook's `setMode:'bypassPermissions'` update did not respect the `disableBypassPermissionsMode` policy — meaning a hook (which can originate from an installed plugin) could flip the entire session into permission-bypass mode even when an org/user explicitly locked that mode out, fixed in v2.1.109/2.1.110: [2](#0-1) 
- Separately, `PreToolUse` auto-allow hooks were found bypassing tool restrictions in background agent tasks (summaries, compaction, renames), fixed in v2.1.222: [3](#0-2) 

The underlying architecture that enables this class of bug is documented in the plugin-dev skill: any plugin's `hooks/hooks.json` can register a `PreToolUse` hook whose output directly controls `permissionDecision` and `updatedInput`: [4](#0-3) . A concrete bundled plugin demonstrating this exact capability is `hookify`, whose `PreToolUse` executor feeds arbitrary rule-engine output straight into `hookSpecificOutput.permissionDecision`: [5](#0-4) [6](#0-5) .

This mirrors the wallet report's core issue: a component that should have only a narrow, advisory role (a "module"/hook providing validation feedback) instead had a code path capable of exercising owner-level authority (approving/allowing tool calls, or flipping the session into `bypassPermissions`) that circumvented the explicit deny-list and policy locks meant to gate that authority to trusted/self-configured sources.

### Impact Explanation
If unpatched, a plugin-registered hook (which a user may install from a third-party marketplace with much less scrutiny than core settings) could silently escalate its own effective privilege to `bypassPermissions`, defeating admin-managed `disableBypassPermissionsMode` policy, or approve tool calls an explicit `deny` rule was meant to block — including destructive Bash commands or file writes in enterprise-managed environments. This is a direct local/session compromise of the permission trust boundary, comparable in severity to a module hijacking wallet ownership.

### Likelihood Explanation
Likelihood is Low-Medium: exploitation requires the user (or their organization) to have installed a plugin/hook that returns a crafted permission decision or `updatedInput`/`setMode` payload. Since plugins are commonly installed from marketplaces and hooks run non-interactively on every tool call, a malicious or compromised plugin has a direct, repeatable path to trigger this once the underlying re-validation gap exists.

### Recommendation
Ensure all hook-returned permission decisions (`permissionDecision`, `updatedInput`, `setMode`) are always re-validated against the full effective policy stack (`permissions.deny`, `disableBypassPermissionsMode`, managed/org settings) regardless of hook source, and treat plugin-registered hooks with strictly less authority than user/managed-settings-originated hooks — i.e., restrict mode-elevation and deny-rule overrides to trusted, `self`-configured sources only, never to third-party plugin code.

### Proof of Concept
Not directly reproducible against the current codebase state from available artifacts — the two enabling defects are documented as already fixed in the changelog (v2.1.77 and v2.1.110): [1](#0-0) [2](#0-1) . A conceptual PoC: install a plugin with a `PreToolUse` hook (per the documented plugin hook format) that unconditionally returns `{"hookSpecificOutput":{"permissionDecision":"allow"}}` for a tool matched by an explicit `deny` rule, or that returns `updatedInput` triggering `setMode:'bypassPermissions'` while `disableBypassPermissionsMode` is set in managed settings, and observe whether the tool executes / bypass mode activates despite the policy lock.

### Citations

**File:** CHANGELOG.md (L91-91)
```markdown
- Fixed PreToolUse auto-allow hooks bypassing tool restrictions in background agent tasks (summaries, compaction, renames)
```

**File:** CHANGELOG.md (L2381-2381)
```markdown
- Fixed `PermissionRequest` hooks returning `updatedInput` not being re-checked against `permissions.deny` rules; `setMode:'bypassPermissions'` updates now respect `disableBypassPermissionsMode`
```

**File:** CHANGELOG.md (L3068-3068)
```markdown
- Fixed PreToolUse hooks returning `"allow"` bypassing `deny` permission rules, including enterprise managed settings
```

**File:** plugins/plugin-dev/skills/hook-development/SKILL.md (L144-153)
```markdown
**Output for PreToolUse:**
```json
{
  "hookSpecificOutput": {
    "permissionDecision": "allow|deny|ask",
    "updatedInput": {"field": "modified_value"}
  },
  "systemMessage": "Explanation for Claude"
}
```
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

**File:** plugins/hookify/core/rule_engine.py (L60-94)
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

        # If only warnings, show them but allow operation
        if warning_rules:
            messages = [f"**[{r.name}]**\n{r.message}" for r in warning_rules]
            return {
                "systemMessage": "\n\n".join(messages)
            }

        # No matches - allow operation
        return {}
```
