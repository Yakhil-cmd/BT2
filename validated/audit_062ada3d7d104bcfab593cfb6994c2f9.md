Found a strong analog. The `hookify` rule engine's `MultiEdit` field extraction concatenates all edits' `new_string` values before pattern matching, but the aggregate/whole-batch text is checked against a single regex rather than validating each edit unit individually against the boundary the rule intends to enforce — mirroring the Boost bug's core defect: a check computed over an aggregate (total boostAmount vs total usdAmount) rather than at the level of the actual atomic unit that crosses the invariant boundary.

### Title
Hookify's MultiEdit content-matching aggregates all edits into one string before pattern evaluation, letting a single edit's dangerous content evade detection that would trigger on it individually - (File: plugins/hookify/core/rule_engine.py)

### Summary
The Sherlock finding is that `SolidlyV2AMO`'s peg-protection check validates only the **aggregate** relationship between the total `boostAmount` sold and the total `usdAmount` received, rather than validating the price at each incremental unit of the swap. Because AMM price moves continuously as the swap executes, the aggregate check can pass (total revenue ≥ total nominal value) even though later portions of the same swap were executed below peg — the boundary check is evaluated at the wrong granularity (whole-batch) instead of the granularity where the invariant actually needs to hold (marginal/per-unit).

`plugins/hookify/core/rule_engine.py`'s `_extract_field` has the analogous structural flaw for `MultiEdit` operations: when a Hookify rule's `pattern`/`conditions` target `new_text`/`content`, the engine does not evaluate the regex against each edit in the `edits` array individually. Instead it joins every edit's `new_string` into one aggregate string with `' '.join(...)` and evaluates the rule once against that combined blob [1](#0-0) .

### Finding Description
Hookify rules are the project's user-configurable `PreToolUse`/`PostToolUse` guard mechanism for blocking or warning on dangerous file edits, e.g. secret exposure, debug code, or sensitive-file writes [2](#0-1) . Documentation explicitly recommends targeting `new_text` conditions to catch things like credentials or sensitive markers being written into a file [3](#0-2) .

For `MultiEdit` tool calls, a single tool invocation can contain many discrete edits, each with its own `old_string`/`new_string`. The engine's field extractor for `MultiEdit` concatenates every edit's `new_string` with a space before the regex/condition check runs:
```python
elif tool_name == 'MultiEdit':
    if field == 'file_path':
        return tool_input.get('file_path', '')
    elif field in ['new_text', 'content']:
        # Concatenate all edits
        edits = tool_input.get('edits', [])
        return ' '.join(e.get('new_string', '') for e in edits)
``` [1](#0-0) 

This is structurally the same defect as the Boost peg check: the boundary condition (`pattern` must not appear / a specific dangerous edit must be caught) is meant to be enforced per-unit (per individual edit), but the enforcement point evaluates an aggregate quantity (the whole-batch concatenated string) instead. A regex written to be strict/anchored against a single edit's content — e.g. `^KEY=` or a pattern relying on a fixed offset/context from a single edit's boundaries — can be satisfied at the aggregate level (i.e. the concatenation as a whole doesn't match, because whitespace-joining or the surrounding edits' content changes what's adjacent) even though one individual edit within the batch is exactly the dangerous content the rule intends to catch. Conversely, content that spans an edit boundary (e.g., part of a secret in one edit, part in the next) can spuriously match a pattern that no single edit satisfies, but the practically important direction (evasion) is the aggregate joining diluting/altering context so that individually-triggering content is missed within a `MultiEdit` batch — mirroring how the AMM's aggregate check silently allows an individually-below-peg sub-trade to pass.

### Impact Explanation
An unprivileged Claude session (or a user relying on Hookify's advertised `block` action to prevent, e.g., committing hardcoded secrets or dangerous debug markers to a file — see the sensitive-files and debug-code examples in the plugin's own docs [4](#0-3) ) can have a rule silently fail to trigger on part of a `MultiEdit` batch, because the check runs against the concatenated aggregate rather than each edit. This directly undermines the approval-bypass/hook-bypass trust boundary Hookify exists to enforce: a rule configured with `action: block` to stop a specific dangerous write is bypassable purely by splitting the dangerous content across multiple `edits` entries within one `MultiEdit` call, or simply by relying on the aggregation to alter word-boundary matching. This is the direct analog of the audited financial loss: the intended per-unit invariant ("boost never sold below peg" / "this specific dangerous edit is always blocked") is checked at the wrong granularity and can be defeated without an attacker needing any privileged access — only the ability to shape the edits presented to the tool (including via prompt injection instructing Claude to split an edit into several sub-edits).

### Likelihood Explanation
This is reachable any time a Hookify `file`-event rule with a `new_text`/`content` condition or pattern is configured and the operation performed is `MultiEdit` (a routine, frequently-used tool for multi-location file edits). No privilege escalation or unusual configuration is required — only that a rule targets `new_text`/`content` and a `MultiEdit` call contains multiple edits. Given Hookify's stated purpose (block dangerous content) and the explicit worked examples in its own docs targeting file content for security purposes, the likelihood of a security-relevant rule relying on this exact code path is high.

### Recommendation
Evaluate `new_text`/`content` conditions (and any pattern/condition-based checks) against **each edit's `new_string` individually** for `MultiEdit`, not against a single concatenated aggregate string, and trigger the rule if any individual edit matches. If aggregate/whole-file context is also desired, that should be an explicit, separately-documented mode — not the only evaluation path — so that a rule author's intent to catch a specific per-edit pattern isn't silently weakened by concatenation.

### Proof of Concept
1. Configure a Hookify rule: `event: file`, `pattern: (?m)^KEY=[A-Za-z0-9]{20,}$`, `action: block` (anchored per-line pattern intended to catch a hardcoded key assignment written on its own line).
2. Have Claude perform a `MultiEdit` on a file with two edits: edit 1's `new_string` is `foo` (no trailing content ensuring line-anchoring context is broken), edit 2's `new_string` is `KEY=abcdefghijklmnopqrstuvwxyz`.
3. `rule_engine.py`'s `_extract_field` concatenates them as `"foo KEY=abcdefghijklmnopqrstuvwxyz"` (single space, single line) before the regex is applied [5](#0-4) .
4. Because the regex is anchored to line-start (`^`) and the join collapses both `new_string`s onto one line without a preceding newline, the pattern that would have matched edit 2 alone no longer matches the concatenated aggregate — the rule fails to fire and the dangerous edit is written through, despite the rule's explicit intent to block exactly this content.

### Citations

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

**File:** plugins/hookify/README.md (L93-185)
```markdown
**Action field:**
- `warn`: Shows warning but allows operation (default)
- `block`: Prevents operation from executing (PreToolUse) or stops session (Stop events)

### Advanced Rule (Multiple Conditions)

`.claude/hookify.sensitive-files.local.md`:
```markdown
---
name: warn-sensitive-files
enabled: true
event: file
action: warn
conditions:
  - field: file_path
    operator: regex_match
    pattern: \.env$|credentials|secrets
  - field: new_text
    operator: contains
    pattern: KEY
---

🔐 **Sensitive file edit detected!**

Ensure credentials are not hardcoded and file is in .gitignore.
```

**All conditions must match** for the rule to trigger.

## Event Types

- **`bash`**: Triggers on Bash tool commands
- **`file`**: Triggers on Edit, Write, MultiEdit tools
- **`stop`**: Triggers when Claude wants to stop (for completion checks)
- **`prompt`**: Triggers on user prompt submission
- **`all`**: Triggers on all events

## Pattern Syntax

Use Python regex syntax:

| Pattern | Matches | Example |
|---------|---------|---------|
| `rm\s+-rf` | rm -rf | rm -rf /tmp |
| `console\.log\(` | console.log( | console.log("test") |
| `(eval\|exec)\(` | eval( or exec( | eval("code") |
| `\.env$` | files ending in .env | .env, .env.local |
| `chmod\s+777` | chmod 777 | chmod 777 file.txt |

**Tips:**
- Use `\s` for whitespace
- Escape special chars: `\.` for literal dot
- Use `|` for OR: `(foo|bar)`
- Use `.*` to match anything
- Set `action: block` for dangerous operations
- Set `action: warn` (or omit) for informational warnings

## Examples

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

### Example 2: Warn About Debug Code

```markdown
---
name: warn-debug-code
enabled: true
event: file
pattern: console\.log\(|debugger;|print\(
action: warn
---

🐛 **Debug code detected**

Remember to remove debugging statements before committing.
```
```
