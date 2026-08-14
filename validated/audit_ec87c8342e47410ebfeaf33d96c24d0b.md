### Title
Silent truncation of comma-containing rule fields (`pattern`) in hookify inline-dict frontmatter parser causes security `block` rules to fail open - (File: plugins/hookify/core/config_loader.py)

### Summary
### Finding Description
The audited bug class is "incorrectly reading a fixed offset/field boundary from encoded data, depending on which structural variant was used to pack it, causing the wrong value to be extracted." The `hookify` plugin's `extract_frontmatter()` function has a directly analogous flaw: it uses a *positional/delimiter-based* mini-YAML parser that assumes a rigid structure for inline list-dict items (`- field: X, operator: Y, pattern: Z`), and naively splits on `,` to separate the sub-fields: [1](#0-0) 

```
if ':' in item_text and ',' in item_text:
    # Inline comma-separated dict: "- field: command, operator: regex_match"
    item_dict = {}
    for part in item_text.split(','):
        if ':' in part:
            k, v = part.split(':', 1)
            item_dict[k.strip()] = v.strip().strip('"').strip("'")
    current_list.append(item_dict)
    in_dict_item = False
```

Exactly as with the Solidity report — where the offset used to read `depositNonce` was correct for some `flag`s but wrong for others because the packing layout differed — this parser's comma-splitting assumption is correct only when none of the sub-field values (`field`, `operator`, `pattern`) themselves contain a comma. If a rule author writes a `pattern` value containing a comma (a very common case for regex patterns combining multiple destructive command alternatives, e.g. `rm -rf /, dd if=, mkfs`), the split produces extra chunks that don't contain `:`; those chunks are silently dropped by the `if ':' in part` guard, and the resulting `pattern` field is silently truncated to only the portion before the first comma.

This directly parallels the report's core problem: the code reads a "field" at what it assumes is the correct boundary for all cases, but the boundary actually depends on the content of the data itself, and no validation step catches or reports the misalignment — the corrupted value is used unmodified downstream (`Condition.from_dict()` → `Rule.from_dict()` → `RuleEngine._check_condition()`), just like the corrupted `_depositNonce` was used unmodified in `_clearDeposit()`.

### Impact Explanation
`hookify` is explicitly documented as a security/guardrail mechanism: it powers unprivileged, per-project custom `block` hooks intended to prevent Claude from executing destructive shell operations (`rm -rf`, `dd`, `mkfs`, etc.) or leaking secrets, as shown in the plugin's own README examples of `action: block` rules and multi-condition secret/credential detection. [2](#0-1) [3](#0-2) 

When a user (or Claude itself, generating a rule via `/hookify`) writes an inline-dict condition whose `pattern` contains a comma, the truncation silently narrows the enforcement regex. The `regex_match`/`contains` operator then only checks the truncated prefix, so commands that should have been blocked (matching the portion of the pattern lost after the comma) are **not blocked**, and the operation is silently allowed (`RuleEngine.evaluate_rules` returns `{}`/no `deny`) — a hook bypass with no error surfaced to the user, matching the "hook bypass" trust-boundary category. This is a genuine unprivileged-user-facing weakening of a locally-configured safety control, reachable purely through normal rule authoring (no malicious external actor required), analogous in root cause and effect to the audited contract bug (wrong data silently used because of an incorrect encoded-field boundary assumption).

### Likelihood Explanation
Moderate-to-high: `pattern` fields combining multiple alternatives are a natural authoring pattern (the README's own `pattern: rm\s+-rf|dd\s+if=|mkfs|format` example uses `|` rather than `,`, avoiding the bug in the shipped examples — but nothing in the `SKILL.md`/`README.md` documents this restriction, and the multi-line dict-item format is used elsewhere with `,`-bearing values as normal English text). Any user or Claude-generated rule that uses the inline `- field: X, operator: Y, pattern: A, B, C` shorthand with a comma inside the regex pattern (e.g., combining sub-patterns, listing multiple sensitive file extensions, or an English message with a comma) will trigger silent truncation with no error/warning emitted — `load_rule_file` and `extract_frontmatter` never validate the parsed field count against expectations.

### Recommendation
- In `extract_frontmatter()` (`plugins/hookify/core/config_loader.py`), replace the naive `split(',')` inline-dict heuristic with a proper key-aware split (e.g., regex that splits only on `, <key>:` boundaries, or require multi-line dict-item syntax for any condition list), so pattern values containing commas are preserved intact.
- Alternatively, deprecate the inline comma-separated shorthand entirely in favor of the multi-line `- field: ...\n  operator: ...\n  pattern: ...` format, which does not have this ambiguity.
- Add a validation step in `Rule.from_dict`/`load_rule_file` that warns (non-silently) when a `conditions` entry appears to have fewer than the expected `field`/`operator`/`pattern` keys, so authors are alerted when their rule was parsed incorrectly instead of having it fail open silently.

### Proof of Concept
1. Create `.claude/hookify.block-destructive.local.md`:
```markdown
---
name: block-destructive
enabled: true
event: bash
action: block
conditions:
  - field: command, operator: regex_match, pattern: rm -rf /, dd if=, mkfs
---

Blocked destructive command.
```
2. Load it via `load_rule_file()` (`plugins/hookify/core/config_loader.py`, `extract_frontmatter` lines 163-172). The inline-dict comma split yields:
   - `field: command` → `"command"`
   - ` operator: regex_match` → `"regex_match"`
   - ` pattern: rm -rf /` → `"rm -rf /"`
   - ` dd if=` and ` mkfs` → dropped (no `:`), silently lost.
3. Resulting `Condition.pattern` is only `"rm -rf /"` instead of the intended combined pattern.
4. Run `Bash` tool with `dd if=/dev/zero of=/dev/sda` — `RuleEngine._check_condition` (`plugins/hookify/core/rule_engine.py` lines 166-167) evaluates `regex_match("rm -rf /", "dd if=/dev/zero of=/dev/sda")` → `False`, so the intended `block` rule never fires and the destructive command is executed without any warning that the rule was malformed.

### Citations

**File:** plugins/hookify/core/config_loader.py (L163-172)
```python
            # Check if this is an inline dict (key: value on same line)
            if ':' in item_text and ',' in item_text:
                # Inline comma-separated dict: "- field: command, operator: regex_match"
                item_dict = {}
                for part in item_text.split(','):
                    if ':' in part:
                        k, v = part.split(':', 1)
                        item_dict[k.strip()] = v.strip().strip('"').strip("'")
                current_list.append(item_dict)
                in_dict_item = False
```

**File:** plugins/hookify/README.md (L97-120)
```markdown
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
