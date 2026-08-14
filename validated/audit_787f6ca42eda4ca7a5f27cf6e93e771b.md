### Title
Hookify frontmatter parser silently downgrades `block` rules to `warn` when a pattern field contains a literal `---` sequence - (File: `plugins/hookify/core/config_loader.py`)

### Summary
`extract_frontmatter` splits rule file content on the literal substring `---` with `content.split('---', 2)`, without any YAML-aware quoting/escaping awareness. If an attacker-influenced `pattern` (or `message`) value embedded in a `.claude/hookify.*.local.md` rule contains the three-character sequence `---`, the split prematurely terminates the "frontmatter" region before the real closing delimiter, pushing subsequent frontmatter lines (including `action: block`) into the parsed "message" body instead of the frontmatter dict. `Rule.from_dict` then falls back to the default `action = 'warn'` [1](#0-0) , even though the raw file visibly contains `action: block`, silently downgrading enforcement in `RuleEngine.evaluate_rules` from "deny"/"block" to a mere warning that still allows the dangerous tool call [2](#0-1) .

### Finding Description
`extract_frontmatter` locates the frontmatter block purely via `content.split('---', 2)`: [3](#0-2) 

This is not a real YAML parser — it has no concept of quoted strings, so any `---` occurring *inside* a quoted or unquoted value (e.g., a `pattern` regex matching a URL, git diff marker, or command containing `---`) is indistinguishable from the actual closing `---` delimiter. Because `split(..., 2)` stops after the second occurrence of `---` anywhere in the file, a value containing `---` before the "real" closing delimiter causes everything after that embedded `---` (including the true `action: block` line and the true closing `---`) to be absorbed into `message` rather than `frontmatter_text`.

Example: a rule file that visually reads as a valid block rule:
```
---
name: block-exfil
enabled: true
event: bash
pattern: curl .*---payload
action: block
---
Blocked dangerous exfiltration command.
```
`content.split('---', 2)` treats the `---` inside the `pattern` value as the second delimiter. `frontmatter_text` ends at `pattern: curl .*`, and `action: block` plus the "real" trailing `---` and message text all end up appended into `message`. `Rule.from_dict` then receives a frontmatter dict lacking `action`, so `action=frontmatter.get('action', 'warn')` [4](#0-3)  defaults to `'warn'`.

In `RuleEngine.evaluate_rules`, a rule with `action != 'block'` is placed in `warning_rules` rather than `blocking_rules`; blocking rules are the only path that produces `"permissionDecision": "deny"` for `PreToolUse`/`PostToolUse` or `"decision": "block"` for `Stop` [5](#0-4) . A downgraded rule therefore only emits a `systemMessage` while the underlying dangerous `Bash`/`Edit`/`Stop` action is still permitted by `pretooluse.py`/`posttooluse.py`, which always exit 0 and only pass along whatever JSON `RuleEngine` produces [6](#0-5) .

**Attacker reachability via `/hookify`:** The `/hookify` command generates these rule files based on conversation content and user-selected `pattern` values [7](#0-6) ; the `conversation-analyzer` agent extracts "actual command that was problematic" directly from conversation/tool-output text to populate the `pattern` field [8](#0-7) . Because patterns are derived verbatim from observed commands/text (which can originate from untrusted repository content, file contents, or tool output the user pastes/discusses), an attacker who can influence the text that ends up copied into a `pattern` field (e.g., a malicious command string containing `---`, such as `curl http://evil.com/---x`) can cause a "block" rule the user believes they created to be silently stored/interpreted as `warn`. There is no validation step that cross-checks the parsed `Rule.action` against what the user selected in "Question 2: … Block operation" of the `/hookify` flow [9](#0-8) .

Existing checks do not catch this: `load_rule_file` only rejects rules with `frontmatter == {}` entirely [10](#0-9) ; a partially-parsed frontmatter (missing `action`) is accepted as valid with silently defaulted fields, and there is no schema/round-trip validation confirming the parsed `Rule` matches the literal file content.

### Impact Explanation
This breaks the invariant that rule semantics (block vs. warn) must be determined unambiguously by the visible rule file content. A rule intended by the user/operator to **block** a dangerous `Bash`, `Edit`/`Write`/`MultiEdit`, or `Stop` action can be silently coerced into **warn-only** enforcement due to a formatting collision in the `pattern`/`message` text, allowing the dangerous tool invocation (e.g., destructive `rm -rf`, credential exfiltration via `curl`, or a `Stop`-blocking completion-check) to execute despite the operator's explicit intent to hard-block it. This is a local approval/deny-control bypass: it does not require the attacker to have direct code execution — only the ability to influence text that later gets embedded as a `pattern` (or message) value in a generated hookify rule.

### Likelihood Explanation
- No maintainer/admin privilege or leaked credentials required — only the ability to get a `---`-containing string into a `pattern`/message field, which is plausible whenever `/hookify` (or the `conversation-analyzer` agent) generates rules from real command examples pulled from conversation/tool output.
- The parser bug is deterministic and 100% reproducible for any frontmatter value containing a literal `---`.
- Reduced further by the fact `/hookify`'s command doc explicitly instructs embedding "Actual command that was problematic" verbatim into `pattern` [11](#0-10) , so any dangerous command containing `--` sequences (e.g., long-form flags like `git push --force`, `--no-verify`, URLs with `---`) is a realistic trigger, not a contrived edge case.

### Recommendation
Replace the naive `content.split('---', 2)` with a delimiter search that only recognizes `---` when it appears alone on its own line (i.e., matches `^---\s*$` via regex/line-based scanning), consistent with standard YAML frontmatter semantics, so that `---` embedded inside a quoted or unquoted scalar value is never mistaken for a delimiter. Additionally, use a real YAML parser (e.g., `yaml.safe_load`) instead of the hand-rolled line parser to eliminate this and related class of ambiguities, and add a post-parse validation that logs/rejects rule files where expected keys (`action`, `pattern`/`conditions`) are missing when they appear to be present in the raw text, or add a round-trip check between the raw file's declared `action:` value and the parsed `Rule.action`.

### Proof of Concept
Unit test to add to `plugins/hookify/core/config_loader.py`'s test suite (or a new `test_config_loader.py`):

```python
from hookify.core.config_loader import extract_frontmatter, Rule

def test_embedded_delimiter_downgrades_block_to_warn():
    content = """---
name: block-exfil
enabled: true
event: bash
pattern: curl .*---payload
action: block
---
Blocked dangerous exfiltration command.
"""
    frontmatter, message = extract_frontmatter(content)
    rule = Rule.from_dict(frontmatter, message)

    # Expected (correct) behavior: rule should block
    assert rule.action == 'block', (
        f"Rule action was silently downgraded to '{rule.action}' "
        "due to embedded '---' in pattern field, even though the raw "
        "file explicitly declares action: block"
    )
```

Running this against the current implementation demonstrates `rule.action == 'warn'` (the default), proving the parsed `Rule` object diverges from the visible file content and that `RuleEngine.evaluate_rules` would treat a matching dangerous command as a warning instead of a deny/block, as required by the "fast validation" criteria in this question.

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

**File:** plugins/hookify/core/config_loader.py (L94-103)
```python
    if not content.startswith('---'):
        return {}, content

    # Split on --- markers
    parts = content.split('---', 2)
    if len(parts) < 3:
        return {}, content

    frontmatter_text = parts[1]
    message = parts[2].strip()
```

**File:** plugins/hookify/core/config_loader.py (L256-258)
```python
        if not frontmatter:
            print(f"Warning: {file_path} missing YAML frontmatter (must start with ---)", file=sys.stderr)
            return None
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

**File:** plugins/hookify/hooks/pretooluse.py (L54-70)
```python
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

**File:** plugins/hookify/commands/hookify.md (L70-76)
```markdown

**Question 2: For each selected behavior, ask about action:**
- "Should this block the operation or just warn?"
- Options:
  - "Just warn" (action: warn - shows message but allows)
  - "Block operation" (action: block - prevents execution)

```

**File:** plugins/hookify/commands/hookify.md (L82-102)
```markdown
### Step 3: Generate Rule Files

For each confirmed behavior, create a `.claude/hookify.{rule-name}.local.md` file:

**Rule naming convention:**
- Use kebab-case
- Be descriptive: `block-dangerous-rm`, `warn-console-log`, `require-tests-before-stop`
- Start with action verb: block, warn, prevent, require

**File format:**
```markdown
---
name: {rule-name}
enabled: true
event: {bash|file|stop|prompt|all}
pattern: {regex pattern}
action: {warn|block}
---

{Message to show Claude when rule triggers}
```
```

**File:** plugins/hookify/agents/conversation-analyzer.md (L55-66)
```markdown
**Extract concrete examples:**
- For Bash: Actual command that was problematic
- For Edit/Write: Code pattern that was added
- For Stop: What was missing before stopping

### 3. Create Regex Patterns

Convert behaviors into matchable patterns:

**Bash command patterns:**
- `rm\s+-rf` for dangerous deletes
- `sudo\s+` for privilege escalation
```
