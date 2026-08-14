### Title
Regex-based `hookify` PreToolUse guard evaluates only the static `command` string, so a permitted/simulated pattern is not what actually executes on-chain-equivalent shell run - ([File: plugins/hookify/core/rule_engine.py])

### Summary
`hookify` implements a user-defined PreToolUse "firewall": each rule is a regex/`contains`/`equals` check run once against the literal `tool_input.command` string, and the resulting `allow`/`deny` decision is trusted for the entire real `Bash` execution that follows. Because the check operates purely on the static string rather than on how the shell will actually interpret it, an attacker-influenced command can be crafted to look safe to the regex ("simulation") while still executing the dangerous behavior at run time ("on-chain" execution) — directly analogous to the Atlas report's core point that off-chain simulation success does not guarantee on-chain success.

### Finding Description
The rule engine's matching pipeline is:
- `_rule_matches` → `_check_condition` → `_regex_match`, all operating on `field_value = tool_input.get('command', '')`, i.e., the exact string Claude proposes to run [1](#0-0) .
- Blocking decisions are derived solely from whether this static string matches a regex/contains/equals pattern: `if operator == 'regex_match': return self._regex_match(pattern, field_value)` [2](#0-1) .
- If no blocking rule matches, the hook returns `{}` (empty dict = implicit allow), and the real `Bash` tool then executes the command exactly as-is [3](#0-2) .

This is the same trust-boundary problem as the Atlas bug: a party (the DApp/user analog = Claude's generated command, or an untrusted skill/plugin/CLAUDE.md instruction that shapes it) can present a string that "simulates clean" against the deterministic check, but the actual interpreter (bash) evaluates it differently, causing the executed action to diverge from what was approved. Regex-only inspection of shell text is a well-known weak point: command substitution (`$(...)`, backticks), variable expansion, quoting/escaping, `eval`, multi-statement chaining (`;`, `&&`, `||`, newlines), or encoding tricks can make a single static-pattern check pass while the shell still performs the blocked action. The engine has no shell-aware parsing/normalization step (no tokenizer, no `bashlex`/`shlex` walk of subshells) before applying the regex, and conditions are combined with simple `AND` semantics over raw substrings, not a semantic model of what will run [4](#0-3) .

Additionally, `_extract_field` only reads a small fixed set of literal keys (`command`, `content`, `new_string`, `file_path`, etc.) directly off `tool_input`, so any tool argument shape or nested/derived value not covered by these exact field names is invisible to the "simulation" step entirely, silently returning `None` and short-circuiting the condition to non-match [5](#0-4) . The changelog itself documents an entire historical class of these exact static-analysis-vs-actual-execution mismatches for the core Bash permission checker (compound commands, padded/invisible-Unicode text, zsh `[[ ]]` hidden execution, PowerShell quoting) being fixed one at a time [6](#0-5) [7](#0-6) [8](#0-7) , confirming this is a recurring, structurally unsolved bug class rather than a one-off — the `hookify` plugin's user-authored rule engine reintroduces the same weakness in a place with no such hardening.

### Impact Explanation
A rule author (or an org relying on `hookify` to block destructive/exfiltrating Bash commands as a compensating control) gets a false sense of safety: the PreToolUse hook returns "allow" (empty result) for a crafted command whose literal text does not match the configured regex, but which still performs the blocked action when bash actually executes it (e.g., via command substitution, string concatenation, alternate flag encoding, or multi-statement chaining that the AND-of-conditions logic doesn't correlate). This can let an untrusted instruction source (malicious skill/plugin/CLAUDE.md content, or model output influenced by adversarial content in the transcript) bypass a project's local security policy and reach unauthorized shell/file actions, directly reaching the "concrete approval bypass, unauthorized shell/file action" impact category.

### Likelihood Explanation
Medium. `hookify` is an optional plugin, not the built-in core permission system, so exposure depends on whether a project has adopted it as its guardrail. However, its documentation explicitly markets it for exactly this security purpose (blocking dangerous Bash/file operations), and the underlying weakness — regex/substring matching of a command string without shell-semantic understanding — is a generic, easily reachable bypass technique requiring no special access, only the ability to get an adversarial command string in front of the hook (e.g., via a malicious skill, MCP tool description, or prompt-injected instruction that shapes what Claude runs).

### Recommendation
- Do not rely on literal-string regex/contains/equals matching against `tool_input.command` as a security boundary; parse the command with a shell-aware tokenizer (e.g., walk `bashlex`/AST) to enumerate actual subcommands, substitutions, and redirections before applying rules, mirroring the mitigations already applied to the core Bash permission analyzer (compound-statement handling, redirect handling, Unicode/tab padding normalization).
- Default to fail-closed/`ask` for any command containing unrecognized constructs (`$(...)`, backticks, `eval`, uncommon redirects) rather than allowing when a field can't be confidently extracted (`_extract_field` returning `None` currently causes silent non-match/allow).
- Document clearly in `hookify`'s README/SKILL that it is a best-effort deterministic filter, not a sandbox, and recommend pairing it with `sandbox.filesystem`/network isolation for real containment, consistent with the Atlas report's conclusion that this class of bug is very difficult to fully mitigate and defense-in-depth (allowlisting, reduced trust in untrusted DApps/skills) is the practical mitigation.

### Proof of Concept
Given a project rule file `.claude/hookify.no-rm.local.md`:
```yaml
---
name: block-rm-rf
enabled: true
event: bash
pattern: "rm\\s+-rf"
action: block
---
Dangerous rm command blocked.
```
This compiles to a `Condition(field="command", operator="regex_match", pattern=r"rm\s+-rf")` [9](#0-8) , and is evaluated only against the literal `tool_input.command` string in `_regex_match` [1](#0-0) .

A command such as:
```
X=rf; rm -$X /tmp/target
```
or
```
sh -c "$(printf 'rm -rf /tmp/target')"
```
does not literally contain the substring matched by `rm\s+-rf` in the tool_input string as authored, so `_rule_matches` returns `False` and `evaluate_rules` returns `{}` (implicit allow) [3](#0-2) , yet bash still performs the destructive `rm -rf` at actual execution time — the "simulated" (regex-checked) safety verdict diverges from the real on-execution behavior.

*Note: I could not find the actual bash-tool execution path or core permission-analyzer source in this indexed repository (only CHANGELOG/plugin/doc content was available), so I cannot verify whether `hookify`'s output is layered on top of, or can fully substitute for, core Bash permission checks in a given deployment. If deeper verification of interaction with the core engine is needed, a Devin session with full repository access would be required.*

### Citations

**File:** plugins/hookify/core/rule_engine.py (L86-94)
```python
        # If only warnings, show them but allow operation
        if warning_rules:
            messages = [f"**[{r.name}]**\n{r.message}" for r in warning_rules]
            return {
                "systemMessage": "\n\n".join(messages)
            }

        # No matches - allow operation
        return {}
```

**File:** plugins/hookify/core/rule_engine.py (L96-125)
```python
    def _rule_matches(self, rule: Rule, input_data: Dict[str, Any]) -> bool:
        """Check if rule matches input data.

        Args:
            rule: Rule to evaluate
            input_data: Hook input data

        Returns:
            True if rule matches, False otherwise
        """
        # Extract tool information
        tool_name = input_data.get('tool_name', '')
        tool_input = input_data.get('tool_input', {})

        # Check tool matcher if specified
        if rule.tool_matcher:
            if not self._matches_tool(rule.tool_matcher, tool_name):
                return False

        # If no conditions, don't match
        # (Rules must have at least one condition to be valid)
        if not rule.conditions:
            return False

        # All conditions must match
        for condition in rule.conditions:
            if not self._check_condition(condition, tool_name, tool_input, input_data):
                return False

        return True
```

**File:** plugins/hookify/core/rule_engine.py (L162-180)
```python
        # Apply operator
        operator = condition.operator
        pattern = condition.pattern

        if operator == 'regex_match':
            return self._regex_match(pattern, field_value)
        elif operator == 'contains':
            return pattern in field_value
        elif operator == 'equals':
            return pattern == field_value
        elif operator == 'not_contains':
            return pattern not in field_value
        elif operator == 'starts_with':
            return field_value.startswith(pattern)
        elif operator == 'ends_with':
            return field_value.endswith(pattern)
        else:
            # Unknown operator
            return False
```

**File:** plugins/hookify/core/rule_engine.py (L182-254)
```python
    def _extract_field(self, field: str, tool_name: str,
                      tool_input: Dict[str, Any], input_data: Dict[str, Any] = None) -> Optional[str]:
        """Extract field value from tool input or hook input data.

        Args:
            field: Field name like "command", "new_text", "file_path", "reason", "transcript"
            tool_name: Tool being used (may be empty for Stop events)
            tool_input: Tool input dict
            input_data: Full hook input (for accessing transcript_path, reason, etc.)

        Returns:
            Field value as string, or None if not found
        """
        # Direct tool_input fields
        if field in tool_input:
            value = tool_input[field]
            if isinstance(value, str):
                return value
            return str(value)

        # For Stop events and other non-tool events, check input_data
        if input_data:
            # Stop event specific fields
            if field == 'reason':
                return input_data.get('reason', '')
            elif field == 'transcript':
                # Read transcript file if path provided
                transcript_path = input_data.get('transcript_path')
                if transcript_path:
                    try:
                        with open(transcript_path, 'r') as f:
                            return f.read()
                    except FileNotFoundError:
                        print(f"Warning: Transcript file not found: {transcript_path}", file=sys.stderr)
                        return ''
                    except PermissionError:
                        print(f"Warning: Permission denied reading transcript: {transcript_path}", file=sys.stderr)
                        return ''
                    except (IOError, OSError) as e:
                        print(f"Warning: Error reading transcript {transcript_path}: {e}", file=sys.stderr)
                        return ''
                    except UnicodeDecodeError as e:
                        print(f"Warning: Encoding error in transcript {transcript_path}: {e}", file=sys.stderr)
                        return ''
            elif field == 'user_prompt':
                # For UserPromptSubmit events
                return input_data.get('user_prompt', '')

        # Handle special cases by tool type
        if tool_name == 'Bash':
            if field == 'command':
                return tool_input.get('command', '')

        elif tool_name in ['Write', 'Edit']:
            if field == 'content':
                # Write uses 'content', Edit has 'new_string'
                return tool_input.get('content') or tool_input.get('new_string', '')
            elif field == 'new_text' or field == 'new_string':
                return tool_input.get('new_string', '')
            elif field == 'old_text' or field == 'old_string':
                return tool_input.get('old_string', '')
            elif field == 'file_path':
                return tool_input.get('file_path', '')

        elif tool_name == 'MultiEdit':
            if field == 'file_path':
                return tool_input.get('file_path', '')
            elif field in ['new_text', 'content']:
                # Concatenate all edits
                edits = tool_input.get('edits', [])
                return ' '.join(e.get('new_string', '') for e in edits)

        return None
```

**File:** plugins/hookify/core/rule_engine.py (L256-273)
```python
    def _regex_match(self, pattern: str, text: str) -> bool:
        """Check if pattern matches text using regex.

        Args:
            pattern: Regex pattern
            text: Text to match against

        Returns:
            True if pattern matches
        """
        try:
            # Use cached compiled regex (LRU cache with max 128 patterns)
            regex = compile_regex(pattern)
            return bool(regex.search(text))

        except re.error as e:
            print(f"Invalid regex pattern '{pattern}': {e}", file=sys.stderr)
            return False
```

**File:** CHANGELOG.md (L71-73)
```markdown
- Fixed a Bash permission bypass where a crafted command could hide parts of itself from permission checks
- Fixed permission prompts so commands padded with tabs or invisible Unicode can no longer hide part of the command from the approval dialog
- Fixed workflow scripts being able to use dynamic `import()` to run code outside the workflow sandbox
```

**File:** CHANGELOG.md (L118-118)
```markdown
- Fixed a Bash tool permission-check bypass where zsh could execute hidden commands in `[[ ]]` regex conditionals; affected commands now prompt for permission
```

**File:** CHANGELOG.md (L297-301)
```markdown
- Fixed a permission-check bypass affecting commands run in Windows PowerShell 5.1 sessions
- Fixed Bash permission checks to fail closed on file-descriptor redirect forms that bash parses differently than the permission analyzer
- Fixed Bash permission checks misjudging very long commands — commands over 10,000 characters now always prompt instead of running automatically
- Fixed Bash permission checks treating zsh variable subscripts and modifiers in `[[ ]]` comparisons as inert text — these commands now prompt for approval
- Fixed Bash permission checks to no longer auto-approve certain `help` and `man` commands that could run unsafe options, command substitutions, or backslash paths
```

**File:** plugins/hookify/core/config_loader.py (L56-73)
```python
        # Legacy style: simple pattern field
        simple_pattern = frontmatter.get('pattern')
        if simple_pattern and not conditions:
            # Convert simple pattern to condition
            # Infer field from event
            event = frontmatter.get('event', 'all')
            if event == 'bash':
                field = 'command'
            elif event == 'file':
                field = 'new_text'
            else:
                field = 'content'

            conditions = [Condition(
                field=field,
                operator='regex_match',
                pattern=simple_pattern
            )]
```
