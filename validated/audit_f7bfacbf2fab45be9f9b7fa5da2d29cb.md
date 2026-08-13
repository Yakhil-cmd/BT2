This confirms the exploit path: `_extract_field` reads the entire raw transcript file with no filtering of provenance [1](#0-0) , and `_check_condition` performs naive substring matching (`contains`/`not_contains`) directly against that raw blob [2](#0-1) .

### Title
Stop-hook `not_contains`/`contains` transcript conditions can be spoofed via attacker-controlled PR/issue text embedded in the raw transcript - (File: plugins/hookify/core/rule_engine.py)

### Summary
The hookify Stop-hook rule engine evaluates `contains`/`not_contains` conditions by doing a raw substring search over the *entire* transcript file content, without distinguishing between text that resulted from genuine tool execution and text that originated from untrusted external content (e.g., a PR/issue body ingested into the conversation). An attacker who controls repository/PR/issue text that Claude reads into context can plant substrings such as `npm test`, `pytest`, or `cargo test` inside otherwise unrelated text, causing a "require-tests-run" Stop-block rule's `not_contains` condition to evaluate as satisfied (i.e., not blocking) even though no tests were actually executed, silently defeating the completion gate.

### Finding Description
The Stop hook entry point `plugins/hookify/hooks/stop.py` loads all enabled `stop` rules and calls `RuleEngine.evaluate_rules` [3](#0-2) . `evaluate_rules` iterates rules, and for any rule whose conditions match with `action: block`, returns `{"decision": "block", "reason": ...}` for the `Stop` event [4](#0-3) .

`_rule_matches` requires ALL conditions to be true for a rule to match [5](#0-4) . For the documented "require-tests-run" pattern (`field: transcript, operator: not_contains, pattern: npm test|pytest|cargo test`) [6](#0-5) , the condition is checked in `_check_condition`, which for `not_contains` does a plain Python substring check: `pattern not in field_value` [7](#0-6) .

The `transcript` field value is produced by `_extract_field`, which simply opens `transcript_path` and reads the **entire raw file** as one string, with no filtering by role, message type, or provenance (i.e., it includes user-submitted text, assistant text, and tool_use/tool_result content all mixed together) [1](#0-0) .

Because Claude Code sessions commonly ingest PR descriptions, issue bodies, or file/diff content that an unprivileged external party authored (e.g., during automated PR review flows referenced by `plugins/pr-review-toolkit/agents/type-design-analyzer.md`), that attacker-authored text becomes part of the transcript once Claude reads/quotes it. If the attacker embeds literal substrings like `npm test`, `pytest`, or `cargo test` anywhere in that ingested text (even as an unrelated code comment, quoted string, or discussion text, not an actual command execution), the raw substring check `pattern not in field_value` becomes `False`, so the condition fails to match, the blocking rule never fires, and Claude is permitted to stop without ever having actually run tests — defeating the intended completion gate. The pattern-string operand (`npm test|pytest|cargo test`) is treated as a literal substring for `not_contains`/`contains` (not compiled as regex — only `regex_match` uses `compile_regex`), so any one of those literal substrings anywhere in the raw transcript suffices.

No component filters transcript content by role/source, verifies that a matched substring came from an actual tool_use/tool_result block (real command execution evidence) versus arbitrary quoted/ingested text, or checks session binding beyond trusting `transcript_path` as supplied by the Claude Code runtime. Thus a maintainer-authored, legitimately enabled required-tests Stop-block can be silently bypassed by content the attacker controls only indirectly (PR/issue text), with no privilege escalation needed.

### Impact Explanation
This is an approval/completion-gate bypass: a "deny means deny" Stop-block intended to force test execution before a session/task is considered complete can be defeated purely by attacker-controlled PR/issue text ingested into context, without the attacker running any tests. This corresponds to a control-bypass / gate-spoofing impact — the security-relevant enforcement decision (`decision: block`) is made against attacker-influenceable raw text rather than verified tool-execution evidence, undermining the guarantee that "tests were run" claims in the transcript reflect real execution.

### Likelihood Explanation
Preconditions: (1) a maintainer must have enabled a `stop`-event rule with `action: block` that checks `transcript` via `contains`/`not_contains` on literal substrings (this is the exact pattern documented as the recommended usage in `plugins/hookify/README.md`); (2) the session must ingest attacker-influenced text (PR body, issue text, file content) into the transcript, which is a normal automated-review workflow. Given these ordinary conditions, the bypass is fully reproducible and repeatable — the attacker only needs to include the target substring anywhere in text that gets echoed into the transcript.

### Recommendation
- Do not do raw whole-transcript substring matching for gating decisions. Restrict `transcript`-field evaluation to specific, structurally-verified events (e.g., only `tool_use`/`tool_result` blocks with `role` distinguishing actual command executions), not arbitrary ingested prose.
- For "tests were run" style checks, verify against structured signals (e.g., actual `Bash` tool_use entries whose `command` matched a test-runner pattern and whose corresponding `tool_result` indicates success) rather than literal substring presence anywhere in the transcript text.
- If literal substring matching on transcript must remain supported, document and warn that it is trivially spoofable by any text quoted into the conversation (including PR/issue content) and is not a reliable completion-verification mechanism.

### Proof of Concept
Unit test for `plugins/hookify/core/rule_engine.py`:
1. Create a `Rule` with `event='stop'`, `action='block'`, and a `Condition(field='transcript', operator='not_contains', pattern='npm test|pytest|cargo test')` (matching the documented "require-tests-run" example).
2. Write a fake transcript file whose content is a raw JSONL-like blob containing only a `user` message quoting attacker-controlled PR text, e.g. `{"role":"user","content":"PR description: please note we already ran npm test locally"}` — with NO actual `Bash` tool_use command execution present anywhere in the transcript.
3. Call `RuleEngine().evaluate_rules([rule], {"hook_event_name": "Stop", "transcript_path": <path to fake transcript>})`.
4. Assert the result is `{}` (rule did not fire, Stop is allowed) even though no tests were actually executed — demonstrating the required-tests gate is bypassed solely because the literal substring `npm test` appears in attacker-influenced quoted text rather than in genuine tool-execution evidence.
5. Contrast with a transcript containing an actual `{"type":"tool_use","name":"Bash","input":{"command":"npm test"}}` entry to show the intended, legitimate case also passes the same way — proving the engine cannot distinguish the two, which is the root cause.

### Citations

**File:** plugins/hookify/core/rule_engine.py (L53-71)
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
```

**File:** plugins/hookify/core/rule_engine.py (L120-125)
```python
        # All conditions must match
        for condition in rule.conditions:
            if not self._check_condition(condition, tool_name, tool_input, input_data):
                return False

        return True
```

**File:** plugins/hookify/core/rule_engine.py (L166-180)
```python
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

**File:** plugins/hookify/core/rule_engine.py (L207-225)
```python
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
```

**File:** plugins/hookify/hooks/stop.py (L36-44)
```python
        # Load stop rules
        rules = load_rules(event='stop')

        # Evaluate rules
        engine = RuleEngine()
        result = engine.evaluate_rules(rules, input_data)

        # Always output JSON (even if empty)
        print(json.dumps(result), file=sys.stdout)
```

**File:** plugins/hookify/README.md (L189-208)
```markdown
### Example 3: Require Tests Before Stopping

```markdown
---
name: require-tests-run
enabled: false
event: stop
action: block
conditions:
  - field: transcript
    operator: not_contains
    pattern: npm test|pytest|cargo test
---

**Tests not detected in transcript!**

Before stopping, please run tests to verify your changes work correctly.
```

**This blocks Claude from stopping** if no test commands appear in the session transcript. Enable only when you want strict enforcement.
```
