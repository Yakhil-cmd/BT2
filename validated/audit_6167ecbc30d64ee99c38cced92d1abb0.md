### Title
ReDoS in `RuleEngine._regex_match`/`compile_regex` via unguarded rule regex enables PreToolUse hook timeout and fail-open bypass - ([File: plugins/hookify/core/rule_engine.py])

### Summary
`compile_regex` and `_regex_match` in `plugins/hookify/core/rule_engine.py` compile and execute attacker-influenced regex patterns from `.claude/hookify.*.local.md` rule files against attacker/user-controlled `tool_input.command` text with no timeout, length cap, or safe-regex validation. A catastrophic-backtracking pattern (e.g. `(a+)+b`) combined with an adversarial command string causes `re.Pattern.search` to hang, and because `pretooluse.py` is invoked as a Claude Code command hook with a fixed `"timeout": 10` in `hooks/hooks.json`, a hang here causes the hook process to be killed by timeout rather than to return a deny decision.

### Finding Description
`load_rule_file`/`Rule.from_dict` in `plugins/hookify/core/config_loader.py` (lines 44-84, 244-274) parse `pattern`/`conditions[].pattern` directly out of markdown frontmatter with no validation of regex safety. [1](#0-0) 
These rules are loaded by `load_rules()` from any `.claude/hookify.*.local.md` file found via `glob.glob` in the current working directory. [2](#0-1) 

At evaluation time, `RuleEngine._check_condition` calls `_regex_match(pattern, field_value)` for `operator == 'regex_match'`, which calls the module-level `compile_regex` (LRU-cached `re.compile`) and then `regex.search(text)` with no timeout, length limit, or ReDoS-safe engine. [3](#0-2) [4](#0-3) 
`_extract_field` pulls the `command` field directly from `tool_input` for `Bash` tool calls, so the text matched against the attacker-supplied pattern is fully attacker/user controlled. [5](#0-4) 

`pretooluse.py` is registered as a `PreToolUse` command hook with `"timeout": 10` in `plugins/hookify/hooks/hooks.json`. [6](#0-5) 
The script's own `try/except/finally: sys.exit(0)` only executes for in-process Python exceptions or normal completion; it cannot run if the whole process hangs inside `re.Pattern.search` and is subsequently killed externally by Claude Code's hook-timeout enforcement. [7](#0-6) 
Whether Claude Code's core hook runner treats a killed/timed-out `PreToolUse` hook as "allow" or "deny" is implemented outside this repository (the plugin/hook execution harness itself is not part of the indexed codebase), so the precise post-timeout decision cannot be confirmed from repo content alone — only the in-repo ReDoS primitive and the fixed 10s timeout are verifiable facts.

### Impact Explanation
If the plugin/host treats a hook timeout as fail-open (a commonly documented behavior for Claude Code command hooks to avoid indefinitely blocking the agent), a `block`-action rule with a catastrophic regex would never return its `permissionDecision: "deny"` in time, allowing an attacker-chosen dangerous `Bash` command (e.g., `rm -rf`) to execute unchecked. Even absent confirmed fail-open semantics, this is at minimum a reliable denial-of-service against the `PreToolUse`/`PostToolUse`/`Stop`/`UserPromptSubmit` hook chain for any command matching the pathological pattern, since `compile_regex`/`_regex_match` have no bound on backtracking work.

### Likelihood Explanation
Exploitation requires an attacker to get a `.claude/hookify.*.local.md` rule file with a catastrophic pattern loaded (e.g., via a merged PR adding/editing a hookify rule, or a bundled malicious plugin rule) and a Bash command whose text triggers pathological backtracking against that pattern. This is a real reachable path per the audit's allowed attacker surfaces ("plugin files", "repo-checked-in" content), but it does require write access to the rules directory (via PR/plugin), which is a non-trivial but plausible precondition, and it further depends on unverified (from this repo) core-hook timeout-to-decision semantics.

### Recommendation
- Validate/sandbox rule regex patterns at load time (e.g., static ReDoS pattern detection, or compiling with a bounded-backtracking engine such as `re2`/`regex` module's timeout support).
- Enforce a hard match timeout in `_regex_match` (e.g., via a worker thread/process with `concurrent.futures` and a strict deadline, or `signal.alarm` on POSIX) and treat a timeout for `block`-action rules as `permissionDecision: "deny"` rather than silently returning `False`/allowing.
- Cap the length of `field_value` passed into `regex.search` for defense-in-depth.
- Ensure fail-closed behavior for `block` rules specifically: any internal exception/timeout while evaluating a `block` rule should surface a deny decision, not just an empty result.

### Proof of Concept
Fuzz/unit test plan:
1. Unit test: create a `Rule` with `action='block'`, `conditions=[Condition(field='command', operator='regex_match', pattern='(a+)+b')]`.
2. Call `RuleEngine()._regex_match('(a+)+b', 'a'*40)` (no trailing `b`) and assert it completes within a bounded time (e.g., 1 second) using `pytest-timeout` or a wrapped call with `signal.alarm`; expect the current implementation to exceed this bound, demonstrating unbounded backtracking.
3. Integration test: invoke `RuleEngine().evaluate_rules([rule], {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "a"*40}})` under a wall-clock timeout matching `hooks.json`'s `"timeout": 10`; assert that on timeout the result is `{"hookSpecificOutput": {"permissionDecision": "deny", ...}}` rather than the process hanging past the hook's configured timeout.
4. Fuzz test: generate a corpus of known catastrophic-backtracking regex templates (`(a+)+`, `(a|a)*`, `(a|aa)+`) paired with adversarial-length strings, assert `_regex_match` execution time stays sub-linear/bounded for all inputs.

### Citations

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

**File:** plugins/hookify/core/config_loader.py (L207-212)
```python
    rules = []

    # Find all hookify.*.local.md files
    pattern = os.path.join('.claude', 'hookify.*.local.md')
    files = glob.glob(pattern)

```

**File:** plugins/hookify/core/rule_engine.py (L13-24)
```python
# Cache compiled regexes (max 128 patterns)
@lru_cache(maxsize=128)
def compile_regex(pattern: str) -> re.Pattern:
    """Compile regex pattern with caching.

    Args:
        pattern: Regex pattern string

    Returns:
        Compiled regex pattern
    """
    return re.compile(pattern, re.IGNORECASE)
```

**File:** plugins/hookify/core/rule_engine.py (L230-233)
```python
        # Handle special cases by tool type
        if tool_name == 'Bash':
            if field == 'command':
                return tool_input.get('command', '')
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

**File:** plugins/hookify/hooks/hooks.json (L4-14)
```json
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
