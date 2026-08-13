### Title
ReDoS via attacker-supplied hookify rule `pattern` field causes unbounded regex backtracking on every Bash/Edit hook invocation - (File: `plugins/hookify/core/rule_engine.py`)

### Summary
`RuleEngine._regex_match` compiles and runs an attacker-controllable regex `pattern` (sourced from `.claude/hookify.*.local.md` rule files) against attacker-influenced `command`/`new_text` content on every `PreToolUse`/`PostToolUse` invocation, with no ReDoS-structure validation, length bound, or execution timeout around the match call, unlike the sibling `security-guidance` plugin which explicitly screens for this.

### Finding Description
`load_rules()` globs every `.claude/hookify.*.local.md` file in the working directory and parses its `pattern`/`conditions[].pattern` frontmatter field verbatim into a `Rule`/`Condition` object <cite repo="hirayap/claude-code--023" path="plugins/hookify/core/config_loader.py" start="208="211" /> [1](#0-0) . No regex-safety check is performed anywhere in this load path.

On every Bash/Edit/Write/MultiEdit tool call, `pretooluse.py` and `posttooluse.py` load these rules and call `RuleEngine.evaluate_rules`, which for each rule invokes `_check_condition` → `_regex_match(pattern, field_value)` [2](#0-1) . `_regex_match` compiles the pattern via the module-level `lru_cache`d `compile_regex` and directly calls `regex.search(text)` with no timeout, length cap, or catastrophic-backtracking screen [3](#0-2) . `text` is `command` for Bash or `new_text`/`content` for Edit/Write, i.e., attacker/legitimate tool-input data [4](#0-3) .

By contrast, the `security-guidance` plugin's equivalent user-pattern loader explicitly rejects ReDoS-prone regexes via `_has_redos_structure` before accepting a pattern [5](#0-4) . Hookify's `rule_engine.py`/`config_loader.py` have no analogous protection, so a rule pattern like `(a+)+b` is accepted unchanged and compiled/executed every time a matching tool event occurs.

The `PreToolUse`/`PostToolUse` hooks are invoked with a 10-second `timeout` in `hooks.json` [6](#0-5) , and `pretooluse.py`'s own error handling only guards against `re.error`/Python exceptions inside a try/except that never fires for a hung regex match, and the `finally: sys.exit(0)` cannot run if the whole process is killed for exceeding the hook timeout [7](#0-6) .

### Impact Explanation
A malicious `.claude/hookify.*.local.md` rule file (e.g., landed via a merged PR, since these files are ordinary text files not enforced to be excluded by any parser check) combined with adversarial content in a subsequently-run Bash command or file edit causes the PreToolUse/PostToolUse hook process to hang on `regex.search()` for a duration exponential in input length. This can exhaust the 10s hook timeout on every qualifying tool call, degrading or effectively denying the timely approve/deny decision hookify is meant to provide, and repeats on every subsequent matching Bash/Edit invocation as long as the rule file persists. This is a hook-stage denial-of-service impacting the responsiveness/reliability of tool-use gating rather than a direct code-execution or data-exfiltration compromise.

### Likelihood Explanation
Preconditions: (1) a `.claude/hookify.*.local.md` file with a catastrophic-backtracking `pattern` must exist in the checked-out working directory — reachable if such a file is introduced through ordinary repository content (e.g., a merged pull request) rather than requiring admin/maintainer privilege on the victim machine; (2) the matched field (`command` or `new_text`) must contain an adversarial string that triggers exponential backtracking — this can be authored by the attacker as part of the same PR/content that the assistant is later asked to run or copy. Both conditions are plausible without any privileged access, making the finding realistic though it does require some content-authoring influence over the second condition.

### Recommendation
- Validate rule `pattern` values at load time in `config_loader.py`/`rule_engine.py` (reject or reformulate patterns exhibiting nested-quantifier/ambiguous-repetition structures, similar to `_has_redos_structure` in `plugins/security-guidance/hooks/extensibility.py`).
- Bound the length of `command`/`new_text`/`content` passed into `_regex_match`.
- Enforce a hard per-match timeout (e.g., run `regex.search` in a subprocess/thread with `signal.alarm` or a `regex` module with timeout support) and fail-safe (treat as no-match) on timeout instead of hanging the whole hook process.

### Proof of Concept
Unit/fuzz test in `plugins/hookify/core/rule_engine.py`:
1. Construct a `Rule` with `pattern=r"(a+)+b"`, `event="bash"`, `action="warn"`.
2. Build `tool_input = {"command": "a" * N + "c"}` for increasing `N` (e.g., 20, 25, 30...).
3. Call `RuleEngine()._regex_match(rule.pattern, tool_input["command"])` (or `evaluate_rules`) under a wall-clock timer.
4. Assert that execution time grows exponentially with `N` and exceeds a bounded SLA (e.g., >2s at N=30) with no timeout/short-circuit in place, demonstrating the hook can be stalled well past the 10s `hooks.json` timeout for realistic `N`.

### Citations

**File:** plugins/hookify/core/config_loader.py (L244-261)
```python
def load_rule_file(file_path: str) -> Optional[Rule]:
    """Load a single rule file.

    Returns:
        Rule object or None if file is invalid.
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()

        frontmatter, message = extract_frontmatter(content)

        if not frontmatter:
            print(f"Warning: {file_path} missing YAML frontmatter (must start with ---)", file=sys.stderr)
            return None

        rule = Rule.from_dict(frontmatter, message)
        return rule
```

**File:** plugins/hookify/core/rule_engine.py (L166-167)
```python
        if operator == 'regex_match':
            return self._regex_match(pattern, field_value)
```

**File:** plugins/hookify/core/rule_engine.py (L230-252)
```python
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

**File:** plugins/security-guidance/hooks/extensibility.py (L222-232)
```python
        rule["substrings"] = substrings
    if regex:
        if _has_redos_structure(regex):
            debug_log(f"extensibility: skipping {name}: regex looks ReDoS-prone: {regex!r:.60}")
            return None
        try:
            rule["regex"] = regex
            re.compile(regex)
        except re.error as e:
            debug_log(f"extensibility: skipping {name}: invalid regex: {e}")
            return None
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

**File:** plugins/hookify/hooks/pretooluse.py (L61-70)
```python
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
