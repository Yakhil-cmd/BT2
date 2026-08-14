## Analysis

The C4 report describes a classic "unbounded loop over user-controlled queue" DoS: an attacker cheaply inflates a queue that a privileged function must iterate in full, and that iteration cost eventually exceeds a resource limit (gas), silently disabling the queue's own moderation logic.

The `hookify` plugin in this repo has a structurally identical pattern, but the "resource limit" is a **hook execution timeout**, and the consequence of hitting it is a **fail-open bypass of a PreToolUse security control** rather than a stuck contract — this fits the "hook bypass / tool authorization" trust boundary explicitly allowed by the rules.

- `load_rules()` globs **every** `.claude/hookify.*.local.md` file in the project with no cap and parses each one on **every single tool call** (`PreToolUse`, `PostToolUse`, `Stop`, `UserPromptSubmit`): [1](#0-0) 
- `RuleEngine.evaluate_rules()` then loops over the full, unbounded rule list and, for each rule, loops over its unbounded condition list, calling `_regex_match()` with a **user-controlled regex pattern** on every condition: [2](#0-1) [3](#0-2) 
- The hook wrapper that runs this on every tool call is configured with only a 10-second timeout: [4](#0-3) 
- Critically, `pretooluse.py` is explicitly designed to **always exit 0** (never block) on internal error, and only wraps its *own* exception handling — it has no defense against being killed externally by the timeout wrapper: [5](#0-4) 

### Title
Unbounded Rule-File/Condition Loop in `hookify` Enables PreToolUse Hook-Timeout DoS and Fail-Open Bypass of Security Rules - (File: `plugins/hookify/core/config_loader.py`, `plugins/hookify/core/rule_engine.py`)

### Summary
Every tool call re-globs and re-parses all `hookify.*.local.md` rule files and evaluates every condition of every rule with an attacker-influenced regex, with no cap on file count, rule count, or per-rule condition count. An attacker who can write files into the project's `.claude/` directory (e.g., via a crafted repository, a skill/plugin, or any file-write primitive available to an unprivileged collaborator) can inflate this workload — either by sheer volume of trivial rule files/conditions, or via a small number of catastrophic-backtracking regex patterns — until the per-call cost exceeds the hook's fixed 10-second timeout.

### Finding Description
`load_rules()` performs `glob.glob('.claude/hookify.*.local.md')` and parses every match, with no upper bound on the number of files: [6](#0-5) . `evaluate_rules()` then iterates the full rule list and, per rule, the full condition list, without any per-call budget: [2](#0-1) . Each condition can invoke `_regex_match()` on a pattern taken directly from user-authored `.claude/hookify.*.local.md` frontmatter, with no complexity limits: [3](#0-2) .

This entire pipeline runs synchronously inside `pretooluse.py`/`posttooluse.py`/`stop.py`/`userpromptsubmit.py`, each capped at a 10-second `timeout` in the plugin's `hooks.json`: [7](#0-6) . If the combined glob+parse+evaluate cost exceeds that timeout — via many rule files, many conditions per rule, or a handful of adversarial regexes — the host's `timeout` wrapper kills the process before it can print any JSON decision. This is functionally the same failure mode as the reported Solidity bug: a queue an attacker can cheaply grow becomes too expensive for the privileged consumer to fully process within its budget.

### Impact Explanation
Unlike the Solidity report (where the impact is a stuck queue/DoS), here the killed hook has a security-relevant side effect: `hookify` is specifically used to author `PreToolUse` rules that `block` dangerous operations (its own README frames it as a way to warn/block on things like `rm -rf`, `console.log`, etc.). If the hook times out, Claude Code receives no blocking decision from it, and — consistent with the hook's own explicit "always allow on error" design intent — the tool call proceeds unimpeded. This turns a workload-inflation DoS into a **fail-open bypass of user-authored guardrails**: any rule intended to `deny`/block a dangerous Bash/Edit/Write call can be silently defeated once the rule file corpus (or a single expensive rule) has grown past the point where evaluation fits in 10 seconds. This is a genuine security-control bypass, not merely a UX slowdown.

### Likelihood Explanation
Likelihood is moderate: it requires something/someone to have already written multiple files into the project's `.claude/` directory (attacker-controlled repo content, a malicious skill/plugin invoked earlier in the session, or a compromised collaborator's commit), which is a realistic supply-chain-style vector for this class of local dev tool. No privilege escalation is needed beyond ordinary filesystem write access to the project, which many otherwise-unprivileged inputs into a Claude Code session already have (checked-out repo content, plugin-installed files, etc.).

### Recommendation
- Cap the number of `hookify.*.local.md` rule files processed per invocation (as `security-guidance`'s `extensibility.py` already does via `PATTERN_MAX_RULES`, see `plugins/security-guidance/hooks/extensibility.py` lines 147-168 for a working pattern), and cap conditions per rule.
- Enforce a regex complexity/length limit or use a timeout-bounded/non-backtracking regex engine for `_regex_match()`.
- Make hook-timeout the fail state configurable to fail-closed (deny) for security-sensitive PreToolUse hooks rather than silently allowing the tool call, or at minimum surface a loud warning that a hook was killed by timeout so the user knows their guardrails did not run.
- Cache parsed rules across calls within a session instead of re-globbing and re-parsing on every single tool invocation.

### Proof of Concept
1. In a project directory, create N (e.g., 5,000) files matching `.claude/hookify.<i>.local.md`, each with valid frontmatter (`enabled: true`, `event: all`) and a handful of conditions using a catastrophic-backtracking pattern such as `^(a+)+$` matched against a long attacker-influenced string derived from `tool_input`.
2. Trigger any tool call (e.g., `Bash("ls")`) so `pretooluse.py` runs.
3. Observe `load_rules()` + `RuleEngine.evaluate_rules()` exceeding the hook's 10-second timeout; the process is killed by the `timeout` wrapper before emitting a JSON decision.
4. Confirm that a `deny`-configured hookify rule targeting the same tool call does **not** block execution once the corpus/pattern cost exceeds the timeout, whereas it correctly blocks when the corpus is small — demonstrating the fail-open bypass.

### Citations

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

**File:** plugins/hookify/core/rule_engine.py (L35-58)
```python
    def evaluate_rules(self, rules: List[Rule], input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate all rules and return combined results.

        Checks all rules and accumulates matches. Blocking rules take priority
        over warning rules. All matching rule messages are combined.

        Args:
            rules: List of Rule objects to evaluate
            input_data: Hook input JSON (tool_name, tool_input, etc.)

        Returns:
            Response dict with systemMessage, hookSpecificOutput, etc.
            Empty dict {} if no rules match.
        """
        hook_event = input_data.get('hook_event_name', '')
        blocking_rules = []
        warning_rules = []

        for rule in rules:
            if self._rule_matches(rule, input_data):
                if rule.action == 'block':
                    blocking_rules.append(rule)
                else:
                    warning_rules.append(rule)
```

**File:** plugins/hookify/core/rule_engine.py (L256-269)
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
```

**File:** plugins/hookify/hooks/hooks.json (L1-49)
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
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 ${CLAUDE_PLUGIN_ROOT}/hooks/stop.py",
            "timeout": 10
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python3 ${CLAUDE_PLUGIN_ROOT}/hooks/userpromptsubmit.py",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

**File:** plugins/hookify/hooks/pretooluse.py (L34-70)
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
