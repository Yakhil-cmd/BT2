### Title
Unbounded regex evaluation on attacker-controlled text enables ReDoS-driven hang in `RuleEngine._regex_match` - (File: plugins/hookify/core/rule_engine.py)

### Summary
`_regex_match` compiles rule `pattern` strings with `compile_regex()` and calls `regex.search(text)` on attacker-influenced `text` (Bash `command`, `new_text`/`new_string`, `content`, or `transcript`) with no timeout, length cap, or ReDoS-safety validation. A pattern with nested/ambiguous quantifiers combined with an adversarial input string can trigger catastrophic backtracking and make the PreToolUse/PostToolUse/Stop hook process hang.

### Finding Description
`evaluate_rules` → `_rule_matches` → `_check_condition` → `_regex_match` (`plugins/hookify/core/rule_engine.py:96-181, 256-273`) runs `re.compile(pattern, re.IGNORECASE).search(text)` for every `regex_match` condition, where:
- `pattern` comes from `.claude/hookify.*.local.md` rule frontmatter, parsed by a custom hand-rolled YAML-like parser in `config_loader.py` (`extract_frontmatter`, `Condition.from_dict`, `Rule.from_dict`) with zero validation of the regex's structural safety (`plugins/hookify/core/config_loader.py:16-29, 87-195`).
- `text` is extracted via `_extract_field` directly from tool call parameters an ordinary agent action produces: `tool_input['command']` for Bash, `tool_input['new_string']`/`content` for Write/Edit/MultiEdit, or even file contents read as `transcript` (`plugins/hookify/core/rule_engine.py:182-254`).

Python's `re` module (backtracking engine) is vulnerable to catastrophic backtracking for patterns with nested/overlapping quantifiers (e.g. `(a+)+$`, `(.*)+`, `([a-zA-Z]+)*!`). No length limits are enforced on `text` (a Bash `command` or file `new_string` can be arbitrarily long), and no per-call timeout, worker-process isolation, or `re` timeout wrapper (e.g. `signal.alarm`, subprocess, or `regex` module with timeout support) guards `regex.search`. `compile_regex` only catches `re.error` on malformed patterns, not runtime hangs on `search`.

### Impact Explanation
Each hookify hook (`pretooluse.py`, `posttooluse.py`, `stop.py`, `userpromptsubmit.py`) is configured with a hard `"timeout": 10` in `plugins/hookify/hooks/hooks.json`. A hang inside `_regex_match` that exceeds this window causes the hook process to be killed by the Claude Code hook runner. This repository does not contain the Claude Code hook-runner's own timeout-handling logic, so whether a killed PreToolUse hook fails open (tool proceeds unblocked) or fails closed is not verifiable from this codebase alone. If the runner treats a hook timeout as "no decision" (fail-open), a `block` rule (e.g. blocking dangerous `rm -rf` commands) would silently not fire, allowing the underlying tool call to execute — a hook-enforcement bypass via availability failure. Regardless of the fail-open/fail-closed outcome at the CLI level, the ReDoS itself is a genuine, reproducible availability defect in `_regex_match` with no built-in bound.

### Likelihood Explanation
Feasible under either attacker precondition stated: (1) an attacker who can merge/commit a `.claude/hookify.*.local.md` rule with an ambiguous pattern (e.g. via a PR to a repo that auto-adopts contributor-authored hookify rules), or (2) more realistically, an attacker who only controls reviewed content (a crafted Bash command, file edit `new_string`, or PR/file text an agent later edits) that is matched against an already-existing, unremarkable-looking vulnerable pattern written by a legitimate rule author. Scenario (2) requires no special repo write privilege to the rule file itself, only the ability to get adversarial text into a Bash command or file content the agent touches — a normal, low-privilege interaction. This is repeatable and deterministic given a fixed vulnerable pattern and adversarial text of sufficient length.

### Recommendation
- Enforce a strict length cap on `text` before regex evaluation (e.g. truncate `command`/`new_text`/`transcript` beyond a safe threshold).
- Validate rule patterns at load time for known ReDoS-prone constructs, or switch to a linear-time regex engine (e.g. Google's `re2` via the `google-re2` binding) instead of Python's backtracking `re`.
- Wrap `regex.search` in a hard per-call timeout (e.g. run in a subprocess/thread with `concurrent.futures` and a short deadline, or use `regex` module's `timeout` parameter) and treat a timeout for a `block` rule as a match (fail closed), never as a silent allow.
- Document/verify with the Claude Code hook runner that a PreToolUse hook exceeding its configured `timeout` fails closed (denies the tool call) rather than fails open.

### Proof of Concept
Unit/fuzz test to add to `plugins/hookify/core/` tests:
```python
import time
from hookify.core.rule_engine import RuleEngine
from hookify.core.config_loader import Rule, Condition

def test_regex_match_bounded_time():
    rule = Rule(
        name="redos-rule", enabled=True, event="bash", action="block",
        conditions=[Condition(field="command", operator="regex_match",
                               pattern=r"(a+)+$")],
        message="blocked"
    )
    engine = RuleEngine()
    evil_input = {
        "tool_name": "Bash",
        "tool_input": {"command": "a" * 40 + "!"}  # no trailing match -> full backtrack
    }
    start = time.monotonic()
    result = engine.evaluate_rules([rule], evil_input)
    elapsed = time.monotonic() - start
    # Expect bounded evaluation time (e.g. < 1s) regardless of pattern/input
    assert elapsed < 1.0, f"_regex_match hung for {elapsed}s - ReDoS"
    # A timeout must never be treated as "no match" for a block rule
    # (once a timeout guard is added, assert the fallback still returns block)
```
Fuzz plan: generate a corpus of nested-quantifier regex patterns (`(x+)+`, `(x*)*`, `(x+){1,}y`) paired with increasing-length non-matching strings, run through `RuleEngine._rule_matches`, and assert wall-clock time stays under a fixed bound (e.g. 2s) for all inputs up to a realistic max command/file length (e.g. 1MB).