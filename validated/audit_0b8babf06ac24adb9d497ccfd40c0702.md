Confirmed: the `Stop` hook has a hardcoded 10-second timeout in `plugins/hookify/hooks/hooks.json` (`"timeout": 10`), and one CHANGELOG entry indicates a hook timeout is treated specially rather than as an outright failure ("Fixed a hook callback timeout being misreported to the model as a user rejection, which made unattended sessions stop and wait" — CHANGELOG.md around line 445), which is at least suggestive that a timed-out hook does not reliably produce a hard "deny."

### Title
Unbounded regex evaluation in hookify Stop-hook rule engine enables ReDoS-driven hook-timeout bypass of `block` rules - (File: plugins/hookify/core/rule_engine.py)

### Finding Description
`RuleEngine._regex_match` compiles an attacker-supplied `pattern` string from a rule's `Condition` and calls `regex.search(text)` with no length cap, no timeout, and no catastrophic-backtracking guard: [1](#0-0) . The pattern comes straight from a `.claude/hookify.*.local.md` file's YAML frontmatter, parsed by `config_loader.extract_frontmatter`/`Condition.from_dict` with no sanitization or complexity check on `pattern` [2](#0-1) . For `event: stop` rules, the `field: transcript` condition causes `_extract_field` to read the entire transcript file from disk and hand it to the regex engine as the subject string [3](#0-2) . Python's `re` module has no linear-time guarantee and is vulnerable to catastrophic backtracking on patterns like `(a+)+$` against adversarial input (e.g., many `a`s followed by a non-matching character). Because the transcript can grow arbitrarily large over a long conversation, an attacker-authored `block` rule using such a pattern targeting `field: transcript` can make `regex.search` run for a very long time on ordinary conversation content that merely contains long repetitive runs.

The `Stop` hook is invoked with a fixed 10-second timeout (`"timeout": 10` in `plugins/hookify/hooks/hooks.json`) [4](#0-3) . `stop.py`'s only exception handling is a blanket `try/except Exception` around the whole body, which cannot help against a hang inside a single blocking regex call — there is no per-call timeout, thread, or subprocess wrapping that could interrupt `re.search` mid-evaluation [5](#0-4) . If the hook process fails to produce output before the harness's timeout elapses, the process is killed externally, not by hookify's own code, and `stop.py` has no chance to run its `finally: sys.exit(0)` allow-path — the outcome instead depends entirely on how the surrounding Claude Code harness treats a non-responsive hook.

### Impact Explanation
If a repository-committed `hookify.*.local.md` block-rule uses a catastrophic-backtracking regex against `field: transcript`, the Stop hook can hang past its 10s budget on ordinary long conversations, and depending on harness behavior for unresponsive hooks, this could suppress the intended `block` decision — a "deny means deny" violation for a security-relevant hook mechanism. This matches a hook/trust-boundary-bypass class of impact where enforcement logic can be silently neutralized by content the enforcement logic itself is supposed to be checking.

### Likelihood Explanation
This requires an attacker to get a `.claude/hookify.*.local.md` file with a malicious `pattern` merged/present in the target repository (e.g., via an accepted PR or a copy-pasted rule) — the file itself is a "repo-committed" trust boundary the project must already accept content into, and hookify rules are inherently a "you define your own automation" feature. Given that, triggering the hang is straightforward and reliable (classic ReDoS pattern, standard `re` engine, no mitigations present in `compile_regex`/`_regex_match`). The main uncertainty is what Claude Code's harness actually does when the Stop hook exceeds its timeout (allow vs. deny vs. retry) — I could not find code in this repo that defines that harness-level timeout-handling behavior; the only supporting evidence is the CHANGELOG note about a timeout previously being "misreported to the model as a user rejection," which does not conclusively establish a fail-open/allow behavior. This makes the "bypass of the intended block" half of the claim unverified from repo contents alone, even though the ReDoS root cause and unbounded regex execution are concretely confirmed in code.

### Recommendation
- In `compile_regex`/`_regex_match`, validate patterns against a complexity heuristic or use a linear-time regex engine (e.g., the `re2`/`google-re2` package) instead of Python `re` for untrusted patterns.
- Enforce a hard per-match wall-clock timeout around `regex.search` (e.g., run in a subprocess/thread with `signal.alarm` or `multiprocessing` and terminate on timeout), treating a timed-out match as non-matching but logging a warning rather than allowing an attacker to control the fallback outcome.
- Cap the size of `field: transcript` text passed to regex evaluation (e.g., only scan the last N KB), reducing worst-case backtracking blowup.
- Reject or ignore rule patterns above a fixed compiled complexity/length threshold at load time in `config_loader.load_rule_file`.

### Proof of Concept
Fuzz/unit test plan (`test_rule_engine_redos.py`):
1. Construct a `Rule`/`Condition` with `field="transcript"`, `operator="regex_match"`, `pattern=r"(a+)+$"`, `action="block"`.
2. Write a synthetic transcript string of `"a" * 40 + "!"` (or similar non-matching suffix) to a temp file; set `input_data["transcript_path"]` to it.
3. Call `RuleEngine()._regex_match(pattern, text)` (or `evaluate_rules`) with a wrapping timer (`time.perf_counter()`), asserting execution completes within, e.g., 1 second — expect the assertion to fail (execution time grows exponentially with input length, easily exceeding the hook's 10s budget for transcripts as small as ~40-50 repeated characters).
4. Parametrize with known ReDoS patterns (`(a+)+`, `(a|a)+`, `(a|aa)+$`, `([a-zA-Z]+)*$`) and increasing transcript sizes to show evaluation time scales exponentially, confirming no timeout guard exists in `compile_regex`/`_regex_match`.
5. (Harness-level, not verifiable from this repo) A follow-up integration test would invoke `stop.py` as a subprocess with such a rule file present, feed a crafted `transcript_path`, and assert the subprocess is killed by an external timeout after 10s with no way for `stop.py` to emit a `decision: block` response — demonstrating the enforcement gap; the actual allow/deny fallback semantics of the harness's hook timeout must be confirmed from Claude Code's non-open harness code, which is outside this repo's index.

### Citations

**File:** plugins/hookify/core/rule_engine.py (L206-222)
```python
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

**File:** plugins/hookify/core/config_loader.py (L22-29)
```python
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Condition':
        """Create Condition from dict."""
        return cls(
            field=data.get('field', ''),
            operator=data.get('operator', 'regex_match'),
            pattern=data.get('pattern', '')
        )
```

**File:** plugins/hookify/hooks/hooks.json (L26-35)
```json
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
```

**File:** plugins/hookify/hooks/stop.py (L30-55)
```python
def main():
    """Main entry point for Stop hook."""
    try:
        # Read input from stdin
        input_data = json.load(sys.stdin)

        # Load stop rules
        rules = load_rules(event='stop')

        # Evaluate rules
        engine = RuleEngine()
        result = engine.evaluate_rules(rules, input_data)

        # Always output JSON (even if empty)
        print(json.dumps(result), file=sys.stdout)

    except Exception as e:
        # On any error, allow the operation
        error_output = {
            "systemMessage": f"Hookify error: {str(e)}"
        }
        print(json.dumps(error_output), file=sys.stdout)

    finally:
        # ALWAYS exit 0
        sys.exit(0)
```
