### Title
Incomplete ReDoS heuristic in `_has_redos_structure` allows crafted `security-patterns.yaml` regex to hang PostToolUse hook via catastrophic backtracking - ([File: plugins/security-guidance/hooks/extensibility.py])

### Summary
`_validate_pattern` relies solely on `_has_redos_structure` to reject dangerous custom regexes before they are stored and later executed with `re.search` on every file edit. The heuristic only recognizes two narrow shapes (nested `+`/`*` quantifiers in parentheses, and overlapping alternation under `+`/`*`), so a regex that achieves catastrophic backtracking through other well-known constructs — e.g. bounded `{m,n}` repetition instead of `+`/`*`, or "quantifier pile-up" without any parentheses at all (`a?a?a?a?a?a?a?a?a?a?aaaaaaaaaa`) — passes validation unmodified and is stored for use in `check_patterns`.

### Finding Description
The load path is: `load_for_session` → `_load_user_patterns` (plugins/security-guidance/hooks/extensibility.py:147) → `_validate_pattern` (line 199) → `_has_redos_structure` (line 272). The gate at line 224 is the only place a ReDoS regex is filtered: [1](#0-0) 

`_has_redos_structure` only checks two fixed shapes: [2](#0-1) 

Both `_REDOS_SHAPES` regexes require a literal `+` or `*` immediately inside a parenthesized group *and* a trailing `+`/`*`/`?` quantifier on that same group — they never match `{m,n}` bounded-repetition nesting (e.g. `(a{1,50}){1,50}`) and never match quantifier-pileup patterns with no grouping at all (e.g. `a?a?a?a?a?a?a?a?a?a?aaaaaaaaaa`, or `x*x*x*x*x*x*y`). `_ALT_UNDER_REP` similarly only flags alternation with a literal prefix relationship under `+`/`*`, and is bypassed by the same non-paren / brace-based constructs. Any regex using these unrecognized shapes is treated as safe, stored into the rule dict (`rule["regex"] = regex`), and later matched via `re.search` on file content on every `PostToolUse` edit (per the documented call path in `patterns.py`/`security_reminder_hook.py`), with no execution timeout wrapping the match. On adversarial input engineered to trigger worst-case backtracking (e.g. a long run of the "optional" character followed by one non-matching tail character), the match can take exponential time, hanging the hook.

### Impact Explanation
This is a local denial-of-service: the PostToolUse hook thread performing pattern checks will hang (potentially indefinitely / until process kill) on every subsequent file edit that triggers a `re.search` against the malicious rule, degrading or blocking the editing workflow for anyone using the repository with that `security-patterns.yaml`. It does not grant code execution, secret disclosure, or approval bypass — it is scoped to availability/DoS of the security-guidance hook, consistent with the "local DoS hanging the PostToolUse hook" impact described in the question.

### Likelihood Explanation
Feasible and repeatable: an attacker only needs to get a `security-patterns.yaml`/`.json`/`.local.yaml` file into the discovery paths checked by `_config_paths` (e.g. via a PR that adds `.claude/security-patterns.yaml` to a project, which is the documented "project, committed" precedence tier) — no special privilege beyond ordinary contribution/PR access is required, matching the "unprivileged attacker, repository content" threat model. Crafting a bypassing regex is straightforward and well documented in ReDoS literature (quantifier pileup, brace-based nested repetition); no exotic conditions are needed. The bug is deterministic — the same malicious rule will attempt `re.search` on the content of every subsequent edit.

### Recommendation
Replace or augment the static heuristic with a robust defense-in-depth mechanism rather than relying purely on shape-matching:
- Generalize `_REDOS_SHAPES`/`_ALT_UNDER_REP` to also detect quantified groups using `{m,n}` (not just `+`/`*`), and detect quantifier-pileup sequences of optional/repeated single-char quantifiers without grouping.
- More importantly, don't rely on static heuristics alone: enforce a hard runtime bound when executing user-supplied regexes in `check_patterns`, e.g. run `re.search` with a wall-clock timeout (via a worker process/thread with `signal.alarm` on POSIX, or a regex engine with built-in step limits such as the `regex` module's `timeout`/`re2`), and drop/disable any user rule that times out, logging via `debug_log`.
- Consider capping regex length/complexity (e.g. reject regexes containing multiple unbounded quantifiers over a length threshold) as an additional coarse filter.

### Proof of Concept
Unit/fuzz test to add near `_has_redos_structure`'s existing tests:
```python
import re, time
from extensibility import _has_redos_structure

BYPASS_REGEXES = [
    r"a?a?a?a?a?a?a?a?a?a?aaaaaaaaaa",      # quantifier pile-up, no parens
    r"(a{1,20}){1,20}b",                     # nested brace-based repetition
    r"x*x*x*x*x*x*x*x*x*x*y",                # sequential star pile-up, no grouping
]

def test_redos_bypass_regexes_are_not_flagged():
    for rx in BYPASS_REGEXES:
        assert _has_redos_structure(rx) is False  # demonstrates heuristic gap

def test_bypass_regex_causes_catastrophic_backtracking():
    rx = re.compile(r"a?a?a?a?a?a?a?a?a?a?aaaaaaaaaa")
    evil_input = "a" * 30 + "X"  # non-matching tail triggers worst-case backtracking
    start = time.monotonic()
    rx.search(evil_input)
    elapsed = time.monotonic() - start
    assert elapsed < 1.0  # expected to FAIL: demonstrates hang / exponential blowup
```
Expected result: `_has_redos_structure` returns `False` for all three bypass regexes (proving they pass `_validate_pattern`), and the timed match against `evil_input` exceeds the 1-second bound by orders of magnitude, demonstrating that `check_patterns()`'s `re.search(rule['regex'], content)` would hang the PostToolUse hook on such content.

### Citations

**File:** plugins/security-guidance/hooks/extensibility.py (L223-232)
```python
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

**File:** plugins/security-guidance/hooks/extensibility.py (L265-269)
```python
_REDOS_SHAPES = [
    re.compile(r"\([^()]*[+*][^()]*\)[+*?]"),  # nested quantifier: (a+)*  (a*b)*
    re.compile(r"\(\.\*[^()]*\)[+*]"),         # wildcard group: (.*)*
]
_ALT_UNDER_REP = re.compile(r"\(([^()]*)\|([^()|]*)(?:\|[^()]*)*\)[+*]")
```
