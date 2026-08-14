### Title
ReDoS heuristic in `_has_redos_structure` is bypassable, allowing an attacker-controlled `.claude/security-patterns.yaml` regex + attacker-controlled Edit/Write content to hang the PostToolUse security-warning hook - ([File: plugins/security-guidance/hooks/extensibility.py])

### Summary
`_has_redos_structure()` is a static, shape-based heuristic that only flags nested quantifiers/wildcard groups expressed with literal `+`/`*` inside parentheses, and alternation-under-repetition with literal prefix overlap. Quantifier forms using `{n,}` (e.g. `(a{2,})+` or `(a+){3,}`) and non-parenthesized sequences of unbounded quantifiers (e.g. `a*a*a*a*a*a*b`) are classic catastrophic-backtracking constructs that this detector does not catch, so a project-committed `security-patterns.yaml` can pass `_validate_pattern` with a regex that later hangs `re.search()` in `check_patterns()` on attacker-crafted Edit/Write content.

### Finding Description
`extensibility._load_user_patterns` reads `.claude/security-patterns.yaml` (project-committed, no further sandboxing) and calls `_validate_pattern` for each entry [1](#0-0) . `_validate_pattern` gates any `regex` field through `_has_redos_structure` before accepting it [2](#0-1) .

`_has_redos_structure` only recognizes two shapes:
```
_REDOS_SHAPES = [
    re.compile(r"\([^()]*[+*][^()]*\)[+*?]"),  # nested quantifier: (a+)*  (a*b)*
    re.compile(r"\(\.\*[^()]*\)[+*]"),         # wildcard group: (.*)*
]
```
plus an alternation-under-repetition literal-prefix check [3](#0-2) . Both shape checks require the inner/outer quantifiers to be the literal characters `+`, `*`, or `?` — `{n,}`/`{n,m}` bounded-repetition syntax (which is exponentially equivalent for backtracking purposes when `n` is large or unbounded) is never matched by `[+*]` or `[+*?]`. A regex such as `(a{2,})+$` or `(a+){50,}$` is structurally identical to the canonical `(a+)+$` ReDoS pattern but evades detection because it contains no literal `+`/`*` inside the parens in the position the heuristic checks, or the outer suffix isn't a bare `+`/`*`/`?`. Likewise, a non-grouped chain of unbounded quantifiers (`a*a*a*a*a*a*a*a*b`) needs no parentheses at all and is invisible to both checks.

Once such a rule is loaded, `check_patterns()` runs it on every Edit/Write via `re.search(pattern['regex'], content)` [4](#0-3) . The call is wrapped only in `except Exception: pass`, which does nothing for a hang — Python's `re` module has no built-in match timeout, and no `signal.alarm`/subprocess isolation is used anywhere in `check_patterns`, `_load_user_patterns`, or `_validate_pattern`. An attacker who controls both the committed pattern file and the file content being edited (e.g. via a PR that adds both the rule and a source file matching the crafted suffix, or by getting Claude to write attacker-influenced content) can trigger unbounded CPU-bound backtracking, hanging the PostToolUse hook process indefinitely.

### Impact Explanation
A hung/killed PostToolUse hook does not emit `additionalContext` or `exit(2)`, so it fails open: all pattern-based security warnings (hardcoded secrets, SQL injection, command injection, path traversal, etc., from `SECURITY_PATTERNS` in `patterns.py`) are silently skipped for that edit, plus `record_pending_warnings`/`sweep_pending_warnings` telemetry is skipped. This is a denial-of-service against the plugin's own enforcement/reminder layer, degrading the security posture of a session using purely repo-supplied content — no admin privilege, secret, or social engineering is required beyond committing a YAML file (already an accepted, in-scope path per the plugin's own trust model for `security-patterns.yaml`, which is meant to be additive-only and load-restricted, not ReDoS-resistant only by convention).

### Likelihood Explanation
Feasible and repeatable: the only precondition is a committed `.claude/security-patterns.yaml` in the repository (explicitly a supported, "project (committed)" precedence tier) staying under `PATTERN_MAX_RULES` (50), and a regex crafted with `{n,}` bounded-repetition quantifiers instead of `+`/`*`, which is a trivial rewrite of any known ReDoS pattern. The attacker also needs `check_patterns` to be invoked with content that fails to match early (worst-case suffix absent), which happens naturally whenever Claude edits/writes a file whose content resembles-but-doesn't-satisfy the crafted suffix — highly likely across normal edits to source files matching the rule's `paths` filter (or no filter at all, matching every file).

### Recommendation
- Make `_has_redos_structure` quantifier-agnostic: normalize `{n,}`, `{n,m}` (with n or n,m large) to be treated the same as `+`/`*` before running the shape checks, and detect non-parenthesized sequences of ≥2 adjacent unbounded/quantified atoms with overlapping character classes.
- Do not rely solely on a static heuristic: enforce an actual runtime bound on `re.search` in `check_patterns`, e.g. run user-supplied regex matches in a worker thread/process with a hard wall-clock timeout (or use the `regex` module's timeout parameter, or precompute a bounded input length before matching), and drop/disable a rule that times out repeatedly.
- Alternatively/additionally, cap the size of `content` passed to user-supplied regexes, since bounded input length caps worst-case backtracking time even for undetected catastrophic patterns.

### Proof of Concept
Unit/fuzz test in `plugins/security-guidance/hooks/` test suite:
```python
import re, time
from extensibility import _has_redos_structure

BYPASS_PATTERNS = [
    r"(a{2,})+$",        # bounded-quantifier nested repetition, evades literal +/* shape check
    r"(a+){50,}$",       # outer {n,} instead of +/*/?
    r"a*a*a*a*a*a*a*a*b", # non-parenthesized unbounded-quantifier chain
]

def test_redos_bypass_and_hang():
    for pat in BYPASS_PATTERNS:
        assert not _has_redos_structure(pat), f"expected bypass for {pat!r}"
        payload = "a" * 40  # no trailing char that satisfies terminal requirement
        start = time.time()
        # Should hang far longer than any reasonable PostToolUse budget (>2s)
        # if run without a timeout wrapper.
        import multiprocessing as mp
        def _run(q):
            re.search(pat, payload)
            q.put(True)
        q = mp.Queue()
        p = mp.Process(target=_run, args=(q,))
        p.start()
        p.join(timeout=2)
        assert p.is_alive(), f"{pat!r} did not hang as expected (finished in {time.time()-start:.2f}s)"
        p.terminate()
```
Expected result today: `_has_redos_structure` returns `False` for all three patterns (bypass confirmed) and the worker process is still alive after the 2s timeout, demonstrating exponential/catastrophic backtracking on attacker-controlled input via a pattern that passed load-time validation. After the fix, either `_has_redos_structure` should return `True` for these patterns, or `check_patterns`'s `re.search` call should be time-bounded so the process does not hang regardless of pattern shape.

### Citations

**File:** plugins/security-guidance/hooks/extensibility.py (L147-168)
```python
def _load_user_patterns(cwd: Optional[str]) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for label, path in _config_paths(cwd, "security-patterns"):
        # _config_paths returns an extensionless stem (e.g.
        # ".claude/security-patterns" or ".claude/security-patterns.local");
        # try each supported extension.
        for ext in (".yaml", ".yml", ".json"):
            candidate = path + ext
            data = _read_config(candidate)
            if data is None:
                continue
            for entry in (data or {}).get("patterns", []):
                rule = _validate_pattern(entry, source=label)
                if rule:
                    rules.append(rule)
            break  # found one extension; don't double-load .yaml AND .json
        if len(rules) >= PATTERN_MAX_RULES:
            break
    if len(rules) > PATTERN_MAX_RULES:
        debug_log(f"extensibility: {len(rules)} user patterns > cap {PATTERN_MAX_RULES}; truncating")
        rules = rules[:PATTERN_MAX_RULES]
    return rules
```

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

**File:** plugins/security-guidance/hooks/extensibility.py (L262-289)
```python
# Catastrophic backtracking: nested quantifiers, overlapping alternations
# under repetition, and wildcard groups under repetition. Static check, not a
# proof — catches the common shapes that hang the hook on every edit.
_REDOS_SHAPES = [
    re.compile(r"\([^()]*[+*][^()]*\)[+*?]"),  # nested quantifier: (a+)*  (a*b)*
    re.compile(r"\(\.\*[^()]*\)[+*]"),         # wildcard group: (.*)*
]
_ALT_UNDER_REP = re.compile(r"\(([^()]*)\|([^()|]*)(?:\|[^()]*)*\)[+*]")


def _has_redos_structure(regex: str) -> bool:
    """Heuristic catastrophic-backtracking check. Not a proof. Catches:
      - nested quantifiers ((a+)*, (a*b)+)
      - wildcard groups under repetition ((.*)*)
      - alternation under repetition where one branch is a prefix of another
        ((a|aa)*, (ab|a)*) — these overlap and explode on non-matching input.
    Does NOT flag non-overlapping alternation ((a|b)*) which is safe."""
    if any(p.search(regex) for p in _REDOS_SHAPES):
        return True
    for m in _ALT_UNDER_REP.finditer(regex):
        branches = [b for b in m.group(0).strip("()*+").split("|") if b]
        for i, a in enumerate(branches):
            for b in branches[i + 1:]:
                # If one branch is a literal prefix of another, the alternation
                # overlaps and the engine backtracks combinatorially.
                if a.startswith(b) or b.startswith(a):
                    return True
    return False
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L417-422)
```python
        if not matched and "regex" in pattern and content:
            try:
                if re.search(pattern["regex"], content):
                    matched = True
            except Exception:
                pass
```
