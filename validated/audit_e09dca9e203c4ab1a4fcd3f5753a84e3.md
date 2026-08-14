### Title
`_has_redos_structure()` ReDoS heuristic bypassable via nested/adjacent quantified groups, allowing malicious `security-patterns.yaml` regex to hang `check_patterns()` - ([File: plugins/security-guidance/hooks/extensibility.py])

### Summary
`_has_redos_structure()` only recognizes two flat, non-nested shapes (`_REDOS_SHAPES`) and a flat alternation-prefix-overlap heuristic (`_ALT_UNDER_REP`), all of which require the offending group to contain **no inner parentheses** (`[^()]*`). A regex whose catastrophic-backtracking structure is hidden one level deeper — e.g. an outer repeated group wrapping two or more adjacent unbounded-quantifier subgroups, such as `((a+)(a+))+` — contains no character that trips either check, yet still exhibits classic exponential backtracking, letting an attacker's rule pass `_validate_pattern` and later hang `re.search()` in `check_patterns()`.

### Finding Description
`_validate_pattern` (extensibility.py:199-244) calls `_has_redos_structure(regex)` (extensibility.py:224) before accepting a user-supplied rule from `security-patterns.yaml`. The heuristic (extensibility.py:262-289) is:
- `_REDOS_SHAPES[0]`: `\([^()]*[+*][^()]*\)[+*?]` — matches only a single, non-nested group directly followed by a quantifier.
- `_REDOS_SHAPES[1]`: `\(\.\*[^()]*\)[+*]` — same restriction for wildcard groups.
- `_ALT_UNDER_REP`: matches only a single-level `(a|b)` group (again `[^()]*`, no inner parens) followed by a quantifier, then checks for literal-prefix overlap between branches.

All three regexes explicitly forbid parentheses inside the matched span. Consequently, any classic catastrophic-backtracking shape that is expressed with more than one nesting level, or as **adjacent** (not nested) quantified subgroups inside an outer repeated group, is invisible to the heuristic. For example `((a+)(a+))+`:
- The outer group `((a+)(a+))` contains nested parens, so it can never match `_REDOS_SHAPES` (which requires `[^()]*` content).
- The inner groups `(a+)` are each followed by another group, not directly by `+`/`*`, so they don't match `_REDOS_SHAPES` either.
- There is no alternation, so `_ALT_UNDER_REP` never fires.

Yet `((a+)(a+))+` (and equivalent shapes such as `(a+a+)+`, `((a*)(a*))+`, or bounded-repetition variants using `{n,m}` instead of literal `+`/`*`, which the heuristic doesn't scan for at all since it only looks for the literal characters `+`/`*`) is a well-known catastrophic-backtracking pattern: on a non-matching input like `"a"*30 + "b"`, `re.search` exhibits exponential run time. The rule is accepted, stored via `_load_user_patterns` → `user_patterns()`, and used later by `check_patterns()` (`security_reminder_hook.py`) which runs `re.search(pattern['regex'], content)` against every file written in the PostToolUse hook, with no compiled-pattern timeout or wall-clock guard visible in this code path.

### Impact Explanation
Because the PostToolUse hook is invoked on essentially every file edit, a single malicious rule committed to `.claude/security-patterns.yaml` (or its `.local` variant) causes `re.search` to hang indefinitely (exponential in input length) on any subsequent edit whose content triggers the pathological backtracking. This is a denial of the security-gate hook itself — matching the "hook-availability DoS" impact class: the pattern-based guard becomes unusable/unresponsive for the whole session, and any workflow depending on the hook completing (e.g., blocking on a warning) stalls.

### Likelihood Explanation
The precondition is that an attacker can get content into `.claude/security-patterns.yaml`, `.yml`, or `.json` under the project (or its `.local` variant) — e.g., via a malicious PR that a maintainer merges, or a repo the user opens that ships such a file. This is the same trust boundary the file already assumes review is needed for pattern rules, but the code's own stated intent ("Custom regexes are validated at load for catastrophic-backtracking structure and skipped... if they look ReDoS-prone") is not actually enforced against this whole class of shapes, so the check gives false confidence. No special privilege beyond adding/merging a config file is required, and the crash is fully repeatable/deterministic given the crafted input content.

### Recommendation
- Replace the purely syntactic heuristic with an actual runtime guard: compile and execute user-supplied regexes with a hard timeout (e.g., `signal.alarm`, a subprocess with a wall-clock limit, or the `regex` module's timeout support) before/while using them in `check_patterns()`, rather than relying solely on static shape-matching.
- If a static heuristic is still desired as an additional layer, recursively strip/normalize nested groups so `[^()]*`-based detection is applied at every nesting depth, and also flag adjacent (not just nested) unbounded-quantifier subgroups sharing overlapping character classes, and extend detection to `{m,n}` bounded quantifiers, not just literal `+`/`*`.
- Enforce a hard cap on regex length/complexity and always execute `re.search` against a length-bounded content window with a timeout, defense-in-depth against any future heuristic gaps.

### Proof of Concept
```python
import re, time
from plugins.security_guidance.hooks.extensibility import _has_redos_structure

evil = r"((a+)(a+))+b"
assert _has_redos_structure(evil) is False  # heuristic fails to flag it

payload = "a" * 32 + "c"  # does not match trailing 'b'
start = time.time()
re.search(evil, payload)  # hangs / exponential time
elapsed = time.time() - start
assert elapsed < 1.0, f"ReDoS: match took {elapsed}s on {len(payload)}-byte input"
```
Expected result: `_has_redos_structure` returns `False` (bypass confirmed), and the `re.search` call exceeds the 1-second budget by orders of magnitude as input length grows linearly, demonstrating that a rule using this shape — once accepted through `_validate_pattern` — will hang `check_patterns()` on any file content matching the pattern's non-matching prefix, denying the PostToolUse hook.