### Title
Unbounded `yaml.safe_load` on attacker-committed `security-patterns.yaml` enables billion-laughs/alias-expansion resource-exhaustion DoS - ([File: plugins/security-guidance/hooks/extensibility.py])

### Summary
`_read_config` reads the full contents of `.claude/security-patterns.yaml`/`.yml` with no size limit and feeds it directly into `yaml.safe_load` with no depth/alias-count guard or execution timeout. Because `security-patterns.yaml` is discovered from the project directory (a file that ships in the repo and can be committed by any contributor via PR), an attacker with only ordinary PR-write access can plant a YAML "billion laughs"/alias-expansion payload that causes memory/CPU exhaustion the moment any user runs the hook in that checkout. The `!!python/object/apply`-style tag-bypass part of the question is not valid: `yaml.safe_load` (SafeLoader) rejects those tags with a `ConstructorError`, which is a subclass of `yaml.YAMLError` and is caught cleanly by the existing `except yaml.YAMLError` handler.

### Finding Description
Call path: `load_for_session(cwd)` → `_load_user_patterns(cwd)` → `_read_config(candidate)`. [1](#0-0) 

`_read_config` opens the candidate file and does `raw = f.read()` with **no size cap** (unlike `_load_guidance`, which explicitly truncates at `GUIDANCE_MAX_BYTES`): [2](#0-1) 

For YAML files it calls `yaml.safe_load(raw)` directly, with only a `try/except yaml.YAMLError` wrapper and no timeout, no depth limit, and no restriction on alias/anchor expansion: [3](#0-2) 

`security-patterns.yaml` is discovered from `<cwd>/.claude/security-patterns.yaml`, which the module's own docstring describes as "project, committed" — i.e., ordinary repo content that ships with the checkout and is loaded automatically by `load_for_session()` before hook dispatch, with no user confirmation: [4](#0-3) [5](#0-4) 

A classic YAML alias-expansion payload (e.g. dozens of nested anchors each referencing the previous one several times — the "billion laughs" pattern) expands to gigabytes of in-memory data or takes exponential time to construct even under `SafeLoader`, because alias/anchor expansion is a core YAML feature unrelated to the "safe" tag-construction restriction. `yaml.safe_load` only restricts *which Python types* can be constructed (blocking `!!python/object/apply`); it does not bound the *size* of the constructed structure from anchors/aliases. Since there is no pre-parse byte cap and no post-parse structural cap, a small file (a few KB) can expand to an enormous in-memory object or hang the process, causing the hook invocation (and thus the surrounding Claude Code operation) to stall or be OOM-killed.

The tag-bypass half of the question is not exploitable here: `yaml.safe_load` uses `SafeLoader`, which has no constructor registered for `!!python/object/apply` and raises `yaml.constructor.ConstructorError` (a `YAMLError` subclass) on such input — caught and logged at line 194-196, returning `None` safely.

### Impact Explanation
Scoped impact is local denial-of-service: the hook process (and by extension the `PostToolUse` pattern-check path of the plugin) can hang or exhaust memory when processing an attacker-controlled `.claude/security-patterns.yaml` shipped in an untrusted/malicious repository or PR checkout. This matches a resource-exhaustion/DoS class finding — it does not grant code execution, approval bypass, or secret disclosure, but it can degrade or crash the local tool session whenever the victim opens/works in the malicious repo.

### Likelihood Explanation
Preconditions are modest and match the unprivileged-attacker model: the attacker only needs to get a `security-patterns.yaml` file into the project's `.claude/` directory (e.g., via a PR, a forked/cloned malicious repo, or a repo the victim is asked to review), and PyYAML must be installed (a common dependency). No maintainer/admin privilege, leaked keys, or social engineering beyond "get your file into the repo" is required, and the vulnerable path (`load_for_session` → `_load_user_patterns` → `_read_config`) runs automatically and unconditionally whenever the hook initializes for that `cwd`.

### Recommendation
- Cap the raw file size read in `_read_config` before parsing (mirror `GUIDANCE_MAX_BYTES`-style truncation, e.g. reject/truncate files over a few KB), since legitimate pattern files are small.
- Load YAML with alias/anchor expansion protections: use `yaml.safe_load` combined with a loader that limits the number of nodes/aliases processed (e.g., set a max alias count, or use `yaml.load` with a custom `SafeLoader` subclass that overrides `construct_mapping`/`flatten_mapping` to enforce depth/width limits), or post-parse validate that the resulting structure's total size/depth is bounded before use.
- Wrap `yaml.safe_load(raw)` in a hard timeout (e.g., via a worker thread/process with a deadline) so a pathological payload cannot hang the hook indefinitely.
- Enforce `PATTERN_MAX_RULES`-style bounds earlier — validate structural size (node count / nesting depth) immediately after parse and before iterating `data.get("patterns", [])`.

### Proof of Concept
Unit/fuzz test for `_read_config`:
1. Construct a "billion laughs"-style YAML string:
```yaml
a: &a ["x","x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: [*d,*d,*d,*d,*d,*d,*d,*d,*d,*d]
```
2. Write this to a temp `.claude/security-patterns.yaml` and call `_read_config(path)` (or `_load_user_patterns(cwd)`), asserting the call either raises within a bounded time budget (e.g., 2 seconds via `pytest-timeout` / `signal.alarm`) or returns a result whose serialized/expanded size is below a fixed cap (e.g., `sys.getsizeof`/element-count check < 10_000).
3. Expected current behavior: the test times out or consumes excessive memory, demonstrating the missing bound. Expected post-fix behavior: `_read_config` returns `None` (rejected as oversized/too-deep) quickly and deterministically.
4. Separately confirm the tag-bypass claim is inert: call `yaml.safe_load('!!python/object/apply:os.system ["id"]')` directly and assert it raises `yaml.constructor.ConstructorError`, confirming `_read_config`'s existing `except yaml.YAMLError` already handles it — no additional fix needed for that vector.

### Citations

**File:** plugins/security-guidance/hooks/extensibility.py (L13-19)
```python
Discovery, in precedence order (matching CLAUDE.md / settings.json):
  - ``~/.claude/<name>``                  (user)
  - ``<cwd>/.claude/<name>``              (project, committed)
  - ``<cwd>/.claude/<name>.local.<ext>``  (project local, gitignored)

Managed delivery via ``managed-settings.json`` is not yet supported.
Org admins can still push files to ``~/.claude/`` via MDM/GPO.
```

**File:** plugins/security-guidance/hooks/extensibility.py (L105-125)
```python
def _load_guidance(cwd: Optional[str]) -> str:
    parts = []
    for label, path in _config_paths(cwd, GUIDANCE_BASENAME):
        try:
            with open(path, encoding="utf-8") as f:
                txt = f.read().strip()
        except OSError:
            continue
        if txt:
            parts.append(f"### {label} security guidance\n{txt}")
            debug_log(f"extensibility: loaded {len(txt)} chars from {path}")
    if not parts:
        return ""
    combined = "\n\n".join(parts)
    if len(combined) > GUIDANCE_MAX_BYTES:
        debug_log(
            f"extensibility: claude-security-guidance.md combined size "
            f"{len(combined)} > {GUIDANCE_MAX_BYTES}; truncating"
        )
        combined = combined[:GUIDANCE_MAX_BYTES]
    return combined
```

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

**File:** plugins/security-guidance/hooks/extensibility.py (L171-196)
```python
def _read_config(path: str) -> Optional[Dict[str, Any]]:
    """Read a YAML or JSON config file. Returns None on missing/malformed."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except OSError:
        return None
    if not raw.strip():
        return None
    if path.endswith(".json"):
        try:
            return json.loads(raw)
        except ValueError as e:
            debug_log(f"extensibility: skipping {path}: invalid JSON: {e}")
            return None
    # YAML: import lazily so the hook works without PyYAML (JSON still works).
    try:
        import yaml  # type: ignore
    except ImportError:
        debug_log(f"extensibility: skipping {path}: PyYAML not installed (use .json)")
        return None
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError as e:  # type: ignore
        debug_log(f"extensibility: skipping {path}: invalid YAML: {e}")
        return None
```
