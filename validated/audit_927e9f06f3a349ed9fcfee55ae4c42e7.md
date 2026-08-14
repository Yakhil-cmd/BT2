### Title
Deterministic, attacker-predictable file-priority scoring lets a diff-file bypass the automated Stop-hook security review - ([File: plugins/security-guidance/hooks/gitutil.py])

### Summary
The `security-guidance` plugin's Stop-hook security review truncates over-cap diffs using a fixed, publicly-known scoring heuristic (`_prioritize_diff_files`) before sending files to the LLM reviewer. Because the scoring rules (risk-token list, low-priority suffix/path lists) are static and inspectable in the shipped plugin source, an attacker who controls file naming/paths within a session's diff can deliberately keep a malicious change's score low so it is excluded from the review, exactly mirroring the SEDA bug class where a deterministic sort/allocation order can be gamed by a participant who controls the sorted key.

### Finding Description
`_prioritize_diff_files` caps the files sent to the security-review LLM when a diff exceeds `MAX_DIFF_FILES`, ranking files by a tuple `(risk_tokens_in_path, not_low_priority, added_lines)` and keeping only the top-`cap` entries — the rest are silently dropped from review: [1](#0-0) 

The scoring inputs are static, fully known lists shipped in the plugin itself: a fixed set of "risky" path substrings that raise a file's score, [2](#0-1) 
and fixed suffix/path patterns that push a file to the back of the priority order regardless of its actual content: [3](#0-2) 

Because these lists are deterministic and visible to anyone who can read the open-source plugin, a change author (an unprivileged contributor whose commits/diff feed the Stop-hook review) can choose file paths/names that avoid every token in `_SECURITY_RISK_PATH_TOKENS` and instead match a `_LOW_PRIORITY_SUFFIXES`/`_LOW_PRIORITY_PATH_TOKENS` pattern (e.g. naming a sensitive handler `foo.gen.ts`, or placing it under a `/migrations/`-style path token), while padding an over-cap diff with many other files. The ranking function then always sorts the crafted malicious file toward the bottom, causing it to be excluded from the top-`cap` set and never reach the LLM vulnerability scan — analogous to the SEDA report's executors/proxies choosing keys that always sort first to be prioritized: here the attacker chooses a path that always sorts last, to be de-prioritized out of the review.

### Impact Explanation
This directly undermines the trust boundary the security-guidance plugin is meant to enforce: the Stop-hook LLM review is Claude Code's last line of automated defense that forces Claude to "continue and address findings" before ending a turn. If a crafted file is deterministically excluded from that review because of a known, static scoring function, a malicious or vulnerable change (e.g., introducing a hardcoded secret, command injection, or auth bypass) can slip through undetected in large diffs, which is exactly the scenario `_prioritize_diff_files` is meant to triage, not bypass entirely.

### Likelihood Explanation
Exploitability requires only (a) knowledge of the static, open-source scoring tables (trivially available since this is a public repo) and (b) the ability to shape file paths/names and diff size within a session — both realistic for any contributor whose changes are diffed and reviewed by this plugin, especially in large auto-generated or multi-file commits that already exceed the cap. No privileged access or race condition is needed, only awareness of the fixed heuristic.

### Recommendation
Do not rely on a static, attacker-visible token list as the sole gate for which files get reviewed under a cap. Consider: (1) never fully dropping files past the cap — instead batch/review all files across multiple LLM calls; (2) randomizing tie-breaking or adding non-deterministic/content-based signals (e.g., actual diff semantics, entropy/secret-scanning heuristics) so the ranking cannot be reliably predicted or gamed from the source alone; (3) logging/flagging when files are dropped due to the cap so users know some changes were not reviewed automatically, matching the docstring's own dropped-count tracking to a visible warning rather than silent exclusion.

### Proof of Concept
1. Prepare a diff exceeding `MAX_DIFF_FILES` (as enforced in `security_reminder_hook.py`) with dozens of trivial filler files.
2. Introduce the malicious change in a file whose path avoids every token in `_SECURITY_RISK_PATH_TOKENS` and matches a `_LOW_PRIORITY_SUFFIXES`/`_LOW_PRIORITY_PATH_TOKENS` pattern (e.g., `src/widgets/exfil.config.js` or `src/migrations/0001_leak.py`). [4](#0-3) 
3. Trigger the Stop hook; `_prioritize_diff_files` ranks and truncates the file set, and because the malicious file scores lowest, it is dropped from the top-`cap` files sent to the LLM reviewer. [5](#0-4) 
4. The Stop-hook security review completes without ever inspecting the malicious file's content, allowing the introduced vulnerability to pass unreviewed.

### Citations

**File:** plugins/security-guidance/hooks/gitutil.py (L486-509)
```python
_SECURITY_RISK_PATH_TOKENS = (
    "auth", "login", "session", "token", "secret", "credential", "perm",
    "acl", "rbac", "iam", "policy",
    "route", "handler", "controller", "endpoint", "api/", "/api", "gateway",
    "middleware", "view",
    "exec", "subprocess", "shell", "spawn", "command",
    "client", "request", "fetch", "http", "url",
    "serialize", "pickle", "yaml", "parse", "deser",
    # Short tokens that would substring-match unrelated names (`format`,
    # `transform`, `sandbox`, `platform`) are intentionally omitted —
    # `sql`/`query` already cover the DB surface.
    "sql", "query",
)
# Suffixes that pass _is_reviewable_source but are almost always low-signal
# in large scaffolds — generated clients, migrations, test fixtures, config
# shims. These go to the BACK of the priority sort, not dropped outright.
_LOW_PRIORITY_SUFFIXES = (
    ".gen.ts", ".gen.tsx", ".generated.ts", "_gen.py",
    ".test.ts", ".test.tsx", ".test.py", ".spec.ts", ".spec.js",
    ".config.js", ".config.ts", ".config.mjs", ".config.cjs",
)
_LOW_PRIORITY_PATH_TOKENS = (
    "/migrations/", "/alembic/versions/", "/__tests__/", "/fixtures/",
)
```

**File:** plugins/security-guidance/hooks/gitutil.py (L512-547)
```python
def _prioritize_diff_files(diff_files, cap):
    """When `diff_files` exceeds `cap`, return the top-`cap` by security
    relevance plus the count dropped. Otherwise return (diff_files, 0).

    Score = (risk_tokens_in_path, not_low_priority, added_lines). The
    added-lines proxy is `content.count('\\n+')` which counts diff additions
    cheaply without re-parsing hunks. This is a heuristic, not a guarantee —
    the goal is to review the likely-dangerous subset of an over-cap diff
    instead of reviewing nothing. Diffs that exceed the cap are typically
    large multi-file scaffolds, and the cross-file source→sink vulnerabilities
    in them concentrate in a handful of api/client/route files.
    """
    if len(diff_files) <= cap:
        return diff_files, 0

    def _score(item):
        fp, content = item
        low = fp.lower()
        # Prepend "/" so leading-slash patterns in _LOW_PRIORITY_PATH_TOKENS
        # match top-level dirs (git diff paths are repo-root-relative, e.g.
        # `migrations/001.py` not `/migrations/001.py`). Same trick as
        # _is_reviewable_source.
        low_slashed = "/" + low
        risk = sum(1 for t in _SECURITY_RISK_PATH_TOKENS if t in low)
        low_prio = (
            fp.endswith(_LOW_PRIORITY_SUFFIXES)
            or any(t in low_slashed for t in _LOW_PRIORITY_PATH_TOKENS)
        )
        # added_lines: count('\n+') over-counts by including '+++' header and
        # any literal '+' at line start in context, but it's a consistent
        # ordinal across files in the same diff which is all we need.
        added = content.count("\n+")
        return (risk, not low_prio, added)

    ranked = sorted(diff_files, key=_score, reverse=True)
    return ranked[:cap], len(diff_files) - cap
```
