### Title
Byte-budget diff capping in `cap_diff_for_prompt` lets attacker-controlled padding files fully omit a dangerous file from the security review prompt - (File: `plugins/security-guidance/hooks/review_api.py`)

### Summary
`cap_diff_for_prompt` enforces a global `DIFF_TOTAL_BYTES` (400,000) budget by iterating `files` in whatever order they are handed to it and, once the running total exceeds the cap, replacing the remaining files' content with an `[omitted by security-guidance: total diff byte cap reached]` placeholder rather than proportionally truncating each file. Because the risk-based reordering (`_prioritize_diff_files`) only runs when the file count exceeds `MAX_DIFF_FILES` (30), diffs at or under that count are capped in their raw (effectively path-alphabetical, git-diff-order) sequence, so a large, low-risk file that sorts before a small dangerous file can consume the whole byte budget and cause the dangerous file's actual content to be dropped from the prompt sent to the review LLM entirely.

### Finding Description
`cap_diff_for_prompt` in [1](#0-0)  walks `files` in list order, tracking `total` bytes against `DIFF_TOTAL_BYTES`. Once `room <= 0` for a given file, its content is replaced wholesale with the omission marker — no partial content, no truncation marker inside real content, just a fixed string. This same pattern is duplicated in `_cap_files_for_prompt` in `llm.py` [2](#0-1) .

The callers only reorder files by security-relevance heuristics (`_prioritize_diff_files`) when the file count exceeds `MAX_DIFF_FILES` [3](#0-2) ; for diff sets at or below that cap, the list is passed through in the order `parse_diff_into_files` produced it (i.e., the order `git diff`/`git show` emits files, which is deterministic and generally path-sorted) directly into `cap_diff_for_prompt`/`_cap_files_for_prompt` [4](#0-3) , [5](#0-4) .

Because ordering is path-based rather than risk-based below the file-count cap, an attacker who can influence the set/paths of files changed in a session (e.g. via prompt-injected instructions from repo content, an issue, or a PR that causes Claude to also write a large low-risk file with a path that sorts earlier) can pad that file up to the 80,000-byte per-file cap (or use multiple such files) to exhaust the 400,000-byte total budget before the reviewer ever sees the bytes of the actually dangerous file. The dangerous file's diff is then replaced entirely with the omission placeholder, so the review LLM (single-shot `analyze_code_security` or the agentic investigate stage via `build_investigate_prompt`) never receives the dangerous `+` lines and cannot flag them — the Stop/commit-review/push-sweep hooks that gate on `concrete_guidance`/`vulns` being non-empty will see nothing to report and exit cleanly, silently bypassing the security review for that file.

This is distinct from — and does not require — any linguistic prompt-injection instructions embedded in the diff text itself; the "instructions" that suppress review are structural (file ordering + size), and the existing mitigation (`_prioritize_diff_files`) explicitly does not engage at this file-count range. The code comments in `_prioritize_diff_files` even acknowledge this is "a heuristic, not a guarantee," but that heuristic is bypassed for the common case of diffs at/under `MAX_DIFF_FILES`.

### Impact Explanation
This breaks the invariant that prompt assembly must not let untrusted/attacker-influenced repo content suppress review of dangerous changes. The practical effect is a silent security-control bypass: a genuinely dangerous change (e.g., a backdoor, credential exfiltration, or removed authz check) can be dropped from the reviewer's input via budget starvation, so the plugin never surfaces a finding and never blocks/exit(2)s to force remediation — matching the "Security-control bypass that silently disables or routes around blocking, review, or permission boundaries" impact class.

### Likelihood Explanation
Requires the attacker to influence the set of changed files in a single review unit (one Stop-hook fire, one commit, or one push range) such that a large low-risk file sorts before the small dangerous file and the total exceeds 400 KB, while keeping the total file count at or under 30 (`MAX_DIFF_FILES`) so the risk-based `_prioritize_diff_files` reorder never triggers. This is plausible in realistic workflows: a compromised/prompt-injected task that causes Claude to regenerate or vendor a moderately large file (lockfile-like, generated boilerplate, a large config) alongside a small malicious edit in an alphabetically-later file. It is fully deterministic and repeatable once the size/order conditions are met — no LLM randomness is involved in the capping logic itself.

### Recommendation
Apply the same security-risk scoring used in `_prioritize_diff_files` to order (or interleave/round-robin) files before applying the total-byte cap in `cap_diff_for_prompt`/`_cap_files_for_prompt`, regardless of file count, so higher-risk files are never starved by lower-risk ones. Alternatively, cap each file's contribution proportionally (e.g., `DIFF_TOTAL_BYTES / len(files)` floor per file before falling back to first-come order) so no single file can be fully omitted just because of position, and always emit a metric (already partially done via `diff_truncated`) when any file is fully omitted so operators can detect the condition.

### Proof of Concept
Unit test against `review_api.cap_diff_for_prompt`:
```python
from review_api import cap_diff_for_prompt, DIFF_TOTAL_BYTES

def test_alpha_padding_starves_dangerous_file():
    padding = "a" * (DIFF_TOTAL_BYTES - 100)  # consumes almost the whole total budget
    dangerous = "+os.system(user_input)  # backdoor"
    files = [
        ("aaa_padding.py", padding),          # sorts first alphabetically
        ("zzz_backdoor.py", dangerous),       # the actually dangerous file
    ]
    capped, dropped = cap_diff_for_prompt(files)
    backdoor_content = dict(capped)["zzz_backdoor.py"]
    # FAILS today: backdoor_content is the omission placeholder, not the
    # dangerous code — the reviewer prompt never sees it.
    assert "os.system(user_input)" in backdoor_content
```
Expected today: the assertion fails because `zzz_backdoor.py`'s content is replaced with `"[omitted by security-guidance: total diff byte cap reached]"`, demonstrating that the dangerous file/path is not present and correctly anchored after capping — confirming the invariant violation.

### Citations

**File:** plugins/security-guidance/hooks/review_api.py (L31-64)
```python
def cap_diff_for_prompt(
    files: list[tuple[str, str]],
) -> tuple[list[tuple[str, str]], int]:
    """Cap per-file and total diff bytes; return (capped_files, bytes_dropped).

    Truncation markers are written inside the content so the reviewer
    knows the file is incomplete.
    """
    out: list[tuple[str, str]] = []
    dropped = 0
    total = 0
    for fp, content in files:
        if len(content) > DIFF_PER_FILE_BYTES:
            dropped += len(content) - DIFF_PER_FILE_BYTES
            content = (
                content[:DIFF_PER_FILE_BYTES]
                + "\n... [truncated by security-guidance: file exceeds per-file byte cap]"
            )
        room = DIFF_TOTAL_BYTES - total
        if room <= 0:
            dropped += len(content)
            out.append(
                (fp, "[omitted by security-guidance: total diff byte cap reached]")
            )
            continue
        if len(content) > room:
            dropped += len(content) - room
            content = (
                content[:room]
                + "\n... [truncated by security-guidance: total diff byte cap reached]"
            )
        total += len(content)
        out.append((fp, content))
    return out, dropped
```

**File:** plugins/security-guidance/hooks/llm.py (L158-183)
```python
def _cap_files_for_prompt(files):
    """Cap per-file and total content bytes before they're packed into the
    review prompt. Returns the capped (path, content) list. Sets module-level
    _last_review_truncated_bytes to the number of bytes dropped (0 if none) so
    the Stop hook can emit a `diff_truncated` metric. Truncation markers are
    written INSIDE the content so the reviewer knows the file is incomplete.
    """
    global _last_review_truncated_bytes
    _last_review_truncated_bytes = 0
    out = []
    total = 0
    for fp, content in files:
        if len(content) > DIFF_PER_FILE_BYTES:
            _last_review_truncated_bytes += len(content) - DIFF_PER_FILE_BYTES
            content = content[:DIFF_PER_FILE_BYTES] + "\n... [truncated by security-guidance: file exceeds per-file byte cap]"
        room = DIFF_TOTAL_BYTES - total
        if room <= 0:
            _last_review_truncated_bytes += len(content)
            out.append((fp, "[omitted by security-guidance: total diff byte cap reached]"))
            continue
        if len(content) > room:
            _last_review_truncated_bytes += len(content) - room
            content = content[:room] + "\n... [truncated by security-guidance: total diff byte cap reached]"
        total += len(content)
        out.append((fp, content))
    return out
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

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1192-1201)
```python
    if len(diff_files) > 10 * MAX_DIFF_FILES:
        debug_log(f"Commit review: pathological diff ({len(diff_files)} files), skipping")
        emit_metrics({"skipped": True, "skip_reason": 31, **_base,
                      "diff_files_count": len(diff_files)})
        sys.exit(0)
    diff_files, _dropped = _prioritize_diff_files(diff_files, MAX_DIFF_FILES)
    if _dropped:
        debug_log(f"Commit review: prioritized to {len(diff_files)} files "
                  f"(dropped {_dropped} lower-risk)")
        _base = {**_base, "diff_files_dropped": _dropped}
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1824-1847)
```python
    diff_files = parse_diff_into_files(diff_output)
    if not diff_files:
        debug_log("Stop hook: no source code files in diff")
        _skip(7)

    # Mirror commit-review: hard-bail only on pathological diffs (>300 files,
    # usually a bad baseline), otherwise prioritize by security-risk path
    # tokens and review the top MAX_DIFF_FILES. Stop is the only surface for
    # uncommitted edits; the old hard-skip at >30 files dropped the 31-300
    # bucket entirely, which is where cross-file source→sink vulns hide.
    # _cap_files_for_prompt already bounds bytes downstream.
    _stop_dropped = 0
    if len(diff_files) > 10 * MAX_DIFF_FILES:
        debug_log(f"Stop hook: pathological diff ({len(diff_files)} files > "
                  f"{10 * MAX_DIFF_FILES}), skipping")
        _skip(8, diff_files_count=len(diff_files))
    if len(diff_files) > MAX_DIFF_FILES:
        diff_files, _stop_dropped = _prioritize_diff_files(
            diff_files, MAX_DIFF_FILES)
        debug_log(f"Stop hook: prioritized to {len(diff_files)} files "
                  f"(dropped {_stop_dropped} lower-risk)")

    # Filter out pre-existing content from file rewrites
    diff_files = filter_preexisting_from_diff(diff_files, cwd, baseline_sha)
```
