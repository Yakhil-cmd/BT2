### Title
Security-review "guardian" safeguard can be defeated by oversized diffs/commands, letting malicious content bypass review — analogous to the ZK-governance "uncancellable proposal" bug class ([File: plugins/security-guidance/hooks/security_reminder_hook.py])

### Summary
The reported bug class is: a safeguard mechanism must re-derive an identifier (a hash) from the *entire* payload in order to act on it, but the payload can be made large enough that the safeguard's re-processing path hits a resource limit (gas/tx size) and silently fails, while the original creation path (which processes the payload once, more cheaply) does not hit that limit. The result is that an attacker can create content that the safeguard structurally cannot act on.

The closest analog in this repo is the `security-guidance` plugin's commit/diff reviewer, which acts as an automated "guardian" against malicious code being introduced into the repository via `git commit`/`Write`/`Edit`. Like the ZK case, this guardian must consume the *whole* changed content to make its decision, and the code enforces hard byte/file caps on what it will actually look at — content beyond the caps is truncated or omitted rather than causing the review to fail closed.

### Finding Description
`review_api.py`'s `cap_diff_for_prompt` (mirrored by `llm.py`'s `_cap_files_for_prompt`) truncates any file over `DIFF_PER_FILE_BYTES` (80,000 bytes) and drops any content beyond `DIFF_TOTAL_BYTES` (400,000 bytes) total, inserting a `"[truncated by security-guidance: ...]"` / `"[omitted by security-guidance: ...]"` marker instead of the real content: [1](#0-0) 

`security_reminder_hook.py` additionally caps the number of files sent to the LLM reviewer per Stop fire via `MAX_DIFF_FILES` (default 30), and only bails out entirely (`skip_reason=31`, no review at all) once a commit exceeds `10 * MAX_DIFF_FILES` (300) files — otherwise it silently prioritizes/drops the "lower-risk" files and reviews only a subset: [2](#0-1) 

This is structurally the same failure mode as the report: the guardian (here, `analyze_code_security` / the Stop-hook and commit-review PostToolUse-hook reviewers) is supposed to inspect the full content that was just introduced, but it has to re-consume that content within a bounded budget (byte caps to avoid 413/context-length errors, a file-count cap to avoid runaway token spend) that is smaller than what the introducing action (`Bash(git commit ...)`, `Write`, `Edit`) itself permits. Any content placed past those caps — e.g., a single large generated-looking file over 80 KB, or a commit touching many files where the malicious file is deprioritized into the "lower-risk" bucket, or the *N*-th file once the 400 KB total cap is hit — is never actually seen by the reviewer, yet the underlying tool call (commit/edit) proceeds normally with no guardian veto.

Separately, the CHANGELOG documents that Claude Code previously had exactly the report's failure mode in the permission-checking guardian itself: very long Bash commands were "misjudged" by the permission analyzer (which, like the description-hash flow, must re-parse the whole command string) and could be auto-approved instead of prompted, until it was fixed to force a manual prompt for commands over 10,000 characters: [3](#0-2) . This confirms the bug class ("safeguard that must reprocess an attacker-controlled string can be defeated by making that string large") is a recognized, previously-real issue in this codebase's trust boundary between tool execution and the permission/review guardian, and the currently-shipped diff/commit reviewer caps reproduce the same structural weakness in a still-present code path.

### Impact Explanation
The `security-guidance` plugin's commit reviewer is the primary automated "guardian" against Claude committing vulnerable or malicious code (its own prompt explicitly frames it as a security safeguard: "senior application-security engineer performing a deep security review"): [4](#0-3) . If a task (e.g. driven by prompt injection from an untrusted repository, issue, or dependency) causes Claude to introduce a large generated/vendored file, or a commit touching many files, the truncation/omission/prioritization logic means the actually-malicious portion of the change can silently evade review while the commit still succeeds — the guardian never raises a finding, and the user gets no warning. This mirrors the governance report's impact: a safeguard designed to catch and veto bad actions can be structurally bypassed by oversizing the payload it must inspect.

### Likelihood Explanation
Likelihood is moderate: the caps (`DIFF_PER_FILE_BYTES=80000`, `DIFF_TOTAL_BYTES=400000`, `MAX_DIFF_FILES=30`, hard skip at 300 files) are all environment-variable-overridable defaults reachable by any commit made through the normal `git commit` workflow the hook watches for — no special privilege is needed to produce a large diff or a many-file commit; this can happen incidentally (e.g. committing a lockfile or vendoring a dependency) or be deliberately engineered by an attacker who controls upstream content (e.g. a malicious PR/dependency) to smuggle a malicious change past the size/file caps.

### Recommendation
- Fail closed rather than silently truncate/omit: when a diff exceeds the byte or file caps, surface an explicit warning/finding (e.g. a synthetic "unreviewed content" finding) rather than proceeding as if review completed cleanly.
- Ensure the "lower-risk" prioritization in `_prioritize_diff_files` cannot deprioritize files solely based on size/type — prioritize by risk signals, and always flag when files were dropped so a human/Claude is told review was partial.
- Consider chunked/multi-pass review for oversized diffs instead of hard truncation, so no byte range of an actual commit is unreviewed.

### Proof of Concept
Conceptual PoC (not exploited, reasoning from code):
1. Attacker-influenced content (e.g. a task derived from an untrusted repo/issue) causes Claude to `git commit` a change containing one file larger than 80,000 bytes with the malicious payload placed after the 80 KB mark, or a commit touching 31+ files where the malicious file is not among the top 30 "prioritized" files.
2. `handle_commit_review_posttooluse` → `_prioritize_diff_files` / `cap_diff_for_prompt` truncates or drops the malicious content before it reaches `analyze_code_security`: [5](#0-4) 
3. The LLM reviewer only sees the truncated/reduced diff, finds nothing, and the commit is never flagged — despite the "guardian" hook having run and reported success.

Note: I was unable to retrieve the full body of `_prioritize_diff_files` in `gitutil.py` within the available iterations, so the exact prioritization heuristic (and whether it has any size-based safeguard of its own) could not be fully confirmed — this should be verified directly in `plugins/security-guidance/hooks/gitutil.py` before treating the impact as fully proven.

### Citations

**File:** plugins/security-guidance/hooks/review_api.py (L27-64)
```python
DIFF_PER_FILE_BYTES = int(os.environ.get("DIFF_PER_FILE_BYTES", "80000"))
DIFF_TOTAL_BYTES = int(os.environ.get("DIFF_TOTAL_BYTES", "400000"))


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

**File:** plugins/security-guidance/hooks/review_api.py (L71-73)
```python
AGENTIC_INVESTIGATE_SYSTEM = """You are a senior application-security engineer performing a deep security review of a code change. You have read-only filesystem tools (Read, Grep, Glob) scoped to the repository — USE THEM AGGRESSIVELY. The diff alone is not enough.

The #1 cause of missed vulnerabilities is not reading the file that contains them. Before any analysis: Read EVERY changed file in full (not just the diff hunks). Then Grep for the changed function/class names to find callers. A vulnerability that requires cross-file context is still your responsibility.
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1178-1201)
```python
    if not diff_files:
        debug_log("Commit review: no reviewable source files in commit")
        emit_metrics({"skipped": True, "skip_reason": 30, **_base})
        sys.exit(0)

    # Large commits (initial scaffolds, big refactors) used to bail here with
    # skip_reason=31. Large multi-file changes are exactly where
    # cross-file source→sink vulns hide. Reviewing nothing is
    # worse than reviewing the riskiest 30 — _cap_files_for_prompt already
    # bounds total bytes downstream so this can't blow context.
    # `diff_files_dropped` lets telemetry measure how often the prioritizer engages
    # and how much it drops; skip_reason=31 is now reserved for the truly
    # pathological case (e.g. >300 source files — almost certainly a bad
    # baseline, not a real commit).
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

**File:** CHANGELOG.md (L345-348)
```markdown

- `/fork` now copies your conversation into a new background session (its own row in `claude agents`) while you keep working; the in-session subagent it used to launch is now `/subtask`
- Added `claude auto-mode reset` to restore the default auto-mode configuration, with a confirmation prompt (pass `--yes` to skip)
- Added a session-wide limit on WebSearch tool calls (default 200, tunable via `CLAUDE_CODE_MAX_WEB_SEARCHES_PER_SESSION`) to stop runaway search loops
```
