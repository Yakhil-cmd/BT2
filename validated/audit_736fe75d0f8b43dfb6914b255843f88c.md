### Title
Amend delta-review in `_resolve_amend_pre_sha` skips previously-unreviewed pre-amend content, permanently hiding it from security review - (File: `plugins/security-guidance/hooks/security_reminder_hook.py`)

### Summary
`_resolve_amend_pre_sha` decides to review only the `pre_amend_sha..post_amend_sha` delta of a `git commit --amend`, instead of the full commit diff, based solely on reflog subject checks (`commit (amend)`) and a cross-repo SHA match. It never verifies that `pre_amend_sha` was itself previously reviewed by this hook (i.e., present in `.git/sg-reviewed-shas`). Any commit that reaches `HEAD` without going through a successful security-guidance review and is subsequently amended will have its unchanged, still-present dangerous content excluded from review forever, and the amended SHA gets recorded as "reviewed," which also short-circuits the push-sweep.

### Finding Description
In `handle_commit_review_posttooluse` [1](#0-0) , when a single non-chained `git commit --amend` is detected, `_resolve_amend_pre_sha(repo_root, expected_post_sha=shas[0])` is called to find the pre-amend SHA via reflog. The function's only checks are: HEAD@{0}'s reflog subject starts with `commit (amend)`, HEAD@{1} is not itself an amend, and `expected_post_sha` prefix-matches HEAD@{0} (cross-repo guard) [2](#0-1) . It never consults `_load_reviewed_shas(repo_root)` to confirm the returned `pre_amend_sha` was actually reviewed by this tool before.

When `pre_amend_sha` is returned, the caller runs `git diff pre_amend_sha sha` instead of `git show -p sha` [3](#0-2) . `git diff` only shows what changed *between the two commits*, whereas `git show -p` on the post-amend commit would show the diff against its parent (typically unchanged by amend), which would include any dangerous content already baked into the pre-amend commit. The design rationale explicitly assumes the pre-amend content was "already reviewed on the original commit" [4](#0-3) , but this assumption is never checked.

Realistic ways a commit can reach `HEAD` without ever being reviewed by this hook include: `COMMIT_REVIEW_ENABLED` false at the time, missing API credentials, `api.anthropic.com` unreachable, hourly rate limit hit, or `skip_reason` paths such as 21/23/24/25/26/28/32/33 in `handle_commit_review_posttooluse` [5](#0-4) , or a commit made before the plugin was enabled/installed in the clone, or pulled in from another contributor. Once such an unreviewed dangerous commit sits at `HEAD`, a subsequent ordinary `git commit --amend` (e.g., fixing a typo in the message or an unrelated trivial edit) causes the delta-only path to review only the trivial change, while the dangerous code — still present, unchanged — never gets sent to `analyze_code_security`. The post-amend SHA is then appended to `.git/sg-reviewed-shas` via `_append_reviewed_shas`, permanently marking it reviewed and also causing push-sweep (which trusts the same reviewed-shas file to advance its diff base [6](#0-5) ) to skip it as well.

### Impact Explanation
Dangerous code that was never actually security-reviewed becomes durably marked "reviewed" and is excluded from the Stop hook, commit-review, and push-sweep surfaces for the remainder of the clone's lifetime, allowing it to be committed, pushed, and executed without ever forcing the exit-code-2 "wake"/block path that Claude Code's security-guidance relies on to keep the agent honest about dangerous actions. This effectively lets an attacker (via prompt injection, malicious task instructions, or a pre-seeded malicious commit) achieve local command/code execution that bypasses the intended review/approval gate — matching the "unauthorized local command execution that bypasses Claude Code approval or deny controls" impact class, scoped to the security-guidance hook's own guarantees.

### Likelihood Explanation
The precondition (an unreviewed commit reaching `HEAD`, followed by a normal, single, non-chained `git commit --amend`) is common in ordinary workflows — rate limits, transient network failures, disabled review mode, or commits made before the plugin was active are all plausible without any special privilege. The exploit requires no admin/maintainer rights, no key leakage, and no social engineering beyond normal repository/task content driving Claude to run `git commit --amend`. It is fully reproducible with a deterministic reflog-based test.

### Recommendation
In `_resolve_amend_pre_sha`, before returning `pre_amend_sha`, additionally verify that `pre_amend_sha` is present in `_load_reviewed_shas(repo_root)` (or otherwise known to have been fully reviewed). If it is not, return `None` so the caller falls back to the full `git show -p` review of the post-amend commit.

### Proof of Concept
Integration test plan (pytest-style, using a scratch git repo):
1. Init a repo, disable `COMMIT_REVIEW_ENABLED` (or otherwise avoid triggering review), and commit a file containing an obviously dangerous pattern (e.g., `eval(input())`) — assert `.git/sg-reviewed-shas` does NOT contain this SHA.
2. Re-enable `COMMIT_REVIEW_ENABLED` / satisfy all gating conditions, then simulate a Bash `git commit --amend -m "typo fix"` PostToolUse event through `handle_commit_review_posttooluse`, with `tool_response.stdout` containing a normal `[branch sha]` + diffstat line.
3. Assert that `_resolve_amend_pre_sha` returns the prior dangerous SHA (since reflog-only checks pass) and that the resulting `diff_files` passed to `analyze_code_security` do NOT contain the `eval(input())` line.
4. Assert that after the hook runs, the post-amend SHA is written to `.git/sg-reviewed-shas`, and that a subsequent push-sweep pass treats the dangerous commit range as fully covered/skipped.
5. Expected (fixed) behavior: `_resolve_amend_pre_sha` should return `None` because the pre-amend SHA is not in `_load_reviewed_shas`, forcing a full `git show -p` review that surfaces the `eval(input())` finding and blocks/warns as intended.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L517-573)
```python
def _resolve_amend_pre_sha(repo_root, expected_post_sha=None):
    """For a `git commit --amend` we just ran, return the pre-amend SHA via
    reflog, or None if it can't be safely determined.

    expected_post_sha: the post-amend SHA the caller parsed from bash stdout
    (or reflog). If provided, HEAD@{0} of `repo_root` must match it (prefix
    compare — bash stdout SHAs are abbreviated, reflog %H is 40 chars) before
    we trust the reflog-derived pre-amend SHA. This guards against the
    cross-repo case (`cd ../other && git commit --amend && cd -`) where
    `repo_root` happens to have its own recent amend that's unrelated to
    the bash command we're reviewing.

    We require HEAD@{0}'s reflog subject to start with `commit (amend)` —
    otherwise our `--amend` regex matched something that didn't actually
    perform an amend (e.g., `git commit --amend --dry-run`, aliased commands,
    aborted amends), and HEAD@{1} would be the wrong commit. Also requires
    HEAD@{1} to NOT itself be an amend, since back-to-back amends would have
    HEAD@{1} as the previous-amend's post state — the original commit we
    want to compare against is then HEAD@{2}, but at that point we're
    reaching and fall back to a full review.

    Bytes + decode('utf-8', errors='replace'): reflog subjects embed commit
    subjects, which git stores as raw bytes (commit messages may be latin-1
    / cp1252 / etc.). text=True would raise UnicodeDecodeError (a
    ValueError, not OSError) on non-UTF8 bytes and crash the hook.
    """
    if not repo_root:
        return None
    try:
        r = subprocess.run(
            [*GIT_CMD, "log", "-g", "-2", "--format=%H|%gs", "HEAD"],
            cwd=repo_root, capture_output=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    if r.returncode != 0:
        return None
    stdout_text = r.stdout.decode("utf-8", errors="replace")
    lines = [ln for ln in stdout_text.splitlines() if "|" in ln]
    if len(lines) < 2:
        return None
    head0_sha, _, head0_subj = lines[0].partition("|")
    head1_sha, _, head1_subj = lines[1].partition("|")
    if not head0_subj.startswith("commit (amend)"):
        return None
    if head1_subj.startswith("commit (amend)"):
        return None
    # Cross-repo guard: the post-amend SHA the caller is about to review must
    # match HEAD@{0} of repo_root. Otherwise the bash command was likely run
    # in a different repo than repo_root, and the reflog we just read is
    # unrelated. Prefix-compare: expected_post_sha is typically the 7-char
    # abbreviated SHA captured from bash stdout by _COMMIT_SHA_RE (git's
    # default core.abbrev floor), while head0_sha is the full 40-char %H —
    # strict equality would always fail and silently disable the delta path.
    if expected_post_sha and not head0_sha.startswith(expected_post_sha):
        return None
    return head1_sha or None
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L999-1023)
```python
    if not COMMIT_REVIEW_ENABLED:
        debug_log("Commit review: disabled, skipping")
        emit_metrics({"skipped": True, "skip_reason": 32, **_base})
        sys.exit(0)

    if not ENABLE_CODE_SECURITY_REVIEW or not HAS_API_CREDENTIALS:
        debug_log("Commit review: LLM review disabled or no API credentials")
        emit_metrics({"skipped": True, "skip_reason": 22, **_base})
        sys.exit(0)

    if not ensure_anthropic_reachable():
        debug_log("Commit review: api.anthropic.com unreachable")
        emit_metrics({"skipped": True, "skip_reason": 24, **_base})
        sys.exit(0)

    if not cwd:
        debug_log("Commit review: no cwd")
        emit_metrics({"skipped": True, "skip_reason": 25, **_base})
        sys.exit(0)

    repo_root = _git_toplevel(cwd)
    if not repo_root:
        debug_log("Commit review: not in a git repo")
        emit_metrics({"skipped": True, "skip_reason": 26, **_base})
        sys.exit(0)
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1064-1070)
```python
    # `git commit --amend`: review only the delta added by the amend
    # (pre-amend..post-amend) instead of the full amended commit. Without this,
    # the amend re-reviews the entire commit including code already reviewed
    # on the original commit, costing 30-60s of LLM time and re-flagging
    # findings the user may have just amended IN ORDER TO fix. Pre-amend
    # SHA comes from the reflog and is validated to be an amend (see
    # _resolve_amend_pre_sha) — otherwise we fall back to full-commit review.
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1100-1111)
```python
    is_amend = bool(_GIT_AMEND_RE.search(command))
    commit_invocations = len(_GIT_COMMIT_RE.findall(command))
    pre_amend_sha = None
    if (is_amend and not _reflog_shas and len(all_shas) <= 1
            and commit_invocations <= 1):
        pre_amend_sha = _resolve_amend_pre_sha(repo_root, expected_post_sha=shas[0])
    if is_amend and pre_amend_sha:
        _base = {**_base, "amend_delta_review": True}
        debug_log(
            f"Commit review: --amend detected; reviewing delta "
            f"{pre_amend_sha[:12]}..{shas[-1][:12]}"
        )
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1117-1132)
```python
    diff_files = []
    resolved = 0
    for sha in shas:
        try:
            if pre_amend_sha:
                # Delta review: pre-amend → post-amend. `git diff` (not show)
                # so the output is a pure unified diff with no commit header.
                result = subprocess.run(
                    [*GIT_CMD, "diff", "--no-color", "--no-ext-diff", pre_amend_sha, sha, "--"],
                    cwd=repo_root, capture_output=True, timeout=15
                )
            else:
                result = subprocess.run(
                    [*GIT_CMD, "show", "-p", "--no-color", "--no-ext-diff", sha, "--"],
                    cwd=repo_root, capture_output=True, timeout=15
                )
```

**File:** plugins/security-guidance/hooks/diffstate.py (L207-221)
```python
# ─── push-sweep reviewed-commit tracking ────────────────────────────────────
#
# Repo-local (not session-local) record of which commits the commit-review
# hook has already reviewed, so the push-sweep can advance its diff base past
# the contiguous reviewed prefix and skip entirely when everything pushed was
# already covered. Lives under `.git/` (same precedent as CC's
# `.git/claude-trailers`) so it survives across sessions and is per-clone.
#
# Format: one line per reviewed sha, append-only:
#   <40-hex-sha>\t<unix-ts>\t<pv>\t<vulns_found>
#
# The trailing columns are observability only — load reads just the sha set.
# GC keeps the last _REVIEWED_SHAS_CAP entries; the file is small (~64 bytes
# per line) so even at the cap it's ~32KB.

```
