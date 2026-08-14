### Title
Commit-review dedup-by-path silently drops the diff of an earlier commit's vulnerable file when a later commit incidentally touches the same file - (`plugins/security-guidance/hooks/security_reminder_hook.py`)

### Summary
`handle_commit_review_posttooluse` deduplicates `diff_files` "by path, keep first occurrence" on the assumption that the newest commit's `git show -p <sha>` output for a given path is a complete/superset view of all changes to that file. That assumption only holds for `--amend` (same parent), not for two independent sequential commits, so the vulnerable content added by the earlier commit can be entirely dropped from what is sent to the LLM reviewer.

### Finding Description
When commit stdout is suppressed (e.g. `-q`/redirection), `handle_commit_review_posttooluse` falls back to the reflog scanner `_git_reflog_recent_commits`, which returns `fresh` SHAs newest-first [1](#0-0) . For a chained Bash call like `git commit -m "add vuln" -q && git commit -m "unrelated tweak" -q` touching the same file twice, `shas` ends up `[sha_b, sha_a]` (newest first) [2](#0-1) .

Because `_reflog_shas` is non-empty, the amend-delta path is explicitly skipped ("guard 1" in the comment) [3](#0-2) , so each SHA is independently `git show -p`'d against its own immediate parent [4](#0-3) . For two ordinary sequential commits (not an amend), `git show -p sha_b` yields only the *incremental* diff of `sha_b` vs `sha_a` — it does NOT include the vulnerable lines that `sha_a` introduced (they are unchanged context or entirely outside the hunk for `sha_b`). The subsequent dedup keeps only the first-seen entry per file path: [5](#0-4) 

Since `shas` is `[sha_b, sha_a]`, `sha_b`'s (mostly benign, incremental) diff for the shared file path is processed first and wins; `sha_a`'s diff — which is the one actually containing the newly introduced vulnerable code — is discarded outright because `fp` was already `_seen`. The comment justifying this ("the first occurrence is the most recent version of the file — keep it") is true only for `--amend`, where the amend's parent equals the original commit's parent so its diff is a full superset. It is false for two independent commits sharing a file, where each `git show -p` diff is a disjoint incremental slice, not a cumulative rewrite.

No existing guard catches this: the "3 guards" documented above (`not _reflog_shas`, `len(all_shas) <= 1`, `commit_invocations <= 1`) only gate the amend-delta optimization, not the unconditional post-loop path-dedup, which runs whenever `len(shas) > 1` regardless of whether the commits are related by amend or are independent commits.

### Impact Explanation
This causes the automated LLM commit-security-reviewer to never see the diff hunk that actually introduced a vulnerability, as long as a second commit in the same chained Bash call touches the same file elsewhere. This is a security-control-bypass: a plugin/PR/repo-content-driven prompt that gets Claude to run two quiet, chained commits touching a shared file can suppress the intended commit-review protection for the vulnerable commit's content, letting insecure code land without the intended LLM flag/exit(2) rewake. This matches "trust-boundary bypass of a security review gate" impact.

### Likelihood Explanation
Requires: (1) commit-review reflog fallback to trigger, i.e., both commits' `[branch sha]` stdout suppressed (`-q`, pipe, redirect — a common and unremarkable pattern), and (2) two commits in the same chained Bash invocation that both touch a common file. Neither condition requires elevated privilege — any content that steers Claude into running a compound `git commit -q ... && git commit -q ...` sequence (e.g., via a crafted commit-message/workflow suggestion embedded in repo docs, an issue, or a plugin) can trigger it. It is deterministic once the preconditions are met, not a low-probability race.

### Recommendation
Do not dedup purely by "first occurrence keeps the newest" for the reflog multi-SHA path unless the SHAs are verified to be amend-of-each-other (same parent chain). Instead, either: (a) merge/concatenate diffs for the same path across all SHAs rather than dropping any, or (b) diff each earlier SHA fully against a common ancestor / the working tree rather than its own immediate parent so each per-SHA diff is a true cumulative view, or (c) restrict the current dedup-and-keep-first behavior strictly to the case where `sha[i].parent == sha[i+1]` truly forms a linear amend/rewrite chain, falling back to reviewing full concatenated hunks otherwise.

### Proof of Concept
Unit test plan (pytest, monkeypatching `subprocess.run` used inside `handle_commit_review_posttooluse`):

1. Monkeypatch `_git_reflog_recent_commits` to return `(["sha_b", "sha_a"], 0)` and `_load_reviewed_shas` to return `set()`, forcing the reflog fallback path with `shas = ["sha_b", "sha_a"]`.
2. Monkeypatch the `git show -p` subprocess calls so that:
   - `sha_b` → returns a diff for `app/handler.py` that only touches an unrelated line (e.g. adds a comment), no vulnerable code.
   - `sha_a` → returns a diff for `app/handler.py` that introduces a vulnerable pattern (e.g. `os.system(user_input)`).
3. Call `handle_commit_review_posttooluse` (or directly exercise the dedup block with `diff_files = parse_diff_into_files(sha_b_diff) + parse_diff_into_files(sha_a_diff)` and `shas = ["sha_b", "sha_a"]`).
4. Assert: currently, `diff_files` after dedup contains only the `sha_b` (benign) content for `app/handler.py` and the `os.system(user_input)` line from `sha_a` is absent — demonstrating the vulnerable diff is dropped rather than merged/preserved.
5. Expected (fixed) behavior: the deduped `diff_files` for `app/handler.py` must include the vulnerable line from `sha_a`'s diff (either by keeping both hunks concatenated or by diffing cumulatively), i.e., `"os.system(user_input)" in dict(diff_files)["app/handler.py"]` should be `True`.

### Citations

**File:** plugins/security-guidance/hooks/gitutil.py (L273-300)
```python
    fresh, stale = [], 0
    for idx, line in enumerate(r.stdout.splitlines()):
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        sha, ct, subject = parts
        # `commit: msg`, `commit (amend): msg`, `commit (initial): msg`,
        # `commit (merge): msg` — all create a reviewable commit object.
        if not subject.startswith("commit"):
            continue
        try:
            age = now - int(ct)
        except ValueError:
            continue
        # HEAD@{0} (idx==0) is exempt from the age gate. The gate exists to
        # bound the WIDENED HEAD@{1..max_n-1} scan from picking up commits
        # made by *prior* Bash calls; HEAD@{0} is by definition the most
        # recent reflog entry and was previously accepted unconditionally
        # (_git_reflog_head_if_just_committed previously had no age check).
        # Applying max_age_s to idx==0 made the not-yet-visible-HEAD skip
        # noticeably more frequent on chained
        # `git commit && <slow command>` where %ct is >120s old by the
        # time the async PostToolUse hook fires.
        if idx == 0 or age <= max_age_s:
            fresh.append(sha)
        else:
            stale += 1
    return fresh, stale
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1040-1051)
```python
    if _reflog_shas:
        # Output-based detection already failed above; the reflog SHAs are the
        # authoritative ones. Don't re-parse bash_output here — any bracketed
        # token it contains is by construction NOT the `[branch sha]` line
        # (or commit_succeeded would have been True via the fast path). The
        # list is newest-first and may contain >1 entry when a single Bash
        # call made multiple commits (`git commit -m a && git commit -m b`);
        # all are reviewed.
        shas = _reflog_shas
    else:
        all_shas = _COMMIT_SHA_RE.findall(bash_output)
        shas = [all_shas[-1]] if all_shas else []
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1079-1091)
```python
    # 1. `not _reflog_shas`: reflog fallback path was taken (both commits'
    #    bash output suppressed via -q / pipe / redirect). The multi-SHA scan
    #    already populates `shas` with every fresh commit (amend + any
    #    pre-amend WIP) and the loop below `git show`s each, so coverage is
    #    correct without delta — and the delta path doesn't compose with a
    #    multi-SHA `shas` list (it would diff every entry against the same
    #    pre-amend SHA). Losing the 30-60s saving on the reflog-fallback
    #    fraction is an acceptable trade.
    #
    # 2. `len(all_shas) <= 1`: both commits visible (no -q). Two `[branch
    #    sha]` lines in bash_output → all_shas len 2. Only defined on the
    #    bash-output path; short-circuit ordering keeps it unevaluated when
    #    `_reflog_shas` is non-empty.
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1119-1145)
```python
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
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            _cmd = "git diff" if pre_amend_sha else "git show"
            debug_log(f"Commit review: {_cmd} {sha} error: {e}")
            continue
        if result.returncode != 0:
            # SHA not in this repo (cross-repo commit) or already gc'd. Better
            # to skip than to fall back to HEAD and review the wrong commit.
            _cmd = "git diff" if pre_amend_sha else "git show"
            debug_log(f"Commit review: {_cmd} {sha} rc={result.returncode}")
            continue
        resolved += 1
        diff_files.extend(parse_diff_into_files(
            result.stdout.decode("utf-8", errors="replace")))
```

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L1147-1157)
```python
    # Dedup by path. The widened reflog scan can return >1 SHA (e.g.
    # `git commit && git commit --amend` within 120s); a path that appears in
    # both diffs would consume two MAX_DIFF_FILES slots and be re-analyzed.
    # `shas` is newest-first so the first occurrence is the most recent
    # version of the file — keep it.
    if len(shas) > 1:
        _seen = set()
        diff_files = [
            (fp, c) for fp, c in diff_files
            if not (fp in _seen or _seen.add(fp))
        ]
```
