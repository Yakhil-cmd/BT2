### Title
Reflog-fallback commit review can be evicted from its 5-entry scan window by decoy commits, permanently skipping review of an attacker's quiet commit - ([File: plugins/security-guidance/hooks/security_reminder_hook.py])

### Summary
`handle_commit_review_posttooluse`'s reflog fallback (`_git_reflog_recent_commits` in `gitutil.py`) only scans the last `max_n=5` HEAD reflog entries when the triggering `git commit`'s stdout is suppressed. Because the fallback runs asynchronously (`asyncRewake`) and can be dispatched after additional commits have already landed, an attacker who issues a quiet commit followed by ≥5 additional (loud) commits before the fallback fires can push the quiet commit's reflog entry entirely out of the scanned window, so it is never classified as fresh or stale and is silently never reviewed, while the decoy commits are reviewed via their own normal PostToolUse invocations.

### Finding Description
In `handle_commit_review_posttooluse` (`plugins/security-guidance/hooks/security_reminder_hook.py`, lines 965-989), when a `git commit` command's Bash output lacks the `[branch sha]` success marker (e.g. quieted with `-q`, piping, or redirection), the hook falls back to `_git_reflog_recent_commits(_root)`: [1](#0-0) 

`_git_reflog_recent_commits` (`gitutil.py`, lines 227-300) runs `git log -g -n 5 --format=%H|%ct|%gs HEAD` — i.e. it only ever looks at the 5 most recent reflog entries: [2](#0-1) 

Because commit-review is dispatched as `asyncRewake` (per the docstring at line 904-909 of `security_reminder_hook.py`), the model/agent can continue issuing further Bash tool calls — including additional `git commit`s — before this hook's fallback logic actually executes. If ≥5 additional commits land in the same repo between the quiet commit and the fallback's execution, the quiet commit's reflog entry is pushed entirely out of the `-n 5` window. It is then not present in either the `fresh` or `stale` buckets returned by `_git_reflog_recent_commits`, so `_reflog_shas` never contains it, and the handler exits via `skip_reason=21` (with `_skip_21_sub` in {2,3,4}) at line 991-997 without ever reviewing that commit.

The decoy commits, having non-suppressed stdout, are picked up and reviewed through the normal fast path (the `[branch sha]` regex match) on their own separate PostToolUse invocations, and get recorded into `sg-reviewed-shas` — so they appear "reviewed" while the actual malicious commit is not. The code's own safety commentary (`gitutil.py` lines 244-254) explicitly reasons about a *single* extra commit racing ahead ("HEAD raced ahead... both commits appear in the scan and both get reviewed — correct") but does not account for more than `max_n - 1` extra commits evicting the target entry from the fixed 5-entry window.

There is no existing check that verifies the specific commit produced by the triggering Bash call is still within the scanned reflog window before concluding "no commit happened" — the fallback silently treats eviction the same as "commit review already done" or "no commit."

### Impact Explanation
This allows an unprivileged agent action (a sequence of ordinary `git commit` Bash calls) to reliably suppress LLM-based security review of a specific commit's diff while unrelated decoys are reviewed, defeating the commit-review safety net (`ENABLE_COMMIT_REVIEW`) that is meant to catch vulnerabilities introduced by any commit. This maps to a trust-boundary/detection-bypass impact: a malicious or vulnerable commit escapes the automated security review pipeline that other, non-target commits go through, undermining the review-target binding invariant the hook is designed to enforce.

### Likelihood Explanation
Requires: `ENABLE_COMMIT_REVIEW=1` (default), a Bash-driven `git commit` invocation with stdout hidden (`-q`, piping, or redirection — a common and unremarkable pattern), and ≥5 subsequent `git commit`s in the same repo before the asyncRewake fallback executes. Since commit-review runs asynchronously and Claude Code can keep issuing tool calls in the interim, this is readily achievable within a single automated session (e.g., a burst of small fixup commits) and is fully repeatable — it does not depend on timing races beyond ordinary tool-call sequencing.

### Recommendation
Do not bound the reflog fallback scan to a small fixed `max_n`. Instead, widen the scan (or scan until reaching an entry older than `max_age_s`, or until reaching a known/previously-observed HEAD) so a burst of subsequent commits cannot silently evict a not-yet-reviewed entry from the window. Alternatively, capture and pin the specific commit's likely SHA at the time the triggering Bash tool call returns (rather than relying purely on a later, unbounded-in-time reflog re-scan) so eviction by unrelated later commits cannot suppress review of that specific commit.

### Proof of Concept
Integration test outline (extending existing tests around `handle_commit_review_posttooluse` / `_git_reflog_recent_commits`):
1. Initialize a temp git repo.
2. Make a quiet commit: `git commit -q -m "malicious" 2>&1 | tail -0` (stdout suppressed) — capture its SHA as `quiet_sha`.
3. Before invoking the hook's fallback logic, make 6 additional normal (loud) commits in the same repo — call `handle_commit_review_posttooluse` for each with normal stdout so they go through the fast path and get added to `sg-reviewed-shas`.
4. Now invoke `handle_commit_review_posttooluse` for the original quiet commit's tool_response (interrupted=False, empty/suppressed stdout) and assert:
   - `_git_reflog_recent_commits(repo_root)` does NOT return `quiet_sha` in `fresh` (nor count it in `stale`).
   - The hook exits with `skip_reason=21` and never calls `git show`/`analyze_code_security` on `quiet_sha`.
   - `quiet_sha` is absent from `sg-reviewed-shas` after the run, while all 6 decoy SHAs are present — demonstrating the malicious quiet commit escaped review while benign decoys were reviewed.

### Citations

**File:** plugins/security-guidance/hooks/security_reminder_hook.py (L965-989)
```python
    _reflog_shas: List[str] = []
    _skip_21_sub = 0
    if not commit_succeeded and not interrupted and cwd:
        _root = _git_toplevel(cwd)
        _fresh, _stale = _git_reflog_recent_commits(_root)
        if _fresh:
            _already = _load_reviewed_shas(_root)
            _reflog_shas = [s for s in _fresh if s not in _already]
            if _reflog_shas:
                commit_succeeded = True
                debug_log(
                    f"Commit review: stdout had no `[branch sha]`; reflog "
                    f"shows {len(_reflog_shas)} fresh unreviewed commit(s) "
                    f"({_reflog_shas[0][:12]}...)"
                )
            else:
                # Fresh commit(s) in reflog but all already in
                # sg-reviewed-shas — likely a Bash retry or the commit was
                # reviewed via a prior fire. Correct to skip; sub=2 lets telemetry
                # split this from genuine fails.
                _skip_21_sub = 2
        elif _stale:
            _skip_21_sub = 3  # commit entries exist but all >120s old
        else:
            _skip_21_sub = 4  # no commit-action entries — genuine fail
```

**File:** plugins/security-guidance/hooks/gitutil.py (L262-300)
```python
        r = subprocess.run(
            [*GIT_CMD, "log", "-g", "-n", str(max_n),
             "--format=%H|%ct|%gs", "HEAD"],
            cwd=repo_root, capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return [], 0
    if r.returncode != 0:
        return [], 0
    import time as _time
    now = int(_time.time())
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
